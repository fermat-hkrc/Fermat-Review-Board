# PoC Report: fscrypt ReadKeyFile() TOCTOU — Encryption Key Substitution

## Vulnerability Summary

| Field | Value |
|-------|-------|
| Component | OpenHarmony storage_service |
| File | `foundation/filemanagement/storage_service/services/storage_daemon/libfscrypt/src/fscrypt_control.c` |
| Function | `ReadKeyFile()` (line 277) |
| CWE | CWE-367 (Time-of-check Time-of-use Race Condition) |
| Severity | CRITICAL |
| Impact | Encryption key substitution → user data encrypted with attacker-controlled key |

## Root Cause

`ReadKeyFile()` validates file size via `stat()`, resolves path via `realpath()`, then opens and reads via `open()+read()`. Between these operations, file content can be atomically replaced:

```c
static int ReadKeyFile(const char *path, char *buf, size_t len) {
    struct stat st;
    stat(path, &st);                    // validates st.st_size == len
    // ← RACE WINDOW: file content can be atomically replaced
    char *realPath = realpath(path, NULL);
    // ← RACE WINDOW: content at realPath can change
    int fd = open(realPath, O_RDONLY);
    read(fd, buf, len);                 // reads potentially wrong key
}
```

Since fscrypt keys are fixed-size (8 bytes for descriptors, 32 bytes for identifiers), the attacker just needs to write a different key value of the same size — the size check always passes.

## Trigger Path (Full Call Chain)

```
ActSetFileXattr()                                    [fscrypt_control.c:417]
  → SpliceKeyPath(keyDir, ..., PATH_KEYDESC, ...) → pathBuf
  → ReadKeyFile(pathBuf, keyDesc, FSCRYPT_KEY_DESCRIPTOR_SIZE)
    → stat(path, &st)                               ← size check (8 == 8)
    → realpath(path, NULL)                           ← resolve
    → open(realPath, O_RDONLY)                       ← open
    → read(fd, buf, 8)                              ← reads substituted key
  → memcpy_s(PolicySDP.masterKeyDescriptor, ..., keyDesc, ...)
  → ioctl(dirFd, F2FS_IOC_SET_SDP_ENCRYPTION_POLICY, &PolicySDP)
```

Also called from:
- `SetPolicyLegacy()` → `ReadKeyFile(pathBuf, keyDesc, FSCRYPT_KEY_DESCRIPTOR_SIZE)` [line 319]
- `SetPolicyV2()` → `ReadKeyFile(keyIdPath, keyId, FSCRYPT_KEY_IDENTIFIER_SIZE)` [line 344]
- `KeyCtrlLoadAndSetPolicyLegacy()` → `ReadKeyFile(pathBuf, keyDesc, ...)` [line 471]

## Build Environment

- **OS**: Linux (any)
- **Compiler**: GCC
- **Dependencies**: pthreads
- **Build command**: `gcc -o poc poc.c -lpthread -O2`

## Reproduction Steps

1. Compile: `gcc -o poc poc.c -lpthread -O2`
2. Run: `./poc`
3. Observe the key substitution race win

## PoC Output

```
=== fscrypt ReadKeyFile() TOCTOU PoC ===
Target: OpenHarmony storage_service libfscrypt/src/fscrypt_control.c
Bug: stat() validates size, then open()+read() — content can change
Impact: Encryption key substitution → data encrypted with attacker key

[*] Key file: /tmp/poc_fscrypt_keys/key_desc (8 bytes)
[*] Legitimate key: AABBCCDDEEFF1122
[*] Evil key:       DEADBEEFCAFEBABE

[!] RACE WON at iteration 626!
[!] Expected key: AABBCCDDEEFF1122
[!] Got key:      DEADBEEFCAFEBABE

[+] PoC SUCCESS: Key substitution via TOCTOU
[+] Real-world impact:
[+]   1. Compromised service races storage daemon's key loading
[+]   2. fscrypt policy is set with attacker's key descriptor
[+]   3. User data encrypted with attacker-controlled key
[+]   4. Attacker can later decrypt the data

[+] Fix: Open file first (O_NOFOLLOW), fstat() the fd, then read.
[+]       Never stat() a path and then open() it separately.
```

## Real-World Attack Scenario

1. A compromised system service or kernel module has write access to key storage directory (`/data/service/el2/{userId}/crypto/`)
2. Attacker monitors for user login events (key loading occurs during user session start)
3. During the brief window when storage_daemon loads the fscrypt key, attacker writes their own key material to the key file
4. storage_daemon reads the attacker's key and sets the fscrypt policy with it
5. All new files created by the user are encrypted with the attacker's key
6. Attacker can later decrypt the user's data using their known key

## Preconditions

- Attacker needs write access to the fscrypt key storage directory
- This is achievable via: compromised system service running as `storage_daemon` group, kernel vulnerability granting arbitrary file write, or SELinux policy misconfiguration
- The race window is wide because `realpath()` adds significant latency between `stat()` and `open()`

## Fix Recommendation

Use fd-based operations to eliminate the TOCTOU:

```c
static int ReadKeyFile(const char *path, char *buf, size_t len) {
    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) return -EFAULT;
    struct stat st;
    if (fstat(fd, &st) != 0 || (size_t)st.st_size != len) {
        close(fd); return -EINVAL;
    }
    if (read(fd, buf, len) != (ssize_t)len) {
        close(fd); return -EBADF;
    }
    close(fd);
    return 0;
}
```
