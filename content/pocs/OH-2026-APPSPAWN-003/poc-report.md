# PoC Report: TOCTOU Race Condition in OpenHarmony appspawn HNP Installer

## Vulnerability Summary

| Field | Value |
|-------|-------|
| Component | appspawn (HNP installer) |
| File | `base/startup/appspawn/modules/hnp/hnp_file.c:178` |
| Function | `HnpDeleteFolder` |
| Type | CWE-367: TOCTOU Race Condition |
| Impact | Arbitrary directory deletion (DoS / privilege boundary bypass) |
| Severity | High |

## Root Cause

`HnpDeleteFolder` and its callers (`HnpUnInstall`, `HnpInstallForceCheck`) use a check-then-act pattern:

1. `access(path, F_OK)` verifies the path exists (CHECK)
2. Processing occurs (package info parsing, logging)
3. `HnpDeleteFolder(path)` recursively deletes contents (USE)

Between steps 1 and 3, a malicious app running under the same UID can replace the directory at `path` with a symlink pointing to an arbitrary directory. Since `opendir()` follows symlinks, the deletion is redirected to the symlink target.

## Affected Code Paths

### HnpDeleteFolder (hnp_file.c:178)
- `opendir(path)` follows symlinks without `O_NOFOLLOW` equivalent
- Recursive deletion traverses through the symlinked target

### HnpUnInstall (hnp_installer.c:422)
- `access(dstPath, F_OK)` then later `HnpDeleteFolder(privatePath)`
- Gap includes package info processing

### HnpInstallForceCheck (hnp_installer.c:474)
- `access(hnpSoftwarePath, F_OK)` then `HnpDeleteFolder(hnpSoftwarePath)`
- Force-reinstall path is exploitable

## Build Environment

- OS: Linux (any glibc-based system)
- Compiler: GCC
- Build command: `gcc -o poc poc.c -lpthread -O2`
- No external dependencies beyond pthreads

## Reproduction Steps

```bash
gcc -o poc poc.c -lpthread -O2
./poc
```

## Expected Output

```
=== OpenHarmony appspawn HNP TOCTOU PoC ===
Target: HnpDeleteFolder race condition (hnp_file.c:178)
Vector: Symlink replacement between access() and opendir()

[*] Test environment created:
    HNP path (will be replaced): /tmp/hnp_toctou_poc/data/hnp/1000/hnp/com.example.pkg
    Victim directory:            /tmp/hnp_toctou_poc/victim_credential_store

[*] Before attack:
    HNP dir exists: YES
    Victim file exists: YES

[appspawn] Starting HNP uninstall for com.example.pkg...
[appspawn] access() check passed, path exists
[attacker] Race window detected! Replacing directory with symlink
[attacker] Symlink created: /tmp/hnp_toctou_poc/.../com.example.pkg -> /tmp/hnp_toctou_poc/victim_credential_store
[appspawn] Calling HnpDeleteFolder("...")

=== Results ===
[+] Race condition exploited successfully
[+] Symlink replacement completed during TOCTOU window
[+] VICTIM FILE DELETED: /tmp/hnp_toctou_poc/victim_credential_store/device_auth.key

[VULNERABLE] The TOCTOU race in HnpDeleteFolder allows
             arbitrary directory deletion via symlink replacement.
             Impact: Deletion of credential stores, system configs,
             or other app data accessible to the uid.
```

## Attack Scenario (On-Device)

1. Malicious app installs legitimately, gaining access to `/data/hnp/{uid}/`
2. App sets up inotify watch on its own HNP directory
3. When a legitimate HNP uninstall is triggered (e.g., OTA update, user uninstall)
4. App detects `access()` via inotify `IN_ACCESS` event on the path
5. App atomically replaces the directory: `rename()` + `symlink()` to target
6. `HnpDeleteFolder` follows the symlink, deleting the target directory

Practical targets include:
- `/data/service/el1/public/deviceauth/` (device credential store)
- `/data/service/el1/public/huks_service/` (key management)
- Other apps' private data directories under the same UID

## Fix Recommendation

1. Use `openat()` with `O_NOFOLLOW` + `O_DIRECTORY` to open directories
2. Use `fstatat()` with `AT_SYMLINK_NOFOLLOW` for path checks
3. Perform operations relative to directory file descriptors (`unlinkat`, `fdopendir`)
4. Alternatively, validate the path does not contain symlink components using `realpath()` immediately before use, and re-check after `opendir()`

## PoC Technique Notes

The PoC simulates the race deterministically by signaling between threads. In a real attack:
- The race window is widened by kernel scheduling and the processing between CHECK and USE
- inotify provides reliable detection of the access() syscall
- `rename()` + `symlink()` is atomic enough on ext4/f2fs to win the race reliably
- Multiple attempts can be made as HNP operations are retriggerable
