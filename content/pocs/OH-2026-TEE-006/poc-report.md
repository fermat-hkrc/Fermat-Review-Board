# PoC Report: Shared Memory TOCTOU in copy_from_shared_buf

## Vulnerability Summary

| Field | Value |
|-------|-------|
| Component | tee_os_framework / crypto_syscall_common.c |
| Function | `copy_from_shared_buf()` (line 149) |
| Type | TOCTOU (Time-of-Check to Time-of-Use) Race Condition |
| Trigger | Malicious CA modifies shared memory between validation and use |
| Impact | Out-of-bounds pointer advance; TEE memory read/write outside shared buffer |
| Severity | High (Secure World memory corruption from Normal World) |

## Root Cause

The function `check_share_mem_size()` validates all `buf_size` fields in shared memory to ensure they fit within the allocated buffer. Then `copy_from_shared_buf()` re-reads these same `buf_size` values from shared memory to process them. Since shared memory is mapped into both Normal World (CA) and Secure World (TA), a malicious CA can modify `buf_size` after validation but before the second read.

The critical double-read pattern:
1. `check_share_mem_size()` reads `buf_size` from `shared_buf` → validates total fits in bounds
2. **TOCTOU WINDOW** — CA overwrites `buf_size` with a large value
3. `copy_from_shared_buf()` re-reads `buf_size` from the same `shared_buf` location → gets attacker's new large value
4. `*shared_buf += *buf_size` advances the cursor past the shared memory boundary
5. Subsequent accesses operate on TEE-internal memory

## Trigger Path

```
CA (Normal World)                         TA (Secure World)
─────────────────                         ─────────────────
1. Setup shared mem with valid sizes
2. Invoke crypto ioctl
                                          3. check_share_mem_size() → PASS
4. Racing thread overwrites buf_size
   with 0xFFFFFFFF
                                          5. copy_from_shared_buf() re-reads
                                             buf_size → gets 0xFFFFFFFF
                                          6. shared_buf += 0xFFFFFFFF → OOB
                                          7. Next read/write corrupts TEE mem
```

## Build Environment

- Compiler: GCC (any version supporting C99)
- OS: Linux (simulates the CA/TA shared memory model)
- Command: `gcc -o poc poc.c -lpthread -O2`

## Reproduction Steps

1. Compile: `gcc -o poc poc.c -lpthread -O2`
2. Run: `./poc`
3. The PoC spawns a racing thread that flips `buf_size` in shared memory
4. The main thread repeatedly invokes the simulated TEE path
5. When the race is won, OOB pointer advance is reported

Expected output (race won):
```
[TEE] check_share_mem_size PASSED: total_offset=72 <= len=256
[TEE] buf1: size=4096, ptr=0x...
[TEE] *** OOB DETECTED: cursor=0x... > end=0x... (overrun by 3868 bytes) ***
STATUS: RACE WON - Out-of-bounds pointer advance demonstrated!
```

## Real-World Attack Scenario

A malicious Android/OpenHarmony application installs a CA that:
1. Opens a session with the Crypto TA via the TEE driver
2. Allocates shared memory and populates it with valid crypto operation parameters
3. Spawns a thread that continuously flips `buf_size` fields between valid and overflow values
4. Repeatedly invokes the crypto ioctl
5. When the race hits: the TEE processes data at arbitrary addresses in Secure World

This enables:
- **Information disclosure**: Reading TEE secrets (keys, attestation data) past the shared buffer
- **Code execution in Secure World**: Writing attacker-controlled data to TEE heap/stack via the `buf_ptr` returned by `copy_from_shared_buf` (subsequent crypto operations use this pointer)
- **Full TEE compromise**: Combined with heap spray, achieves arbitrary code execution in S-EL1

## Fix Recommendation

Copy all parameters from shared memory into a TEE-local buffer **once**, then operate exclusively on the local copy:

```c
/* Fix: Single copy into local buffer, never re-read from shared memory */
static int get_share_mem(uint8_t *shared_buf, uint32_t shared_buf_len)
{
    uint8_t *local_buf = tee_malloc(shared_buf_len);
    if (!local_buf)
        return CRYPTO_ERROR_SECURITY;

    /* Single atomic copy - no TOCTOU possible after this point */
    if (memcpy_s(local_buf, shared_buf_len, shared_buf, shared_buf_len) != EOK) {
        tee_free(local_buf);
        return CRYPTO_ERROR_SECURITY;
    }

    /* All validation and parsing operates on local_buf only */
    if (check_share_mem_size(local_buf, shared_buf_len) != 0) {
        tee_free(local_buf);
        return CRYPTO_ERROR_SECURITY;
    }

    /* Parse from local_buf - values cannot change */
    ...
}
```
