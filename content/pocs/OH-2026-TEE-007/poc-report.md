# PoC Report: Buffer Overflow in copy_from_shared_buffer (OEM Key Driver)

## Vulnerability Summary

| Field | Value |
|-------|-------|
| Component | tee_os_framework / tee_oemkey_driver.c |
| Function | `copy_from_shared_buffer()` (line 38) |
| Type | Buffer Overflow (memcpy_s safety bypass) |
| Trigger | CA supplies large buf_size via shared memory |
| Impact | Stack/heap buffer overflow in Secure World |
| Severity | Critical (deterministic, no race needed) |

## Root Cause

The function reads `buf_size` from attacker-controlled shared memory, then calls:

```c
memcpy_s(buf, *buf_size, shared_buf, *buf_size)
```

The `memcpy_s` signature is: `memcpy_s(dest, destMax, src, count)`

Here, both `destMax` and `count` are set to the same attacker-controlled `*buf_size`. The safety check in `memcpy_s` is `count <= destMax`, which is trivially `*buf_size <= *buf_size` — always true. This completely negates the purpose of `memcpy_s`.

The actual destination buffer `buf` is allocated by the caller with a fixed size (e.g., 256 bytes for OEM key storage), but `memcpy_s` has no knowledge of this real size since `destMax` is provided by the attacker.

## Trigger Path

```
CA (Normal World)                              TA (Secure World)
─────────────────                              ─────────────────
1. Place [size=4096][payload*4096]
   in shared memory
2. Invoke OEM key ioctl
                                               3. Allocate key_buf[256] on stack
                                               4. Call copy_from_shared_buffer(
                                                    key_buf, &size, shared_mem)
                                               5. Read size=4096 from shared_mem
                                               6. memcpy_s(key_buf, 4096,
                                                    shared_buf, 4096)
                                                  → check: 4096 <= 4096 ✓
                                                  → copies 4096 bytes into
                                                    256-byte buffer
                                               7. STACK OVERFLOW → ROP/shellcode
```

## Build Environment

- Compiler: GCC (any version supporting C99)
- OS: Linux (simulates TEE execution environment)
- Command: `gcc -o poc poc.c -lpthread -O2`
- For crash demonstration: `gcc -o poc poc.c -lpthread -O2 -fno-stack-protector`

## Reproduction Steps

1. Compile: `gcc -o poc poc.c -lpthread -O2`
2. Run: `./poc`
3. Observe: The PoC demonstrates that memcpy_s allows copying 1024 bytes into a 256-byte logical buffer because destMax == count

Expected output:
```
[memcpy_s] ALLOWED: count(1024) <= destMax(1024) - copying...
Logical buffer size: 256 bytes
Attacker-controlled size: 1024 bytes
Bytes written past logical boundary: 768
VERIFIED: Attacker data (0x41) found at offset 256 (past buffer end)
STATUS: BUFFER OVERFLOW CONFIRMED
```

## Real-World Attack Scenario

A malicious CA on an OpenHarmony device:
1. Opens a session with the OEM Key TA
2. Prepares shared memory with `buf_size = 4096` and a ROP payload
3. Invokes the OEM key operation ioctl
4. The TA's `copy_from_shared_buffer` overflows the stack buffer with attacker data
5. Return address is overwritten with ROP gadget addresses
6. On function return, execution jumps to attacker's ROP chain

This is a deterministic exploit — no race condition or heap grooming needed. A single ioctl call is sufficient to achieve code execution in the Trusted Execution Environment, compromising:
- Hardware-backed key storage
- DRM secrets
- Biometric data
- Secure boot chain

## Fix Recommendation

The caller must pass the actual buffer size as a separate parameter, independent of shared memory:

```c
static int32_t copy_from_shared_buffer(void *buf, uint32_t buf_capacity,
                                        uint32_t *buf_size, uint8_t *shared_buf)
{
    if (buf_size == NULL || buf == NULL)
        return -1;

    if (memcpy_s(buf_size, sizeof(uint32_t), shared_buf, sizeof(uint32_t)) != EOK)
        return -1;

    shared_buf += sizeof(uint32_t);

    /* Validate against ACTUAL buffer capacity, not attacker-supplied size */
    if (*buf_size > buf_capacity) {
        tloge("buf_size %u exceeds capacity %u\n", *buf_size, buf_capacity);
        return -1;
    }

    if (memcpy_s(buf, buf_capacity, shared_buf, *buf_size) != EOK)
        return -1;

    return 0;
}
```
