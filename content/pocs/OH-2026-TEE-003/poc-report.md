# PoC Report: DCLP Race in __self_init (drv_io_share.c:33)

## Vulnerability Summary

| Field | Value |
|-------|-------|
| Component | OpenHarmony tee_os_kernel |
| File | drv_io_share.c:33 |
| Function | `__self_init()` |
| Type | Race Condition (Broken Double-Checked Locking Pattern) |
| Impact | Use of uninitialized/partially-initialized hash table; double-free on re-init |
| Severity | High |
| Platform | ARM (AArch64) - weak memory ordering required |

## Root Cause

The `__self_init()` function implements a Double-Checked Locking Pattern (DCLP) that is broken on ARM's weak memory model:

1. The first read of `io_init` (line 33) occurs outside the mutex with no acquire barrier.
2. On ARM, store-store reordering means Thread A can set `io_init = true` before `init_htable()`'s stores to `addr2ent` are globally visible.
3. Thread B reads `io_init == true` (relaxed), skips initialization, and uses `addr2ent` while its internal fields (buckets pointer, size) are still zero/stale.
4. Additionally, the reset/re-init path creates a window where `init_htable` is called multiple times, causing double-free of `addr2ent.buckets`.

## Trigger Path

1. TEE kernel boots, multiple TA threads start concurrently.
2. Each TA thread calls into I/O sharing code, which calls `__self_init()`.
3. Thread A enters the mutex, begins `init_htable()`.
4. Thread A sets `io_init = true` (ARM may reorder this before init completes).
5. Thread B reads `io_init == true` without barrier, returns early.
6. Thread B uses `addr2ent` with NULL buckets pointer -> NULL dereference or corruption.

## Build Environment

```
Compiler: gcc (any version with pthread support)
Flags:    gcc -o poc poc.c -lpthread -O2
TSan:     gcc -fsanitize=thread -o poc poc.c -lpthread (recommended)
Target:   x86_64 for PoC; bug manifests reliably on ARM/AArch64
```

## Reproduction Steps

1. Compile: `gcc -o poc poc.c -lpthread -O2`
2. Run: `./poc`
3. Observe double-init count > 0 and/or use-before-init events.
4. For guaranteed detection: `gcc -fsanitize=thread -o poc poc.c -lpthread && ./poc`
5. ThreadSanitizer will report data races on `io_init` and `addr2ent` fields.

## Expected Output

```
=== PoC: DCLP Race in __self_init (drv_io_share.c:33) ===
...
[BUG] Double initialization detected! Thread XXXX re-initializing already-initialized htable
...
[VULNERABLE] Race condition confirmed!
```

## Real-World Attack Scenario

A malicious Trusted Application (TA) running in the TEE can:

1. Spawn multiple threads that simultaneously trigger I/O sharing operations.
2. Exploit the race window to use `addr2ent` while partially initialized.
3. The NULL `buckets` pointer dereference causes a kernel crash (DoS).
4. With heap spray techniques, a controlled value at the NULL-page (if mappable) could redirect hash table lookups, leading to arbitrary read/write in the TEE kernel address space.
5. This breaks TEE isolation guarantees, potentially leaking secure world secrets.

## Fix Recommendation

Replace the broken DCLP with `pthread_once` or use proper atomic operations:

```c
#include <stdatomic.h>

static atomic_bool io_init = false;

static void __self_init(void)
{
    if (atomic_load_explicit(&io_init, memory_order_acquire)) {
        return;
    }
    pthread_mutex_lock(&lock);
    if (!atomic_load_explicit(&io_init, memory_order_relaxed)) {
        init_htable(&addr2ent, HTABLE_SIZE);
        atomic_store_explicit(&io_init, true, memory_order_release);
    }
    pthread_mutex_unlock(&lock);
}
```

Or preferably, use `pthread_once()` which handles all barriers correctly.
