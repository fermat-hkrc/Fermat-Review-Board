# PoC Report: Arbitrary Write-Zero via dead() (syscall_dispatcher.c:933)

## Vulnerability Summary

| Field | Value |
|-------|-------|
| Component | OpenHarmony tee_os_kernel |
| File | syscall_dispatcher.c:933 |
| Function | `dead()` |
| Type | Arbitrary Memory Write (CWE-123) |
| Impact | Arbitrary write-zero primitive; TEE kernel compromise |
| Severity | Critical |
| Platform | All (deterministic, no race condition required) |

## Root Cause

The `dead()` function is called when an unsupported syscall number is passed to `__syscall6`. Instead of simply logging and aborting, it casts the syscall number (a user-controlled `long`) to a pointer and writes zero to it:

```c
void dead(long n)
{
    printf("Unsupported syscall %d, bye.\n", n);
    volatile int *addr = (int *)n;
    *addr = 0;  // Writes zero to attacker-controlled address
}
```

The syscall number register is directly controlled by the calling TA. A malicious TA simply invokes an SVC/HVC with a register value set to the target address.

## Trigger Path

1. Malicious TA prepares a target address (e.g., a kernel permission flag, page table entry, or function pointer).
2. TA invokes a syscall via SVC with the syscall number register set to the target address value.
3. `__syscall6` dispatcher doesn't recognize the number, calls `dead(target_address)`.
4. `dead()` dereferences `target_address` and writes zero to it.
5. Result: arbitrary 4-byte zero-write to any mapped TEE kernel address.

## Build Environment

```
Compiler: gcc (any version)
Flags:    gcc -o poc poc.c -O2
```

## Reproduction Steps

1. Compile: `gcc -o poc poc.c -O2`
2. Run: `./poc`
3. Observe that heap variables are zeroed by passing their address as syscall number.
4. Observe SIGSEGV when unmapped address is used (DoS demonstration).

## Expected Output

```
=== PoC: Arbitrary Write-Zero via dead() (syscall_dispatcher.c:933) ===
...
[Test 1] Write-zero to heap variable via crafted syscall number
  Before: *target = 0x41414141 (at 0x...)
  ...
  After:  *target = 0x00000000
  [VULNERABLE] Successfully wrote zero to arbitrary address!

[Test 2] Overwrite security flag (simulated auth bypass)
  auth_required = 1 (authentication enforced)
  ...
  auth_required = 0 (authentication BYPASSED!)

[Test 3] DoS via write to unmapped address
  [CRASH] SIGSEGV caught! TEE kernel would panic here.
```

## Real-World Attack Scenario

This is a deterministic, single-shot exploit with no timing dependency:

1. **Authentication bypass**: Zero out TA verification flags to load unsigned code in the TEE.
2. **Privilege escalation**: Zero out permission bitmasks in proc_node or session structures.
3. **Code execution**: Zero part of a function pointer (partial overwrite), redirecting execution to a controlled address aligned to a zero-containing page.
4. **Denial of Service**: Pass an unmapped address to crash the TEE kernel, forcing a device reboot.
5. **Chain with info leak**: If an info-leak exists, attacker can identify exact addresses of kernel structures, then zero critical fields.

The vulnerability is trivially exploitable because:
- No race condition needed (single syscall triggers it)
- No heap spray needed (direct address write)
- Attacker fully controls the target address
- The write-zero primitive is sufficient for many exploitation techniques

## Fix Recommendation

Remove the pointer dereference entirely. The function should log and abort/panic without dereferencing user-controlled values:

```c
void dead(long n)
{
    printf("FATAL: Unsupported syscall %ld from TA. Terminating session.\n", n);
    /* Kill the offending TA session, do NOT dereference n */
    abort_ta_session(current_session());
}
```

Additionally, validate syscall numbers at the dispatcher entry point before they reach any handler:

```c
if (syscall_num < 0 || syscall_num >= NR_SYSCALLS) {
    log_error("Invalid syscall %ld", syscall_num);
    return -ENOSYS;
}
```
