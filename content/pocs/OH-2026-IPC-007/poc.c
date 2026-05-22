/*
 * Target-Compile PoC: RegisterSensorChannel Uninitialized Memory (CWE-908)
 *
 * Target: sensors_sensor_lite — frameworks/src/sensor_agent_proxy.c
 * Vulnerable function: RegisterSensorChannel (line 272)
 *
 * Trigger path:
 *   RegisterSensorChannel(proxy, sensorId=0)
 *     → IsRegisterCallback() = false (first registration)
 *     → g_sensorEvent = malloc(sizeof(SensorEvent))  ← no memset/calloc
 *     → client->Invoke returns SENSOR_OK
 *     → g_sensorEvent retains heap residual data
 *
 * Verification:
 *   BEFORE patch (malloc): g_sensorEvent contains uninitialized heap data
 *   AFTER  patch (calloc): all bytes zeroed, no ASan trigger
 *
 * Build (target-compile):
 *   clang -c -Dstatic= -O0 -g \
 *       -I sensors_sensor_lite/interfaces/kits/native/include \
 *       -I <ohos-toolkit-stubs> \
 *       -I sensors_sensor_lite/frameworks/include \
 *       -I sensors_sensor_lite/services/include \
 *       sensors_sensor_lite/frameworks/src/sensor_agent_proxy.c -o sensor_agent_proxy.o
 *
 *   clang++ -O0 -fsanitize=address -fno-omit-frame-pointer \
 *       -o poc_bin sensor_agent_proxy.o cJSON.o ohos_stubs.o poc.o memcpy_s.o \
 *       -lpthread -lstdc++
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

extern SensorEvent *g_sensorEvent;
extern IpcObjectStub g_objectStub;
extern SvcIdentity g_svcIdentity;

#define REAL_SENSOR_MAX 30
extern void *g_callbackNodes[REAL_SENSOR_MAX];

static int MockInvoke(struct IClientProxy *proxy, int funcId, IpcIo *request,
                      void *owner, int (*notify)(void*, int, IpcIo*))
{
    if (owner) *((int32_t*)owner) = 0;
    return 0;
}
static int MockQueryInterface(void *iUnknown, int version, void **target) { return 0; }
static int MockAddRef(void *iUnknown) { return 1; }
static int MockRelease(void *iUnknown) { return 0; }

int main(void)
{
    g_sensorEvent = NULL;
    memset(g_callbackNodes, 0, sizeof(void*) * REAL_SENSOR_MAX);

    IClientProxy mockProxy;
    mockProxy.QueryInterface = (QueryInterface)MockQueryInterface;
    mockProxy.AddRef = (AddRef)MockAddRef;
    mockProxy.Release = (Release)MockRelease;
    mockProxy.Invoke = (int (*)(struct IClientProxy*, int, IpcIo*, void*,
                                int (*)(void*, int, IpcIo*)))MockInvoke;

    int32_t ret = RegisterSensorChannel((const void *)&mockProxy, 0);
    fprintf(stderr, "[POC] RegisterSensorChannel returned: %d\n", ret);

    if (g_sensorEvent != NULL) {
        fprintf(stderr, "[POC] g_sensorEvent allocated at %p\n", (void*)g_sensorEvent);
        fprintf(stderr, "[POC] sensorTypeId=%d, dataLen=%d, version=%d\n",
                g_sensorEvent->sensorTypeId, g_sensorEvent->dataLen, g_sensorEvent->version);

        unsigned char *bytes = (unsigned char *)g_sensorEvent;
        int all_zero = 1;
        for (size_t i = 0; i < sizeof(SensorEvent); i++) {
            if (bytes[i] != 0) { all_zero = 0; break; }
        }
        if (all_zero) {
            fprintf(stderr, "[POC] calloc zeroed all memory (patch effective)\n");
        } else {
            fprintf(stderr, "[POC] memory contains non-zero bytes (uninitialized)\n");
        }
        free(g_sensorEvent);
        g_sensorEvent = NULL;
    }

    return 0;
}
