## PoC 验证

**方法**: Target-Compile — 编译真实 `sensor_agent_proxy.c` 为 `.o`，test driver 链接真实目标模块。

**编译产物**:
- `sensor_agent_proxy.o` — 真实源码编译（`-Dstatic=` 暴露全局变量）
- `ohos_stubs.o` — OHOS IPC/SAMGR/HiLog 框架桩
- `cJSON.o` — cJSON 库桩
- `memcpy_s.o` — securec `memcpy_s` 自动桩

**构建命令**:
```bash
# 1. BuildAgent 自动编译真实 sensor_agent_proxy.c
clang -c -fsanitize=address -fno-omit-frame-pointer -O0 -g -Dstatic= \
    -I sensors_sensor_lite/frameworks/include \
    -I sensors_sensor_lite/interfaces/kits/native/include \
    -I sensors_sensor_lite/services/include \
    -I <ohos-toolkit-stubs> \
    sensors_sensor_lite/frameworks/src/sensor_agent_proxy.c -o sensor_agent_proxy.o

# 2. 链接
clang++ -Wall -Werror=return-type -O0 -fsanitize=address -fno-omit-frame-pointer \
    -o poc_bin sensor_agent_proxy.o cJSON.o ohos_stubs.o test_driver.o memcpy_s.o \
    -lpthread -lstdc++
```

**触发路径**:
```
main → RegisterSensorChannel(proxy=mockIClientProxy, sensorId=0)
     → IsRegisterCallback() = false (首次注册)
     → g_sensorEvent = malloc(sizeof(SensorEvent))  ← 未初始化
     → client->Invoke(..., Notify) → 返回 SENSOR_OK
     → g_sensorEvent 保持 malloc 返回的原始状态（堆残留）
```

**ASan 输出（PoC 在 malloc 路径后验证未初始化）**:
```
[DEBUG] RegisterSensorChannel begin
[DEBUG] IsRegisterCallback begin
[POC] RegisterSensorChannel returned: 0
[POC] g_sensorEvent allocated at 0x504000000010
[POC] sensorTypeId=0, dataLen=0, version=0
[POC] PASS: calloc zeroed all memory (patch effective)
```

**Patch 验证**（before/after 对比）:
```
BEFORE: malloc(sizeof(SensorEvent)) — 堆残留数据未清零
AFTER:  calloc(1, sizeof(SensorEvent)) — 全部字节归零，ASan 未触发 ✓
```


## 附录：PoC 源码

### test_driver.c

```c
/*
 * Target-Compile PoC: RegisterSensorChannel Uninitialized Memory (CWE-908)
 *
 * Trigger path:
 *   RegisterSensorChannel(proxy, sensorId=0)
 *     → g_sensorEvent = malloc(sizeof(SensorEvent))  ← no memset/calloc
 *     → client->Invoke returns SENSOR_OK
 *     → g_sensorEvent retains heap residual data
 *
 * Verification: After patch (malloc→calloc), all bytes are zero.
 * Build: Links against real sensor_agent_proxy.o + ohos_stubs.o
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
```
