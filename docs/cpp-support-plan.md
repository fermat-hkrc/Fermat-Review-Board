# OHOS Build Toolkit: C++ 模块支持计划

## 目标

扩展 `~/data/ohos-build-toolkit/` 使其支持编译 OHOS C++ 模块为静态库（.a），
用于 Target-Compile PoC 验证。当前工具链仅支持纯 C 模块。

## 当前状态

| 能力 | 支持 |
|------|------|
| C 模块编译为 .a | 已支持 |
| gcc/g++ + ASan + UBSan | 已支持 |
| 客户端桩（IpcIo/SAMGR/HiLog） | 已支持（ohos_stubs.c） |
| 服务端桩（HalMalloc/HalFree） | 已支持（hal_stubs.c） |
| C++ 模块编译 | **已支持** ✓ |
| OHOS C++ 基础类桩（RefBase/sptr/IRemoteBroker） | **已支持** ✓ |
| OHOS IPC 框架桩（MessageParcel/Parcel） | **已支持** ✓ |
| NAPI/JS 绑定桩 | 未支持 |
| setup_build.py C++ 自动检测 | 未支持 |

## 实施步骤

### Phase 1: C++ 编译器支持 — COMPLETE ✓

**验证日期**：2026-05-17

`custom_build/toolchain/BUILD.gn` 已有 `cxx` 工具定义。`cflags_cc` 配置为 `-std=c++17 -fno-rtti`。

已验证 castengine_wifi_display 的 C++ 源码编译通过（rtp_packet.cpp, data_buffer.cpp, rtp_poc.cpp）。

**关键技术发现**：GN 的 `set_defaults()` 不会将 cflags 传播到各个 target。ASan 标志（`-fsanitize=address,undefined`）必须在每个 target 的 `configs` 列表中显式声明。这是导致 RtpPacket PoC 无法触发 ASan 的根本原因——代码在未启用 ASan 插桩的情况下编译，但链接了 ASan 运行时，导致越界读取静默通过。

修复方法：在每个 `static_library` 和 `executable` target 的 BUILD.gn 中添加：
```gn
config("asan_config") {
  cflags = ["-Wall", "-O0", "-g", "-fPIC", "-fsanitize=address,undefined", "-fno-sanitize-recover=undefined"]
  cflags_cc = ["-std=c++17", "-fno-rtti", "-Wno-non-virtual-dtor"]
  ldflags = ["-fsanitize=address,undefined", "-lstdc++", "-lm", "-lpthread"]
}
```

当前工具链只定义了 `cc`（C 编译器）。需要添加 `cxx`（C++ 编译器）。

```python
# custom_build/toolchain/BUILD.gn
tool("cxx") {
    depfile = "{{output}}.d"
    command = "g++ -MMD -MF $depfile {{defines}} {{include_dirs}} {{cflags}} {{cflags_cc}} -c {{source}} -o {{output}}"
    depsformat = "gcc"
    description = "CXX {{output}}"
    outputs = [ "{{source_out_dir}}/{{target_output_name}}.{{source_name_part}}.o" ]
}
```

同时需要 `cflags_cc` 配置：

```python
# custom_build/configs/BUILD.gn
config("gcc_defaults") {
    cflags = [ "-Wall", "-O0", "-g", "-fPIC", "-fsanitize=address,undefined" ]
    cflags_cc = [ "-std=c++17", "-fno-exceptions", "-fno-rtti" ]
    ldflags = [ "-fsanitize=address,undefined", "-lstdc++", "-lm", "-lpthread" ]
}
```

**注意**：OHOS 使用 `-fno-exceptions` 和 `-fno-rtti` 以减小二进制体积。
如果目标模块依赖异常或 RTTI，需要移除这些标志。

### Phase 2: OHOS C++ 基础类桩 — COMPLETE ✓

**验证日期**：2026-05-17

已实现并验证的桩代码在 `~/data/ohos-build-toolkit/stubs/ohos_cpp_stubs.h`：
- RefBase（侵入式引用计数基类）
- sptr\<T\>（智能指针模板）
- Parcel / MessageParcel（IPC 数据序列化）
- IRemoteObject（IPC 远程对象基类）
- IRemoteBroker（IPC 代理接口）
- IPCSkeleton（GetCallingPid/Uid/TokenID 静态方法）
- HiLog C++ 版本

已通过以下模块的编译 + ASan 触发验证：
- DataBuffer（CWE-170）：拷贝构造函数 heap-buffer-overflow
- RtpPacket（CWE-125）：GetCsrcData 越界读取 heap-buffer-overflow

**注意**：当前 DataBuffer 和 RtpPacket 模块不需要 OHOS 框架桩（仅依赖标准库 + securec），因此 Phase 2 桩代码虽然已编写，尚未在需要 IPC 框架的模块中实际测试。

这是最大的工作量。OHOS C++ 模块普遍依赖以下基础类：

**2.1 RefBase / sp / wp（智能指针）**

路径：`commonlibrary/utils_lite/include/` 或 `utils/native/base/include/refbase.h`

OHOS 的 `sptr<T>` 是 intrusive smart pointer，类似于 Android 的 `sp<T>`。
每个使用 RefBase 的类都必须继承 `RefBase`。

最小桩：

```cpp
// stubs/ohos_cpp_stubs.h
class RefBase {
public:
    RefBase() : refCount_(1) {}
    virtual ~RefBase() = default;
    void IncRef() { refCount_++; }
    void DecRef() { if (--refCount_ == 0) delete this; }
private:
    int refCount_;
};

template<typename T>
class sptr {
public:
    sptr() : ptr_(nullptr) {}
    sptr(T* p) : ptr_(p) { if (p) p->IncRef(); }
    sptr(const sptr& other) : ptr_(other.ptr_) { if (ptr_) ptr_->IncRef(); }
    ~sptr() { if (ptr_) ptr_->DecRef(); }
    T* operator->() const { return ptr_; }
    T* GetRefPtr() const { return ptr_; }
    operator bool() const { return ptr_ != nullptr; }
private:
    T* ptr_;
};
```

**2.2 IRemoteObject / IRemoteBroker / MessageParcel（IPC 框架）**

路径：`foundation/communication/ipc/interfaces/innerkits/`

OHOS IPC 的核心接口。服务端 `OnRemoteRequest` 接收 `MessageParcel`。

最小桩：

```cpp
class Parcel {
public:
    bool WriteInt32(int32_t value) { /* mock */ return true; }
    int32_t ReadInt32() { /* mock */ return 0; }
    bool WriteString(const std::string& value) { /* mock */ return true; }
    const std::string ReadString() { /* mock */ return ""; }
    bool WriteInterfaceToken(const std::string& token) { return true; }
};

class MessageParcel : public Parcel {
    // 继承 Parcel，添加 IPC 特有方法
};

class IRemoteObject : public RefBase {
public:
    virtual int SendRequest(uint32_t code, MessageParcel& data,
                           MessageParcel& reply) = 0;
};

class IRemoteBroker {
public:
    virtual ~IRRemoteBroker() = default;
    virtual sptr<IRemoteObject> AsObject() = 0;
};
```

**2.3 IPCSkeleton（调用者身份）**

```cpp
class IPCSkeleton {
public:
    static pid_t GetCallingPid() { return getpid(); }
    static pid_t GetCallingUid() { return getuid(); }
    static uint32_t GetCallingTokenID() { return 0; }
    static std::string GetCallingDeviceID() { return "local"; }
};
```

### Phase 3: NAPI 桩（用于有 JS 绑定的模块）

如果模块有 NAPI（Node-API）绑定（如 castengine_wifi_display），
需要为 `napi_env`, `napi_value`, `napi_callback_info` 提供桩。

```cpp
// 最小 NAPI 桩
struct napi_env__ { int dummy; };
typedef napi_env__* napi_env;

struct napi_value__ { int type; void* data; };
typedef napi_value__* napi_value;

// 关键函数桩
napi_status napi_get_cb_info(napi_env env, napi_callback_info cbinfo,
                              size_t* argc, napi_value* argv, ...);
napi_status napi_get_value_string_utf8(napi_env env, napi_value value,
                                        char* buf, size_t bufsize, size_t* result);
```

### Phase 4: 模块特化适配

每个 C++ 模块可能有额外的框架依赖。适配流程：

1. **读取模块的 BUILD.gn** — 找出所有 `external_deps` 和 `include_dirs`
2. **识别需要的桩** — 对比 external_deps 和已有桩库
3. **创建缺失的桩** — 为每个缺失的头文件创建最小桩
4. **验证编译** — gn gen + ninja，修复编译错误
5. **编写测试驱动** — 调用模块的公开 C++ API

### Phase 5: setup_build.py 自动化

扩展 `setup_build.py` 以自动处理 C++ 模块：

```python
# setup_build.py 增强功能
def detect_module_type(source_dir):
    """检测模块是 C 还是 C++"""
    for root, dirs, files in os.walk(source_dir):
        for f in files:
            if f.endswith(('.cpp', '.cc', '.cxx')):
                return 'cpp'
    return 'c'

def auto_generate_stubs(source_dir, output_dir):
    """根据模块依赖自动生成桩代码"""
    # 解析 BUILD.gn 中的 external_deps
    # 为缺失的头文件创建桩
    pass
```

## 案例：castengine_wifi_display 适配方案

以 `castengine_wifi_display` 为例说明完整适配流程：

### 依赖分析

```
external_deps = [
    "bounds_checking_function:libsec_shared",    # 已有
    "access_token:libaccesstoken_sdk",            # 需要桩
    "ipc:core",                                   # 需要桩 (MessageParcel 等)
    "init:libsystemparam",                        # 已有 (system_param_stubs.c)
    "hilog:libhilog",                             # 已有 (ohos_stubs.c)
    "napi:ace_napi",                              # 需要桩
    "ability_base:base",                          # 需要桩
    "device_info_manager:devicemanager",          # 需要桩
]
```

### 需要创建的桩

| 桩 | 依赖模块 | 复杂度 | 说明 |
|----|---------|--------|------|
| RefBase/sptr | utils_base | 中 | 智能指针，几乎所有 C++ 模块都用 |
| IRemoteObject/MessageParcel | ipc_core | 高 | IPC 框架，OnRemoteRequest 处理 |
| IPCSkeleton | ipc_core | 低 | 几个静态方法 |
| napi_env/napi_value | ace_napi | 中 | JS 绑定，如果只测 C++ 层可跳过 |
| AccessToken | access_token | 低 | 权限检查，mock 为始终允许 |
| HiLog (C++ 版) | hilog | 低 | 日志输出到 stderr |
| DeviceManager | device_info | 中 | 设备管理，mock 基本功能 |

### 预计工作量

| 阶段 | 工作量 | 说明 |
|------|--------|------|
| Phase 1: C++ 工具链 | 1-2 小时 | 修改 GN 工具定义 |
| Phase 2: C++ 基础桩 | 4-8 小时 | RefBase, IPC, HiLog |
| Phase 3: NAPI 桩 | 2-4 小时 | 仅在有 JS 绑定时需要 |
| Phase 4: 模块适配 | 2-4 小时 | 每个模块不同 |
| Phase 5: 自动化 | 4-8 小时 | setup_build.py 增强 |

总计：**每个新 C++ 模块约 2-4 小时适配**（基础桩就绪后）

## 用户指南

当用户（安全研究员）使用我们的工具扫描到一个 C++ 模块的漏洞时：

### 步骤 1：评估模块复杂度

```bash
# 检查模块是 C 还是 C++
find ~/data/test-repos/<module> -name "*.cpp" -o -name "*.cc" | wc -l
# > 0 表示 C++ 模块

# 检查依赖数量
grep -r "external_deps" ~/data/test-repos/<module>/*/BUILD.gn | wc -l
```

### 步骤 2：设置构建根

```bash
python3 ~/data/ohos-build-toolkit/setup_build.py \
    --source ~/data/test-repos/<module> \
    --output /tmp/<module>_build
```

### 步骤 3：创建桩代码

根据模块的 `external_deps`，在 `test/` 目录创建对应的桩。

### 步骤 4：编写 BUILD.gn

为模块的源文件创建静态库目标，为测试驱动创建可执行目标。

### 步骤 5：编译和测试

```bash
gn gen out/default && ninja -C out/default
./out/default/obj/test/<poc_name>
```

## 维护策略

1. **桩代码版本化**：每个桩文件标注对应的 OHOS API 版本
2. **增量积累**：每个新模块适配后，通用桩保留在工具链中
3. **测试覆盖**：每个桩应有最小测试验证 ABI 兼容性
4. **文档同步**：新桩添加后更新 README.md
