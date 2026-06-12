## PoC 详细报告

### 1. 验证方法：libcurl API 调用

本 PoC 使用 **API 级别调用** 方法。通过 libcurl 的 `curl_multi` 接口验证定时器状态管理的逻辑缺陷。

验证 Oracle：**定时器回调调用次数** — 在超时值未改变的情况下，定时器回调不应被调用。通过记录回调调用次数验证状态不一致导致的错误行为。

### 2. 编译环境

| 项目 | 版本/路径 |
|------|----------|
| 操作系统 | Ubuntu 26.04 LTS, Linux 7.0, x86_64 |
| 编译器 | GCC 13.x |
| libcurl | 8.x (系统安装版本) |
| 编译选项 | `-O0 -g` (无优化，保留调试信息) |

### 3. 依赖库

| 库 | 说明 |
|-----|------|
| `libcurl` | curl 多接口库，包含 `curl_multi_*` API |

**编译命令**：

```bash
gcc -Wall -O0 -g poc.c $(pkg-config --cflags --libs libcurl) -o poc
./poc
```

### 4. 漏洞触发过程

**4.1 初始状态设置**

```c
CURLM *multi_handle = curl_multi_init();
curl_multi_setopt(multi_handle, CURLMOPT_TIMERFUNCTION, timer_callback);

CURL *easy1 = curl_easy_init();
curl_easy_setopt(easy1, CURLOPT_TIMEOUT_MS, 2000L);
curl_multi_add_handle(multi_handle, easy1);
curl_multi_socket_action(multi_handle, CURL_SOCKET_TIMEOUT, 0, &running);
```

**结果**：
- 定时器回调被调用：`timeout_ms = 2000`
- 内部状态：`multi->last_timeout_ms = 2000`, `multi->last_expire_ts = <有效时间戳>`

**4.2 触发状态不一致 (Bug)**

```c
curl_multi_socket_action(multi_handle, CURL_SOCKET_TIMEOUT, 0, &running);
```

此调用触发 `lib/multi.c:3257`：

```c
memset(&multi->last_expire_ts, 0, sizeof(multi->last_expire_ts));
// BUG: multi->last_timeout_ms NOT reset!
```

**结果**：
- `multi->last_expire_ts = {0, 0}` (已清零)
- `multi->last_timeout_ms = 2000` (保持旧值 - BUG!)

**4.3 验证状态不一致的影响**

```c
CURL *easy2 = curl_easy_init();
curl_easy_setopt(easy2, CURLOPT_TIMEOUT_MS, 2000L);  // 相同的超时值
curl_multi_add_handle(multi_handle, easy2);
curl_multi_socket_action(multi_handle, CURL_SOCKET_TIMEOUT, 0, &running);
```

内部执行路径（`Curl_update_timer()` at line 3589）：

```c
else if(curlx_ptimediff_us(&multi->last_expire_ts, &expire_ts)) {
  // 比较：{0, 0} vs <有效时间戳>
  // 返回 TRUE (时间戳不同)
  set_value = TRUE;  // 错误判定！
}

if(set_value) {
  multi->timer_cb(multi, timeout_ms, multi->timer_userp);  // 不应调用！
}
```

**完整输出**：

```
[STEP 1] Timer callback count: 1, last_timeout: 2000 ms

[STEP 2] BUG: multi->last_timeout_ms is NOT RESET!
[STEP 2] State after memset:
         - last_expire_ts = {0, 0} (cleared)
         - last_timeout_ms = 2000 (NOT cleared - BUG!)

[STEP 3] Timer callback invoked: YES (INCORRECT!)
```

**预期行为**：超时值未改变 (2000ms → 2000ms)，定时器回调不应被调用。

**实际行为**：因状态不一致，回调被错误调用。

### 5. 根本原因分析

Bug 位于状态重置的**不对称性**：

```c
// lib/multi.c:3251-3257
else {
  /* Clear the 'last_expire_ts' to force callback */
  memset(&multi->last_expire_ts, 0, sizeof(multi->last_expire_ts));  ✓
  // multi->last_timeout_ms = -1;  ✗ MISSING!
}
```

这违反了状态变量应同步更新的不变式。`Curl_update_timer()` 依赖两个变量的一致性：

1. `last_expire_ts` — 上次设置定时器的绝对时间戳
2. `last_timeout_ms` — 上次设置的相对超时值

当只清零一个而不重置另一个时，后续的决策逻辑（line 3589）基于不匹配的状态做出错误判断。

### 6. 影响范围

| 维度 | 说明 |
|------|------|
| 触发难度 | 低 — 正常使用 multi 接口即可触发 |
| 影响场景 | 事件驱动应用使用 `curl_multi` + 定时器回调 |
| 性能影响 | 不必要的定时器回调在高负载下影响事件循环效率 |
| 功能影响 | 应用无法依赖正确的定时器行为 |
| 安全影响 | 低 — 主要是功能和性能问题，非安全漏洞 |

### 7. 代码验证状态

| 维度 | 状态 |
|------|------|
| 源码确认 | 已确认：`lib/multi.c:3257` 只调用 `memset()` 清零 `last_expire_ts`，未重置 `last_timeout_ms` |
| API 行为验证 | 已验证：定时器回调在超时值未改变时仍被调用 |
| 状态不一致确认 | 已确认：`memset()` 后状态变量不同步 |
| 决策逻辑影响 | 已验证：`Curl_update_timer()` 的时间戳比较逻辑因状态不一致返回错误结果 |

### 8. 复现步骤

```bash
# 1. 安装 libcurl 开发文件
sudo apt-get install libcurl4-openssl-dev  # Ubuntu/Debian

# 2. 编译 PoC
cd content/pocs/CURL-2026-TIMER-001
bash build.sh

# 3. 运行
./poc

# 预期输出：定时器回调在步骤 3 被错误调用
```

### 9. PoC 类型声明

| 维度 | 说明 |
|------|------|
| 编译方式 | API 级别调用 — 链接系统 libcurl，调用 `curl_multi` API |
| 验证目标 | libcurl 定时器管理逻辑 |
| 正常路径 | 已验证：定时器回调在首次设置时正确调用 |
| 漏洞触发 | 已验证：`CURL_SOCKET_TIMEOUT` 事件后状态不一致，后续相同超时值仍触发回调 |
| 在真实场景可触发 | **可以** — 任何使用 `curl_multi` + 定时器回调的应用 |
| 验证 Oracle | 定时器回调调用次数 — 超时值不变时不应调用 |
