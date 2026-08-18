---
id: OH-2026-TELEPHONY-003
date: "2026-08-18"
repo: telephony_core_service
repo_url: https://gitcode.com/openharmony/telephony_core_service
title: "SIM I/O 等待超时后仍返回缓存响应且状态码不反映超时"
severity: LOW
cwe: CWE-754
cwe_name: Improper Check for Unusual or Exceptional Conditions
status: PENDING
gitcode_issue_type: "缺陷"
report_count: 1
affected_version: "e313c25c811710e5425c3c51338521719b086c2b"
component: SIM I/O synchronous request handling
language: C++
file_paths:
  - services/sim/src/sim_state_manager.cpp
  - services/sim/src/sim_state_handle.cpp
  - services/sim/src/sim_manager.cpp
  - services/core/src/core_service_sim.cpp
  - services/core/src/core_service_stub.cpp
  - frameworks/native/src/core_service_proxy.cpp
author: Zirui
vendor: terminal
---

## 漏洞概述

`SimStateManager::GetSimIO()` 向 RIL 提交 SIM I/O 请求后，最多等待 3 秒接收响应。条件变量超时时，循环只执行 `break`；函数没有记录或返回超时错误，仍从 `SimStateHandle` 读取持久缓存的 `simIORespon_`，把其中的 `sw1`、`sw2` 和 `response` 复制给本次调用方，并返回最初提交请求时的状态码。

如果本次请求没有收到响应，调用方可能获得对象初始化时的默认值，或上一笔成功请求留下的缓存值，同时仍收到表示“请求已成功提交”的返回码。源码能够确认受影响的精确基线为 `e313c25c811710e5425c3c51338521719b086c2b`；尚未确认首个受影响或已修复的公开发行版。

## 根本原因

### 超时分支只退出等待循环

`SimStateManager::GetSimIO()` 把 `ret` 设置为向下层提交请求的结果，然后等待共享的 `responseReady_`：

```cpp
responseReady_ = false;
int32_t ret = SIM_AUTH_FAIL;
ret = simStateHandle_->GetSimIO(slotId, requestInfo);
while (!responseReady_) {
    if (cv_.wait_for(lck,
        std::chrono::seconds(WAIT_TIME_SECOND)) ==
        std::cv_status::timeout) {
        break;
    }
}
SimAuthenticationResponse retResponse =
    simStateHandle_->GetSimIOResponse();
response.sw1 = retResponse.sw1;
response.sw2 = retResponse.sw2;
response.response = retResponse.response;
return ret;
```

代码在循环之后没有检查 `responseReady_`。`ret` 只表示 `SimStateHandle::GetSimIO()` 是否把任务提交给 `TelRilManager`，不表示 RIL 已经在等待期限内返回本次 SIM I/O 结果。因此，提交成功而响应超时时，返回码仍可能是成功。

### 响应对象没有与本次请求绑定

`SimStateHandle` 将响应保存为长期成员，并仅在收到完成事件时覆盖：

```cpp
SimAuthenticationResponse simIORespon_ = { 0 };

simIORespon_.sw1 = response->sw1;
simIORespon_.sw2 = response->sw2;
simIORespon_.response = response->response;
```

发起新请求时没有清空 `simIORespon_`，也没有请求序号或代次字段把响应与当前等待者关联。对象创建后首次超时会读取默认值；已有成功请求后超时则会读取上次缓存。迟到响应还可能在调用已经返回后更新同一缓存。

### 完整调用链与权限边界

已确认的调用链为：

1. `CoreServiceClient::GetSimIO()` 通过 `CoreServiceProxy` 发送 `GET_SIM_IO_DONE` IPC。
2. `CoreServiceStub::OnGetSimIO()` 调用 `CoreService::GetSimIO()` 和 `CoreServiceSim::GetSimIO()`。
3. `CoreServiceSim::GetSimIO()` 要求调用方通过 `ohos.permission.GET_TELEPHONY_STATE` 检查，然后调用 `SimManager::GetSimIO()`。
4. `SimManager` 验证槽位存在 SIM、输入数据至少 6 个字符，并构造 `SimIoRequestInfo`。
5. `SimStateManager::GetSimIO()` 经 `SimStateHandle`、`TelRilManager` 和 `TelRilSim` 向 RIL HDI 提交请求并同步等待。
6. 正常响应由 `SimStateHandle::GetSimIOResult()` 写入 `simIORespon_`，随后 `ProcessEvent()` 调用 `SyncCmdResponse()` 设置 `responseReady_` 并唤醒等待者。

该入口不是未认证接口。调用者必须持有 `GET_TELEPHONY_STATE` 权限，并满足 SIM 和参数检查。普通无权限应用不能直接通过该 IPC 到达等待逻辑；能否由有权限应用稳定造成 RIL 超时尚未确认。

### 生产构建与引入历史

根 `BUILD.gn` 的正式共享库目标 `tel_core_service` 编译 `sim_state_manager.cpp`、`sim_state_handle.cpp`、`sim_manager.cpp`、`core_service_sim.cpp` 和 `core_service_stub.cpp`。`bundle.json` 将该服务、System Ability 配置和启动配置列入 service 构建组；客户端代理位于正式的 `tel_core_service_api` 目标。因此该路径属于生产 SIM 服务和 inner-kit IPC 实现。

提交 `e581647fd95167f53aaaf070791f30a88ad328ce` 引入 `GetSimIO` 调用链时即包含当前的等待、超时 `break`、读取缓存响应和返回提交状态码的逻辑。精确基线 `e313c25c811710e5425c3c51338521719b086c2b` 仍未区分超时结果。

## 影响

有权限的调用方无法可靠区分“本次 SIM I/O 已完成”和“请求已提交但等待超时”。默认或过期的 `sw1`、`sw2` 与响应负载可能被误认为本次操作结果，从而导致错误的 SIM 文件解析、状态判断或后续业务决策。

当前证据只证明结果完整性和错误传播问题。缓存位于同一 SIM 状态对象中，源码没有证明可跨越权限边界泄露其他进程数据，也没有证明超时可被普通应用稳定控制。因此不应将影响扩大为内存泄露、越权读取或稳定拒绝服务。

## 触发条件

1. 调用方通过 core service inner-kit 发起 `GetSimIO()`，并持有 `ohos.permission.GET_TELEPHONY_STATE`。
2. 指定槽位存在 SIM，且输入数据长度和参数通过 `SimManager` 检查。
3. 请求成功提交到 `TelRilManager`，但对应完成事件未在 3 秒内使 `responseReady_` 变为真。可能原因包括 RIL/HDI 延迟、丢失响应或下层异常。
4. 等待超时后，函数读取尚未针对本次请求更新的 `simIORespon_` 并返回提交阶段的 `ret`。

如果此前没有成功响应，返回字段为默认值；如果同一对象此前处理过成功请求，则可能返回上一笔缓存值。

## 修复建议

1. 保存 `wait_for()` 的结果，并在超时或 `responseReady_` 仍为假时立即返回明确的 Telephony 超时错误，不要复制 `simIORespon_`。
2. 在等待前检查请求提交结果。提交失败时直接返回原错误，避免继续等待一个不会到来的响应。
3. 为每次 SIM I/O 请求分配独立响应状态，或加入单调递增的请求标识。完成事件只应唤醒并更新匹配的等待者，迟到响应不得被下一次调用当作当前结果。
4. 在新请求开始时重置输出对象，并且只在确认收到本次有效响应后复制 `sw1`、`sw2` 和负载。
5. 将 RIL 返回的完成状态与 SIM I/O 响应字段一起传播，避免把“成功提交”当作“成功完成”。

## 参考

- [CWE-754: Improper Check for Unusual or Exceptional Conditions](https://cwe.mitre.org/data/definitions/754.html)
- [OpenHarmony telephony_core_service](https://gitcode.com/openharmony/telephony_core_service)
