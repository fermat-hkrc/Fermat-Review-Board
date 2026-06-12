---
id: CURL-2026-TIMER-001
date: "2026-06-11"
repo: curl
repo_url: https://github.com/curl/curl
title: "Timer state inconsistency in curl_multi_socket_action — last_timeout_ms not reset with last_expire_ts"
cwe: CWE-665
cwe_name: Improper Initialization
severity: MEDIUM
status: PENDING
language: C
component: multi interface
file_paths:
  - lib/multi.c
author: Zirui
has_poc: true
---

## 漏洞概述

`curl_multi_socket_action()` 在处理 `CURL_SOCKET_TIMEOUT` 事件时，通过 `memset()` 清空 `multi->last_expire_ts` 以强制触发定时器回调，但未同步重置 `multi->last_timeout_ms` 为 `-1`。这导致状态不一致：时间戳已清零但超时值保留旧值，使 `Curl_update_timer()` 基于不匹配的状态做出错误决策。

## 根本原因

**位置**: `lib/multi.c:3257`

```c
else {
  /* Asked to run due to time-out. Clear the 'last_expire_ts' variable to
     force Curl_update_timer() to trigger a callback to the app again even
     if the same timeout is still the one to run after this call. That
     handles the case when the application asks libcurl to run the timeout
     prematurely. */
  memset(&multi->last_expire_ts, 0, sizeof(multi->last_expire_ts));
  // BUG: multi->last_timeout_ms NOT reset here!
}
```

**问题**:

1. `memset()` 将 `multi->last_expire_ts` 清零
2. `multi->last_timeout_ms` 保持上一次的值（如 2000ms）
3. 两个状态变量应当同步更新但实际脱节

## 影响

状态不一致导致 `Curl_update_timer()` 在 line 3589 做出错误判断：

```c
else if(curlx_ptimediff_us(&multi->last_expire_ts, &expire_ts)) {
  /* We had a timeout before and have one now, the absolute timestamp
   * differs. The relative timeout_ms may be the same, but the starting
   * point differs. Let the application restart its timer. */
  set_value = TRUE;
}
```

当比较清零的 `last_expire_ts` 与有效的 `expire_ts` 时，函数错误判定时间戳不同，导致：

- **不必要的定时器回调调用**: 即使超时值未改变，仍触发回调
- **违反 API 契约**: 定时器回调不应在超时值不变时被调用
- **性能退化**: 高负载场景下频繁的无效回调影响事件循环效率
- **定时器管理逻辑错误**: 应用层无法依赖正确的定时器行为

## 触发条件

1. 应用使用 `curl_multi` 接口并设置定时器回调
2. 添加 easy handle，定时器回调被调用（如 timeout = 2000ms）
3. 调用 `curl_multi_socket_action(CURL_SOCKET_TIMEOUT)` 处理超时
4. 此时 `last_expire_ts` 被清零，但 `last_timeout_ms` 仍为 2000
5. 添加另一个 handle，超时值相同（2000ms）
6. `Curl_update_timer()` 因状态不一致错误判定为"时间戳不同"
7. 定时器回调被不必要地再次调用

## 修复建议

在 `lib/multi.c:3257` 的 `memset()` 之后添加重置：

```c
memset(&multi->last_expire_ts, 0, sizeof(multi->last_expire_ts));
multi->last_timeout_ms = -1;  // ADD THIS LINE
```

确保两个状态变量同步重置，维持状态一致性。

## 参考

- CWE-665: Improper Initialization: https://cwe.mitre.org/data/definitions/665.html
- curl multi interface: https://curl.se/libcurl/c/libcurl-multi.html
- CURLMOPT_TIMERFUNCTION: https://curl.se/libcurl/c/CURLMOPT_TIMERFUNCTION.html
