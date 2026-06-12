---
id: CURL-2026-TIMER-002
date: "2026-06-11"
repo: curl
repo_url: https://github.com/curl/curl
title: "Uninitialized memory read in Curl_update_timer — expire_ts not initialized before use"
cwe: CWE-908
cwe_name: Use of Uninitialized Resource
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

`Curl_update_timer()` 中声明局部变量 `struct curltime expire_ts` 但未初始化。虽然 `multi_timeout()` 在当前代码路径中会初始化该变量，但该模式极其脆弱：如果未来代码修改引入新的返回路径，或在特定边界条件下 `multi_timeout()` 未设置输出参数，line 3604 将读取未初始化内存并将垃圾数据写入 `multi->last_expire_ts`。

## 根本原因

**位置**: `lib/multi.c:3567` 和 `lib/multi.c:3604`

```c
CURLMcode Curl_update_timer(struct Curl_multi *multi)
{
  struct curltime expire_ts;  // Line 3567 - UNINITIALIZED
  long timeout_ms;
  bool set_value = FALSE;

  if(!multi->timer_cb || multi->dead)
    return CURLM_OK;
    
  multi_timeout(multi, &expire_ts, &timeout_ms);  // Line 3574
  
  // ... logic to determine set_value (lines 3576-3601)
  
  if(set_value) {
    multi->last_expire_ts = expire_ts;  // Line 3604 - POTENTIAL UNINIT READ
    multi->last_timeout_ms = timeout_ms;
    // ...
  }
}
```

**问题**:

1. `expire_ts` 在 line 3567 声明但无初始化
2. `multi_timeout()` 预期设置 `*expire_time` 参数
3. 当前代码路径下 `multi_timeout()` 确实会初始化该变量
4. 但模式脆弱：未来代码修改可能引入未初始化路径
5. Line 3604 读取 `expire_ts` 时若未初始化则触发 UB

## 影响

- **未定义行为**: 读取未初始化内存违反 C 标准（ISO/IEC 9899）
- **垃圾时间戳**: `multi->last_expire_ts` 可能包含任意栈数据
- **定时器逻辑错误**: 后续定时器决策基于无效时间戳
- **非确定性行为**: bug 表现取决于栈内容
- **内存安全检测工具报告**: MemorySanitizer 会标记为未初始化值使用

## 触发条件

理论触发路径（当前版本不易触发，但代码模式存在风险）：

1. `multi->last_expire_ts` 已通过 `memset()` 清零（Bug #1 的副作用）
2. `multi->last_timeout_ms` 保留先前值
3. 调用 `Curl_update_timer()`，声明未初始化的 `expire_ts`
4. `multi_timeout()` 在某些边界条件下未完全设置 `*expire_time`
5. Line 3585-3595 的逻辑设置 `set_value = TRUE`
6. Line 3604 读取未初始化的 `expire_ts` 并写入 `multi->last_expire_ts`

## 修复建议

**推荐方案**: 在声明时初始化变量（防御性编程）：

```c
struct curltime expire_ts = {0, 0};  // Initialize to zero
```

**备选方案**: 审计 `multi_timeout()` (lines 3483-3542) 确保所有返回路径都初始化 `*expire_time`。

推荐使用第一种方案，防御性初始化遵循纵深防御原则。

## 参考

- CWE-908: Use of Uninitialized Resource: https://cwe.mitre.org/data/definitions/908.html
- curl multi interface: https://curl.se/libcurl/c/libcurl-multi.html
- ISO/IEC 9899 (C Standard): Uninitialized variables produce indeterminate values
