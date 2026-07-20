---
id: CANN-2026-PYTORCH-001
date: "2026-04-29"
repo: pytorch
repo_url: https://gitcode.com/Ascend/pytorch
title: "ParallelTcpServer ctx.erase(fd) 值传递导致客户端上下文泄漏"
cwe: CWE-775
cwe_name: Missing Release of File Descriptor after Effective Lifetime
severity: MEDIUM
status: CONFIRMED_FIXED
language: "C++"
issue_url: https://gitcode.com/Ascend/pytorch/issues/1731
author: Zirui
---

## GitCode 安全漏洞报告指引

GitCode 安全漏洞报告功能允许用户能够快速、安全地报告代码安全漏洞和隐私泄漏等敏感信息，以促进项目的安全性和可靠性。它涵盖了多个方面，包括代码漏洞、依赖关系漏洞、安全警报等：

- **漏洞报告**：漏洞报告指的是在代码中发现的潜在安全问题或漏洞。这些漏洞可能导致系统受到攻击或遭受损害，例如 SQL 注入、跨站脚本 (XSS)、路径遍历等
- **依赖漏洞**：项目所依赖的外部库或软件包中存在的安全问题，避免攻击者可以利用依赖漏洞来执行恶意代码
- **安全警报**：代码中存在的安全风险，例如编码错误、设计缺陷或未经授权的访问等原因而产生的安全风险等

### CVE 编号
            
暂无（已提交待分配）

### 影响程度
            
中等（Moderate）— 长时间运行的分布式训练场景下，内存泄漏累积导致服务不可用；fd 复用时可能造成数据损坏
### 漏洞代码

```cpp
// ParallelTcpServer.hpp:136 — 函数声明，fd 为值传递
void ProcessClientEvent(int epFd, int fd, uint32_t event,
    std::unordered_map<int, ClientIoContext> &ctx) noexcept;
```

```cpp
// ParallelTcpServer.cpp:451-459 — ProcessClientEvent
void ParallelTcpServer::ProcessClientEvent(int epFd, int fd, uint32_t event,
    std::unordered_map<int, ClientIoContext> &ctx) noexcept {
    if ((event & (EPOLLRDHUP | EPOLLHUP)) != 0) {
        epoll_ctl(epFd, EPOLL_CTL_DEL, fd, nullptr);  // line 455: 从 epoll 移除（使用原始 fd）
        close(fd);                                      // line 456: 关闭 fd（使用原始 fd）
        fd = -1;                                        // line 457: 修改局部副本为 -1
        ctx.erase(fd);                                  // line 458: erase(-1) → 无操作！
        return;
    }
    // ...
    auto pos = ctx.find(fd);  // line 462: 后续使用 fd 在 ctx 中查找
    if (pos == ctx.end()) {
        pos = ctx.emplace(fd, ClientIoContext{ fd, ... }).first;  // line 464: 新连接注册
    }
}
```

调用者（`LoopProcessClients`）持有 `clientCtx` 局部变量：

```cpp
// ParallelTcpServer.cpp:393-413
void ParallelTcpServer::LoopProcessClients(int epollFd) noexcept {
    std::unordered_map<int, ClientIoContext> clientCtx;  // line 397: 局部 map
    while (running_) {
        count = epoll_wait(epollFd, events, MAX_EVENT_COUNT, 1000);
        for (auto i = 0; i < count; i++) {
            ProcessClientEvent(epollFd, events[i].data.fd, events[i].events, clientCtx);
        }
    }
    for (auto &ctx : clientCtx) { close(ctx.first); }  // line 410-412: 退出时清理
}
```

无其他清理机制。断连路径中 `erase(-1)` 是空操作，残留条目直到服务关闭才被清理。

### 触发步骤

1. 客户端连接到 `ParallelTcpServer`
2. `ProcessClientEvent` 在 line 464 通过 `ctx.emplace(fd, ...)` 注册上下文
3. 客户端断开连接（正常关闭或异常），触发 `EPOLLRDHUP`
4. `close(fd)` 关闭 fd，`fd = -1` 修改局部副本，`ctx.erase(-1)` 擦除不存在的键
5. 原始 fd 对应的 `ClientIoContext` 永远留在 map 中
6. Linux 复用 fd 编号，新客户端获得相同 fd 时，`ctx.find(fd)` 在 line 462 找到残留的旧上下文

### 影响

- **内存泄漏**：每次断连泄漏一个 `ClientIoContext`，长时间分布式训练中持续累积
- **数据损坏**：新连接复用 fd 时使用旧连接的缓冲区，可能发送/接收错误数据
- **信息泄漏**：残留缓冲区中可能包含前一次连接的训练数据
### 补丁
            
修复已提交，待上游确认合并。

### 解决方法
            
在 `close(fd)` 前先执行 `ctx.erase(fd)`，或保存原始 fd 值后再执行 erase。
### 建议修复（伪代码）

```cpp
// ===== 方案一：先擦除，再关闭 =====
void ParallelTcpServer::ProcessClientEvent(int epFd, int fd, uint32_t event,
    std::unordered_map<int, ClientIoContext> &ctx) noexcept {
    if ((event & (EPOLLRDHUP | EPOLLHUP)) != 0) {
        epoll_ctl(epFd, EPOLL_CTL_DEL, fd, nullptr);
-       close(fd);
-       fd = -1;
-       ctx.erase(fd);
+       ctx.erase(fd);   // 先擦除原始 fd 对应的条目
+       close(fd);        // 再关闭
        return;
    }

// ===== 方案二：保存原始 fd =====
    if ((event & (EPOLLRDHUP | EPOLLHUP)) != 0) {
        epoll_ctl(epFd, EPOLL_CTL_DEL, fd, nullptr);
+       int origFd = fd;  // 保存原始值
        close(fd);
-       fd = -1;
-       ctx.erase(fd);
+       ctx.erase(origFd);  // 用原始值擦除
        return;
    }
```
### 参考资料
            
- CWE-775: Missing Release of File Descriptor after Effective Lifetime
- CWE-403: Exposure of File Descriptor to Unintended Control Sphere

### 常见弱点枚举（CWE）
            
CWE-775 (Unreleased Resource) / CWE-403
### 严重程度
            
中等（Moderate）
