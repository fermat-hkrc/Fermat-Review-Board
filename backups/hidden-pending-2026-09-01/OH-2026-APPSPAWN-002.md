---
id: OH-2026-APPSPAWN-002
date: "2026-06-15"
repo: startup_appspawn
repo_url: https://gitcode.com/openharmony/startup_appspawn
title: "appspawn_sandbox CreateDemandSrc chown 跟随符号链接允许任意文件所有权篡改"
severity: HIGH
cwe: CWE-367
cwe_name: Time-of-check Time-of-use (TOCTOU) Race Condition
status: PENDING
hidden_from_dashboard: true
hidden_date: "2026-09-01"
language: C
component: sandbox
file_paths:
  - modules/sandbox/modern/appspawn_sandbox.c:342
  - modules/sandbox/modern/appspawn_sandbox.c:358
author: Zirui
has_poc: true
vendor: cbg
---

## 漏洞概述

`CheckAndCreateSandboxFile()` 创建文件并关闭文件描述符后，`CreateDemandSrc()` 对同一路径调用 `chown()`。`chown()` 默认跟随符号链接。攻击者可在文件创建后、`chown()` 执行前将文件替换为指向目标文件的符号链接，使 `chown()` 修改目标文件的所有权为被 spawn 的应用 uid。

## 根本原因

**位置**: `modules/sandbox/modern/appspawn_sandbox.c:342+358`

```c
void CheckAndCreateSandboxFile(const char *file)
{
    if (access(file, F_OK) == 0) return;
    MakeDirRec(file, FILE_MODE, 0);
    int fd = open(file, O_CREAT, FILE_MODE);
    close(fd);   // ← 文件已创建，fd 释放
}

void CreateDemandSrc(...)
{
    CheckAndCreateSandboxFile(args->originPath);
    // ← 竞争窗口：文件可被替换为 symlink
    chown(args->originPath, uid, gid);   // ← 跟随 symlink，修改目标文件所有权
    chmod(args->originPath, mode);        // ← 同样跟随 symlink
}
```

**问题**:
1. `CheckAndCreateSandboxFile` 创建文件后立即关闭 fd
2. 攻击者用 inotify 监控文件创建事件
3. 创建事件触发后，攻击者删除文件并替换为 symlink
4. `chown()` 跟随 symlink 修改目标文件所有权

## 影响

- **任意文件所有权篡改**：攻击者可将任何文件的所有者改为目标 app uid
- **权限提升**：修改 `deviceauth` 凭证、SELinux 策略文件等的所有权后获得读写权限
- **沙箱逃逸**：通过控制沙箱外文件实现持久化

## 触发条件

1. 恶意应用 A 有权写入 demand source 路径的父目录
2. 另一应用 B 被 spawn（触发 `DoSandboxPathNodeMount`）
3. appspawn 为 B 创建 demand 文件
4. A 通过 inotify 检测到文件创建，立即替换为 symlink → 目标文件
5. appspawn 的 `chown()` 将目标文件所有权改为 B 的 uid
6. B（攻击者控制）获得目标文件的读写权限

## 修复建议

使用 `fchownat` + `O_NOFOLLOW` 避免跟随符号链接：

```c
void CreateDemandSrc(...)
{
    CheckAndCreateSandboxFile(args->originPath);
    int fd = open(args->originPath, O_PATH | O_NOFOLLOW);
    if (fd < 0) {
        APPSPAWN_LOGE("demand path may be a symlink");
        return;
    }
    fchownat(fd, "", uid, gid, AT_EMPTY_PATH);
    fchmodat(fd, "", mode, AT_EMPTY_PATH);
    close(fd);
}
```

## 参考

- [CWE-367: TOCTOU Race Condition](https://cwe.mitre.org/data/definitions/367.html)
- [CWE-59: Improper Link Resolution](https://cwe.mitre.org/data/definitions/59.html)
