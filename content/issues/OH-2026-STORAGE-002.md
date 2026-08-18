---
id: OH-2026-STORAGE-002
date: "2026-06-15"
repo: storage_service
repo_url: https://gitcode.com/openharmony/filemanagement_storage_service
title: "fscrypt ReadKeyFile TOCTOU 竞态允许加密密钥替换"
severity: CRITICAL
cwe: CWE-367
cwe_name: Time-of-check Time-of-use (TOCTOU) Race Condition
status: PENDING
language: C
component: libfscrypt
file_paths:
  - services/storage_daemon/libfscrypt/src/fscrypt_control.c:277
author: Zirui
has_poc: true
vendor: cbg
---

## 漏洞概述

`ReadKeyFile()` 先通过 `stat()` 验证文件大小，再通过 `realpath()` 解析路径，最后通过 `open()+read()` 读取密钥内容。在 `stat()` 与 `open()` 之间存在竞争窗口，攻击者可原子替换文件内容为相同大小的恶意密钥材料。由于 fscrypt 密钥为固定大小（descriptor=8字节, identifier=32字节），替换后大小检查仍通过，导致用户数据被错误的密钥加密。

## 根本原因

**位置**: `services/storage_daemon/libfscrypt/src/fscrypt_control.c:277`

```c
static int ReadKeyFile(const char *path, char *buf, size_t len)
{
    struct stat st;
    stat(path, &st);                    // CHECK: 验证 st.st_size == len
    // ← 竞争窗口：文件内容可被原子替换
    char *realPath = realpath(path, NULL);  // 路径解析增加延迟
    // ← 竞争窗口扩大
    int fd = open(realPath, O_RDONLY);   // USE: 打开（可能已是不同内容的）文件
    read(fd, buf, len);                  // 读取攻击者的密钥材料
}
```

**问题**:
1. `stat()` 检查文件大小 — 此时文件内容合法
2. `realpath()` 增加显著延迟（路径解析涉及多次系统调用）
3. 攻击者在窗口期将密钥文件内容替换为相同大小的恶意值
4. `open()+read()` 读取的是攻击者提供的密钥
5. 系统使用攻击者密钥设置 fscrypt 策略

## 影响

- **密钥替换**：用户数据被攻击者控制的密钥加密
- **数据窃取**：攻击者持有密钥，可后续解密用户数据
- **不可逆损害**：已加密数据无法用正确密钥恢复

## 触发条件

1. 攻击者获得对 fscrypt 密钥存储目录的写权限（`/data/service/el2/{userId}/crypto/`）
2. 通过已沦陷的系统服务、内核漏洞或 SELinux 策略错误实现
3. 监控用户登录事件（密钥加载发生在用户会话启动时）
4. 在 `stat()` 返回后、`open()` 执行前，将密钥文件内容替换为恶意密钥（相同大小）
5. storage_daemon 读取并应用恶意密钥

## 修复建议

```c
static int ReadKeyFile(const char *path, char *buf, size_t len)
{
    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) return -EFAULT;

    struct stat st;
    if (fstat(fd, &st) != 0 || (size_t)st.st_size != len) {
        close(fd);
        return -EINVAL;
    }
    if (read(fd, buf, len) != (ssize_t)len) {
        close(fd);
        return -EBADF;
    }
    close(fd);
    return 0;
}
```

## 参考

- [CWE-367: TOCTOU Race Condition](https://cwe.mitre.org/data/definitions/367.html)
- [CWE-59: Improper Link Resolution](https://cwe.mitre.org/data/definitions/59.html)
