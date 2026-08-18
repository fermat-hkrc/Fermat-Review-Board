---
id: OH-2026-APPSPAWN-003
date: "2026-06-15"
repo: startup_appspawn
repo_url: https://gitcode.com/openharmony/startup_appspawn
title: "HNP 安装器多处 TOCTOU 竞态允许通过 symlink 实现任意目录删除"
severity: HIGH
cwe: CWE-367
cwe_name: Time-of-check Time-of-use (TOCTOU) Race Condition
status: PENDING
language: C
component: hnp
file_paths:
  - service/hnp/base/hnp_file.c:178
  - service/hnp/src/hnp_installer.c:422
  - service/hnp/src/hnp_installer.c:377
  - service/hnp/src/hnp_installer.c:474
author: Zirui
has_poc: true
vendor: public
---

## 漏洞概述

HNP（Harmony Native Package）安装器中的 `HnpDeleteFolder`、`HnpUnInstall`、`BssUninstall`、`HnpInstallForceCheck` 均使用 `access(path, F_OK)` 检查路径存在后执行删除/创建操作。HNP 路径位于 `/data/hnp/{uid}/` 下，应用进程对该路径有写权限。攻击者可在 `access()` 返回后将目录替换为指向敏感目录的符号链接，使后续 `opendir()+rmdir()` 递归删除目标目录。

## 根本原因

**位置 1**: `service/hnp/base/hnp_file.c:178`

```c
int HnpDeleteFolder(const char *path)
{
    if (access(path, F_OK) != 0) {   // CHECK: 路径存在
        return 0;
    }
    // ← 竞争窗口：路径可被替换为 symlink
    DIR *dir = opendir(path);         // USE: 跟随 symlink 打开目标目录
    while ((entry = readdir(dir)) != NULL) {
        // 递归删除目录内容
        if (entry->d_type == DT_DIR) {
            HnpDeleteFolder(subPath);
        } else {
            remove(subPath);
        }
    }
    closedir(dir);
    rmdir(path);                      // 删除（目标）目录本身
}
```

**位置 2**: `service/hnp/src/hnp_installer.c:422`

```c
static int HnpUnInstall(int uid, const char *packageName)
{
    // dstPath = "/data/hnp/{uid}"
    if (access(dstPath, F_OK) != 0) {   // CHECK
        return HNP_ERRNO_UNINSTALLER_HNP_PATH_NOT_EXIST;
    }
    // ... 处理包信息 ...
    (void)HnpDeleteFolder(privatePath);  // USE: 可被重定向
}
```

**位置 3**: `service/hnp/src/hnp_installer.c:474`

```c
static int HnpInstallForceCheck(...)
{
    if (access(hnpInfo->hnpSoftwarePath, F_OK) == 0) {   // CHECK
        if (hnpInfo->isPublic == false) {
            HnpDeleteFolder(hnpInfo->hnpSoftwarePath);    // USE
        }
    }
    HnpCreateFolder(hnpInfo->hnpVersionPath);             // USE: 可在 symlink 目标创建
}
```

**问题**:
1. 所有操作路径在 `/data/hnp/{uid}/` 下，app uid 进程可写
2. `access()` 检查通过后到实际操作之间存在竞争窗口
3. 攻击者将目录替换为 symlink → 任意路径
4. `opendir`/`rmdir` 跟随 symlink 操作目标路径

## 影响

- **任意目录删除**：通过 symlink 重定向删除设备认证凭证、系统配置等
- **服务拒绝**：删除关键系统服务的数据目录导致服务无法启动
- **权限提升前置**：删除安全策略文件为后续攻击创造条件

## 触发条件

1. 恶意应用安装 HNP 包，在 `/data/hnp/{uid}/hnp/{packageName}/` 下创建目录
2. 应用触发 HNP 卸载操作（通过包管理接口或强制重装）
3. appspawn 调用 `HnpUnInstall` → `access()` 检查通过
4. 恶意应用在 `access()` 返回后立即将目录替换为 symlink → `/data/service/el1/public/deviceauth/`
5. `HnpDeleteFolder` 递归删除设备认证凭证目录

## 修复建议

使用 `openat` + `O_NOFOLLOW` + `unlinkat` 实现安全的递归删除：

```c
int HnpDeleteFolder(const char *path)
{
    int fd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    if (fd < 0) {
        if (errno == ELOOP) {
            // 路径是 symlink，拒绝操作
            unlink(path);
            return 0;
        }
        return (errno == ENOENT) ? 0 : -1;
    }
    // 使用 fd-relative 操作递归删除
    // fdopendir(fd) + unlinkat(fd, entry->d_name, ...)
    DIR *dir = fdopendir(fd);
    // ...
}
```

## 参考

- [CWE-367: TOCTOU Race Condition](https://cwe.mitre.org/data/definitions/367.html)
- [CWE-59: Improper Link Resolution](https://cwe.mitre.org/data/definitions/59.html)
