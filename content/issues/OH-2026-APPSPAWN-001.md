---
id: OH-2026-APPSPAWN-001
date: "2026-06-15"
repo: startup_appspawn
repo_url: https://gitcode.com/openharmony/startup_appspawn
title: "appspawn_utils ReadFile TOCTOU 竞态允许注入恶意沙箱配置"
severity: HIGH
cwe: CWE-367
cwe_name: Time-of-check Time-of-use (TOCTOU) Race Condition
status: PENDING
language: C
component: util
file_paths:
  - util/src/appspawn_utils.c:238
author: Zirui
has_poc: true
---

## 漏洞概述

`ReadFile()` 先调用 `stat()` 获取文件大小用于内存分配，再调用 `fopen()+fread()` 读取文件内容。在 `stat()` 与 `fopen()` 之间存在竞争窗口，攻击者可将文件内容替换为相同大小的恶意 JSON。该函数被 `ParseJsonConfig()` 调用以加载沙箱配置，注入恶意配置可操纵应用沙箱的挂载规则。

## 根本原因

**位置**: `util/src/appspawn_utils.c:238`

```c
char *ReadFile(const char *fileName)
{
    struct stat fileStat;
    stat(fileName, &fileStat);          // CHECK: 获取文件大小
    // ← 竞争窗口：文件内容可被替换为相同大小的恶意内容
    fd = fopen(fileName, "r");          // USE: 打开文件
    buffer = malloc(fileStat.st_size + 1);
    fread(buffer, fileStat.st_size, 1, fd);  // 读取已被替换的内容
}
```

调用链：
```
ParseJsonConfig("etc/sandbox", sandboxName, ...)
  → GetJsonObjFromFile(path)
    → ReadFile(jsonPath)
  → cJSON_Parse(buffer)   // 解析为沙箱配置
```

**问题**:
1. `stat()` 获取文件大小 — 此时文件内容为合法沙箱配置
2. 攻击者将文件替换为相同大小的恶意 JSON 沙箱配置
3. `fopen()+fread()` 读取恶意内容
4. `cJSON_Parse()` 解析为沙箱挂载规则
5. appspawn 根据恶意规则设置应用沙箱

## 影响

- **沙箱逃逸**：恶意配置可添加 `/data` 等敏感路径到应用沙箱挂载列表
- **权限提升**：通过操纵 mount namespace 获取本不应有的文件系统访问
- **影响所有后续应用**：配置加载后对该类型所有应用生效

## 触发条件

1. 攻击者对 appspawn 扫描的配置目录有写权限
2. `GetCfgFiles("etc/sandbox")` 返回的路径中存在攻击者可写的覆盖目录
3. 在 `stat()` 返回后、`fopen()` 执行前替换文件内容
4. 替换内容大小与原文件相同（通过 padding 实现）
5. 应用 spawn 时加载被篡改的沙箱配置

## 修复建议

```c
char *ReadFile(const char *fileName)
{
    int fd = open(fileName, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) return NULL;

    struct stat fileStat;
    if (fstat(fd, &fileStat) != 0 || fileStat.st_size <= 0 ||
        fileStat.st_size > MAX_JSON_FILE_LEN) {
        close(fd);
        return NULL;
    }
    char *buffer = malloc(fileStat.st_size + 1);
    if (buffer == NULL) { close(fd); return NULL; }

    ssize_t n = read(fd, buffer, fileStat.st_size);
    close(fd);
    if (n != fileStat.st_size) { free(buffer); return NULL; }

    buffer[n] = '\0';
    return buffer;
}
```

## 参考

- [CWE-367: TOCTOU Race Condition](https://cwe.mitre.org/data/definitions/367.html)
