# 验证报告：缓存短写被报告为成功且内存记录被清空

## 1. 验证目标与判定标准

| 项目 | 内容 |
| --- | --- |
| 目标仓库版本 | `communication_dhcp` `f705027a799e8fe915417026b5c9d90628c40793` |
| 生产入口 | `DhcpResultStoreManager::SaveConfig` |
| 生产文件 | `services/dhcp_client/src/dhcp_result_store_manager.cpp` |
| 输入 | 一条待保存的 `IpInfoCached` 记录 |
| 故障模型 | `fwrite` 返回 0，表示无内容被写入 |
| 判定标准 | 保存应返回失败，且内存缓存必须保留以便重试 |

## 2. 使用的生产代码与替换边界

测试直接链接生产 `DhcpResultStoreManager::SaveConfig`。driver 只做以下设置：把一条记录放入 `m_allIpCached`，提供可写目标路径，并通过链接器 `--wrap=fwrite` 使唯一的系统写入边界返回 0。

序列化内容生成、`fwrite` 返回值处理、`fflush` / `fsync` / `fclose` 调用、清空 vector 和最终返回值均来自生产实现。替换 `fwrite` 是对空间耗尽或 I/O 异常导致短写的最小模型，不改变保存函数的控制流。

## 3. 输入构造

```cpp
manager.m_fileName = "/tmp/dhcp_cache_write_loss.conf";
IpInfoCached entry {};
entry.bssid = "00:11:22:33:44:55";
entry.ssid = "test-network";
manager.m_allIpCached.push_back(entry);
```

写入替身：

```cpp
extern "C" size_t __wrap_fwrite(const void *, size_t, size_t, FILE *)
{
    return 0;
}
```

## 4. 完整触发链

```text
driver 放入 1 条缓存记录
  → production SaveConfig()
    → fopen(path, "w")
    → 序列化记录为 content
    → fwrite(content) = 0                   // 唯一替换点
    → 生产代码仅记录日志，不 return
    → 忽略 fflush / fsync / fclose 返回值
    → m_allIpCached.clear()
    → return 0
```

`"w"` 模式在写入前截断旧文件，因此短写路径既不保留旧文件内容，也不保留内存中的当前记录。

## 5. 实际结果

```text
save_result=0 cache_entries_after_write_failure=0 expected_nonzero_and_preserved
```

| 观察项 | 期望 | 实际 |
| --- | --- | --- |
| `SaveConfig` 返回值 | 非零失败码 | 0 |
| 内存缓存条目数 | 1（保留） | 0 |
| 文件写入字节数 | 未完整写入 | 0（故障模型） |

driver 仅当函数正确返回失败且保留记录时才返回非零；当前退出成功代表错误行为已出现。

## 6. 结论与边界

该验证证明短写错误处理失败；同一代码还无条件忽略刷新、同步与关闭错误，但本次没有对后三者逐一注入。它不涉及路径访问控制，也不依赖任意非标准文件名。

## 7. 修复后的回归判定

修复后对 `fwrite=0`、部分写入、`fflush` 失败、`fsync` 失败和 `fclose` 失败分别执行测试：

- 函数必须返回失败；
- `m_allIpCached` 必须保留；
- 若改用临时文件和原子替换，原缓存文件也必须仍可读取；
- 只有完整成功写入后才允许释放内存缓存。

## 8. 文件说明

| 文件 | 用途 |
| --- | --- |
| `driver.cpp` | 准备真实缓存管理器并在唯一写入边界注入短写 |
| `build.sh` | 编译生产 store 管理器与链接器 wrap 参数 |
| `output.txt` | 本次保存返回值与内存条目数 |
