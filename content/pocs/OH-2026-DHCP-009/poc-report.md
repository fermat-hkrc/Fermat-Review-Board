# 验证报告

## 验证范围

- 生产源文件：`services/dhcp_server/src/dhcp_s_server.cpp` 与 `services/dhcp_server/src/dhcp_option.cpp`
- 入口：`GetHostNameOption`，通过已有租约的 DHCP REQUEST 更新路径调用。
- 方法：先让真实逻辑写入较长 Host Name，再以相同租约写入较短 Host Name。

## 触发链

1. 现有租约的名称缓冲区包含 `long-name`。
2. 后续请求携带有效的单字符名称 `x`。
3. 真实 `GetHostNameOption` 仅复制一个字节，不清空尾部也不补终止符。
4. 读取同一租约名称得到旧后缀。

## 判定条件

短名称更新后应为 `x`。实际结果为 `hostname_after_short_update='xong-name'`。

## 边界说明

driver 只构造 DHCP 选项和租约上下文；选项查询、复制与名称保存均来自生产源文件。
