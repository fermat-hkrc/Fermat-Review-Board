# 扫描问题的 PoC 审核结果

审核日期：2026-07-17

范围：`communication_connected_nfc_tag` 与 `communication_dhcp` 的本轮扫描结果。

判定规则：只有能编译并运行、使用真实生产源文件、能展示完整触发链和非预期结果的项目，才算正报。未生成这类 PoC 的项目不列入正报。这个结论不表示对应源码一定没有缺陷，只表示本轮没有取得可提交的复现证据。

## 结果总览

| 结论 | 数量 |
| --- | ---: |
| 已确认，可作为 issue 候选 | 12 |
| 未通过严格 PoC 审核，不作为正报 | 8 |

## 已确认的问题

| 问题 | 仓库 | 类型 | 正常触发链 | 观察到的结果 | 复现入口 |
| --- | --- | --- | --- | --- | --- |
| NDEF 写入结果错位 | `communication_connected_nfc_tag` | IPC 协议/功能 | 应用写入有效 NDEF 数据，真实 proxy 调用真实 stub 和服务实现 | 服务返回成功，客户端却把数据长度当作错误码 | `nfc_write_reply_mismatch/build.sh` |
| DHCP 成功事件含未初始化 DNS 计数 | `communication_dhcp` | 数据完整性 | DHCP 成功结果含 DNS 列表，真实 `DhcpClientCallBack::OnIpSuccessChanged` 生成回调数据 | 回调得到极大的随机 DNS 数量 | `dhcp_event_uninitialized/run-pattern.sh` |
| DHCP 服务端回调字段错位且两类回调丢失 | `communication_dhcp` | IPC 协议/功能 | 服务端正常上报设备上线、租约变化或服务退出，真实 proxy 到真实 stub | 接收方接口名为空、设备数错误；租约和退出事件未送达 | `dhcp_server_callback_wire/build.sh` |
| Option Overload 中的 DNS 被忽略 | `communication_dhcp` | DHCP 协议解析 | DHCP 服务端使用有效 Option Overload，把 DNS 放入 FILE 字段 | 真实解析器找不到 DNS 配置 | `dhcp_option_overload/build.sh` |
| 缓存写入失败被报告为成功并清空内存缓存 | `communication_dhcp` | 数据丢失 | 正常租约缓存保存时发生真实短写或存储空间错误 | `SaveConfig` 返回成功，缓存条目被清空 | `dhcp_cache_write_loss/build.sh` |
| 跨网段范围内的地址被错误拒绝 | `communication_dhcp` | 地址分配逻辑 | 配置一个跨较小子网边界、但仍在掩码范围内的合法 DHCP 地址池 | 真实 `IpInRange` 返回不在范围内 | `dhcp_network_order/build.sh` |
| 公共 C API 不能用 C 编译 | `communication_dhcp` | API/构建 | C 开发者按声明使用公开 C 头文件 | C11 编译因 C++ 默认参数和缺失 `bool` 定义失败 | `dhcp_c_api_c_compat/build.sh` |
| Lite 配置无法编译 | `communication_dhcp` | 产品构建 | 以 Lite 宏编译实际 Lite 源文件 | 真实编译器报未声明变量、错误类名和错误成员访问 | `dhcp_lite_build/build.sh` |
| Lite 客户端启动假成功 | `communication_dhcp` | Lite IPC 协议 | Lite 客户端正常调用 `StartDhcpClient`，真实 proxy 请求进入真实 server stub | 客户端返回成功，但服务端启动函数一次也没有被调用 | `dhcp_client_lite_wire/build.sh` |
| 短主机名更新保留旧后缀 | `communication_dhcp` | DHCP 租约信息 | 同一租约先收到较长主机名，后收到较短有效主机名 | 真实 `GetHostNameOption` 得到短名称加旧后缀 | `dhcp_hostname_stale/build.sh` |
| DHCP 回复发送失败仍报告成功 | `communication_dhcp` | 网络错误处理 | 服务器准备好正常回复后，底层 `sendto` 返回失败 | 真实 `TransmitOfferOrAckPacket` 仍返回成功 | `dhcp_send_failure/build.sh` |
| DHCP Decline 重复携带两个标准选项 | `communication_dhcp` | DHCP 协议生成 | 地址冲突触发真实 `DhcpDecline`，测试边界捕获其发送的真实报文 | 请求地址和服务器标识各出现两次，本应各一次 | `dhcp_decline_duplicate_options/build.sh` |

## 未通过严格 PoC 审核的项目

| 扫描结论 | 仓库 | 本轮结论 | 原因 |
| --- | --- | --- | --- |
| IPv6 `select` 超时后可能忙循环 | `communication_dhcp` | 不作为正报 | 源码中 timeout 只在循环外初始化，但未生成完整可运行的 IPv6 Netlink 触发链。 |
| 全局 DHCP 服务状态可能覆盖多网卡状态 | `communication_dhcp` | 不作为正报 | 找到全局状态，但没有证实产品是否设计为单服务实例，也没有复现多网卡用户影响。 |
| `calloc` 或 `memset` 用于含 C++ 成员对象 | `communication_dhcp` | 不作为正报 | 有潜在对象生命周期风险，但没有得到真实运行时 Sanitizer 报告或用户可触发结果。 |
| 异步启动和停止可能竞争 | `communication_dhcp` | 不作为正报 | 未构建出可稳定触发的并发时序和实际错误结果。 |
| DHCP 服务端畸形选项解析 | `communication_dhcp` | 不作为正报 | 没有得到可运行的实际越界、崩溃或错误接受 PoC。 |
| Lite `ParseDhcpClientInfos` 输入校验不足 | `communication_dhcp` | 不作为正报 | Lite 主构建本身已失败，未能独立证明该路径运行后的用户影响。 |
| IPv6 设置作用于全部接口 | `communication_dhcp` | 排除 | 实际代码构造的是当前接口对应的 sysctl 路径，而非全部接口路径。 |
| Lite token 可为空或为前缀 | `communication_dhcp` | 不作为正报 | 内层比较存在问题，但服务管理器还会先按 UID 策略拦截请求。本地范围内没有证实普通调用方能穿过外层策略。 |

## PoC 可信性说明

所有确认项目都重新构建并运行过。测试驱动没有复制目标函数实现：它们编译生产翻译单元，或在仅为访问内部函数时直接包含生产源文件。对 IPC、文件写入、网络发送等平台边界只提供最小替身，用于模拟实际可发生的失败或传输；业务函数、序列化和解析逻辑均来自目标仓库。

`fermat-MESA` 的 `fermat-poc verify` 适合 Sanitizer 类内存和并发证据。上述多数项目属于协议和功能逻辑，因此采用其目标编译和最小触发器方式验证；其中 DNS 计数问题还使用模式初始化证明了未初始化数据会进入实际回调。

## 运行方式

在 dashboard 根目录执行对应目录中的 `build.sh`。每个脚本会重新编译真实目标源文件，并在观察到预期的错误行为时以成功状态退出。
