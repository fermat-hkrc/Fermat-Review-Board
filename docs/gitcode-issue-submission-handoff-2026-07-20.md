# GitCode Issue 提交交接（2026-07-20）

## 当前状态

- 本轮只授权提交下表四份 Issue。不要扩展为 README 中列出的其他 DHCP 项目。
- 四份 Dashboard 条目均保持 `PENDING`，作者字段均为 `Zirui`。
- 尚未在 GitCode 创建任何一份 Issue，也没有发送测试内容。
- 已验证的本地复现资料存在，但不要自动上传或附加这些文件到 GitCode。
- 上一次对 GitCode 的重复条目检查在 2026-07-17 完成；实际创建前必须重新检查一次。

## 待提交清单

| ID | GitCode 仓库 | 标题 | Dashboard 条目 | 本地复现资料 |
| --- | --- | --- | --- | --- |
| `OH-2026-DHCP-002` | `openharmony/communication_dhcp` | DHCP Server OnServerSuccess 回调 IPC 字段顺序不一致导致设备信息错误 | [`content/issues/OH-2026-DHCP-002.md`](../content/issues/OH-2026-DHCP-002.md) | `poc-validation/20260717/dhcp_server_callback_wire/` |
| `OH-2026-DHCP-003` | `openharmony/communication_dhcp` | DHCP Option Overload 扩展字段选项解析仍读取主 options 区域 | [`content/issues/OH-2026-DHCP-003.md`](../content/issues/OH-2026-DHCP-003.md) | `poc-validation/20260717/dhcp_option_overload/` |
| `OH-2026-DHCP-009` | `openharmony/communication_dhcp` | DHCP Host Name 由长名称更新为短名称后保留旧后缀 | [`content/issues/OH-2026-DHCP-009.md`](../content/issues/OH-2026-DHCP-009.md) | `poc-validation/20260717/dhcp_hostname_stale/` |
| `OH-2026-NFC-001` | `openharmony/communication_connected_nfc_tag` | WriteNdefTag 成功后向应用返回输入长度而非服务结果 | [`content/issues/OH-2026-NFC-001.md`](../content/issues/OH-2026-NFC-001.md) | `poc-validation/20260717/nfc_write_reply_mismatch/` |

可直接提交的 GitCode 正文位于：

- [`gitcode-draft-OH-2026-DHCP-002.md`](gitcode-draft-OH-2026-DHCP-002.md)
- [`gitcode-draft-OH-2026-DHCP-003.md`](gitcode-draft-OH-2026-DHCP-003.md)
- [`gitcode-draft-OH-2026-DHCP-009.md`](gitcode-draft-OH-2026-DHCP-009.md)
- [`gitcode-draft-OH-2026-NFC-001.md`](gitcode-draft-OH-2026-NFC-001.md)

这些是面向开发者的正文，不是 Dashboard front matter。提交时只使用每份文件中的“标题”和“正文”，不要加入 Dashboard 的 `id`、严重度、CWE、作者或本地目录路径。

## 已确认的来源版本与证据范围

| 仓库 | 上次确认的 `master` 提交 | 结论 | 已观察到的结果 |
| --- | --- | --- | --- |
| `communication_dhcp` | `f52429ee1873c13c8ed55bde0cb9914b2dfedc43` | 三份报告均使用生产翻译单元构建并运行 | 回调字段错位；扩展 DNS 未被解析；短主机名保留旧后缀 |
| `communication_connected_nfc_tag` | `f6e27a0939cb605da53430b0249811d453604e21` | 使用生产 proxy 与 stub 验证 IPC 返回字段 | 服务返回 `0`，proxy 收到输入长度 `3` |

上述提交均在 2026-07-17 记录。创建前应重新读取 GitCode 最新主线的相关文件；若相应代码已经修复，不创建该条目。

## 创建前的强制检查

1. 使用可创建 Issue 的 GitCode API 授权，不要使用浏览器自动化会话，也不要创建测试 Issue。
2. 先做只读身份查询，确认授权账号是用户指定的 `Zirui`。GitCode 上的作者由授权账号决定，不能在请求中伪造。
3. 对目标仓库重新检索现有 Issue 标题和正文。至少检索完整标题、核心函数名和两个关键文件路径；发现同根因条目时停止并记录链接，不重复创建。
4. 重新读取最新主线中的问题代码。若字段顺序、指针来源、复制逻辑或 reply 字段已被修正，停止对应条目。
5. 创建时仅填写标题和正文。不要设置标签、指派人、里程碑、附件、隐私选项或其他可选字段。
6. 一次只创建一份。每次创建后只读打开返回的公开 URL，核对仓库、标题、完整正文和作者，再处理下一份。
7. 成功后只汇报四个实际 URL、创建账号和每条创建结果；不要修改 Dashboard，除非用户另行要求。

GitCode 官方文档：

- [Issue 使用说明](https://docs.gitcode.com/v1-docs/docs/repo/issues/)
- [创建 Issue API](https://docs.gitcode.com/en/docs/apis/post-api-v-5-repos-owner-issues/)
- [个人访问令牌说明](https://docs.gitcode.com/en/docs/help/home/user_center/security_management/user_pat/)

## 重复检查关键词

| ID | 建议检索词 |
| --- | --- |
| `OH-2026-DHCP-002` | `OnServerSuccess`、`DhcpServerCallbackProxy`、`RemoteOnServerSuccess`、`dhcp_server_callback_proxy.cpp` |
| `OH-2026-DHCP-003` | `Option Overload`、`CheckOptionsData`、`GetDhcpOption`、`dhcp_options.cpp` |
| `OH-2026-DHCP-009` | `GetHostNameOption`、`deviceName`、`DHCP Host Name`、`dhcp_s_server.cpp` |
| `OH-2026-NFC-001` | `WriteNdefTag`、`OnWriteNdefTag`、`nfc_tag_stub.cpp`、`nfc_tag_proxy.cpp` |

## 给接手者的边界说明

- 只提交上表四份内容。Dashboard 审核资料中还存在其他已验证项目，但不在本轮范围内。
- 不要将本地最小复现程序、构建命令、二进制文件或内部绝对路径复制到公开 Issue。
- NFC 报告的 3 字节输入用于验证 IPC 返回协议；不要描述为在实际物理 Tag 上写入了字面量 `abc`。
- DHCP Option Overload 报告讨论 RFC 2132 支持的合法报文布局，不需要构造损坏报文。
- DHCP-009 仅陈述名称元数据不一致，不扩大为数组越界或其他未验证结论。
- 已提交的正文经过用户审阅；不要改成 GitCode 表单的通用问答标题，也不要压缩为简短摘要。
