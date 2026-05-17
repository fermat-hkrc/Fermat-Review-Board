# C++ Target-Compile 测试计划

## 目标

系统性地验证 OHOS C++ 模块的 Target-Compile PoC 能力，从低依赖到高依赖逐步推进。

## 测试目标：castengine_wifi_display

当前唯一包含大量 C++ 代码的测试仓库（169 .cpp, 116 .h, 94 BUILD.gn）。
这是一个 WiFi Display (Miracast) 引擎，实现了 RTP/RTCP/RTSP 协议栈。

## 模块优先级

### Priority 1: protocol/rtcp（最简单验证）

| 属性 | 值 |
|------|-----|
| 路径 | `services/protocol/rtcp/` |
| 源文件 | `rtcp.cpp`, `rtcp_context.cpp` |
| 外部依赖 | bounds_checking_function, hilog（仅 2 个） |
| 预估工作量 | 1-2 小时 |

**漏洞类型**：
- Integer overflow: `RtcpSR::Create(int32_t itemCount)` 分配 `sizeof(RtcpHeader) + itemCount * sizeof(ReportItem)` 不检查乘法溢出
- Packed struct OOB: `RtcpFB::GetFciPtr()` 返回基于位域计算的偏移量，不验证边界

**验证策略**：
1. 编译 rtcp.cpp + rtcp_context.cpp 为 .a
2. 构造恶意 RTCP 包（大 itemCount 或短 payload）
3. 调用 Create() 和 GetFciPtr() 验证 ASan 触发

### Priority 2: protocol/rtsp（字符串解析）

| 属性 | 值 |
|------|-----|
| 路径 | `services/protocol/rtsp/` |
| 源文件 | `rtsp_request.cpp`, `rtsp_response.cpp`, `rtsp_common.cpp`, `rtsp_sdp.cpp` |
| 外部依赖 | sharing_common, sharing_utils, bounds_checking_function, hilog（4 个） |
| 预估工作量 | 2-4 小时 |

**漏洞类型**：
- Integer overflow: `atoi()`/`strtol()` 解析 RTSP Content-Length 无范围检查
- Protocol injection: CRLF 注入可能性
- String parsing OOB: 分割字符串时可能越界

**验证策略**：
1. 编译 rtsp_*.cpp 为 .a（需要 sharing_common + sharing_utils 的头文件）
2. 构造恶意 RTSP 请求/响应（超大 Content-Length、畸形 SDP）
3. 调用 RtspRequest::Parse(), RtspResponse::Parse() 验证崩溃

### Priority 3: utils/DataBuffer（内存管理）

| 属性 | 值 |
|------|-----|
| 路径 | `services/utils/` |
| 源文件 | `data_buffer.cpp`, `data_queue.cpp`, `utils.cpp` |
| 外部依赖 | c_utils, hilog, openssl（3 个） |
| 预估工作量 | 1-2 小时 |

**已有验证**：DataBuffer 拷贝构造函数（CWE-170）已验证。

**待验证漏洞**：
- Resize() 整数溢出: `new uint8_t[capacity_]` 然后 `memcpy_s(data2, capacity_, data_, size_)` 当 `size_ > capacity_` 时越界
- DataBuffer(int size) 负数 size: `new uint8_t[size + 1]` 当 size=-1 时分配 0 字节
- DataQueue 竞态条件: 多线程 push/pop 无锁保护

### Priority 4: protocol/rtp（复杂协议）

| 属性 | 值 |
|------|-----|
| 路径 | `services/protocol/rtp/` |
| 源文件 | 10+ .cpp（rtp_pack, rtp_unpack, codec_*, rtp_factory） |
| 外部依赖 | sharing_common, sharing_rtcp_srcs, sharing_utils, c_utils, ffmpeg, hilog |
| 预估工作量 | 3-4 小时 |

**已有验证**：RtpPacket GetCsrcData（CWE-125）已验证。

**待验证漏洞**：
- H.264 FU-A 分片: NAL unit 重组时的边界检查
- RtpUnpack 状态机: 解包过程中的类型混淆
- Codec factory: 编解码器选择时的 reinterpret_cast

### Priority 5: interaction/ipc_codec（需要 IPC 桩）

| 属性 | 值 |
|------|-----|
| 路径 | `services/interaction/ipc_codec/` |
| 源文件 | `ipc_codec.cpp`, `ipc_msg_encoder.cpp`, `ipc_msg_decoder.cpp` |
| 外部依赖 | ipc, hilog, c_utils（需要 OHOS IPC 框架桩） |
| 预估工作量 | 3-4 小时 |

**漏洞类型**：
- Unchecked deserialization: `vec.resize(size)` 其中 size 来自 MessageParcel::ReadInt32()（不受信任）
- Integer overflow: 负数 size 转为 size_t 产生极大值
- Type confusion: 模板反序列化不验证消息类型

**特殊需求**：这是第一个需要使用 `ohos_cpp_stubs.h` 中 MessageParcel/IRemoteObject 桩的模块。
成功验证将证明 Phase 2 的 C++ 框架桩在实际模块中可用。

## 执行计划

```
Week 1:
  Day 1-2: Priority 1 (rtcp) + Priority 3 (utils/DataBuffer 扩展)
  Day 3-4: Priority 2 (rtsp)
  Day 5:   整理发现，提交 Review Board

Week 2:
  Day 1-2: Priority 4 (rtp 扩展)
  Day 3-4: Priority 5 (ipc_codec — 需要 IPC 桩)
  Day 5:   总结，更新文档
```

## 新仓库建议

当 castengine_wifi_display 验证完成后，建议添加以下 OpenHarmony C++ 仓库：

1. **graphic_2d** — 图形渲染引擎（buffer 溢出、整数溢出风险高）
2. **audio_framework** — 音频框架（音频解码器通常是漏洞热点）
3. **communication_bluetooth** — 蓝牙协议栈（L2CAP/ATT 协议解析）
4. **player_framework** — 媒体播放框架（demux/codec 攻击面大）

这些仓库都有丰富的 C++ 协议解析代码和外部输入处理。
