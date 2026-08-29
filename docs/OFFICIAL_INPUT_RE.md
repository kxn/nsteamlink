# 官方 Steam Link 输入路径逆向调研

> 目的：BUG-M4-HID-001（串流中偶发 host/game 输入无响应 ~20 秒）的根因排查进入
> "host 侧 apply 停滞"阶段后，客户端侧可观测手段已用尽（见 decisions D-030/D-034/D-039/D-040
> 与 issue #1 时间线）。本文档逆向官方 Steam Link Android 客户端（v1.3.32）的输入路径，
> 与 ihslib 实现逐项对照，为后续对齐提供证据基础。
> 证据纪律：每条标注【已验证】（工具/地址可复核）或【推断】（由证据支持但未直接观测）。
> 日期：2026-08-29。

## 1. 材料与方法

| 材料 | 来源 |
|---|---|
| `Steam Link_1.3.32_apkcombo.com.xapk`（含 base + 4 ABI split） | 用户提供 |
| `lib/arm64-v8a/libmain.so`（15.9MB，含流媒体核心，24922 个动态符号，C++ 符号未剥离） | xapk 解包 |
| `lib/arm64-v8a/libshell_arm64-v8a.so`（23.1MB，Qt 外壳） | xapk 解包 |
| 工具 | radare2、devkitPro aarch64 objdump/nm、c++filt、strings |
| 对比 pcap | `test.pcapng.gz`（我们的会话，已删除，数据以本 issue #1 评论记录为准）；`good.pcapng.gz`（官方 Android 平板会话，4m40s，1.1M 包） |
| host 日志 | kxn-pc `Steam/logs/` 的 `streaming_log.txt`、`remote_connections.txt`（用户提供） |

## 2. 官方客户端架构（符号级还原）

【已验证】动态符号表枚举（nm -D + c++filt，libmain.so）：

- 流媒体会话核心：`CStreamClient`（连接/协商/控制包处理）、`CStreamPlayer`（媒体与输入回放）。
- 输入子系统：
  - `CStreamPlayer::CHIDDeviceReportThread::Run` —— 专用报告线程；
  - `CStreamPlayer::CHIDDeviceReportGenerator` —— 报告生成器，按设备类型多态：
    `BInjectGamepadStateGenericGamepad / SteamController / MobileTouch / TritonController`；
  - `EncodeDelta`、`AllocateBuffer / SendBuffer / ReleaseBuffer` —— delta 编码与缓冲池；
  - `CreateInputMark / FinishInputMark / StartPlayingInput` —— 输入标记与回放（latency test 用）。
- 输入数据模型：`CRecordedInput`（单条输入事件，带 `type`（EStreamControlMessage 值）与
  `timestamp`，oneof 含 touch/mouse/key/**hid**）与 `CRecordedInputStream`（repeated entries，
  时间戳事件批量流）。proto 定义见 ihslib `protobuf/remoteplay.proto`（Valve 同步版）。
- 传输层多实现：`CStreamTransportUDP`、`CStreamTransportSteamNetworkingSocketsBase`、
  `CStreamTransportSDR`、`CStreamTransportClient`。
- 音视频：FEC 队列（`CFECIncomingQueue/CFECOutgoingQueue`）、Android 硬解
  （`CAndroidVideoDecoder`）、SDL3。

## 3. 官方输入发送路径（SendBuffer 调用链）

【已验证】`CHIDDeviceReportGenerator::SendBuffer(CUtlBuffer*)` @ `0x7d00f0`，
objdump（devkitPro aarch64-none-elf-objdump -dC）解析调用：

- `CUtlQueueBaseImpl::ImplAddToTail(unsigned char**)` —— 编码后的报告**入队**（消费者为
  `CHIDDeviceReportThread::Run`，与生成器解耦）；
- 构造 `CHIDMessageFromRemote` → `DeviceInputReports` → `CHIDDeviceInputReport`（与 ihslib
  同一 protobuf 消息结构）；
- **`CHIDDeviceInputReport::set_delta_report(void const*, unsigned long)`** —— 设置的是
  **delta 报告**。

【已验证】`CHIDDeviceInputReportGenerator` 侧存在 `EncodeDelta`；配套 proto 字段
（`hiddevices.proto`）：

```proto
message CHIDDeviceInputReport {
    optional bytes full_report = 1;
    optional bytes delta_report = 2;
    optional uint32 delta_report_size = 3;
    optional uint32 delta_report_crc = 4;
}
```

【推断】官方常态输入 = delta 报告（小包），依据：SendBuffer 明确调用 `set_delta_report`
（符号级）；pcap 实测输入批量 98B（与本机 73B 全量+封装的 138B 相比明显更小，与 delta
尺寸特征一致）。**包内容加密，未能从线上直接验证 delta/full 字段选择。**

【未知】delta 与 full 的触发策略（首包/心跳/丢失恢复时何时切 full）；批量刷新的精确节奏
（实测 ~31/s，与游戏帧率相关的推断未证实）。

## 4. 官方会话线上数据（pcap 实测）

【已验证】官方 Android 平板（LENOVO TB375FC，Android 16）会话 4m40s，
host 日志（streaming_log.txt 2557 行起）记录协商结果：k_EStreamQualityBeautiful、
50 Mbit/s（burst 250M）、Maximum capture 2944x1840@60、
`CLIENT: Sending HID device 0000/11fb/-1 Mobile Touch Control at touch://0`。

上行（平板→host）122/s 总量：

| len | 包数 | 速率 | 判定 |
|---|---|---|---|
| 82 | 24,228 | ~86/s | 视频/音频 ACK（混合） |
| **98** | **8,685** | **~31/s** | **输入批量**【推断：尺寸与 delta 批量特征一致，内容加密不可见】 |
| 21 | 583 | ~2/s | 控制/keepalive 类 |

下行（host→平板）：1465B 视频 ×1,014,774（60fps）、185B 音频 ×15,936（57/s）、
21B ACK ×27,292（97/s）。

【已验证】官方会话 pcap 窗口内（含用户报告的唯一一次卡死前后）上行/下行均无中断
（下行最大间隔 30ms）。

## 5. host 日志对比（kxn-pc streaming_log.txt）

【已验证】同一 host 上两次会话的 host 侧控制消息记录量：

- 官方平板会话：`CLIENT:` 前缀控制消息 **287 条**（SetQoS ×2、SetTargetBitrate ×2、
  ControllerConfigMsg ×18、TouchConfig 族 ×17、VideoEncoderInfo ×7、SetTitle/SetCursor/
  SetActivity 等）；
- 我们的会话（nsteamlink-switch，19:23 段）：**0 条**。

【已验证·代码】ihslib 客户端模式实际发送的控制消息全集（grep src 逻辑代码，排除
protobuf 枚举表）：RemoteHID、ClientHandshake、AuthenticationRequest、KeepAlive（5s）、
StopRequest、NegotiationSetConfig/Complete、InputTouch*/KeyDown/Up/Text、
StartVideoData/StopVideoData、StartAudioData/StopAudioData、VideoDecoderInfo、
cursor 族、EnableHighResCapture。
**SetQoS / SetTargetBitrate / ControllerConfigMsg / TouchConfig 族 / VideoEncoderInfo
（client 方向）从不发送**——与 host 日志的 0/287 差异互相印证。

【已验证】host 日志中我们的会话（含卡死会话）全程 `Slow framerate: ... (network)`，
network 计时值异常巨大（58518652ms 量级）——我们的帧反馈时间戳与 host 时钟不同步，
host 的网络瓶颈判定基于失真数据。官方会话同位置数值正常（未在摘录段出现异常值）。
【推断】此失真可能影响 host 的码率/节奏控制决策质量，与输入 apply 的关系未证实。

## 6. 协商差异

【已验证·代码】ihslib 客户端协商（ch_control_negotiation.c）：

- `OnNegotiationInit` **忽略** host 在 `CNegotiationInitMsg` 中宣告的
  `reliable_data / supports_remote_hid / supports_touch_input`；
- 发送的 `CNegotiationSetConfigMsg` 中硬编码 `reliable_data = false`。

【已验证·逆向】官方 `CStreamClient::OnNegotiationInit`（@ `0x7ad698`）**读取** host
InitMsg 的三个 bool 宣告（`ldrb [InitMsg+0x68/0x69/0x6a]` → 存入
`CStreamClient+0x158/0x159/0x15a`，并置 has-bit）——官方将 host 的宣告纳入客户端状态。

【未知】官方实际**发送/生效**的 reliable_data 值（SetConfig 的构造未定位到；host 日志
无 "reliable" 字样）。host 端对该字段的处理逻辑未知。

## 7. 20 秒卡死机制的当前结论（截至本文件）

【已验证】卡死会话（D-039/D-040 修复后）：丢一个可靠包（21020）→ 25+ 次重传零 ACK →
3s 放弃触发即恢复传输（giveups 计数、out 归零、新包立即确认）——**传输层自愈正常**；
同期 host ACK 延迟全程 ≤99ms——**host 传输层一直在正常收包确认**；
但用户输入无响应持续 ≈20s。

【结论】卡死的停留点在 **host 对控制流洞后消息的 apply 停滞**：host 的有序窗口在洞后
 hold 输入 apply，直至其内部计时器（估 ~20s）滑动窗口放弃洞并恢复——时长由 host 决定，
客户端的放弃/重传策略只影响自己的队列，不影响 host 的 hold 时长。

【未知】为什么 host 对我们的流会进入这种 hold（官方同环境未复现）：候选因素按当前证据
强度排序——(a) 输入批量/尺寸/速率模式差异（第 4 节）；(b) 控制对话缺失（第 5 节）；
(c) reliable_data 协商差异（第 6 节）。**目前没有任何一条被证实为因果。**

## 8. ihslib 现状与对齐候选

【已验证·代码】ihslib 的 delta 基础设施完整且休眠：`IHS_HIDReportHolderAddDelta`
（report.c:129）实现 `ComputeDelta`（changed-byte 掩码 + 变化字节）+ `IHS_CRC32` +
`delta_report/size/crc` 三字段——与官方 `set_delta_report` 的字段集完全一致。
当前 fork 的 SDL provider 事件处理器已不调用 AddDelta（D-034 时代移除），常态只发
`ReplaceWithFullForced`（full_report）。host 侧 `DeviceRequestFullReport` 的处理
（回全量）在 ihslib 与本项目中均已实现。

### 候选对齐路线（每条独立可证伪，均需真机验证）

| # | 路线 | 依据 | 验证判据 | 风险/成本 |
|---|---|---|---|---|
| A | 恢复 delta 编码：常态 AddDelta（带 CRC），100ms 心跳发 full | 官方 set_delta_report 实证；带宽降 ~70% | 输入包尺寸/速率对齐第 4 节；卡死是否变化 | **推翻 D-034"线上只发完整状态"的假设**，需新决策记录；delta 链在 host hold 场景下的行为需分析 |
| B | 补控制对话：SetQoS / SetTargetBitrate / ControllerConfigMsg（游戏切换时请求配置）| host 日志 287 vs 0；官方会话含完整协商 | host 日志出现对应记录；卡死是否变化 | 中；部分消息语义需进一步逆向 |
| C | 帧反馈时间戳校准 | host 的 network 计时失真（第 5 节）| SessionStats 的 network 值正常化 | 低 |
| D | reliable_data 对齐 | 见第 6 节 | 待 host 宣告值采集后评估 | **用户已否决无证据实验**；官方值逆向未完成 |

## 9. 未决问题

1. 官方输入批量的帧可靠性选择（Reliable/Unreliable 帧）：加密流量不可见；D-030 实验曾
   观测"Unreliable 帧类型导致会话秒断"，与官方行为矛盾，说明该实验存在未理解的细节；
2. 官方 delta/full 触发策略与批量节奏的生成逻辑（需动态分析：模拟器 + Frida hook
   `CHIDDeviceReportGenerator::SendBuffer`）；
3. host 对控制流洞的 hold/丢弃计时器时长（~20s）与其是否依赖客户端行为的条件；
4. `reliable_data` 在 host 端的确切语义；
5. 官方 MobileTouch 虚拟设备（`touch://0`）与通用 gamepad 在 host 输入管线上是否
   走不同 apply 路径。

## 10. 与既有决策的关系

- 本文**不推翻** D-039（放弃窗口）与 D-040（单在途/槽位回收/每帧一次）：传输层修复
  已真机验证（不再永久楔死）；
- 候选路线 A 若实施，将**部分推翻 D-034 的"SDL 线上只发完整状态"**——需先写决策记录
  （含 delta 链 + host hold 场景的行为分析），再动代码；
- D-030 时代"delta 链丢失导致永久错状态"的结论需要修正表述：在 host `DeviceRequestFullReport`
  恢复机制（已实现）与 CRC 校验（ihslib 已有）配合下，delta 方案的丢包自愈路径是存在的，
  当年的放弃决策缺少对这套配套机制的分析。
