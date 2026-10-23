# 官方 Steam Link 输入路径逆向调研

> **2026-09-07 证据更正**：本文包含相互矛盾的历史结论。
> 解密递增时机、NACK 与帧统计的独立复核见
> [协议参考 §14](STEAMLINK_PROTOCOL_RE.md#14-独立汇编复核与协议反例2026-09-07)。
> §18 不能用作“已排除客户端协议问题／NVENC 是卡死根因”的证明。

> **2026-09-04 更正与拆分**：本文档的协议层结论已由系统再逆向复核，
> 新权威参照为 `docs/STEAMLINK_PROTOCOL_RE.md`。对本文的具体更正：
> ① §5 对 host 日志 `CLIENT:` 前缀的解读有误——官方客户端二进制中不存在 SetQoS(87)/
>    SetTargetBitrate(94)/VideoEncoderInfo(90)/SetTitle(81)/SetActivity(98)/TouchConfig 下行族
>    (110/112/114/116) 的任何发送代码路径（SendControlMessage 全部 35 个调用点已枚举），
>    这些消息全部有 On* 接收 handler，故 `CLIENT:` 前缀 = host→client 方向，
>    287 条记录不能作为"官方客户端发送控制对话"的证据；
> ② §8 候选路线 B（客户端补发 SetQoS/SetTargetBitrate）前提作废；
> ③ §15/§16 `CStreamFrame::Send(conn, bool)` 的 bool 映射写反：true=可靠 Send，
>    false=SendUnreliable；且 SendControlMessage 两路均硬编码 reliable=true——
>    "官方输入可能默认走不可靠通道"的猜测不成立；
> ④ §6 【未知】项部分落地：官方把 host InitMsg 的 reliable_data 回显进自己的
>    NegotiationSetConfig.config.reliable_data（无条件字节拷贝）；
> ⑤ §13.2 "时间戳单位 bug 已修（ms）"方向反了：官方 GetStreamTimestamp 是
>    **16.16 定点秒**；旧文进一步解释为“减连接起点”是错误的，已撤回。
>    实际为首事件加时钟偏移，后续事件间 delta，见协议参考 §14.4、§14.10。
> 输入链的完整报告、active_input、禁用门控也须按 §14.10 的调用链解释；
> §14 "不合并批次"表述由 STEAMLINK_PROTOCOL_RE.md §9b.2 更正（官方单消息多设备合批）。

> 目的：排查串流中偶发 host/game 输入无响应约 20 秒。旧文“客户端可观测手段已用尽”
> 没有成立；传输确认不等于 host 应用确认。本文逆向 Android 客户端（v1.3.32）的输入路径，
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

【已验证·全量反汇编交叉引用】（main.disasm 1,694,052 行，2026-08-29 补充分析）：

- **`set_full_report` 的 PLT（0xc10020）在全二进制中零调用**——官方 Android 客户端的
  输入报告**全部为 delta_report，从不发送 full_report**。初始状态同步依赖 delta 的
  "全掩码"能力（ComputeDelta 掩码覆盖全部字节时等价全量）与 host 侧中性初始化；
- 完整发送链：`ReportGenerator`（EncodeDelta 编码入队）→
  `BCollectReports(CHIDMessageFromRemote_DeviceInputReports*, bool*)`
  （收集全部生成器的报告，@ `0x7cf884`）→ `SendBuffer`（打包）→
  `ImplAddToTail`（报告线程队列）→ 报告线程发送；
- 产生节奏：pcap 实测 31/s 批量，与 30fps 游戏的逐帧收集一致。

【推断】delta 丢失的自愈路径：delta 带 size+CRC32，host 端 CRC 校验失败或基线状态缺失时，
通过 `CHIDMessageToRemote.DeviceRequestFullReport`（proto 字段存在，ihslib 已实现
客户端侧响应）请求客户端重发——客户端以"全掩码 delta"响应（set_full_report 无调用者，
全量只能以 delta 形态发出）。该路径未被动态观测证实。

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

### 路线 A 的补充事实（2026-08-29 全量反汇编补充）

- 官方 `set_full_report` 零调用：**官方从不发 full_report**，初始/恢复态一律以"全掩码
  delta"表达；我们若对齐，心跳的 full 也应以全掩码 delta 或保留 full_report 字段发送
  （host 对两种字段的接受度未知，需实验）；
- ihslib 的 `IHS_HIDReportHolderAddDelta`（report.c:129）已实现与官方一致的
  delta+size+CRC32 三件套，属"休眠的完整基础设施"，恢复 = 重新接线而非新写；
- 上游 ihslib（8c5a17c）与 plume 实测即运行在此 delta 路径上；**但 plume 可用性用户无法
  独立验证，不作为因果证据，仅作为上游行为参照**。

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

## 11. 十轮全链路核验（2026-08-29，应用户要求启动；代码冻结直至收敛）

核验方法：每轮以一个独立视角走完整条输入链（采集→状态→编码→打包→传输→host 接收→apply），
对官方（逆向+pcap+host 日志）与 ihslib/我们（源码+diag 日志）逐环节比对。发现即记录，
**收敛（连续两轮无新发现）前不改任何代码**。

### R1 wire 编码策略 ✅

【已验证】官方 `SendBuffer`（0x7d00f0）对每帧状态做掩码差分后**自适应选择**：

```
deltaLen + 8 < fullLen  →  set_delta_report（掩码+变化字节）+ delta_report_size + CRC32(全态)
deltaLen + 8 ≥ fullLen  →  set_full_report（完整态直发）+ 重置内部计数
```

（反汇编原文：0x7d035c-0x7d03b8，`cmp x8,x26 / b.cs → full` 分支。）

**更正**：此前"set_full_report 零调用"的断言系 grep 制表符不匹配造成的假阴性，作废。
官方 delta/full 双模自适应；本文件第 3 节相应段落以本条为准。

### R2 报告生成与排队 ✅（触发节奏需动态确认）

【已验证】生成与发送解耦：generator 编码入队（`ImplAddToTail`），
`CHIDDeviceReportThread::Run`（0x7c9e40）为独立消费线程；
`BCollectReports`（0x7cf884，虚表调用——静态 xref 不可达，虚表分派）收集全部生成器。

### R3 传输封装 ✅

【已验证】`SendRemoteHIDMessage`（0x7ab374）：
`CHIDMessageFromRemote` 序列化 → 包进 `CRemoteHIDMsg.data` → 同时录入
`CRecordedInput`（`GetStreamTimestamp()` 时间戳，type==0xd 即 hid）→
**`CStreamClient::SendControlMessage(EStreamControlMessage, MessageLite const&)`**（0x7a7d90）→
`CStreamFrame(type, channel)` → `Put` → `BEncrypt(seq)` → `Send`。
与 ihslib 同构：输入走控制通道、加密、带序列号。**输入的可靠性级别未在此层见到
特殊分支**（帧类型参数来源于更上层，R4 继续）。

### R4 丢失恢复 ◐

【已验证·字符串】传输层序列跟踪五计数器：`recvseq / inorder / dup / lurch / ooo`
（官方术语 "lurch" = 乱序落点）。"Sender sent reliable stream pos… expected next…"。
【未知】host 对控制流洞后消息：hold 后按序补 apply，还是丢弃（客户端 delta 链基线
失配 → CRC 失败 → RequestFullReport 恢复）。两种行为与观测均兼容，需动态实验区分。

### R5 时序与速率 ✅

【已验证】官方输入批量间隔（8684 个间隔）：均值 30.5ms、中位 11.1ms、p90 56.8ms、
p99 414.6ms、最大 1222ms；89% 的间隔 <50ms——**事件驱动逐帧批量，无固定速率**；
221 秒中仅 3 秒无输入批量。

### R6 会话生命周期 ✅（2026-08-29 修正：用户指出后重核，此前推断有误）

【已验证】pcap **完整覆盖**了会话起点（用户重启 app 后开始抓包，信标首包即入）。
host 日志显示 8-29 00:11-00:15 共三次会话（app 重启所致），最终会话（:46304，
00:15:00 起，直进游戏 Girls Made Pudding）自首秒起即有输入批量流动：

- 会话第 1 秒起输入批量（98B）即以 ~41/s 流动（前 49 秒含 2033 个 98B 包），
  **无初始 full 同步**——host 侧虚拟设备中性初始化后，客户端直接以 delta 流积累状态，
  与 `set_full_report` 零调用互证；
- 官方 app 重启 = 新端口新会话（48554→55851→46304），host 每次均正常重建流。

【结论】ihslib 对齐时会话起点无需初始 full：直接进入 delta 流即可（host 中性初始化
+ delta 掩码差分天然从零基线开始）。此前的"pcap 未覆盖会话起点"推断有误，已修正。

### R7 host 接收行为 ✅（现象确认，成因未知）

【已验证】官方会话 host 记录 287 条 CLIENT: 控制消息；我们会话 0 条（ihslib 代码证实
相关消息我们不发）。另：我们会话的 host 帧反馈计时失真（network≈58518652ms）。

### R8 协商能力 ◐

【已验证·代码】ihslib 已加日志输出 host InitMsg 宣告的
`reliable_data / supports_remote_hid / supports_touch_input`（3d16df4），
待下次真机连接采集。【未知】官方实际生效值。

### R9 静态-动态交叉 ✅

【已验证】R1 的自适应策略可解释观测的双簇尺寸分布（82B=轻中度变化的 delta，
98B=大 delta/多设备批量）；无 >140B 的独立 full 态包簇——与"full 仅在
delta 压不下时出现"一致（出现的 full 混在 98B 簇中不可分）。

### R10 端到端事件追踪 ⬜

待 R4 的 host hold 行为区分实验后进行（需动态注入或 Frida）。

## 12. 收敛状态

已产生新发现的轮次：R1（自适应规则，推翻 D-041"不出现 full_report"的假设——
**D-041 附录需再修正：全掩码 delta 应改为官方的自适应规则**）。
收敛判定：未达成。代码改动继续冻结（D-041 已实施的 delta flush 与本轮发现冲突的
部分，待 R2-R10 完成后一并修正）。

## 13. 客户端→host 消息字段逐项审计（2026-08-29）

审计范围：ihslib 客户端模式实际发送的全部控制消息（代码 grep 验证全集），逐字段核对
来源与官方对照。**本节只记录，不含任何代码修改。**

### 13.1 NegotiationSetConfig（三层）

已填字段：config（reliable_data=false、enable_remote_hid=1、音视频编解码选择、
分辨率/帧率）、clientConfig（quality=Balanced、1280x720@60、6000kbps、audio 2ch、
HEVC off、performance_overlay=true、controller_overlay_hotkey="auto"）、
caps（system_info、system_can_suspend、max_decode 30000/burst 90000、codecs、
form_factor=TV）。

发现的问题：

- P1【确认】`supported_colorspaces` 未声明 → host 会话选 BT.601 limited。
  HD 内容按 601 采样存在色彩精度损失。修复方向：声明 BT.709/601（含 Full）。
  对照：官方会话 host 日志无 "Capture colorspace" 行（成因未知，见 P9）。
- P2【确认】`display/quality/runtime/decoder_limit`（CStreamVideoLimit）未声明。
  官方二进制存在该消息族的使用痕迹（待动态确认取值）。
- P3【确认】`enable_unreliable_fec` 未设（false）。与 FEC 队列类
  （CFECIncoming/OutgoingQueue）及输入批量是否走 FEC 通道的问题相关（第 9 节）。
- P4【确认】`reliable_data=false` 硬编码。官方流程从 host InitMsg **读取**该宣告
  （0x7ad6fc），声明方向不同；官方生效值未知。
- P5【观察】caps.system_info 为硬编码假串（263MB RAM、1 核、JN-MD133BFHDR 面板）。
  host 端用途未知。
- P6【观察】quality=Balanced/6M/720p vs 官方 Beautiful/50M/2944x1840——有意低配，
  非缺陷；但影响 SessionStats 的对比基线。

### 13.2 其余消息快审

- AuthRequest：version/steamid/HMAC-SHA256("Steam In-Home Streaming") token ✓ 标准；
- ClientHandshake：network_test=true ✓；
- KeepAlive：空消息，5s 周期 ✓（host 有 ping timeout 断连机制，间隔待对照）；
- StartVideoData：**客户端不发送**（host 推送启动）✓ 与官方一致；
- RemoteHID wrapper：has_active_input=true + active_input=true（0010 补丁），
  官方同字段的取值未逆向（低优先）；
- 帧反馈：CFrameStatsListMsg（k_EStreamStatsFrameEvents，stats 通道，1s 周期，
  reliable）——时间戳单位 bug 已修（见第 12 节前文）；
- 包头 sendTimestamp：ms 修复已推送（ab8712d）。

### 13.3 官方会话 host 日志的独有现象

- 官方会话段无 "Capture colorspace" 行（我们会话均有 BT.601 行）——成因未知（P1 相关）；
- 官方会话段 `Slow framerate: game 16.00` 常驻（游戏自身帧率 16fps，
  非网络/客户端问题）。

### 13.4 审计状态

字段审计完成度：NegotiationSetConfig ✓、AuthRequest/ClientHandshake/KeepAlive ✓、
StartVideo/Audio ✓（不发送）、RemoteHID wrapper ✓（active_input 待官方对照）、
帧反馈 ✓（时间戳已修）、ACK/包头 ✓（ms 已修）。
colorspaces 官方构造点、ControllerConfigMsg 官方载荷：静态到边界，需动态分析（Frida）。

## 14. R2 补充：官方输入报告线程（全量反汇编解析）

【已验证】`CStreamPlayer::CHIDDeviceReportThread::Run()`（0x7c9e40）：

```
while (m_bRunning) {
    UpdateHIDDeviceReports();     // ← 收集所有设备 delta/full + SendRemoteHIDMessage
    ThreadSleep(8);               // ← 8 毫秒
    if (loop_count % 125 == 0) {  // ← ~每秒一次
        UpdateHIDDeviceInfo();    // ← 更新设备信息
    }
    if (has_virtual_controller) {
        UpdateControllerState();  // ← 虚拟控制器状态
    }
}
```

- `ThreadSleep(8)` = **125Hz 发送频率**，每次循环遍历所有设备收集 delta/full 并立即发送
- `UpdateHIDDeviceReports()` 内部（0x7bd838）：
  - 持锁遍历设备列表
  - 对每个设备调用虚函数 `BCollectReports(DeviceInputReports*, bool*)` 收集
  - **有数据就立即调 `SendRemoteHIDMessage` 发送**（不等 ACK、不合并批次）
  - 无数据的设备构造 CloseDevice 消息（设备已断开的通知）

【结论】官方输入不是事件驱动（"有变化才发"），也不是低频心跳，而是**固定 125Hz 高频
轮询发送**——每次都收 delta（或全掩码 delta 当变化太大时），不管 host 是否确认上一包。
单在途限制在官方架构中不存在——125Hz 高频本身就是丢失容忍策略的一部分：
丢一个 delta 8ms 后下一条就到了，不需要重传也不需要等待。

【与我们的对比】
- 历史实现（D-041 后，已由 D-042 取代）：每帧一次 flush（~60Hz 或 vsync 率）+ 100ms 心跳 full + 单在途
- 官方：125Hz 专用线程 + delta/full 自适应 + 不等 ACK + 不限在途

【含义】如果要对齐官方，关键是 **8ms 高频 delta 线程**（而非我们的每帧 flush），
以及**放弃单在途限制**（允许连续多包在途——官方就是这样做的，丢一个不影响后续）。

## 15. R3 完成：传输封装与可靠性选择（全量反汇编解析）

【已验证】`CStreamClient::SendRemoteHIDMessage(CHIDMessageFromRemote const*, bool reliable)`（0x7ab374）：

```
1. 检查连接状态（== 6 即 k_EStreamConnectionStateConnected）
2. CHIDMessageFromRemote::ByteSizeLong() → 序列化到 buffer
3. 构造 CRemoteHIDMsg → data = 序列化后的 DeviceInputReports
4. GetStreamTimestamp() → CRecordedInput.timestamp（16.16 秒时间戳）
5. CRecordedInput.type = 0xd (13 = hid)
6. CRecordedInput.hid = CRemoteHIDMsg
7. 加入 CRecordedInputStream.entries（repeated 批量）
8. CStreamClient::SendControlMessage(k_EStreamControlRemoteHID=106, CRemoteHIDMsg)
```

【已验证】`CStreamClient::SendControlMessage`（0x7a7d90）：
```
CStreamFrame(type=106, channel)
CStreamFrame::Put(protobuf_msg, bool)
CStreamFrame::Send(conn, bool)  ← bool 参数选择路径：
  → CStreamConnection::Send()            (可靠有序)
  → CStreamConnection::SendUnreliable()  (不可靠)
```

【已验证】`Send()` 的 bool 参数决定走 `Send()` 还是 `SendUnreliable()`——
官方客户端有**两条路径**：可靠有序通道 和 不可靠直发通道。

### 对比 ihslib

ihslib 的 `IHS_SessionChannelControlSend` 只有一条路径：所有控制消息（含 RemoteHID）
走 Reliable 有序通道。无 Unreliable 选项。**官方输入可以走不可靠通道，
ihslib 不能——这是架构级差异。**

### 125Hz 不等 ACK 的原因

官方 125Hz 输入线程每次产生新报告，如果走不可靠通道：丢一个 delta 8ms 后下一条就到，
无需重传——**高频不可靠 delta 是官方的丢失容忍策略核心**。
如果走可靠通道，125Hz 会严重塞满上行（每包都需 ACK + 重传），上游 ihslib 注释
已警告过此问题。官方可能默认走不可靠通道用于输入。

## 16. R4 补充：SendRemoteHIDMessage 的可靠性与调用者分析

【已验证】`SendRemoteHIDMessage(msg, bool)` 三个调用点（0x7bd74c / 0x7bd978 / 0x7bd9d8）：

- 前两个传 `w2=wzr`（false）→ `SendControlMessage` → `CStreamFrame::Send(conn, false)`
  → `Send()` 走**可靠有序通道**
- 第三个（0x7bd9d8，UpdateHIDDeviceReports 内的批量发送路径）bool 来自变量——
  需要跟踪上下文确定

【已验证】`SendControlMessage` → `CStreamFrame::Send(conn, bool)`:
```
Send():
  if (bool) → CStreamConnection::SendUnreliable()  
  else      → CStreamConnection::Send()
```

【结论】官方输入至少部分走可靠通道。但 `Send()` 存在 `SendUnreliable()` 路径
意味着官方**具备**不可靠发送输入的能力（可能用于高频场景下的降级）。
ihslib 只有 `IHS_SessionChannelControlSend` 一条路径（全可靠有序）。

传输层序列跟踪（字符串证据）：`recvseq/inorder/dup/lurch/ooo` 五个计数器
——官方传输层独立跟踪乱序/重复，与 ihslib 的 window.c 不同。

## 17. Generic Gamepad wire 模式定论与 is_generic_gamepad 语义（2026-09-07）

背景：上一构建移除 `is_generic_gamepad`（意图让 host 按真实 NS Pro 处理）后
真机实测 host 完全不认输入。本轮对 libmain.so 做了生成器/解析器全链路反汇编，
得到决定性证据。

### 17.1 设备类型→wire 格式选择（ReportGenerator 构造函数 0x7cf2bc）【已验证】

`CHIDDeviceReportGenerator::CHIDDeviceReportGenerator(player, deviceId, IHIDDevice*,
info, int, int)` 对 `CHIDDeviceInfo` 拷贝执行：

```
this+144 = GuessControllerType(info.vendor_id, info.product_id)  // EControllerType
this+148 = wire 类型：
  if (info 偏移 88 处 bool != 0)   → 4 (Generic)
  else switch (EControllerType):
    2,3,4            → 1 (SteamController)
    0xa (10)         → 2 (Triton = SteamControllerV2，BIsTritonDongle VID 0x28de)
    0x2b (43)        → 3
    100..129 ∩ 0x04010007 → 1
    其他             → Log + AssertMsgHelper("unknown controller type")
```

EControllerType 的 Nintendo 值（辅助函数位掩码解码，均【已验证】）：
`BIsSwitchController`（0x745354，掩码 0x01800440000000）→ t ∈ {38,42,51,52}；
`BIsJoyconController`（0x745370）→ t ∈ {39,40,41}。

【结论】**Nintendo 手柄类型不在任何 wire 分支内——没有 generic 标志时，
官方代码对 Nintendo 设备直接走到断言。"声明真实 NS Pro VID/PID 且不带
generic 标志"在官方客户端中不是合法发送模式。** 与真机观察（移除标志后
host 完全不认输入）一致。

### 17.2 官方为 SDL 手柄声明 is_generic_gamepad（EnumerateDevices 0x75480c）【已验证】

`CHIDDeviceListSDL::EnumerateDevices` 构造 CHIDDeviceInfo：

```
w22 = (SDL_GetGamepadType(pad) != XBOX360)
usage = w22 ? 5 : 4
has_bits |= 0x380            // interface_number + ostype + is_generic_gamepad
if (w22) { has_bits |= 0x100000; *(bool*)(info+88) = 1; }  // 0x754bbc
vendor_id/product_id = SDL 真实 VID/PID（GuessControllerType 的输入）
caps_bits/caps_bits2 由辅助函数从 SDL gamepad 能力计算
```

【结论】官方 Android 客户端对 **除 Xbox360 型之外的一切 SDL 手柄
（含 Nintendo Pro/Joycon/PS）** 都置 `is_generic_gamepad=true`，同时保留
真实 VID/PID。我们的 InfoFromHID 恢复该标志即与官方一致。

### 17.3 Generic wire 格式 = RAW V2 结构体，版本字节 3【已验证】

`CStreamPlayer::CHIDDeviceReportGenerator` 的两个分发器按 this+148 分发
（`BParseGamepadState` 0x7d0044 / `BInjectGamepadState` 0x7d0074）：
1=SteamController、2=Triton、4=Generic（Pack 内联）、其余 false。
`BParseGamepadStateMobileTouch`/`BInjectGamepadStateMobileTouch` 为 8 字节
空桩——触摸不走生成器（对应独立 control 消息族）。

`BParseGamepadStateGenericGamepad`（0x7d089c）双模式，由输入 byte[27] 选择：
- byte[27]==0（ENCODED）：axes = u16[6] @0..11；buttons = byte[12..26] 展开
  为 state+16 u32 位域 bit0..14；随后 state byte[27] = 3（0x7d0a50）。
- byte[27]!=0（RAW）：`memcpy(state, input, min(len,72))`；version≤2 时
  flags `orr 0xc00`（bits 10,11）兼容修正。

客户端链路（BCollectReports 0x7cf884，【已验证】）：
本地 IHIDDevice 读报告 → Parse（Generic 模式，本地报告为 ENCODED）→
`CStreamPlayer::BFilterGamepadState`（0x7bc5c8）过滤 → 注入 wire 缓冲
（Generic= `Pack(state, buf, cap)`，0x7cfd8c → RAW 模式输出整个 V2 结构体）。
Parse 失败的原始报告整条丢弃。

**官方 wire 上的 Generic 报告 = RAW 模式 V2 结构体（最长 72B），byte[27]=3**：
```
[0..11]  axes 6×s16 (LX,LY,RX,RY,LT,RT)
[12..15] flags u32（version=3 时 host 不做修正；官方值未逐位确认）
[16..19] buttons u32，EGamepadButton 位
[20..26] 0
[27]     版本字节 = 3（RAW 选择器）
[28..71] IMU/touch 区；gyro s16[3] @28、accel s16[3] @34、touch @40
```
ENCODED 28B 格式只存在于本地 SDL 层与生成器之间，不上 wire。
host 两种模式都能解析（同一函数），但 RAW+版本 3 是官方实际发送形态。

> **2026-10-22 更正**：上表 [28..71] 不再视为“布局未确认、发 0”。
> 官方 Linux 1.3.9.258 客户端（SHA-256 `191cc079…c149e4`）的
> `CHIDDeviceSDLGamepad::OnSensorEvent @0x269740` 明确写入 gyro `+0x1c`
> 与 accel `+0x22`，并置 flags bit1/bit2；`BInjectGamepadStateGenericGamepad
> @0x2dac70` 在 byte[27]!=0 时最多拷贝 56B。旧的“发 0”实现会丢弃全部
> IMU。单位与 Switch 接入见 §19。

### 17.4 EGamepadButton 枚举值（名表 0x3dabc4 反解，27 项）【已验证】

```
0 BeforeFirst   1 Y(north)      2 DPad_Down    3 A(south)
4 RStick_Right  5 RStick_Up     6 R3           7 RStick_Left
8 LB            9 RB           10 Start       11 Select
12 LStick_Left 13 Trigger_Left 14 Trigger_Right 15 X(west)
16 Steam(guide) 17 LStick_Right 18 L3         19 DPad_Up
20 LStick_Down 21 LStick_Up    22 RStick_Down 23 AfterLast
24 B(east)     25 DPad_Right   26 DPad_Left
```
按钮位域在 state+16（`SetButton` 0x761094：u32 @+16，索引<0x20 断言）。

### 17.5 SendBuffer 发送语义（0x7d00f0）【已验证】

- 与 lastSent（this+328）len+memcmp 相同 → 整包回收**不发送**（去重）；
- 否则填 `DeviceInputReports`（proto 指针存 this+256）：
  `device` = 设备 managed id；`full_report` 整包，或自适应
  **delta_report**：逐字节变化位图 + 变化字节，仅当 `deltaLen+8 < fullLen`
  才发 delta，附 `delta_report_size`=fullLen、`delta_report_crc`=CRC32；
- delta 用的缓冲含上次发送内容（this+320/328 链）。

我们 report.c 的 AddDelta/去重/自适应规则与之一致（本轮已对照）。

### 17.6 生效代码改动

- `control_hid.c InfoFromHID`：恢复 `is_generic_gamepad=true`
  （17.2 证据；2026-09-07 真机移除标志 → host 不认输入的直接回归证据）；
- `sdl_hid_common.h`：`IHS_HIDReportSDLPackWire` 重写为 RAW V2（按钮经
  SDL3→EGamepadButton 映射，byte[27]=3），`IHS_HIDDeviceSDLWireReportLength`
  = min(host 通告长度, 72)；
- 历史 `sdl_hid_event.c` 三条路径（flush delta / resync full-mask / neutral reset；full-mask 依据已撤回）
  统一走共享 packer，缓冲 48→72。

### 17.7 遗留矛盾（待验证，不影响本轮修复）

旧 ihslib 48B 结构体直发（SDL3 按钮位 0..15 直写 +16 位域）在 host 侧按
§17.3 RAW 解析应产生错乱按钮（bit1=Y、bit3=A…），但历史真机按钮基本可用。
最可能解释（【推断】）：历史构建未设 is_generic_gamepad，host 对
Nintendo VID/PID 走了非 generic 解析路径（其行为未逆向，host 侧为 PC Steam，
不在 libmain.so 内）。git 考古可确认历史 InfoFromHID 的标志状态。

### 17.8 部署状态

2026-09-07 构建通过（switch NRO），待 netloader 推送真机验证：
预期 ABXY/十字键/L3/R3 映射按 §17.4 位置语义直达 host Steam Input 的
Generic 模板（Nintendo 布局习惯的 A/B 互换由 host 端 Steam Input 设置承担，
与官方 Android 客户端行为相同）。

### 17.9 更正：按钮位域是 SDL 序，不是 EGamepadButton（2026-09-07 真机回归后）

§17.4 的 EGamepadButton 位分配解算本身没错（枚举名表 0x3dabc4 反解正确），
但**该 protobuf 枚举与 state+16 位域无关**。决定性证据：

`CHIDDeviceSDLGamepad::OnButtonEvent`（0x754034）【已验证】：

```
mask = 1 << ev->button;      // SDL_GamepadButton 值直接移位
if (down) state+16 |= mask;  else state+16 &= ~mask;
// 另：byte[162] 标志置位时 button==5(GUIDE) 被吞掉不上报
```

即 wire 位域位序 = SDL_GamepadButton（0 起始：A=0,B=1,X=2,Y=3,BACK=4,
GUIDE=5,START=6,L3=7,R3=8,LB=9,RB=10,十字 上11/下12/左13/右14,MISC1=15）。
ihslib 原版 `1 << SDL_button` 本来就是对的。

上一构建用 EGamepadButton 位（A=3,B=24,X=15,Y=1）发送，host 按 SDL 序解释，
真机症状与错位预测完全吻合：Y→bit1=host B（触发菜单/返回类动作）、
A→bit3=host Y（UI 无反应）、X→bit15=host MISC1（无反应）、B→bit24（越界丢弃）；
左摇杆走轴字节不受影响。

已回退按钮映射为 SDL 位直通（sdl_hid_common.h），RAW V2 结构体与版本字节 3
不变。本节同时收回 §17.4 末段对该映射的实现引用。

## 18. 2026-09-07 卡死会话取证（prev stream_diag 2791587B 全量离线分析）

会话：20:17:42 开始，~20:26:27 结束（525s），两次 ~20s 卡死（第二次以持续旋转
右摇杆为标记）。按钮映射修复（§17.9）真机确认生效。

### 18.1 客户端健康度（卡死期间）【已验证】

- hidEvAge（事件捕获年龄）全程 max ≤50ms —— SDL 事件泵健康；
- hidrep（报告提交）时间戳全程无 ≥5s 空洞 —— flush/发送线程健康；
- 全程无 Frames window overflow / disconnect / Failed-to-decrypt。

【结论】两次游戏内卡死期间客户端侧事件、提交、发送全部正常，
上述日志只能证明记录到的事件与报告提交仍在发生；不能证明所有报告实际发出、
被 host 正确解密或应用。hidrep 存在截断和排队滞后，详见协议参考 §14.6。
早期 31-51s / 74-97s 两个零事件窗口在进游戏前（40.7s 处有 2.5s 视频停顿），
与游戏内卡死无关。

### 18.2 加密计数器失配：观测保留，所谓“官方成功才递增”撤回

Evidence：`/tmp/stream_diag_prev.log:14412` 起有 45 条序列失配日志；
首条为 `312 (expect 311), id=348`。这证明收到的加密序列与本地期望不同，
不能单凭日志断言是哪一层丢弃、跳过或多消费了消息。

**撤回旧结论**：“官方仅解密成功才递增，因此 8bb05be 修复了确定性 bug”。
重新反汇编同一 `libmain.so`：`0x7ad060 add`、`0x7ad064 str` 先更新计数器，
`0x7ad06c bl BDecrypt` 后解密，`0x7ad070 tbz` 才分成功/失败。
官方实际为 `BDecrypt(recvSequence++, ...)`，失败不回滚；8bb05be 与该语义相反。

此外，我方窗口在解密前就已 Poll 并释放该帧，解密失败仍确认 packet ID。
因此“冻结计数器后迟到的重传自然自愈”也没有成立：已越过的旧 packet ID 不会
重新交付。正确性依赖可靠传输不误确认、不跳洞；详见协议参考 §14.1–14.3。

### 18.3 待验证（需 host 侧证据）

- 两次 ~20s 卡死的确切机制仍未定位。工作假设【推断】：同一时段的丢包
  突发在我们的输入流上造成 host 侧解密计数器失配/窗口洞，host 停止
  apply 我们的输入消息，~20s 后经某种重同步恢复。客户端日志无法区分
  "host 解密丢弃"与"host 内部停滞"，需要 kxn-pc `streaming_log.txt`
  对应时段（20:17-20:27）比对 host 侧是否有解密/序列错误。
- ~27 帧 host 消息百余秒未送达：若官方 host 无限重传未 ACK 包，则
  我们的累计 ACK/NACK 反馈可能让 host 误信洞已填。需结合 host 日志
  与/或下一步 pcap 密文层时序分析。

### 18.4 host 日志比对（kxn-pc streaming_log.txt，2026-09-07 会话）【已验证】

游戏：黑神话：悟空（gameID 2358720），20:17:47 串流开始，20:26:29 退出到桌面。

host 侧唯一异常窗口 **20:24:21**：
```
NVENC: Hardware encoding is too slow, disabling
Encoder stage failed [type=2, codec=4]
CGameStreamVideoStageMFX: Couldn't init session ×4 → MFX not supported
Created encoder X264 (libx264 superfast zerolatency, 4 threads)
>>> Capture method set to Game polled D3D11 NV12 + libx264 main
Setting target framerate: 30.00 [game 35.59ms (game)]
```
与客户端证据对齐：
- 客户端加密失配起点 20:24:00（丢 host 一帧）——比 NVENC 宣告死亡早 21s，
  即 "too slow" 恶化期从 ~20:24:00 已开始（GPU/场景重载）；
- 客户端第二次卡死的右摇杆事件簇 20:25:28-20:25:59 紧跟该窗口之后；
- 20:18:34 game=111ms 尖峰（游戏加载）对应客户端 40.7s 处 2.5s 视频停顿
  与 31-51s 零输入窗口——第一次卡死【推断】为游戏加载期。

**撤回旧结论**：“host 日志没有输入报错，所以没有输入流洞；卡死是 NVENC
负载事件，非协议 bug；协议唯一缺陷已修”。日志未报告错误不能证明接收、
解密、delta CRC 和虚拟控制器应用均成功。Android 客户端汇编也不能证明
Windows host 内部存在某个 20 秒恢复计时器。

本节所引 NVENC 错误在 20:24:21，而列出的右摇杆事件簇在 20:25:28–20:25:59；
不能把两者直接当作同一故障窗口。GPU/编码负载与输入停滞的因果关系仍是
hypothesis。原始 host 日志在此次本地复核中未取得，以上摘录按历史转述保留。
客户端 NACK 双向错误已在真实代码离线复现，不能排除协议问题。

### 18.5 "Slow framerate" 异常统计：旧单位解释不足

host 日志每秒 `Slow framerate: ... network 3118880768.00, decode 3xx,
display 7xx-10xx (network)(decode)(display)` 中 network/decode/display 三列
为 10^8-10^9 量级假值：均由我方上报的帧级时间戳推导，单位仍不正确
（§18.1 期间客户端真实帧率正常、hidEvAge≤50ms）。game 列（host 本机测量）
真实有效。已修的 16.16 定点秒（packet.c）覆盖了帧事件时间戳，
但 FrameEvents 的事件差分编码本身不匹配官方（协议参考 §14.4），
不能继续只按单位解释；统计反馈对输入卡死的影响尚未建立因果证据。

## 19. Switch 六轴（陀螺仪 + 加速度计）接入（2026-10-22）

### 19.1 为什么此前“协议支持但没有打开”【已验证】

1. **SDL 的 Switch 驱动不提供传感器事件。** devkitPro SDL 2.28.5-4 的
   `SWITCH_JoystickSetSensorsEnabled` 只有 `mov w0,#4; b SDL_Error`
   （反汇编 `/opt/devkitpro/portlibs/switch/lib/libSDL2.a` 的 `SDL_sysjoystick.o`），
   即 `SDL_GameControllerSetSensorEnabled()` 在 Switch 上恒失败；`SDL_PollEvent`
   不会产生 `SDL_CONTROLLERSENSORUPDATE`。所以只修 ihslib 的打包逻辑仍不会
   在 Switch 上得到任何样本。
2. **ihslib 的 Generic RAW V2 打包器把 IMU 区清零。** 旧
   `IHS_HIDReportSDLPackWire` 只写 axes/buttons/version，[28..71] 全 0；
   即使桌面 SDL 产生传感器事件，`SetGyro/SetAccel` 写入的内部状态也不会
   进入 wire。历史提交 929767a 曾尝试透传，但 39fcb1d 以“ENCODED 格式
   不含 IMU”为由撤回；该前提只适用于 byte[27]==0 的 ENCODED 分支，
   不适用于本项目实际发送的 RAW+version 3。
3. **host 端协议本来就带 IMU。** 官方 Linux 1.3.9.258 客户端
   （`steamlink`，SHA-256 `191cc079f795cfdff69a8b51041360a2164b3ec64647e9419af2e2d00fc149e4`）
   `CHIDDeviceSDLGamepad::OnSensorEvent @0x269740`：
   - `sensor==2`（GYRO）：把 `event.data[0..2]` 按
     `(v + 34.90659)/69.81317 * 65535 - 32768` 转成三个 s16，写入 state
     `+0x1c/+0x1e/+0x20`，并 `flags |= 0x2`；
   - `sensor==1`（ACCEL）：同样的映射（半量程 19.6133，满量程 39.2266）
     写入 `+0x22/+0x24/+0x26`，并 `flags |= 0x4`。
   常量位于 0x9b72e8–0x9b72fc：65535、32768、34.90659、69.81317、
   19.6133、39.2266。`CHIDDeviceSDLGamepad::Write @0x268e30` 的
   `COMMAND_SET_SENSOR_ENABLED` 分支在 value!=0 时启用 SDL 的
   ACCEL/GYRO 并 `flags |= 0x6`，value==0 时清除 0x6。
   `GetGyroDPSRatingForControllerType @0x161870` 返回 2000，
   `GetAccelerometerGravityConstant @0x161880` 返回 16383（≈1g），
   与“gyro ±2000 dps、accel ±2g 的 s16 定点”一致。
4. **libnx 的底层状态可用。** libnx `HidSixAxisSensorState` 提供
   `angular_velocity`、`acceleration`、`delta_time`、`sampling_number`，
   且可用 `hidGetSixAxisSensorHandles` / `hidStartSixAxisSensor` /
   `hidGetSixAxisSensorStates` 按 `HidNpadStyleTag` 获取。

### 19.2 wire 契约（RAW V2，byte[27]!=0）【已验证】

```
[0..11]  axes 6×s16
[12..15] flags u32：bit1 = gyro present，bit2 = accel present
[16..19] buttons u32（SDL_GamepadButton 位）
[20..26] 0
[27]     version（本项目发 3，非零即 RAW）
[28..33] gyro s16[3]：rad/s × 65535/69.81317，即 ±2000 dps
[34..39] accel s16[3]：m/s² × 65535/39.2266，即 ±2 g
[40..43] touch（本项目仍为 0）
[44..55] 其余 V2 尾部（本项目 0）
```

`BInjectGamepadStateGenericGamepad @0x2dac70` 在 byte[27]!=0 时最多拷贝
56B；Android 1.3.32 的旧记录写 72B，本项目保留 `min(host length, 72)`
的现有上限，但 56B 之后始终为 0。Delta mask 仍按 host 通告长度生成。

### 19.3 单位与轴向对齐【已验证/推断分列】

- **单位（已验证）**：Nintendo 的 `imu_sensor_notes.md` 明确
  “Internally Switch uses revolutions per second instead of degrees”，
  加速度以 g 表示；libnx 直接暴露该状态。SDL 的
  `SDL_SENSOR_GYRO` 是 rad/s、`SDL_SENSOR_ACCEL` 是 m/s²。因此
  `gyro_rad_s = angular_velocity_rev_s * 2π`，
  `accel_m_s2 = acceleration_g * 9.80665`。
- **Switch 共享内存 -> SDL 标准帧（已验证于两个独立模拟器）**：
  yuzu `src/input_common/drivers/sdl_driver.cpp` 把 SDL 样本写成
  `switch_gyro=(x, -z, y)/2π`、`switch_accel=(-x, z, -y)/g`；
  Ryujinx `NpadController.Update` 使用同一轴置换
  `(x, -z, y)`。取逆得到本项目使用的：
  ```
  sdl_gyro  = ( av.x,  av.z, -av.y) * 2π
  sdl_accel = (-acc.x, -acc.z, acc.y) * g
  ```
- **不按 Joy-Con 左右再翻转（推断，待真机确认）**：Switch 的 `hid`
  服务对 Pro/Joy-Con/handheld 输出同一控制器帧；SDL HIDAPI 的
  `(-Y, Z, -X)` 和右手柄 `data[0]/data[1]` 翻转针对的是**绕过服务的
  原始 HID 报告**，不适用于 libnx 已归一化的状态。若真机上左右
  Joy-Con 方向相反，只需在 `sensor_math.c` 增加按 device type 的
  后处理，不改协议层。

### 19.4 实现落点【已验证】

- `third_party/ihslib/src/hid/sdl/src/sdl_hid_report.c`：
  `SetGyro` 置 flags bit1、`SetAccel` 置 bit2；新增
  `IHS_HIDReportSDLClearSensors`。
- `third_party/ihslib/src/hid/sdl/src/sdl_hid_common.h`：
  `IHS_HIDReportSDLPackWire` 复制 flags、gyro、accel、touch 到
  [12..47]；[48..] 保持 0。
- `third_party/ihslib/include/ihslib/hid/sdl.h` + `sdl_hid_event.c`：
  新增 `IHS_HIDSDLInjectSensor(session, joystickId, gyro, accel)`，
  在设备锁内合并到 canonical state；发送仍由既有 8ms flush 线程完成。
- `app/platforms/switch/sensors.c`：
  按 `HidNpadStyleTag` 取 handheld/FullKey/JoyDual/JoyLeft/JoyRight 句柄；
  JoyDual 优先右手柄；每 4ms 取最新 `sampling_number`，转换后注入；
  只从 `pump_sdl_events`（SDL/libnx HID 所属媒体线程）调用，
  会话停止/退出时 `hidStopSixAxisSensor`。
- `app/platforms/common/sensor_math.c`：单位/轴向纯函数，桌面测试覆盖。
- `app/platforms/common/media.c`：会话有效且 input gate 打开时
  `sl_sensors_poll`，否则 `sl_sensors_stop`；shutdown 再 stop 一次。
- 测试：`ihstest_hid_sdl_report` 校验 flags/gyro/accel 的 wire offsets；
  `nsl-sensor-math` 校验单位与轴向；desktop 246/246 通过，Switch
  release NRO 构建通过。

### 19.5 真机六轴采集与轴向结果（2026-10-22，Handheld）

设备地址 `10.10.10.66`，hbmenu netloader + nxlink 推送，未开 Steam 会话。
工具：`nsl-sixaxis-probe`（机器可读采样）和 `nsl-sixaxis-view`（屏幕可视化）。

- **采样路径成立**：`handheld_style=0x2`、`no1_style=0`、`handheld_type=12`；
  `hidGetSixAxisSensorHandles`/`hidStartSixAxisSensor` 均返回 0；只有
  handheld 句柄有数据，fullkey/joydual/joyleft/joyright 句柄返回 0（当前
  没有对应控制器连接）。
- **采样率**：状态 `delta_time=5,000,000 ns`；19.914 秒内 `sampling_number`
  增加 3871，约 **194 Hz**（标称 200 Hz 附近）。
- **静止姿态**：accel 约 `(0.02, -0.29, -1.06) g`，主要沿 **-Z**；转换后
  SDL accel 约 `(-0.2, 10.4, -2.8) m/s²`，主要沿 **+Y**。这符合
  “屏幕朝上/近似平放时重力在 SDL Y 轴”的预期。
- **引导动作（3 轮 REST/YAW/PITCH/ROLL）**：
  - YAW（绕竖直轴左右转）：raw **Z** 范围约 `-0.95..+0.81 rev/s`，
    X/Y 较小；对应 SDL **Y**。
  - PITCH（前后倾）：raw **X** 范围约 `-1.10..+1.19 rev/s`；对应 SDL **X**。
  - ROLL（左右滚）：raw **Y** 范围约 `-0.90..+0.84 rev/s`；对应 SDL **Z**。
  这三组结果支持 `sensor_math.c` 的 `(x, z, -y)` 映射和“libnx X=pitch、
  Y=roll、Z=yaw”的轴向假设。第一轮用户未完全按提示动作，第二轮/第三轮
  的 Z/X/Y 主导关系很清楚。
- **仍未验证**：Pro Controller、单 Joy-Con、左右 Joy-Con 分离时的
  方向/符号；Steam host 是否接受“未先发 `SetSensorEnabled` 即出现 IMU”
  的数据；Steam Input 的 Gyro 正负方向（真机若相反，只需在
  `sensor_math.c` 取反对应分量，wire 格式不变）。

## 20. Steam Windows host 对 Switch Generic IMU 的消费路径（2026-10-23 逆向）

本节只记录可复核的证据、结论和假设，不把“host 显示了 Gyro UI”当成“host 消费了
IMU”。这是 2026-10-22/23 多轮真机对照后的收敛结果。

### 20.1 材料

- Windows Steam host：`steamclient64.dll`，FileVersion `11.12.30.07`，编译时间
  `2026-10-14`，SHA-256
  `e9045710ec7ee47d7b7488d1c5dda2d933dec7e251e965967a5c48f4df68eb4e`。
- 该 DLL 内嵌的源码路径（`__FILE__` 字符串）：
  `src/common/hiddevicesdl.cpp`、`src/common/hiddeviceremote.cpp`、
  `src/clientdll/controllerabstraction.cpp`、
  `src/clientdll/controller_sources/controller_source_gyro.cpp`、
  `src/clientdll/controller_gyroprocessing.cpp`。
- host 侧 VDF：`controller_switch_pro.vdf` 的 group 8 为
  `gyro_to_mouse`，preset 中 `"8" "gyro active"`，
  `controller_caps = 0x8B4BFF`（含 `0x800`）。这证明 Gyro 行为是启用状态，
  不是“没保存”。
- 真机日志（NX 侧注入点）：
  `sensor inject motion=0.117 flags=0x6 wire_gyro=50,0,-60`。
  同一会话 host 反复发 `host sensor enable=1/0`，说明 host 主动请求了
  sensor，且客户端把非零 gyro 写进了 wire。

### 20.2 host 侧 `CHIDDeviceSDLGamepad` 的状态布局

通过 RTTI/vtable 定位（镜像基址 `0x138000000`）：

- RTTI type descriptor `.?AVCHIDDeviceSDLGamepad@@` @ `0x17ce878`；
  vtable @ `0x1392fa7a8`。
- `OnSensorEvent` @ `0x1386d30e0`。它从 `SDL_GamepadSensorEvent`
  取 `[event+0x14]` 的 sensor type 和 `[event+0x18/+0x1c/+0x20]` 的三个
  float，写入 state：
  - 正常分支：gyro s16 @ `state+0x1c`，`flags |= 0x402`；accel s16 @
    `state+0x22`，`flags |= 0x4`；
  - 左/备用分支（SDL sensor type 3/4，即 ACCEL_L/GYRO_L）：gyro 写
    `state+0x38`、accel 写 `state+0x3e`，并置 `0xa00`/`0x4`。
  - 两个分支的选择来自 `[event+0x14]` 的 SDL sensor type，不是来自
    wire flags；`0x400` 是 host 内部 state 的标记，不应直接当成
    “remote gyro valid”位。
- 因此 host 本地 SDL 路径的 gyro 布局与 ihslib 的 `+0x1c` 一致；差异是
  host 本地 flags 带 `0x400`，且存在第二套 `+0x38/+0x3e` 布局。
- 真机试过把客户端 flags 从 `0x6` 改成 `0x406`：**整个手柄输入失效**
  （按键/摇杆都无输入），不是“gyro 开始工作”。这说明 `0x400` 是 host
  内部 state 的语义位，不能安全地直接补到 remote Generic wire flags；
  它会让 host 进入另一套解释，和 Generic V2 的 `+0x16`/`+0x1c` 布局
  不兼容。

### 20.3 host 侧 Generic 抽象

- `CGenericGamepadControllerAbstraction` RTTI
  `.?AVCGenericGamepadControllerAbstraction@@` @ `0x17cb5d8`；
  vtable @ `0x1392ea3d0`。
- 候选 `ProcessState` @ `0x1386793e0`（vtable slot 13）把 HID state 视为位于对象 `+0x18`：
  axes 在 `+0x18..+0x22`，version 在 `+0x33`（即 HID state `+0x1b`），
  RAW 分支从 `+0x18` 起拷贝 `0x48` 字节到局部
  `HIDDeviceSDLGamepadStateV2_t`，因此 gyro `+0x34`（HID `+0x1c`）和
  accel `+0x3a`（HID `+0x22`）在拷贝范围内。
- 候选 state-changed 比较 @ `0x138678ea0` 只读
  `+0x18..+0x22`（axes）和 `+0xc..+0x12`（flags/其他），**没有比较
  `+0x34/+0x3a` 的 gyro/accel**；它把 state 缓存到 `+0x108`，长度
  `0xa0`。
- 远程 HID report 相关函数 @ `0x1386cf580`（同文件断言在 `0x1386d0031` 引用下方字符串）走的是
  `hiddeviceremote.cpp` 的 report-type 分发；字符串
  `CHIDDeviceRemote::ProcessInputReport(): Received unknown report type`
  @ `0x1392f9b30`。这条路径按 report byte/type 构造
  `CHIDDeviceInputReport`，不是直接把 Generic V2 的 tail 当作连续 IMU 流。

### 20.4 真机对照结果

| 配置 | host 布局 | Gyro UI | 震动 | 实际 gyro 输出 |
|---|---|---|---|---|
| Generic `0000:0000`，caps `0x8043ff` | 4 项 | 无 | 正常 | 无 |
| Generic + `0x800`，Steam Input 开 | Gyro 出现 | 有 | 正常 | **无** |
| Switch Pro `057e:2009` + `0x800` | 6 项 | 有，校准成功 | 正常 | **无** |
| Switch Pro + `0x800` + flags `0x400` | 输入全失效 | — | — | — |
| DS4 `054c:09cc` + `0x800` | 6 项（含触控板） | 有 | 正常 | **无** |

`controller_switch_pro.vdf` 里 `gyro_to_mouse` active、`gyro_natural_sensitivity=483`，
但桌面指针、右摇杆、游戏内动作都不响应。校准能成功只说明 host 能拿到
一部分运动样本（校准可用 accel/初始样本完成），不等于连续 gyro 被送进
Gyro action group。

### 20.5 结论与假设

**Evidence：**

1. NX 侧 gyro 已进入 canonical state 和 wire：`flags=0x6`，
   `wire_gyro` 非零；host 主动发 `SetSensorEnabled`。
2. host 的 VDF Gyro group active，caps 含 `0x800`；host 本地
   `CHIDDeviceSDLGamepad::OnSensorEvent` 的 gyro 布局也是 `+0x1c`。
3. host 的 `CGenericGamepadControllerAbstraction` 的 state-change 比较
   不含 `+0x34/+0x3a`（gyro/accel）字段；`CHIDDeviceRemote::ProcessInputReport`
   按 report type 分发，不是连续 IMU 流。
4. 官方 Linux 1.3.9.258 的 `BParseGamepadStateSwitch @0x2da140` 只解析
   Switch 原生报告的按键/摇杆，不读 IMU；官方唯一 IMU 路径是
   `CHIDDeviceSDLGamepad::OnSensorEvent`。

**Retraction（2026-10-23）：** 本节初稿把“host 不消费 IMU”写成了结论，这是
下早了。逐位比对 host VDF 的 `controller_caps = 0x8B4BFF` 与
`InfoFromHID` 的基线 caps 后，发现基线是 `0x8343FF`（ABXY/DPAD/双摇杆/
肩键/扳机/Back/Start/Guide/Misc1/XInput/UNK_3/UNK_4），和 host VDF 只差
**`0x800` + `0x80000`**。真机只补过 `0x800`（Gyro UI 出现、无数据），
**`0x80000` 从未测过**。因此下面的“host 不支持”不能作为结论，降级为待验证。

**Conclusion（当前可下的部分）：**

- 客户端没有丢 IMU；host 的 VDF Gyro group active，UI 能出现。
- 只补 `0x800` 时没有数据输出；`0x400` 直接让输入失效，不能补。
- host 的 Switch 原生 parser 不读 IMU（官方 Linux 客户端
  `BParseGamepadStateSwitch @0x2da140`），所以“改成Switch 原生报告”
  不是显然更优的方向。
- `0x80000` 是否是 host 的 motion/数据通路位，仍为 `待验证`；在它验证
  之前，不能判定 host 不支持 Switch Generic gyro。

**Hypothesis（待验证）：**

- host 的 `CGenericGamepadControllerAbstraction` 只在 axes/flags 变化时
  推进 state；纯 IMU 变化（不动摇杆/按键）不会触发 Gyro source 更新。
  这可以解释“校准成功、但转动完全无输出”。
- 若该假设成立，客户端侧较可行的兼容层是发送 host 已有 gyro 支持的
  **DS4/DualSense 原生报告**（host 的 PS4/PS5 gyro 路径是既有的），
  而不是继续改 Generic caps；这需要实现 DS4 的 input report/feature
  report，成本和风险都高于当前 Generic 路径。
- 另一条待验证路径是让 host 在收到 IMU 时也标记 state changed；这属于
  host 内部行为，客户端无法直接控制。

### 20.6 精确消费点：`CGyroSource::Update` 与 flags `0x800/0x400` 门控（2026-10-23 继续逆向）

继续沿 `controller_source_gyro.cpp` 追到实际消费函数，已定位到一条完整、可解释
“校准成功但 gyro 无输出”的路径：

- **消费函数**：`CGyroSource::Update` @ `0x1386702d0`（`CGyroSource` vtable
  slot 9；vtable @ `0x1392e5218`，RTTI `.?AVCGyroSource@@` @ `0x17cb270`）。
- **输入结构**：`rdx` 指向的 controller/raw state 里，
  accel s16 在 `+0x24/+0x26/+0x28`，gyro s16 在 `+0x2a/+0x2c/+0x2e`。
  `Update` 先检查这 6 个 word；若全为 0，直接跳到 `0x138670788` 返回，
  不产生四元数、不更新 prediction，也不通知 Gyro mode。
- **填充函数**：`CGenericGamepadControllerAbstraction` 内
  `0x1386796f0` 起的循环负责把这 6 个字段写进上述输入：
  - slot 0（`edi=0`）要求 **`flags & 0x800`**；
  - slot 1（`edi=1`）要求 **`flags & 0x400`**；
  - accel 另要求 **`flags & 0x4`**；
  - 通过后把 gyro 写到输入 `+0x2a/+0x2e/+0x2c`，accel 写到
    `+0x24/+0x26/+0x28`（并做一次 y/z 交换和 y 取反）。
- **我们的 wire flags 是 `0x6`**：accel 的 `0x4` 有，所以校准能用 accel 完成；
  gyro 需要的 `0x800`（slot 0）和 `0x400`（slot 1）都没有，填充循环直接跳过，
  输入 6 个 word 保持 0，`CGyroSource::Update` 提前返回 → Gyro mode 永远收不到
  样本。
- **slot 与 wire offset 的对应**（由同一段 `0x1386796f0` 的读写位置直接得出）：
  - slot 0（`flags & 0x800`）读 gyro `+0x38`、accel `+0x3e`；
  - slot 1（`flags & 0x400`）读 gyro `+0x1c`、accel `+0x22`。
  ihslib 目前只写 `+0x1c/+0x22`，所以它天然对应 **slot 1（0x400）**；
  要用 slot 0，必须把同样的 gyro/accel 再写到 `+0x38/+0x3e` 并置 `0x800`。
  之前 `0x400` 导致整只手柄失效的那次是 **Switch Pro 身份**构建，不能
  用来否定 Generic + `0x400`；两者混淆了。

这与真机现象完全一致：Gyro UI、校准、震动都正常（accel/flags 0x4 路径通），
但转动无输出（gyro slot 位未被填充）。因此 **caps `0x80000` 不是当前首要
问题；wire gyro flags 缺 `0x400`/`0x800` 才是**。当前包文写的是 `+0x1c/+0x22`，
所以优先补 **slot 1 的 `0x400`**；只有 `CGyroSource` 索引为 0 时才需要
slot 0 的 `+0x38/+0x3e`。之前 20.5 的 “host 不消费” 假设在此被替换。

**待验证的两个对照构建（均为 Generic 身份，不改 caps/VID/PID）：**

1. `build/switch-gyro400/app/nsteamlink.nro`：flags 改为 `0x402`，wire 仍写
   `+0x1c/+0x22`，对应 slot 1。这是与当前包文最匹配的组合，应优先测。
2. `build/switch-alt/app/nsteamlink.nro`：保留 `+0x1c/+0x22`，另把 gyro/accel
   复制到 `+0x38/+0x3e` 并置 `0x800`（slot 0），用于 `CGyroSource` 索引为 0
   的情况。`build/switch-gyro800/app/nsteamlink.nro` 只置了 `0x800` 但没有写
   `+0x38`，不能作为 slot 0 的有效测试，已废弃。

`CGyroSource::Update` 用 `[this+0xc0]` 选输入 slot；该索引由哪个控制器源
初始化仍是 `待验证`，所以先用 slot 1 的 `0x400` 对照，失败再测 slot 0 的
`+0x38` 布局。

**还有一个未验证前提**：`0x1386796f0` 读的 `edx` 是 host 内部 state 的
flags，不是已经证明与 wire flags 一一对应。官方 Linux 客户端
`OnSensorEvent` 只置 `0x2/0x4`，所以 host 的 remote parser 可能自己把
wire flags 翻译成内部 `0x400/0x800`；如果是这样，直接改 wire flags 不会
生效。两个构建（`0x400` 与 `+0x38/0x800`）就是用来区分这两种情况的；
在真机结果出来前，不能把“wire flags 直接等于内部 flags”当成结论。

### 20.7 官方 Windows packer 交叉验证：wire flags 就是内部 flags

为了确认 `0x1386796f0` 读到的 flags 是否就是 wire flags，检查了本机
`steamclient64.dll` 的官方 packer：

- `CHIDDeviceSDLGamepad` 的 pack 函数 @ `0x1386d35e0`。
- version（state `+0x1b`）非 0 时走 RAW 分支 `0x1386d37a6`：
  - `eax = 0x48`（72）；
  - `rbp = min(requested_len, 72)`；
  - `memcpy(dest, source_state, rbp)`。
- 也就是说 **RAW V2 是把内部 state 的 0..0x47 原样拷到 wire**，没有字段
  重排、没有 flags 翻译。内部 state 的 flags（`+0xc`）就是 wire `+0xc`。
- 同一 DLL 的 `OnSensorEvent @0x1386d30e0` 正常 gyro 分支写
  `state+0x1c`、`flags |= 0x402`；accel 写 `state+0x22`、`flags |= 0x4`。
  因此官方 Windows 客户端在本机带 gyro 的 SDL 手柄上，wire 就是：
  - `flags = 0x402`（加 accel 后 `0x406`）
  - gyro @ `+0x1c`
  - accel @ `+0x22`
- 这和 `CGenericGamepadControllerAbstraction` slot 1（`0x400`）读取
  `+0x1c/+0x22` 完全一致，也证明 **wire flags 与内部 flags 一一对应**，
  20.6 末尾的 `待验证` 前提成立。

**结论：我们应该发送的格式与官方 Windows 客户端完全一致：**

```text
flags = 0x2 | 0x4 | 0x400 = 0x406
gyro  = s16[3] @ +0x1c (28)
accel = s16[3] @ +0x22 (34)
version = 3 @ +0x1b (27)
```

`build/switch-gyro400/app/nsteamlink.nro` 就是这一格式：Generic 身份，
`SetGyro` flags `0x402`，`SetAccel` 保持 `0x4`，wire 偏移不变。

slot 0（`0x800` + `+0x38/+0x3e`）是另一条 sensor 布局（host 的
ACCEL_L/GYRO_L 分支），不是本机单 Pro/handheld 的主路径；
`build/switch-alt` 只作为兜底，不应优先使用。

### 20.8 真机反证：`0x400` 不能放进 remote Generic wire flags

2026-10-23 早上在 `10.10.10.66` 推送 `build/switch-gyro400`（Generic 身份，
`SetGyro` flags `0x402`，线上 flags `0x406`）实测：

- **Gyro 选项直接消失**；
- **按键/摇杆全部失效**。

这不是“只加一个 slot 位”的问题。它说明 host 的 remote Generic parser 把
wire flags 的 `0x400` 当成另一种报告模式/布局，直接拒绝或切换了解析；
`0x400` 是 host **内部 state** 的 sensor 位，不是 remote Generic 可安全
写入的 wire 位。

因此 20.7 的“发送 `0x406`”结论**撤回**：

- 官方 Windows packer 的 `0x402` 是**本地 SDL state** 的内部 flags；
- 它不能证明 remote Generic wire 也接受 `0x400`；
- 真机结果证明 remote Generic 不接受。

稳定可用的 wire flags 仍是 `0x6`（gyro presence `0x2` + accel `0x4`）；
不要再把 `0x400`/`0x800` 加进 wire flags。要设置 host 内部 sensor 位，
必须找到 remote parser/`DeviceInputReports` 一侧的机制，而不是直接改 flags。
