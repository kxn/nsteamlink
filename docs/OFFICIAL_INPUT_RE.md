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
