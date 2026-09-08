# Steam Link Android 客户端协议逆向参考（v1.3.32 / libmain.so）

> **证据更正（2026-09-07）**：本文历史段落的“已验证”不能整体沿用。
> §14 记录从同一 ELF 重新反汇编得到的反例：解密计数器在调用前递增；
> FrameEvents 首项加偏移、后续项为差分；NACK 的确认水位与掩码基址是两个字段。
> §13 的“逐字节等价／未验证 0 项”结论撤回，不能作为现行实现的正确性证明。

> 目的：对官方 Steam Link Android 客户端（v1.3.32，`lib/arm64-v8a/libmain.so`，24922 个动态符号）
> 的线上协议做系统性静态逆向，作为协议行为的权威参照（ihslib 属 legacy 参照，见第 8 节差异表）。
> 证据纪律：标注【已验证】（反汇编地址可复核）或【推断】（证据支持未直接观测）。
> 工作区：`/tmp/slink/`（libmain.so、全量反汇编 main.disasm 1,694,052 行、字符串表、官方会话 pcap）。
> 分析脚本：`/tmp/slink/work_index.py`（函数索引/调用点定位）、`work_scm_args.py`、`work_symlist.py`、`work_xref.py`。
> 工具：radare2 5.9.8、devkitPro aarch64 objdump、jadx 1.5.3（Java 层备用）。
> 日期：2026-09-04。逆向方法按 reverse-skill 路由包 apk-reverse/protocol-reverse 工作流执行。

## 1. 控制消息方向总表

### 1.1 官方客户端→host 发送全集【已验证】

方法：枚举 `CStreamClient::SendControlMessage(EStreamControlMessage, MessageLite const&)`（0x7a7d90）
的全部 35 个调用点（`bl c0e110 <SendControlMessage@plt>`），逐点提取 w1 类型常量与所属函数；
另有 1 个不走 SendControlMessage 的发送点（ClientHandshake，见 3.3）。

| 类型 | 消息 | 发送函数（0x7axxxx） | 备注 |
|---|---|---|---|
| 4 | NegotiationSetConfig | OnNegotiationInit (0x7ad698) | 收到 Init 后立即回应，见第 6 节 |
| 5 | NegotiationComplete | HandleStreamStarting (0x7a6f9c) | |
| 6 | ClientHandshake | OnStreamConnected (0x7ace2c) | **不走 SendControlMessage**，明文直发 |
| 9 | KeepAlive | SendKeepAlive (0x7a8744)、HandleStreaming (0x7a7140) | |
| 54 | InputMouseMotion ×2 | SendMouseMotion ×2 (0x7a9958/0x7a9b94) | float 与 int 两种重载 |
| 55/56/57 | MouseWheel/Down/Up | 0x7a9dc0/0x7a9fe8/0x7aa208 | |
| 58/59 | KeyDown/KeyUp | 0x7aa428/0x7aa660 | |
| 66 | GetCursorImage | 0x7aac40 | |
| 70 | InputLatencyTest | 0x7a910c | |
| 80 | VideoDecoderInfo | 0x7aacf0 | |
| 83 | QuitRequest | 0x7abbe0 | |
| 99 | SetStreamingClientConfig | 0x7b01c4 | |
| 102/104 | VirtualHereRequest/ShareDevice | 0x7aaf20/0x7ab154 | |
| 106 | RemoteHID | SendRemoteHIDMessage (0x7ab374) | 输入主通道，见 3.2 |
| 107/108 | Start/StopMicrophoneData | 0x7a87f0/0x7a8b18 | |
| 109 | InputText | 0x7aa898 | |
| 111/115 | GetTouchConfigData/GetTouchIconData | 0x7ab698/0x7ab748 | |
| 113 | SaveTouchConfigLayout | 0x7ab97c | |
| 117/118/119 | TouchFingerDown/Motion/Up | 0x7a92b4/0x7a94e4/0x7a9714 | |
| 122/123 | Pause/Resume | 0x7b02bc/0x7b0384 | |
| 124/125 | Enable/DisableHighResCapture | UpdateHighResCapture (0x7bbddc) | |
| 129 | StopRequest | 0x7abb4c | |
| 137 | ControllerConfigMsg | 0x7abb30 | |
| 148 | VideoOverflow | 0x7abc90 | 解码溢出上报 |
| — | （回放）任意 | PlayNextRecordedInput (0x7a6234) | 类型取自录制条目，白名单 {3,4,5,6,7,9,10,11,12,13} |

**官方客户端从不发送**（静态全集内不存在构造点）：50/51/52/53（Start/StopAudio/VideoData）、
**87 SetQoS、90 VideoEncoderInfo、94 SetTargetBitrate**、110/112/114/116（TouchConfig 下行族）、
117 以外的 InputTouch 旧族、SetQuality/SetBitrateOverride（134/135，仅有接收 handler）。

### 1.2 官方客户端接收全集（host→client）【已验证】

方法：`CStreamClient::On*` 符号枚举 + `OnStreamPacket`/`HandleIncomingPackets` 分发逻辑。
共 47 个接收 handler：OnServerHandshake、OnAuthenticationResponse、OnNegotiationInit、
OnNegotiationSetConfig、**OnSetQoS (0x7adcd0)、OnSetTargetBitrate (0x7aebb4)、
OnVideoEncoderInfo (0x7aee50)**、OnStartAudioData、OnStopAudioData、OnStartVideoData、
OnStopVideoData、OnSetCaptureSize、OnSetTitle、OnSetIcon、OnSetFlashState、OnShowCursor、
OnHideCursor、OnSetCursor、OnSetCursorImage、OnSetCursorScale、OnDeleteCursor、
OnSetTargetFramerate、OnSetGammaRamp、OnSetActivity、OnSystemSuspend、OnSetStreamingClientConfig、
OnVirtualHereReady、OnSetSpectatorMode、OnTouchConfigActive、OnSetTouchConfigData、
OnSetTouchIconData、OnToggleMagnification、OnSetCapslock、OnSetKeymap、
OnRemotePlayTogetherGroupUpdate、OnSetInputTemporarilyDisabled、OnSetQualityOverride、
OnSetBitrateOverride、OnShowOnScreenKeyboard、OnControllerPersonalizationUpdate、
OnControllerConfigMessage、OnVRConnectionReady、OnCaptureFailed、OnRemoteHIDMessage、OnDataPacket、
OnPingRequest（发现通道）。

### 1.3 方向结论（对 OFFICIAL_INPUT_RE.md §5 的更正）

【已验证】host 日志 `CLIENT:` 前缀的消息（SetQoS ×2、SetTargetBitrate ×2、VideoEncoderInfo ×7、
SetTitle/SetCursor/SetActivity、TouchConfig 族）全部落在 1.2 的接收集内、不在 1.1 的发送集内；
日志语序 "CLIENT: Sending HID device ..." 的主语是写日志的 host。
**结论：`CLIENT:` 前缀 = host 发给 client 的消息**。官方平板会话的 287 条 `CLIENT:` 记录
不能作为"官方客户端发送了这些控制消息"的证据；ihslib 客户端"从不发送 SetQoS/SetTargetBitrate/
VideoEncoderInfo"与官方行为**一致**而非缺失。OFFICIAL_INPUT_RE.md 第 5 节的解读与第 8 节
候选路线 B（补 SetQoS/SetTargetBitrate 控制对话）据此作废；ControllerConfigMsg(137)、
GetTouchConfigData(111)/GetTouchIconData(115)/SaveTouchConfigLayout(113) 是真实的 client→host
消息（发送函数存在），路线 B 中仅这部分有对齐意义。

## 2. 发送与可靠性【已验证，更正 R3/R4】

`CStreamClient::SendControlMessage`（0x7a7d90）：

```
CStreamFrame frame(1 /*k_EStreamChannelControl*/, type);
frame.Put(msg, false);                       // 不带长度前缀
if (type <= 7 && ((1u << type) & 0xC6)) {    // 0xC6 = 位 1,2,6,7
    frame.Send(conn, /*reliable=*/true);     // 明文 + 可靠路径
} else {
    ch = conn->GetChannel(1); lock(ch+0x38);
    frame.BEncrypt(++counter@CStreamClient+0x80, key@+0x40, keylen@+0x54);
    frame.Send(conn, /*reliable=*/true);
    unlock;
}
```

- `CStreamFrame::Send(CStreamConnection*, bool)`（0x7f3078）：**bool=true →
  `CStreamConnection::Send`（可靠有序）；false → `SendUnreliable`**。
  OFFICIAL_INPUT_RE.md §15/§16 把该映射写反，特此更正。
- **SendControlMessage 两条路径都硬编码 reliable=true**：官方客户端所有控制消息
  （含 125Hz 的 RemoteHID 输入流）都走可靠有序通道。§16 末"官方输入可能默认走不可靠通道"
  的猜测不成立；`SendUnreliable` 在客户端控制面存在但 SendControlMessage 不使用
  （数据面/其他路径是否使用待查）。
- 所有 Send* 函数发送前检查连接态 == 6（k_EStreamConnectionStateConnected，CStreamClient+0x100）。
- `SendRemoteHIDMessage(msg, bool)`（0x7ab374）的 bool 参数 = `CRemoteHIDMsg.active_input`
  （信封字段，proto field 2），不是可靠性开关；发送前另有一道字节闸门 CStreamClient+0x267
  （HID 子系统使能）。body 序列化 → 装入 CRemoteHIDMsg.data → SendControlMessage(106)；
  另在录制标志（CStreamClient+0x6b0 非零）时追加 CRecordedInput{type=106, timestamp=GetStreamTimestamp()}
  到 CRecordedInputStream。

## 3. 加密层【已验证】

- **明文消息集合**：发送侧掩码 0xC6 = {1 AuthenticationRequest, 2 AuthenticationResponse,
  6 ClientHandshake, 7 ServerHandshake}（ClientHandshake 在 OnStreamConnected 明文直发，
  与掩码一致）；接收侧掩码 0x63>>(t-1) = 同集合。`BEncryptedControlMessage`（0x7abc74）：
  加密 = {3,4,5} ∪ {>7}。**Negotiation 三条消息全部加密**（密钥在 Auth 握手阶段已协商）。
- 解密失败路径：`BDecrypt` 失败 → `Log("GetMessageName(...)")` → 丢弃（0x7ad07c）。
- **序列号**：发送计数器 CStreamClient+0x80（+128，uint64，每加密帧自增，先取值后增），
  接收计数器 CStreamClient+0x88（+136，调用解密前自增，失败不回滚，见 §14.3）。
  seq 在加密明文的前 8 字节内，**不在明文 UDP 包头中**；接收端另维护期望值，
  隐含要求加密帧严格按序到达——控制通道的可靠有序是加密正确性的前提。
- `CStreamFrame::BEncrypt(seq, key, keylen)`（0x7f342c）：
  `buf = seq(8, LE) || payload`；
  `iv = HMAC-MD5(key, buf)`（`CCrypto::GenerateHMACMD5`）；
  `ct = CCrypto::SymmetricEncryptWithIV(buf, len, iv, 16, key, keylen)`；
  写回 `payload' = iv(16) || ct`。

## 4. 帧与包头格式【已验证】

CStreamFrame 内存布局（栈对象，0x7f2af4 构造器）：
+8 = CStreamPacket*；+16 = hasHeader(bool，构造即 1)；+17 = hasExtHeader；
+20 = 头区偏移(int)；+24 = channel(u8)；+25 = messageType(u8)；
+26 = u16、+28 = u32、+44 = u16、+48 = u32（扩展头四字段）。

发送打包（0x7f3078 Send）：数据区 [0..12] 由连接层填充（13 字节连接头）；
data[13] = messageType；若 hasExtHeader：data[14..25] = 扩展头 12 字节
（+26 u16、+28 u32、+44 u16、+48 u32 依序）；其后为 protobuf 载荷
（`Put(msg, withLen)` 的 withLen=true 时前置 int32 长度 = 序列化长−4，本机小端；
控制通道 `Put(msg,false)` 无长度前缀）。channel 不写入帧数据，作为参数传给
`CStreamConnection::Send/SendUnreliable(packet, channel)`。

接收：`OnStreamPacket`（0x7acfa8）按 channel 分派——channel≥3 为数据通道
（仅接受 type==1，OnDataPacket；扩展头 +48 u32 字段减去 conn+848 的 peer−local 时钟偏移，换算为本地时间，
即**扩展头第 12 字节域是流时间戳**）；channel==1 为控制通道；channel==0（发现/Ping）
由 OnPingRequest 处理。控制通道内 type==9（KeepAlive）静默消费，type==106（RemoteHID）
内联转 IStreamPlayer 虚表槽 10，**其余控制消息经 ThreadInterlockedIncrement 引用计数后
推入 CStreamQueue<CStreamPacket*>（CStreamClient+0x2a0），由 HandleIncomingPackets
（0x7a6368）按类型分派（Setup 类型直接比较；50..147 走 0x4474f8 跳转表）**。

## 5. Negotiation 深挖【已验证】

`OnNegotiationInit`（0x7ad698）从 host CNegotiationInitMsg 读取：

| InitMsg 字段 | 官方处理 |
|---|---|
| reliable_data (bool) | **无条件字节回显**进自身 CNegotiatedConfig.reliable_data（含 hasbit），随 SetConfig 发回 host |
| supported_audio_codecs | 顺序扫描，取首个 ∈ {1, 3}（Raw/Opus）为 selected_audio_codec；无匹配记 0 并在日志使能时告警 |
| supported_video_codecs | 顺序扫描，按客户端解码能力掩码 0x330（位 4,5,8,9 = HEVC/AV1 族，再过
  `CStreamDecoderH264Standalone::BAvailable` 硬解检测）取首个为 selected_video_codec |
| supports_remote_hid | 真 → 置 enable_remote_hid=1（NegotiatedConfig hasbit 0x8） |
| supports_touch_input | 真 → 置 enable_touch_input=1（hasbit 0x10） |
| os_type / gaming_device_type (int32) | 存入 CStreamClient+8/+12 |

随后的 `CNegotiationSetConfigMsg`（0x7ada1c 起）三段整体 CopyFrom 后发送（type 4，加密+可靠）：
`config` ← CStreamClient+0x120（CNegotiatedConfig，成员对象：上述选择结果）、
`streaming_client_caps` ← +0x160（CStreamingClientCaps：supported_video_codecs 内联构建——
恒追加 1/H264，再按 BAvailable 逐个追加 4,5,8,9）、
`streaming_client_config` ← +0x1c8（CStreamingClientConfig，来自 Load/SetStreamingClientConfig）。

**与 ihslib 差异（§6 P4 落地）**：ihslib 硬编码 `reliable_data=false`；
官方把 host 宣告的 reliable_data 原样回显。【推断】host 侧语义 = "host 能力下的可靠数据选项"，
客户端回显表示接受；ihslib 的硬编码在实践中与 host 宣告 false 等价（真机 host 日志未出现异常），
但语义上不再对齐，对齐修改应在读取 host 宣告后回显。

## 6. 会话建立序列（client 视角）【已验证（函数级）/时序待动态确认】

```
发现:  UDP 27036 广播 (31B) → OnPingRequest
连接:  CStreamConnection 建立 (OnStreamConnected: state→2, 记 GetStreamTimestamp→+0x278)
握手:  → ClientHandshake(6, 明文, 可靠) 载荷 CStreamingClientHandshakeInfo(成员 CopyFrom)
       ← ServerHandshake(7, 明文) → StartAuthentication (0x7a7b7c)
认证:  → AuthenticationRequest(1, 明文) [PlayNextRecordedInput 域内的站点为回放路径,
       真实发送点在 StartAuthentication 调用链]
       ← AuthenticationResponse(2, 明文) → 派生密钥
协商:  ← NegotiationInit(3, 加密) → OnNegotiationInit → → NegotiationSetConfig(4, 加密)
       ← NegotiationSetConfig(4)（host 确认）→ OnNegotiationSetConfig（校验
         NegotiatedConfig 与本地 +0x120 一致，Assert 0xa7b=2683 行）
会话:  → NegotiationComplete(5) (HandleStreamStarting) → HandleStreaming
       （进入即发一次 KeepAlive；此后 SendKeepAlive 周期性）
```

## 7. 音视频编解码能力（客户端侧）【已验证】

- 音频：`IsSupportedAudioCodec`——1（Raw）恒真；3（Opus）当 CStreamClient+0x238 == 0；
  解码器 CStreamDecoderRawAudio / CStreamDecoderOpus。
- 视频：`IsSupportedVideoCodec`——掩码 0x330（4,5,8,9）走
  `CStreamDecoderH264Standalone::BAvailable`，1（H264）恒真。
- EStreamVideoCodec 官方值域 ≥9（AV1），协商扫描上界 9。

## 8. 与 ihslib 的差异对照

| # | 项 | ihslib | 官方（逆向） | 影响 |
|---|---|---|---|---|
| 1 | SetConfig.config.reliable_data | 硬编码 false | 回显 host InitMsg 宣告 | 语义不对齐；第 5 节 |
| 2 | 输入可靠性 | 全可靠有序（单在途限制是 fork 自加） | 全可靠有序、**无在途限制**（125Hz 线程连发） | fork 的单在途/槽位回收是自创机制，官方不存在；R2/R15 |
| 3 | ClientHandshake | client 发送 | client 发送（OnStreamConnected，明文） | 一致 |
| 4 | Start/StopVideo/AudioData(50-53) | fork 曾有 client 发送面 | 客户端从不发送（接收 handler 存在） | 与官方一致化后应删除/不使用 |
| 5 | SetQoS/SetTargetBitrate/VideoEncoderInfo | 不发送 | **不发送**（接收 handler 存在） | 路线 B 的前提不成立（§1.3） |
| 6 | ControllerConfigMsg/GetTouchConfig 族 | 不发送 | 发送（游戏/触摸配置请求） | 对齐候选（触摸布局、手柄配置） |
| 7 | VideoOverflow(148) | 无 | 解码溢出时上报两 u16 | Switch 解码异常时可上报，候选 |
| 8 | 加密 seq | send/recv 各自 uint64 计数 | 同构（+0x80/+0x88） | 一致 |
| 9 | 加密范围 | 协商后全加密 | {1,2,6,7} 明文，其余加密 | 一致 |
| 10 | 帧反馈/统计 | CFrameStatsListMsg @stats 通道 | 官方 SendStatsMessage(EStreamStatsMessage) 存在（0x7a8bbc） | 待细化对照 |

## 9. P0：可靠流传输状态机（2026-09-04 补充）【已验证，均为 libmain.so 反汇编】

传输引擎在 `CStreamChannel`（每通道一个；`CStreamConnection::Send/SendUnreliable` 只是锁内转派）。
包类型（包头 byte0 & 0x7F，bit7 为独立标志位，与 ihslib packet.h 命名一致）：
3=Unreliable、4=UnreliableFrag、5=Reliable、6=ReliableFrag、7=ACK、8=NACK、11=FEC
（9/10 存在但 9 在 HandlePacket 被忽略，10 为第二 NACK 变体）。

### 9.1 发送侧：重传永不放弃

- `Send`（0x7f89dc）：全局字节预算检查（超限返回 2）→ 填包头
  （data[0]=5 类型、data[1]=重试计数清零、data[2..3]=conn+12、data[4]=通道号）
  → `AddToOutgoingPacketWindow(+0x70)`（分配包号入窗）→ 立即 `SendReliablePackets(now)`。
- `SendReliablePackets`（0x7f8ac4）：按预算批量遍历发送窗口；重发条件 =
  `now - 上次发送时间(data+9 u32) ≥ 超时`；超时随连接状态（conn+744 与全局
  [f47000+2436/2440] 参与计算，运行时量）。**重试计数 data[1] 只计数不决策，
  封顶 0xFF（0xFF 时连自增都停，但照样重发）。全函数无任何"按重试次数放弃/移除"分支。**
- `HandleAckPacket`（0x7f94b8）：累计 ACK——先推进到 `min(ackseq+1-head, 已用)`，
  再逐格跳过空槽；**被洞卡住的槽不会越过**（只有 ACK/NACK 能释放它）。
  ACK 包同时带时间戳回显（data[9]/conn 头 +13），进 `ProcessTimestamp`（RTT 统计）。
- `HandleNackPacket`（0x7f95dc）：
  - 简单 NACK（len==13）：参考包号 data[9]；过期 NACK（≤上次参考号）忽略。
  - 扩展 NACK（len≥19）：data[7]=基序号 u16、data[13]=时间戳、data[17]=对方连续交付点、
    data[19..]=**占位掩码**（每包 1 bit）。遍历发送窗口：
    **bit=1（对方已收到）→ `ReleasePacketByID` 从发送窗口移除（视同交付）**；
    bit=0（对方缺失）且已超时 → `lastSent=0`（下轮立即重发）。
  - 超时参考 = `((conn->srtt(+732)+2.0)*0.75)` 换算，钳制到全局上限。
- 结论：**可靠包离开发送窗口只有两条路——ACK 累计确认、对方 NACK 掩码确认。
  没有本地放弃计时器、没有重试上限。** 传输层丢包恢复闭环 =
  接收方 NACK（快速）+ 发送方无限重传（兜底），洞在 ~1 RTT 量级愈合。
- "lurch/recvseq/ooo" 等字符串经 xref 确认属 SteamNetworkingSockets 子系统
  （如 0x858a0c DecryptDataChunk 内），与 CStreamChannel UDP 路径无关——
  旧文档 R4 把它们当 UDP 传输层证据系误置，特此更正。
- 本 UDP 传输层**未发现**接收侧"弃洞计时器"：按序上送循环只弹连续头部
  （`PopHeadOfPacketWindow_WithRef`），头部有洞时后续全部滞留。

### 9.2 接收侧：ACK/NACK 生成

`UpdateReliableState`（0x7f9d0c，由 `CStreamChannel::Update`→`Update` 0x7f9c9c 周期调用）：
1. 按序上送：弹出接收窗口连续头部全部包，经 conn 虚表上交（统计到 PacketStats）；
2. ACK：连续交付点前进（+42 u16）即置 +41 标志并发 ACK
   （data[0]=7、data[4]=通道、data[7..8]=连续交付点、+56 区 data[13]=时间回显；
   长度 17 字节级——与 pcap 观测 21B 同量级，UDP 连接头另计）；
   另有周期性重发 ACK（时间偏移对时用）；
3. NACK：扫描接收窗口 (lastAcked..next)，发现空槽且满足速率条件
   （全局 [f47000+2444] 参与限频）→ 构造扩展 NACK（含占位掩码，窗口覆盖上限 0x140=320 包）
   发给对方。

### 9.3 与我们（ihslib fork）的逐条对照

| # | 项 | 官方（地址） | 我们当前 | 差异判定 | 真机判据 |
|---|---|---|---|---|---|
| 1 | 重传放弃 | 无放弃，重传到 ACK/NACK 确认（0x7f8ac4/0x7f94b8/0x7f95dc 全路径） | 3s 放弃（D-039），放弃=从发送窗口除名 | **自创行为**；放弃制造永久洞，但 Host 的 20 秒恢复机制未证实 | 不再出现"重传 25 次后放弃"；卡死时长消失或 <1s 级 |
| 2 | NACK | 收到洞即发扩展 NACK（掩码），收到 NACK 快速重发（0x7f9d0c/0x7f95dc） | ihslib 无 NACK 机制 | **缺失整个快速恢复通道**；host 只能靠自己的重复 ACK/计时发现洞 | tcpdump 可见我们发出的 type-8 NACK 包 |
| 3 | 在途限制 | 无（窗口制，ACK/NACK 驱动滑动，掩码覆盖 ≤320 包） | 单在途（D-040）+ 100ms 心跳 | **自创行为**；单在途把"高频 delta 容忍丢失"变成"串行等待" | 输入包速率/在途数与官方 pcap 对齐（31/s 批量、无 1 包往返） |
| 4 | ACK 语义 | 累计 ACK+空槽跳跃+周期重发+时间回显（0x7f94b8） | ihslib window.c 自实现 | 行为需逐项核对（互操作已通，疑似大体一致） | host ACK 延迟统计正常（≤99ms 已观测） |
| 5 | 接收窗口交付 | 只弹连续头部，无弃洞（0x7f9d0c 第 1 步） | 同构 | 一致 | — |
| 6 | FEC | 不可靠通道带 FEC（SendUnreliableFEC 0x7f90e4、CFECOutgoing/IncomingQueue） | 未实现（enable_unreliable_fec 未协商） | 待评估（视频/音频下行方向，与输入卡死无直接关系） | — |

**原 P0 因果模型部分撤回**：主动放弃可靠包会制造永久缺口，有源码依据；
“Host 固定等 20 秒”“官方一定在一个 RTT 内恢复”没有 Host 端实现或故障包序列证明。
客户端发出的 NACK 修复 host→client 缺口，Host 发出的 NACK 才请求 client→host 补包，
不能把这两个方向混成一个因果链。20 秒故障根因仍须实机验证。

### 9.4 窗口结构与历史实现对照（2026-09-04 快照；修正依据见 §14）

`CStreamPacketWindow`（0x7f7230/0x7f76f4/0x7f9bb0）：+0=count、+4=mask、+8=head(u16)、
+10=连续交付水位(u16)、+16=槽表、+24=时间戳表。
`Advance(n)`：推进 head 逐格释放被跳过的槽（引用计数→析构），水位跟随 head；
`ReleasePacketByID(id)`：ID 在 [head, head+mask] 内→释放该槽（**head 不动**，洞原地释放，
由后续 ACK 的空槽跳跃自然收紧）。NACK 掩码覆盖上限 0x140=320；窗口另按需扩容至 16384（§14.11），两者不是同一个限制。

| 项 | 官方 | ihslib fork（retransmission.c/channel.c） |
|---|---|---|
| 重传节奏 | RTO=`1.25×clamp(srtt)`；NACK age 另算（§14.11–12） | 5ms tick，25ms 起倍增封顶 100ms |
| 放弃 | **无**（重传至 ACK/NACK 确认） | `RETRANSMISSION_GIVE_UP_MS=3000`，放弃=退休（D-039） |
| ACK | **累计**（连续交付点 data[7..8]）+ 周期重发 + 时间回显（RTT 对时） | 逐包 ACK（packetId+fragmentId+body 时间戳） |
| NACK 发送 | 洞检测→扩展 NACK：首洞序号+连续交付点+320 包占位掩码，限频 | 仅单包校验失败时发（ok=false），无窗口状态报告 |
| NACK 接收 | bit=1→ReleasePacketByID；bit=0→超时则强制重发 | （session.c 有分支，语义未对齐官方掩码协议） |
| 窗口 | 按需扩容，累计 ACK 滑动+原地释放（§14.11） | 自实现 window.c |
| 加密 seq 推进 | 按**按序交付**推进（重传补洞后解密，0x7ad06c 的 ++ 在交付路径上） | 按发送推进；放弃后依赖"对端 resync"假设（fork 注释自认） |

**说明**：官方把 BDecrypt 放在按序交付路径上（接收计数器只对交付的包自增），
重传填洞后每个包的解密序号天然正确——不存在"stale sequence 当 replay 丢弃"问题。
fork 的"放弃+resync"设计建立在与官方不同的解密推进模型上，是 D-039 的根源。

## 9b. P1：HID 设备生命周期与输入封装（2026-09-04 补充）【已验证】

### 9b.1 RemoteHID 信封（hiddevices.proto，与 ihslib 同步）

`CHIDMessageFromRemote.oneof command`：`update_device_list`(1, repeated CHIDDeviceInfo)、
`response`(2)、`reports`(3)、`close_device`(4)、`close_all_devices`(5)。
设备以 UpdateDeviceList 宣告，数据走 reports，消失走 close_device。

### 9b.2 UpdateHIDDeviceReports（0x7bd838，125Hz 线程每拍调用）——修正 OFFICIAL_INPUT_RE §14

```
state==6 才继续；
构造一条批量信封 batchMsg（command=reports）；
锁设备表（CStreamPlayer+0x7f8），遍历生成器数组（count+2104, array+2088）：
    generator->BCollectReports(batchMsg.reports, &hasActiveInput)   // 虚表槽 2
    返回 true  → 该设备报告已并入 batchMsg；
    返回 false → 设备消失：
        单独构造 CloseDevice{device=generator+16} 信封 → SendRemoteHIDMessage；
        调生成器虚表槽 1（停止），从数组 memmove 移除；
解锁；
batchMsg.reports.device_reports.size() >= 1 才 SendRemoteHIDMessage(batchMsg, hasActiveInput)。
```

**更正**：OFFICIAL_INPUT_RE §14 "有数据就立即调 SendRemoteHIDMessage（不合并批次）"
表述有误——官方是**每拍至多一条输入消息**，全部设备的多条报告合在同一
`DeviceInputReports.device_reports[]` 里（对应 pcap 98B 批量簇）；CloseDevice 才单独成条。
无任何设备报告时不发空批（无保妙心跳批）。

### 9b.3 触摸与 ControllerConfigMsg 的调用层

`SendTouchFingerDown/Motion/Up`（0x7a92b4/0x7a94e4/0x7a9714）与
`SendControllerConfigMessage`（0x7abb30）在 libmain.so 内**零内部调用点**——
它们是导出符号，由 Qt 外壳 libshell_arm64-v8a.so 跨库调用（UI/MotionEvent 层触发）。
本轮未逆向 libshell（23MB），触发时机（何时发 137、触摸标记如何生成）留待后续或动态确认。

- 触摸消息字段（remoteplay.proto 551-567）：`input_mark`(u32, CreateInputMark 的标记)
  + `fingerid`(u64) + `x_normalized`/`y_normalized`(float, 0..1)。
- 官方触摸有**两条路径**并存：(a) 原始手指消息 117-119（UI 层直发）；
  (b) MobileTouch 虚拟 HID 设备（BInjectGamepadStateMobileTouch 生成器，
  host 日志 "Sending HID device ... Mobile Touch Control at touch://0" 即 host 侧建立），
  把触摸当 Steam Input 手柄用。Switch 客户端的最简对齐 = 路径 (a)；
  路径 (b) 是否影响 host 输入管线（未决问题 §10.6）需实验。

## 9c. P2：统计/帧反馈流与时间戳单位（2026-09-04 补充）【已验证】

### 9c.1 GetStreamTimestamp 是 16.16 定点秒，不是毫秒（全局性更正）

`GetStreamTimestamp()`（0x802a88，u32 版）：`t = Plat_RelativeTicks()`（单调相对时钟），
返回 `(t/freq 的整数秒 << 16) | ((t%freq)<<16/freq)`——**高 16 位秒、低 16 位秒内小数**，
约 18.2 小时回绕。另有 u64 版（0x802b14）。
**凡使用 GetStreamTimestamp 的线上字段（帧事件 timestamp、ACK/数据通道时间戳）都是该单位。**
OFFICIAL_INPUT_RE §13.2 的"ms 修复"（ab8712d、包头 sendTimestamp）方向反了，需再更正。

### 9c.2 SendStatsMessage（0x7a8bbc）

`CStreamFrame frame(2 /*k_EStreamChannelStats*/, type); Put(msg,false); Send(conn, true);`
——stats 通道（channel 2）**不加密**（接收侧 OnStreamPacket 对 channel≠1 跳过解密直接入队）、
可靠、无状态检查。消息集 EStreamStatsMessage：1=FrameEvents、2=DebugDump、3=LogMessage。

### 9c.3 SendFrameEvents（0x7a82e8）——帧反馈构造

> 更正：以下旧文关于 `Save` “时间戳减连接基准”的解释撤回。
> `0x7f4c7c` 是 ADD，`0x7f4cac` 是减前一已输出事件的时间戳，详见 §14.4。

- 每数据类型一个 240 槽环形 `CFastFrameStats`（120B/槽，槽 0 = frameId）；
  遍历未发送帧：帧未完成（+88==0）→ `RecordFrameComplete(type, id, 6)` 标记 Cancelled 照报；
- 逐帧 `CFastFrameStats::Save(CFrameStats*, full=1, conn+848)`：首个输出事件加
  peer−local 时钟偏移，后续事件减前一个已输出事件。单位均为 16.16 秒；
  数据通道接收则先减该偏移，将 host 时间换算为本地时间（§14.4、§14.10）。
- 网络样本取自连接统计：srtt(conn+732)、conn+1152/+1000（×系数 0x3A83126F≈2^-10，
  【推断】µs→定点秒换算）、丢包 = conn+1252×100.0/conn+1248；
- `CFrameStatsAccumulator.Calculate()` 后追加最多 20 条 accumulated_stats
  （EFrameAccumulatedStat：FPS 等）；
- 发送节奏：`HandleStreaming`（0x7a7140）内 `now - last > 0x10000`，**单位即定点秒
  → 精确 1.0 秒一次**；`TriggerDebugDump`（0x7ac6b4）前置一次强制 flush。

### 9c.4 时钟与统计编码的证据边界

`Plat_RelativeTicks`（0x90b0e4）使用 CLOCK_MONOTONIC 纳秒，频率为 1e9。
`GetStreamTimestamp`（0x802a88/0x802b14）换算为 16.16 秒，65536 秒回绕。
`ProcessTimestamp` 根据 ACK echo、peer send、local receive 三个时间估计时钟差；
`CFastFrameStats::Save` 首项加差值，后续项目写事件间 delta，详见 §14.4、§14.10。

**撤回**：“conn+848 是连接建立时刻”“所有帧事件减连接起点即可修复”，以及
据此宣称 network≈58518652ms 的唯一成因已经定案。CLOCK_REALTIME 毫秒和错误的
事件编码均与汇编不符；历史 host 日志的具体异常还涉及如何解读和应用这些字段，
不能将统计修正直接当成 20 秒锁键的根因证明。

### 9c.5 ControllerConfigMsg(137) 触发层（结论）

137 的唯一出口 = `SendControllerConfigMessage`(0x7abb30，内部仅 `state==6` 检查 +
`SendControlMessage(137, msg)`)，libmain 内零直接调用者；libshell 的动态符号表
不导入任何流发送函数（含 SendControlMessage/SendTouchFinger*），跨库经间接机制
（虚表/dlsym 类）。消息语义（proto）：`type`=RequestConfigsForApp(0)/ConfigResponse(1)/
PersonalizationResponse(2)/ActiveConfigChange(3)/RequestActiveConfig(4)，客户端方向只会是
0/4（请求游戏配置）。**对我们的 Switch 客户端：137 为可选增强**（当前不发送也会话可用、
输入可 apply），精确触发时机需要模拟器+Frida 动态观测闭环，静态已到边界。

## 12. 完整串流流程与报文字段手册（实施对照，2026-09-04）

> 目标：按本节即可实现/核对一次完整会话。字段号以 ihslib proto 为准（官方序列化兼容已验证）。
> 各条目【已验证】= 本文 §1–9c 有反汇编地址；标 proto = ihslib 同步版定义。

### 12.0 线包头（每个 UDP 包）

- 连接层包头 13B（ihslib packet.h `IHS_PACKET_HEADER_SIZE`，互操作已证）：byte0=包类型
  （&0x7F，bit7 独立标志）、byte1=重试计数（可靠包，官方只计数不决策）、byte2..3=连接 ID
  （conn+12）、byte4=通道号、byte7..8=包序号 u16（可靠包/ACK 参考）、byte9=时间戳 u32
  （16.16 定点秒）——官方证据：0x7f89dc（发送填头）、0x7f9250（类型分发）、0x7f94b8（ACK）。
- 包类型（ihslib packet.h = 官方实测一致）：0 Unconnected、1 Connect、2 ConnectACK、
  3 Unreliable、4 UnreliableFrag、5 Reliable、6 ReliableFrag、7 ACK、8 NACK、11 FEC。
- Connect（type 1）携带源 CIPAndPort 与连接 ID 校验（0x7facff 对比 conn+13、CompareAdr）。

### 12.1 会话流程（client 视角，→=我们发，←=host 发）

| 步 | 方向 | 消息(类型) | 通道/加密/可靠 | 载荷字段（proto 号） |
|---|---|---|---|---|
| 0 | →/← | 发现广播 27036 | 明文 UDP | CDiscoveryPingRequest/Response（proto）；`gamesRunning` 注意事项见 AGENTS.md |
| 1 | →/← | Connect(1)/ConnectACK(2) | 明文 | 见 12.0 |
| 2 | → | ClientHandshake(6) | ch1 明文可靠 | CClientHandshakeMsg.info = CStreamingClientHandshakeInfo（network_test 等） |
| 3 | ← | ServerHandshake(7) | ch1 明文可靠 | CServerHandshakeMsg.info = CStreamingServerHandshakeInfo |
| 4 | → | AuthenticationRequest(1) | ch1 明文可靠 | CAuthRequestMsg{token=1(HMAC, 见 AUTH 文档), version=2, steamid=3} |
| 5 | ← | AuthenticationResponse(2) | ch1 明文可靠 | result；密钥协商完成（STEAM_REMOTE_PLAY_AUTH.md） |
| 6 | ← | NegotiationInit(3) | ch1 **加密**可靠 | CNegotiationInitMsg{reliable_data=1, supported_audio=2, supported_video=3, supports_remote_hid=4, supports_touch=5, os_type=6, gaming_device_type=7} |
| 7 | → | NegotiationSetConfig(4) | ch1 加密可靠 | 见 §5：config.reliable_data=回显宿宣告；audio=宿列表首个∈{1,3}；video=宿列表首个过 0x330+BAvailable；enable_remote_hid/enable_touch=宿宣告；caps=CStreamingClientCaps（video_codecs 恒 1 + 逐个 4/5/8/9）；streaming_client_config=本机配置 |
| 8 | ← | NegotiationSetConfig(4) | 同上 | host 确认（与本地不一致则 Assert） |
| 9 | → | NegotiationComplete(5) | 同上 | 空消息。状态→Streaming |
| 10 | → | KeepAlive(9) | ch1 加密可靠 | 空消息；进入 Streaming 发一次+周期（HandleStreaming） |
| 11 | ← | StartAudioData(50)/StartVideoData(52) | ch1 加密可靠 | CStartAudioDataMsg{channel=2, codec=3, codec_data=4, frequency=5, channels=6}；channel 值写入数据通道匹配（client+625/626），client 启动解码（IsSupportedAudioCodec：1 恒可、3 视 +0x238） |
| 12 | → | VideoDecoderInfo(80) | ch1 加密可靠 | CVideoDecoderInfoMsg{decoder=1...}（0x7aacf0） |
| 13 | →/← | 输入：UpdateDeviceList(信封1) → host DeviceOpen(下行2)+DeviceStartInputReports(下行11) → 125Hz 报告 | RemoteHID(106) ch1 加密可靠 | 信封 CRemoteHIDMsg{data=1, active_input=2}；下行 oneof 见 §9b/12.2；报告合批规则 §9b.2；delta/full 自适应 R1 |
| 14 | → | 帧反馈 | ch2 **明文**可靠 | CFrameStatsListMsg{data_type=1, stats=2, accumulated=3, latest_frame_id=4}；1.0s；首事件加时钟偏移，后续事件间 delta（§14.4） |
| 15 | ← | 会话中下行 | ch1 加密可靠 | SetQoS(87){use_qos=1}、SetTargetBitrate(94){bitrate=1}、VideoEncoderInfo(90){info=1}、SetTitle(81)/SetActivity(98)、TouchConfigActive(110)/SetTouchConfigData(112)、SetCursor 族(63-68)、OverlayEnabled(74)、SetGammaRamp(89)、CaptureFailed(147) |
| 16 | → | 结束 | ch1 加密可靠 | StopRequest(129)/QuitRequest(83) 空消息；挂起 SystemSuspend(100) |

### 12.2 接收侧处理表（host→client，实现必须响应的部分）

| 消息 | handler（地址） | client 行为【已验证】 |
|---|---|---|
| ServerHandshake(7) | 0x7ad3dc | 解析后触发 StartAuthentication |
| AuthenticationResponse(2) | 0x7ad4bc | 校验结果，派生会话密钥（AUTH 文档） |
| NegotiationInit(3) | 0x7ad698 | §5 全字段读取 → 立即回 SetConfig |
| NegotiationSetConfig(4) | 0x7adb28 | 与本地 NegotiatedConfig(+0x120) 一致性校验 |
| StartAudioData(50) | 0x7add8c | 记数据通道 id（+625）、启动解码器（Raw/Opus） |
| StartVideoData(52) | 0x7ae074 | 记数据通道 id（+626）、启动视频解码 |
| RemoteHID(106) 下行 | 0x7ad2c8→CStreamPlayer::OnRemoteHIDMessage(0x7c695c) | CHIDMessageToRemote.oneof：device_open(2)/device_close(3)/device_write(4，**下行 rumble 等输出报告**)/device_read(5)/feature_report(6,7)/vendor|product|serial(8-10)/start_input_reports(11)/request_full_report(12)/device_disconnect(13)；对应 OnHIDDeviceOpened(0x7b9c54)/Closed(0x7b9d58) |
| 数据包 ch≥3 | 0x7ad148 | 通道匹配 → 时间戳归一 → 解码队列 |
| KeepAlive(9) | 0x7acfa8 内联 | 静默消费 |
| 其余下行 | HandleIncomingPackets 队列分发 | UI 通知/状态存储（SetTitle→显示、TouchConfig→布局缓存等） |

### 12.3 传输层实现要求（对照 §9）

1. 可靠重传：超时重发**永不放弃**（重试计数只统计）；超时参考 srtt。
2. NACK：收到洞 → 扩展 NACK{基序号 data[7], 连续点 data[17], 掩码 data[19..]}（限频）；
   收到 NACK：bit=1→窗口移除，bit=0→超时强制重发。
3. ACK：累计（连续交付点）+ 1s 内周期重发 + 时间回显。
4. 接收：只按序交付；解密在交付路径上（seq 按交付推进）；扩展 NACK 掩码窗口 ≤320 包。
5. 输入：125Hz 线程、单消息多设备合批、无在途限制、无空批。

## 13. fork 与业务代码逐条审计（2026-09-04，代码直查，非文档转述）

审计方法：`git diff origin/master...nsteamlink`（33 commit，session 层 +953/-214）逐文件读 diff，
业务代码直查 `client/main.c`、`client/media.c`（4220+2437 行）。裁定对照官方反汇编地址。

### 13.1 ihslib fork 修改裁定表

| # | 代码位置 | 我们行为 | 官方行为 | 裁定 |
|---|---|---|---|---|
| 1 | retransmission.c（d5645e4） | 3s 放弃退休；25ms 倍增封顶 100ms；supersede≥3 次重试 | 重传永不放弃；超时=f(srtt)（0x7f8ac4/0x7f95dc） | **MISMATCH 自创** |
| 2 | channel.c:203 | NACK 仅单包校验失败时发 | 洞检测→窗口掩码 NACK+限频（0x7f9d0c）；收 NACK→释放/强制重发（0x7f95dc） | **MISMATCH 缺失机制** |
| 3 | channel.c ACK | 逐包 ACK（packetId+fragmentId+body 时间戳） | 累计 ACK+周期重发+时间回显（0x7f94b8） | MISMATCH（互操作兼容） |
| 4 | packet.c:134 | CLOCK_REALTIME epoch 毫秒 | MONOTONIC 16.16 定点秒（0x90b0e4/0x90b1c8/0x802a88） | **MISMATCH 已定案**（§9c.4） |
| 5 | frame_stats.c | 事件时间戳=上述毫秒值 | 首项加偏移、后续 delta（§14.4；旧解释撤回） | **MISMATCH** |
| 6 | ch_control.c:142-186 | 单在途 MAX_IN_FLIGHT=1；coalesce 丢弃中间态；give-up 槽回收 | 窗口制无在途限制；无丢弃；无回收概念（0x7f89dc/0x7f8ac4） | **MISMATCH 自创** |
| 7 | ch_control.c:176 | active_input 硬编码 true | 按当拍 BCollectReports 结果动态传（0x7ab4c8 `and w9,w20,#1`） | MISMATCH-小 |
| 8 | ch_control_negotiation.c | enable_remote_hid 无条件 1 | 按 host 宣告 supports_remote_hid 条件置位（0x7ad9cc） | MISMATCH-小 |
| 9 | 同上 | available_video_modes_obsolete 仍发送（1920x1080@60） | NegotiatedConfig 不填 video modes | MISMATCH-小 |
| 10 | 同上（上游遗留） | reliable_data 硬编码 false | 回显 host 宣告（0x7ad710 无条件字节拷贝） | MISMATCH |
| 11 | 同上:217-223 | system_info 假串（ARM/1 核/263MB/JN-MD133BFHDR 面板） | 真实设备信息：VDF 模板 0x3a1741（13 字段 OSType/CPUID/CPUGHz/核数/RAM/GPU ID/VRAM/分辨率/面板名），`CStreamPlayer::Init`(0x7b4d60) 用本机实测值 Format 填充（0x7b54d4） | **MISMATCH**：格式对、值须真机实测 |
| 12 | ch_control_keepalive.c:37-51 | 首次 5s，之后 10s 周期 | HandleStreaming(0x7a7140)：`now-last > 0xA0000` = 16.16s 单位下**精确 10.0s**；last==0 时进入 Streaming **立即发**（0x7a71b8-e4） | **周期 MATCH（10s）**；首发时机 MISMATCH（官方立即/我们 5s） |
| 13 | sdl_hid_event.c:67 | 状态变化才 AddDelta（48B，恒 delta，无 full 回退） | delta/full 自适应 `deltaLen+8<fullLen`（0x7d035c）+CRC | PARTIAL（48B 场景官方实际也近似恒 delta，但无回退） |
| 14 | ch_control.c hidPending | 单设备单快照，一消息一设备 | 全设备合进一条 DeviceInputReports（0x7bd838） | **MISMATCH** |
| 15 | session.c（c8be119） | StopRequest 等 host ACK 后断开 | SendStopRequest 调用点=BHandleEvent/SendQuitRequest（0x7b9360/0x7b9dd8）；HandleStreamStopping(0x7a7238) 只停解码器/统计/打日志无等待；且 OnStreamPacket 在 state==7 时**丢弃所有入包（含 ACK，0x7acfd8）** | **MISMATCH：官方 Stopping 态不处理任何入包，"等 ACK"在其架构中不可能发生** |
| 16 | media.c:1259-1281 | 8ms 专用 flush 线程 | 125Hz CHIDDeviceReportThread（0x7c9e40） | **MATCH ✓**（M5） |

### 13.2 业务代码审计（client/）

| # | 项 | 现状 | 裁定 |
|---|---|---|---|
| 17 | **触摸** | main.c/media.c 零实现（无 117-119 调用，无 MobileTouch 设备） | **缺失**——对照"按钮触摸一应俱全"目标是功能缺口，官方双路径见 §9b.3 |
| 18 | 会话建立序列 | 握手/认证/协商经 ihslib 标准路径 | MATCH（互操作实证） |
| 19 | VideoDecoderInfo/StopRequest 发送 | 有 | MATCH |
| 20 | 上行 wire 形态（尺寸簇/速率） | 未测 | 待真机 pcap 对照（判据§9.3） |

### 13.2b 收包链专项审计（2026-09-04，第二轮）

> 更正：本节“加密边界/ACK wire 格式/信封/合批：逐字节等价”不能成立。
> §14.1–14.5 给出实际代码、汇编及离线复现反例。

- 未知控制通道包类型：fork 原为断连（一次意外包类型即死会话），官方是忽略——已改为 log+ignore；
- KeepAlive(9)：官方在 OnStreamPacket 内联静默消费（0x7ad0b4），fork 原会落入未处理分支打日志——已静默；
- CaptureFailed(147)/SystemSuspend(100)：官方转 UI 委托，fork 原静默丢弃——已加 error/warn 日志；
- HID 下行 13 种命令全覆盖（含 DeviceRequestFullReport→全量回复、DeviceWrite→设备写）✓；
- 控制消息 switch 40 个 case，覆盖 host 实际会发的全部关键消息；未覆盖的
  （TouchConfig 族/OverlayEnabled/SetGammaRamp/VR/RemotePlayTogether 等）
  走 benign-ignore，与官方未匹配类型的处理一致；
- ACK 政策：逐包 → 每批交付点一次（0x7f9e70），线上格式不变；
- 数据通道：溢出→ReleaseAll+DataLost 上报（对等 SendDataLost）✓；FEC 未实现
  ——但我们从未协商 enable_unreliable_fec，host 不应发送 FEC 包（assert 仅 debug 生效）；
- 加密边界/ACK wire 格式/信封/合批：逐字节等价 ✓。

### 13.2c 跨线程锁审计（2026-09-04，真机卡死定位后）

真机实证：第一次触发震动即全 app 死锁（接收线程 SDL_RumbleGamepad × 媒体线程
SDL_PollEvent/libnx-hid 跨线程竞争）。修复 = DeviceWrite 在接收线程只入队
（设备锁 FIFO，512B 上限），新增公开 API `IHS_HIDSDLApplyPendingWrites`
由**媒体线程**（SDL/libnx-hid 属主，SDL_PollEvent 同线程）执行；flush 线程
不再执行（libnx hid 服务不允许与媒体线程跨线程并发）。

其余跨线程点逐项定性：
- DeviceOpen 的 SDL_OpenGamepad（接收线程）：16+ 会话实证存活；协议要求同步
  RequestResponse 无法延迟——记录为已知风险；
- DeviceClose 的 SDL_CloseGamepad（接收线程）：实证存活（仅收尾时序触发）——记录；
- 字符串/电源信息 getter（接收线程）：与 flush 线程 getter 同类，实证共存；
- 锁序：全路径均为 device → send 单向（flush 先解锁再发送；Write 入队不再
  持锁发送），无 device↔send 反向；sendLock/retransmission/sendQueue 层叠
  与既有高频路径一致；
- 触摸发送（媒体线程 → sendLock）与 flush 发送互斥正确。

### 13.3 结论

本段旧稿的“未验证 0 项”“无新增矛盾”结论撤回：§14 的独立复核发现 NACK
字段/方向、时钟换算、full_report 和 Unconnected 过滤等反例。不能用分类计数
代替逐项证据，也不能把 Android 客户端的 Stopping 分支外推成 Host 的超时策略。
KeepAlive 的立即首发及 10 秒周期有调用点证据；其他裁定应按 §14 的具体边界理解。



1. host 侧超时的确切时长与条件：本二进制不含 Host 实现，不能证明存在所谓
   “弃洞”机制，更不能证明修正客户端后它“永远不会触发”；
2. `SendUnreliable` 的直接静态调用已追到 frame 分发与其调用者，见 §14.16。
   旧稿只搜索 `bl` 会漏掉尾调用 `b`，且不能由包装函数数量推断实际发送者；
3. OnSetQoS/OnSetTargetBitrate/OnVideoEncoderInfo 的接收行为见 §14.16；
4. CStreamingClientHandshakeInfo / CStreamingClientCaps 其余字段取值（Android 官方值）；
5. KeepAlive 的立即首发与 10 秒周期见 §13.3、§14.14；
6. ControllerConfigMsg(137) 官方载荷构造（0x7abb30 只做转发，构造在调用方——
   CStreamPlayer/UI 层，需沿 xref 上溯）。

## 11. 与既有文档/决策的关系

- 本文件更正 OFFICIAL_INPUT_RE.md §5（CLIENT: 方向）、§8 候选路线 B、§15/§16
  （Send bool 映射方向、"官方输入可能走不可靠通道"猜测）；
- R1 delta/full 自适应规则有独立指令证据。R2/R3/R5/R6 的观测与 R7 日志量差异
  不能单独确立因果；D-039/D-040 的放弃与单在途机制已由 D-042 替代；
- 候选路线 B 缩水为"补 ControllerConfigMsg / GetTouchConfig 族 + VideoOverflow"，
  其优先级需要结合第 9 节问题 3（host 下行处理逻辑）重新评估后再立项。

## 14. 独立汇编复核与协议反例（2026-09-07）

### 14.0 证据身份与边界

- 父仓快照 `d6d411f`；ihslib `8bb05be`；比较基线是本项目实际采用的
  `beudbeud/ihslib` pin `8c5a17c`，不是未经确认的“最新上游”。
- `git -C third_party/ihslib diff 8c5a17c` 涉及 54 个文件，包含两处已有未提交
  修改：`frame_stats.c` 与 `channels/video/ch_data_video.c`。本次审计没有改动这些实现。
- 二进制来自仓库根目录 XAPK 的 `config.arm64_v8a.apk!lib/arm64-v8a/libmain.so`。
  SHA-256：`50e1d3147d5d47b71ef1970e1867a2fe4f3e1ecf2ea6153f927fac88b88ea38e`。
  重新解包计算的 hash 与 `/tmp/slink/arm64/lib/arm64-v8a/libmain.so` 一致。
- 下列地址由 `aarch64-linux-gnu-objdump -dC --start-address=... --stop-address=...`
  重新读取 ELF 验证，不以旧文档的“已验证”标签作为证据。
- Android 客户端汇编证明该客户端的行为，不自动证明 Windows host 的内部行为。
  用户观察的“保持最后按键约 20 秒后恢复”保留为主要故障现象；精确超时机制没有闭合证据。
- 可重放反例：从仓库根运行 `./scripts/audit-ihslib-control.sh`。
  它单独构建 Debug 库，调用生产函数，不启动网络 worker；退出 1 表示发现不变量违反。
  C 探针见 `scripts/audit-ihslib-control.c`，预留额外 canary 空间观察越界，避免破坏其他对象。

### 14.1 接收扩展 NACK：把时间戳误读成确认序号（P1）

Evidence：官方 `HandleNackPacket`：

| 汇编地址 | 操作 | UDP payload 中的字段 |
|---|---|---|
| `0x7f9764` | `ldur w10, [x23,#13]` | u32 时间戳 |
| `0x7f9760` | `ldurh w9, [x23,#17]` | u16 最后连续确认 ID |
| `0x7f9770–0x7f97a8` | `confirmed-head+1` 后 Advance | 确认到该 ID，包含端点 |
| `0x7f9810` | `add x26,x23,#19` | bitmap 首字节 |
| `0x7f9848–0x7f984c` | 读 header+7，加 byteIndex×8 | bitmap 以 header.packetId 为基址 |
| `0x7f9854–0x7f987c` | bit=1 时 ReleasePacketByID | 选择性确认该包 |

`IHS_SessionPacketParse` 只剥离 13 字节头及可选 CRC，因此业务层 body 的对应偏移
是 **0=timestamp、4=confirmed、6=bitmap**。然而 `ControlOnNackPacket`
（`ch_control.c:466`）读取 `body[0..1]` 为 confirmed、`body[2..]` 为 bitmap，
还用误读的 confirmed 作为 bitmap 基址。它也没有正确处理确认的包含端点语义。

真实函数离线反例：登记 pending 100、101、102；注入官方格式的
`header.packetId=101, timestamp=200, confirmed=100, bitmap=02`。
对方有 100、102，唯一应保留补发的是 101；实际输出：

```text
RX NACK: missing packet 101 retained=0 (required 1); outstanding=0 (required 1)
```

Conclusion：现行实现会错误删除尚未交付的可靠包，并把这种删除计入 acknowledged。
这是输入上行留下永久缺包的直接机制；“还在提交／acked 增长”不能排除它。
正确实现应使用上述三个独立字段，按 packet ID 确认包括各分片，不可把时间戳当序号。
简单 NACK、旧反馈过滤、重传时间阈值也应分别处理，不可复用错误的扩展布局。
**是否触发了用户那次故障及为何约 20 秒恢复仍是 hypothesis。**

### 14.2 发送扩展 NACK：确认了自己正在请求的缺包（P1）

Evidence：`ControlSendGapNack`（`ch_control.c:507`）计算 `needed=首个缺包`，
同时把 needed 写入 header.packetId 和 body+4 的确认水位。
官方 body+4 是最后连续确认的 ID（见上面的 `+1` 与 Advance），不是下一个所需 ID。
`UpdateReliableState` 的 `0x7fa14c–0x7fa154` 写入独立的 channel+42 确认水位。

真实函数接收 100 后再接收 102，输出：

```text
TX feedback after 102 (101 missing): NACK base=101 contiguous=101 (required 100), mask=02
```

Conclusion：该报文同时说“101 缺失”和“已连续收到 101”。按官方接收算法会先释放
101，随后 bitmap 的 0 位不能恢复已释放的包。正确字段应为 `confirmed=100`。
这可破坏 host→client 的补洞；它与 §18 的下行加密失配有机制上的关联，但尚无故障包序列证明。
此外 `needed==0` 直接返回会在 16 位 ID 回绕处漏发 NACK；0 是合法包号。

### 14.3 解密计数器：“成功才推进”与汇编相反（P1）

Evidence：`CStreamClient::OnStreamPacket`：

```asm
7ad054: ldr x1, [x19, #136]   // 旧计数器作为解密参数
7ad060: add x8, x1, #1
7ad064: str x8, [x19, #136]   // 调用前已写回
7ad06c: bl  CStreamFrame::BDecrypt@plt
7ad070: tbz w0, #0, 7ad07c    // 此后才判断失败，无计数器回滚
```

Conclusion：官方等价于 `BDecrypt(recvSequence++, ...)`。
`8bb05be` 把 `ch_control.c:397–400` 改成成功才递增，其“与官方一致”的理由撤回。
失败帧已经由窗口 Poll 消费并被 ACK，“保持期望值等待旧 packet 重传自愈”不成立。
严格对齐应恢复调用前递增，同时修正可靠窗口的误确认/跳洞问题；单独更改计数器
不能弥补已经越过的加密帧，也不构成 20 秒故障已修复的证明。

### 14.4 FrameEvents 是事件差分，不能逐项写绝对/连接相对时间（P1）

Evidence：`CFastFrameStats::Save`：

- `0x7f4b68–0x7f4b74`：bool 参数为 true 时跳过 event 2–12。
- `0x7f4c48` 按**输出列表中是否第一项**分支。
- 首项 `0x7f4c74–0x7f4c80`：`timestamp = eventTime + 第三个显式参数`（ADD）。
- 后续 `0x7f4ca8–0x7f4cb8`：`timestamp = eventTime - w28`；
  `0x7f4b58` 在每个已输出项后更新 w28 为该项原始时间。
- 调用点 `0x7a8470–0x7a847c`：bool=true、第三参数读自 connection+848。
  **仅此读指令不能把 connection+848 命名为“连接建立时间”。**

Conclusion：线上是首项基准加偏移、后续事件间 delta。例：两事件原始值
1000/1100，第三参数为 50，输出应为 1050/100，而非 950/1050。
`ReportVideoStats`（`ch_data_video.c:487–542`）逐项写时间、已有未提交修改按
event>=13 分开减 timeBase，两者都不符合这个格式。
`GetStreamTimestamp` 的 16.16 单位仍成立（`0x802ab0–0x802ac4`），但单位正确
不能抵消编码方式错误。准确实现还须追清 connection+848 的时间偏移来源，不能用
协商完成时刻代替。由此不能宣称异常 network/decode/display 数字已修复，或与输入故障无关。

### 14.5 ACK 回显与诊断计数不是有效的排除证据

Evidence：官方 ACK body+0 在 `0x7f9ec0–0x7f9ee0` 由
`peerTimestamp + now - localReceiveTime` 构造；`HandleAckPacket` 调用
`ProcessTimestamp` 用其测 RTT/时钟偏移。我方 `channel.c:200–208` 只填本地当前时间。
这个问题在 pin `8c5a17c` 已存在，不应归咎于最近的 fork 改动，但仍是互操作差异。

此外，累计 ACK 主路径是 `session.c:339 → IHS_RetransmissionAcknowledgeThrough`。
该函数不更新 `maxAckLatencyMs`，只有精确 ACK 函数更新；故日志里的最大 ACK 延迟
不是所有可靠包的最大延迟。`ControlOnHIDPacketAck` 无论是否释放了 HID 包都将
hidAcknowledged 加一；`SubmitHIDReport` 即使发送入队失败也增加 hidSent；
`IHS_SessionGetReliabilityStats` 将 hidPending/hidInFlight 硬编码为 0。

Conclusion：不能再用这些计数推导“故障窗口所有输入都被确认且延迟≤62ms”。
确认/丢弃应区分 ACK、NACK confirmed、NACK bitmap、发送失败，并与包号和密文序号关联。
重传周期上限也不是 ACK 延迟上限。

### 14.6 HID 诊断会越界，原始报告记录也不完整（P1）

Evidence：`DrainPendingHIDReports`（`ch_control.c:138–148`）以 144 字节估计一行，
但 96 字节数据仅 hex 就需 192 字符，还不含前缀和换行。`snprintf` 返回应写长度，
一旦超 cap，后续 `cap-written` 下溢。生产调用方 `client/main.c:2743` 使用 4096 字节。
离线探针混合 96/70 字节报告，给生产函数同样的 cap，并检查缓冲区后的 canary：

```text
HID diagnostic drain: capacity=4096 returned=4128; canary bytes overwritten=31 (required 0)
```

Conclusion：这是实测越界写，可能破坏进程内存；不能将其仅归类为打印格式问题。
正确实现必须按完整行所需长度判界、检查 snprintf 返回值，且不可先消费队列再发现无空间。
它是否解释该次输入卡死没有证据，不能替代协议故障分析。

记录可信度还有独立问题：提交数据先截至 96 字节，队列满时静默丢新项。
`/tmp/stream_diag_prev.log` 有 12340 条 hidrep，其中 2949 条长度达到截断上限；
部分 hex 的 protobuf 长度宣告已超过留存数据。相对于前一个 diag 行，hidrep 原始
时间戳最大落后 76937ms（日志第 12743 行）。这不是网络延迟，是落盘积压的证据。
该日志不能支持“逐包完整记录／文件相邻行是同一故障时刻”的假设。

### 14.7 源码层的线程顺序与生命周期缺陷

这些是本项目 C/线程设计问题，Android 汇编不能替代本地锁与所有权证明：

- **退出死锁（P1）**：`client/media.c:1317` 持有 state_lock；禁用分支
  `:1352 → hid_flush_thread_stop → pthread_join` 仍持锁。被 join 的线程在
  `:1292` 获取同一锁。若恰好等待该锁，两线程永久互等。stop→join 应在释放
  worker 所需锁后执行；还应记录线程是否成功创建，不能无条件 join。
- **delta 排序风险**：8ms flush、媒体线程完整状态心跳、接收线程 RequestFullReport
  都可进入 `IHS_SessionHIDSendReport`。它先打包/重置 holder/解设备锁
  （`control_hid.c:258–272`），后取得 control sendLock 入队。允许 A 先取旧
  delta、B 再取新 delta，但 B 先上线、A 后上线。sendLock 只串行加密，不能保证
  报告生成顺序。需要对收集到入发送队列整体排序，或所有输入报告经单一发送者。
  此交错可由源码推出；它是否在故障现场发生、host 如何处理 CRC 失败是 hypothesis。
- **DeviceWrite 累积 offset**：`sdl_hid_write.c:130–170` 消费 pendingWrites 时只
  OffsetBy，不在清空后复位。逻辑 size=0 但 offset 持续增长，追加最终越过初始设定的
  maxCapacity=1024（Debug 断言，关闭断言时可能继续扩容）。所谓 512B 有界队列
  没有约束已消费空间；清空必须复位。此项为源码证明，未在 Switch 上触发测试。
- `hidPendingLock` 在两个线程首次调用时无同步懒初始化，且没有对应销毁；
  这不满足 NRO 返回 loader 前的显式资源清理要求。

### 14.8 可保留的协议结论，以及不能扩大解释的部分

- **SDL 按钮位直通有证据**：`OnButtonEvent 0x7540b8–0x7540d8` 是
  `1 << SDL_button` 写入 state+16。不能再次依据 EGamepadButton 枚举重映射。
- **RAW 分支有证据**：`HIDDeviceSDLGamepadStateV2_t::Pack 0x752dcc–0x752dec`
  在 byte27!=0 时 memcpy(min(cap,72))。这个分支存在不等于所有设备/协商版本
  必须永远使用 RAW；不能将局部 Pack 分支扩大成“全部路径唯一格式”。
- **full_report 存在**：`SendBuffer 0x7d0368–0x7d03b8` 在
  `deltaLen+8 >= fullLen` 时明确调用 set_full_report。因此 `report.c` 的自适应
  回退有汇编支持；早期“零调用”和强制 full-mask delta 的论据撤回。
  代码注释与 D-041 附录的绝对说法不能继续用作协议规范。
- **16.16 时间单位、累计 ACK 的包含端点语义有直接指令证据**；问题在字段、
  水位及事件编码的实际实现，而不是应把所有已工作的协议改回上游。
- **SetInputTemporarilyDisabled 的解释不完整**：`0x7af974–0x7af980` 转入 player；
  `CStreamPlayer::OnSetInputTemporarilyDisabled 0x7c6550` 查找 InputDisabled 对话框，
  false 时 CloseDialog，true 时创建并 OpenDialog（`0x7c6618–0x7c6644`）。
  这段汇编本身没有“停止全部 HID 上报”的赋值；是否经 overlay 间接抑制输入，
  需追踪 OpenDialog/事件消费，不能只凭消息名宣称与我方全局闸门等价。

### 14.9 差异清单的审计口径

54 个差异文件分属构建/SDL2 兼容、认证和协商、HID 编码和设备命令、传输可靠性、
视频/统计、诊断与生命周期、测试/API。上述是带反例的重点核验，**不是 54 个文件
每个 hunk 均已获得汇编证明**。构建适配、NUL 终止、通道数组计数和线程释放应以
C 源码、平台 API 及测试评估；Android 并无可以照搬的 Switch 实现。

初次审计的 8bb05be 源码快照（本次修正前）host CTest 结果为 24/27：managed/unmanaged SDL
device 的 player-index 断言失败（测试仍期待 DeviceWrite 同步生效），frame_stats
断言失败（测试按毫秒输入，已有工作区实现按 16.16 换算）。这些失败证明测试与
实现已经漂移，不能简单解释为三项线上故障，也不能引用历史 27/27 作为本快照的验证。
上述离线协议探针另外复现三项独立违反：NACK 接收误删除、NACK 发送误确认、诊断越界。

本节撤回的是证据不支持的定论，不宣称用户实机故障已修复。协议修复应分别验证：
缺包仍保留可重传、接收方绝不确认洞、加密/报告顺序不跨越缺口、诊断不能破坏内存。
可靠传输确认只证明传输层处理，不能替代 host 解密、delta 重建和游戏应用的证据。

### 14.10 后续调用链确认与修正约束

以下补充撤回 §14.0 中“本次没有改动实现”的初始审计范围说明：在用户明确要求修正后，
本节对应的代码开始按证据修改。§14.1–14.7 的失败输出是修改前反例，不是修改后行为。

**时钟偏移来源（Conclusion）**：`ProcessTimestamp 0x7f9b1c–0x7f9b34`
将 `peerSend - echoedLocal - (localReceive-echoedLocal)/2` 加入 connection+0x2f0。
`TimeOffsetStats::AddSample 0x7fcac8–0x7fcacc` 将有符号样本均值存至该对象+96，
即 connection+752+96=848。构造函数 `0x7fc958–0x7fc964` 设置十秒窗口，
`0x7fc9c8–0x7fc9d8` 按样本年龄过期。`ProcessTimestamp 0x7f9b08–0x7f9b18`
只纳入 RTT≤动态最小 RTT+65 ticks 的样本。`OnDataPacket 0x7ad22c–0x7ad25c`
从 host 时间减去该偏移转为本地时间；Save 首事件加回偏移。代码以此替换连接起始时刻，
不再将 host 的 frame-start 时间冒充 transport send 时间。

**可靠接收窗口（Conclusion）**：构造函数 `0x7f8720–0x7f8728` 明确以 ID=0
初始化 reliable receive window。`UpdateReliableState 0x7f9e08–0x7f9e58`
从已交付帧后的窗口头继续扫描已收到的连续分片；确认的是包的接收水位，而不只是
完整帧的交付水位。因此 reliable 窗口禁止沿用视频 join-midmessage 的跳片策略，
并必须处理第一包丢失、16 位回绕、未拼齐分片和最后一条 ACK 丢失后的重复包。
`tests/session/test_protocol_evidence.c` 用固定的独立报文期望检查这些条件及解密失败计数。

**临时输入禁用（Conclusion，撤回原门控解释）**：
`OnSetInputTemporarilyDisabled 0x7c6550–0x7c6644` 仅增删 InputDisabled 对话框。
`OpenDialog 0x7be088–0x7be1f0` 更新对话框列表、光标与叠层状态。
`BFilterGamepadState 0x7bc888–0x7bc910` 调用顶层对话框的手柄 down/up 处理，
仅在其返回 true 时转入清空输入分支。而
`CInputDisabledDialog::BOnControllerButtonDown 0x766cb8` 和
`BOnControllerButtonUp 0x766cc0` **均返回 false**。
因此这个通知不支持 `IHS_SessionInputEnabled = streamingInput && !temporarilyDisabled`；
保留通知供诊断，只以协商的 enable_input_streaming 门控。

**HID 输出与活动标志（Conclusion）**：generic gamepad 路径
`BCollectReports 0x7cfb24–0x7cfb34 → BParseGamepadStateGenericGamepad`，
解析 ENCODED 分支在 `0x7d0a50` 写 version=3，回到
`0x7cfd84–0x7cfd8c → Pack` 的 RAW 分支。该证据支持本项目 generic SDL
设备的 RAW 发送路径，不能推广到 Steam Controller 等其他设备格式。
`BFilterGamepadState 0x7bc5e8–0x7bc6a4` 检查按钮、摇杆阈值与扳机，
`0x7bc92c–0x7bc93c` 才设置 active_input。松开最后一个按钮的报告可以是 inactive。
`SendBuffer 0x7d00f0` 跳过相同状态，并按 delta/full 大小选择编码；定时发送相同状态
不是该函数的行为，原“官方 full_report 零调用”的论据撤回。

**本地运行时修正（Evidence/设计推论）**：`reportSendLock` 覆盖 holder 收集、重置到
control 入队的完整顺序；失败分配不消费 holder。媒体 flush worker 以 atomic stop、
成功创建标记与 join 管理，join 时不持有 worker 需要的 state_lock。诊断 mutex 由
IHS_Init/Quit 显式创建销毁；每条记录分别标出捕获长度、wire_len 和累计丢弃数。
这些是 C 并发/内存约束，不宣称是从 Android 汇编推导出的 Switch 平台实现。


### 14.11 接收跨度、媒体配置与本地并发约束

**Evidence / Conclusion：窗口不是 320 包上限。** `BInsertPacket 0x7f7270–0x7f7288`
对新 ID 相对窗口头的距离执行 `tst #0xc000`，合法跨度扩容；
`EnsureCapacity 0x7fd21c` 的容量检查为 0x4000。320 是 NACK presence mask
覆盖范围（40 字节），不能据此固定可靠窗口容量。实现保留已收到的稀疏槽位并扩容至
16384；超出序号跨度的包忽略，不能据此越过缺口。发送端仍逐包保存和重传，
没有“单在途”或“三次后 supersede”的证据。旧文中的固定 320 包窗口说法撤回。

**Evidence / Conclusion：重传与 NACK 的时间条件不同。**
`ProcessTimestamp 0x7f9b38–0x7f9b4c` 更新 RTT 平滑值；
`SendReliablePackets 0x7f8b04–0x7f8b2c` 使用 `1.25 × clamp(srtt,65,3276)` ticks。
`HandleNack 0x7f9634–0x7f9688` 使用三秒 RTT 均值计算
`floor((meanRTT_ms+2)×0.75)` 毫秒后换算 ticks，最大 3276；
扩展体的 echo 时间还约束重发候选的最近发送时刻（0x7f976c–0x7f9780）。
不能用固定倍增重传代替这两个不同条件。当前定时器精度为毫秒，周期为 5ms，
因此与 Android 调度时刻并非逐 tick 相同。

**Evidence / Conclusion：媒体必须等待配置。** `OnDataPacket 0x7ad1d0–0x7ad214`
暂存尚无消费者的数据；`OnStartVideoData 0x7ae0c8` 停旧解码器，
`0x7ae1d8` 启新解码器，`0x7ae1f4` 才处理 pending packets。
不能把任意未知通道按 1920×1080 视频创建。实现等待真实 StartAudio/VideoData，
暂存原始包和到达时间；暂存队列 320 包是本地内存限制，**不是汇编中的容量常量**。
`HandlePacket 0x7faff0–0x7fb028` 验证对端地址和连接 ID，旧会话 ACK 不得释放新会话数据。

**明确的平台能力差异：** Android 的可靠媒体实现能回显 reliable_data
（0x7ad710）；ihslib 的媒体接收只处理 Unreliable/UnreliableFrag，所以协商 false。
控制与统计通道继续可靠传输。不能仅复制 Android 的能力声明却没有相应接收实现。
Switch 的分辨率、硬解、SDL2、系统信息和码率限制属于平台选择；不宣称它们与 Android 相同。

**本地源码约束（不冒充汇编结论）：**

- HID 报告从收集、holder 重置到 control 入队由 reportSendLock 统一排序；设备句柄关闭
  与 provider 操作共用设备锁，快照引用的内存延迟到 manager 销毁。
- SDL pending writes 消费后复位 offset，超出有界队列返回失败；诊断逐条先测长度再复制，
  不足一条时不消费。每条最多保存 512B，同时记录 wire_len、截断和累计掉条数。
- 媒体退出在 worker 需要的 state_lock 外 stop/join；已创建标志区分 pthread_create 失败。
  数据和控制的定时任务停止后再销毁依赖。数据 interrupted 使用原子变量。
- `streaming.c` 原来的“先启动 timer、后发布 handle”允许任务结束后发布悬空指针；
  `authorization.c` 的 base 锁→timer 锁与 timer callback→base 锁构成反序。
  两种请求应共用 timer owner 发布/访问/结束协议，避免上下文在 RX 回调期间释放。
  这是对象生命周期修复；pairing PIN、connect PIN 的消息语义仍遵守认证参考。

**验证边界：** 离线 oracle 检查包洞、回绕、分片、重复 ACK、NACK offset/bitmap、
解密尝试序号、时钟过滤、事件 delta、短包和诊断容量；这些测试无法证明 Steam
已将 HID 应用到游戏。20 秒现象与可靠通道缺口、delta 顺序、日志内存破坏的关联仍属
hypothesis，须以修正版本的 Switch、Host 日志及同一时段抓包互相印证。


### 14.12 NACK 分支边界与报告链回归

`0x7f9774 cmp cutoff-seen; 0x7f977c csel ...,lt` 表示选择
`max(now-age, seen)`（按 32 位有符号差比较），**不是 min**。本次复核中曾将此条件
写成 min，现明确撤回；`nack_age_and_trailing_zeros` 用固定序列及隔离的普通重试期限
验证 seen 可以使新近发送的缺包立即获得重发资格。

掩码 `0x7f9840 cbz` 跳过全零字节，`0x7f9868–0x7f9878` 在每字节最高 1 位后结束，
所以“每个 0 位都会触发重发”是过度概括。例如 `02` 确认 base+1 并对 base 检查重发条件，
不对 base+2…base+7 主动加速；这些包仍保留普通 RTO。掩码前的范围由
`0x7f9698` 独立处理。重试批次按旧包到新包发送，对应 SendReliablePackets 的正向窗口遍历。

`SendBuffer 0x7d00f0` 的去重针对上一生成状态；本地 holder 已有未发 press 时，
不能仅因为 release 等于上次已发状态就丢掉该 full report。完整报告与 delta 都需要
保持一批内的 press→release；`test_hid_report_chain.c` 同时覆盖两种编码。
`test_hid_send_order.c` 从四个并发收集者产生 256 次变化，逐条解密实际入队包、应用
delta、检查 CRC 和严格递增的状态编号。它验证本地顺序，不模拟 Host 的应用策略。

音频重建同样有证据：`OnStartAudioData 0x7adddc–0x7addf8` 先停止并销毁旧解码器。
本地 `audio_reconfiguration` 交替重建音频通道检查数组计数和停止/销毁路径。
该测试暴露并修正了直接 SessionDestroy 时仍有 data worker 的遗漏；销毁必须先
interrupt、join session worker、关闭 HID、join/destroy data worker，再释放控制和统计通道。
StopRequest 的 packet ID 必须在 control sendLock 内记录，避免并发 HID 分配使等待的 ACK
错误地指向另一条消息。这两项清理/竞态约束由 C 源码及测试建立，不作为 Android ABI 结论。

### 14.13 Unconnected 探测与连接 ID 的适用边界

**证据：** 官方 `good.pcapng` 第 34 帧 Connected 分配 client `a3` / host `d5`，
第 37 帧发送 ClientHandshake；第 42–74 帧是双方 ID 均为零的 discovery ping 请求/响应，
第 75 帧才是 ServerHandshake。`CStreamSocket::HandleMessage 0x7ff660–0x7ff6f0`
在调用连接的 HandlePacket 前，将 type 0、channel 0 分派给 HandleUnconnectedPacket。
所以 `HandlePacket 0x7faff0–0x7fb028` 的 ID 检查不适用于这种包。

**撤回：** 本次审计新增过滤曾仅为 Unconnected 豁免目标 ID，却仍在 Handshaking
阶段检查来源 ID。该实现错误，会丢弃上述真实握手探测。`handshake_unconnected_probe`
通过实际接收入口先输入 Connected，再输入官方第 43 帧的探测负载，验证响应 sequence=2。
2026-09-07/08 Switch 日志中多次连接均在约 4.3 秒后由 Host 关闭，且没有 ServerHandshake；
这是回归现象的真机证据。过滤缺陷可以离线重现；它是否完整解释真机失败仍须修复后运行确认。

**修复后的真机反例验证：** NRO SHA-256
`6c0e9b4491940de87d77c7cdd111abf99cd01403393390af70f93cec080ab9f8`
重新加载后，`stream desktop hold` 获得 connected=1，首帧 1712ms，H.264 1280×720、
Opus 48kHz 双声道，HID open=1/start=1；25 秒采样期间继续收到音视频且可靠队列清空。
这支持 Unconnected 过滤导致此次握手回归；不证明长期锁键已解决。

**本地生命周期约束：** `diag_disk_write_tick` 调用 IHS 的 HID 诊断队列，退出线程还会
执行最后一次 tick。主程序必须在 IHS_Quit 销毁诊断互斥锁前 stop/join 该线程。
此前先 Quit 再 join 的顺序不满足新诊断实现的依赖关系；正常退出一次不能排除竞态。


### 14.14 上游差异的证据索引

比较基线为 adopted upstream `8c5a17c` 与审计输入 `8bb05be`，下表逐一列出原始 54 个差异文件（路径相对 `third_party/ihslib`）。这是参考索引，不是任务状态表。汇编证明仅限列明的行为；平台适配、诊断和测试无法从 Android 汇编推出 Switch 的实现。

| 文件 | 依据及适用边界 |
| --- | --- |
| `CMakeLists.txt` | 平台：SDL2/SDL3 互斥选择及依赖传播；host SDL2、Switch 交叉构建验证，不属于 Android 协议。 |
| `include/ihslib/session.h` | 接口：状态/诊断/时钟所有权；字段在本地传递，非 wire 布局；§14.4、14.10–14.13。 |
| `src/client/authorization.c` | 源码：新增消息描述符与诊断不改变认证分支；字符串终止及 timer owner 生命周期修复，见认证参考与 §14.11。非 Android 配对全流程等价证明。 |
| `src/client/client.c` | 源码：新增消息描述符与诊断不改变认证分支；字符串终止及 timer owner 生命周期修复，见认证参考与 §14.11。非 Android 配对全流程等价证明。 |
| `src/client/streaming.c` | 源码：新增消息描述符与诊断不改变认证分支；字符串终止及 timer owner 生命周期修复，见认证参考与 §14.11。非 Android 配对全流程等价证明。 |
| `src/hid/CMakeLists.txt` | 平台：SDL2/SDL3 互斥选择及依赖传播；host SDL2、Switch 交叉构建验证，不属于 Android 协议。 |
| `src/hid/device.c` | 汇编：SendBuffer 0x7d00f0、0x7d0368–0x7d03b8；自适应 delta/full 与生成顺序。兼容的强制全掩码 helper 不再由生产路径调用；§14.12、报告链测试。 |
| `src/hid/device.h` | 汇编：SendBuffer 0x7d00f0、0x7d0368–0x7d03b8；自适应 delta/full 与生成顺序。兼容的强制全掩码 helper 不再由生产路径调用；§14.12、报告链测试。 |
| `src/hid/report.c` | 汇编：SendBuffer 0x7d00f0、0x7d0368–0x7d03b8；自适应 delta/full 与生成顺序。兼容的强制全掩码 helper 不再由生产路径调用；§14.12、报告链测试。 |
| `src/hid/report.h` | 汇编：SendBuffer 0x7d00f0、0x7d0368–0x7d03b8；自适应 delta/full 与生成顺序。兼容的强制全掩码 helper 不再由生产路径调用；§14.12、报告链测试。 |
| `src/hid/sdl/CMakeLists.txt` | 平台：SDL2/SDL3 互斥选择及依赖传播；host SDL2、Switch 交叉构建验证，不属于 Android 协议。 |
| `src/hid/sdl/include/SDL3/SDL.h` | 平台：SDL2 头转发、instance ID→device index、按钮枚举及电量适配；本地 SDL 头/SDL provider 测试。电量百分比未知返回 -1，不伪造 Android 值。 |
| `src/hid/sdl/include/SDL3/SDL_events.h` | 平台：SDL2 头转发、instance ID→device index、按钮枚举及电量适配；本地 SDL 头/SDL provider 测试。电量百分比未知返回 -1，不伪造 Android 值。 |
| `src/hid/sdl/include/SDL3/SDL_gamepad.h` | 平台：SDL2 头转发、instance ID→device index、按钮枚举及电量适配；本地 SDL 头/SDL provider 测试。电量百分比未知返回 -1，不伪造 Android 值。 |
| `src/hid/sdl/include/SDL3/SDL_joystick.h` | 平台：SDL2 头转发、instance ID→device index、按钮枚举及电量适配；本地 SDL 头/SDL provider 测试。电量百分比未知返回 -1，不伪造 Android 值。 |
| `src/hid/sdl/include/SDL3/SDL_version.h` | 平台：SDL2 头转发、instance ID→device index、按钮枚举及电量适配；本地 SDL 头/SDL provider 测试。电量百分比未知返回 -1，不伪造 Android 值。 |
| `src/hid/sdl/include/ihslib/hid/sdl.h` | 汇编：按钮 0x7540b8、RAW Pack 0x752dcc、Generic 解析 0x7d0a50、activity 0x7bc5e8；§14.8/14.10。设备/线程所有权另由 C 锁序及 SDL 测试验证。IMU/touch 未实现。 |
| `src/hid/sdl/include/ihslib/hid/sdl/sdl2_compat.h` | 平台：SDL2 头转发、instance ID→device index、按钮枚举及电量适配；本地 SDL 头/SDL provider 测试。电量百分比未知返回 -1，不伪造 Android 值。 |
| `src/hid/sdl/src/config.h.in` | 平台：SDL2/SDL3 互斥选择及依赖传播；host SDL2、Switch 交叉构建验证，不属于 Android 协议。 |
| `src/hid/sdl/src/sdl_hid_common.h` | 汇编：按钮 0x7540b8、RAW Pack 0x752dcc、Generic 解析 0x7d0a50、activity 0x7bc5e8；§14.8/14.10。设备/线程所有权另由 C 锁序及 SDL 测试验证。IMU/touch 未实现。 |
| `src/hid/sdl/src/sdl_hid_device.c` | 汇编：按钮 0x7540b8、RAW Pack 0x752dcc、Generic 解析 0x7d0a50、activity 0x7bc5e8；§14.8/14.10。设备/线程所有权另由 C 锁序及 SDL 测试验证。IMU/touch 未实现。 |
| `src/hid/sdl/src/sdl_hid_event.c` | 汇编：按钮 0x7540b8、RAW Pack 0x752dcc、Generic 解析 0x7d0a50、activity 0x7bc5e8；§14.8/14.10。设备/线程所有权另由 C 锁序及 SDL 测试验证。IMU/touch 未实现。 |
| `src/hid/sdl/src/sdl_hid_feature_report.c` | 源码：保留上游设备命令格式；player index 缓存使异步 Write 可见，SDL 命令在媒体线程执行，有界队列耗尽返回失败。managed/unmanaged 测试含 4096 次 drain；不声称调度与 Android 相同。 |
| `src/hid/sdl/src/sdl_hid_write.c` | 源码：保留上游设备命令格式；player index 缓存使异步 Write 可见，SDL 命令在媒体线程执行，有界队列耗尽返回失败。managed/unmanaged 测试含 4096 次 drain；不声称调度与 Android 相同。 |
| `src/platforms/ihs_ip_posix.c` | 平台：补 socket 声明及 SO_RCVBUFFORCE 宏缺失时回退；Switch 编译和 UDP 串流验证。 |
| `src/platforms/ihs_udp_posix.c` | 平台：补 socket 声明及 SO_RCVBUFFORCE 宏缺失时回退；Switch 编译和 UDP 串流验证。 |
| `src/session/channels/ch_control.c` | 汇编：ACK/NACK 0x7f94b8/0x7f960c、接收水位 0x7fa14c、解密序号 0x7ad054；§14.1–14.7/14.12。诊断容量另有离线 canary/并发测试。 |
| `src/session/channels/ch_control.h` | 汇编：ACK/NACK 0x7f94b8/0x7f960c、接收水位 0x7fa14c、解密序号 0x7ad054；§14.1–14.7/14.12。诊断容量另有离线 canary/并发测试。 |
| `src/session/channels/ch_control_keepalive.c` | 汇编：HandleStreaming 0x7a7140 首发与 0xA0000 ticks 周期；本地 stop/join 定时器生命周期。 |
| `src/session/channels/ch_control_negotiation.c` | 汇编：OnNegotiationInit 0x7ad710、0x7ad9cc、0x7ad9e8；真实能力约束 reliable_data=false，§14.11。分辨率/码率/硬解/system_info 是 Switch 平台选择。 |
| `src/session/channels/ch_control_video.c` | 汇编：真实 StartVideoData 0x7ae0c8–0x7ae1f4、数据时钟换算 0x7ad22c；§14.10/14.11。本地 worker/短包防护及音视频真机验证。 |
| `src/session/channels/ch_discovery.c` | 汇编：Connected 0x7fae30 与 Unconnected 分流 0x7ff660；§14.13。重复 Connected 不重复发送 ClientHandshake；停止任务后释放 channel。 |
| `src/session/channels/channel.c` | 汇编：ACK echo 0x7f9ec0；数组移除计数、重复添加/容量边界属于 C 内存约束，protocol_evidence 音频重建/早到包测试。 |
| `src/session/channels/channel.h` | 汇编：ACK echo 0x7f9ec0；数组移除计数、重复添加/容量边界属于 C 内存约束，protocol_evidence 音频重建/早到包测试。 |
| `src/session/channels/control/control_hid.c` | 汇编：Generic 枚举 0x754bbc、SendBuffer 0x7d00f0、输入对话框 0x766cb8/0x766cc0；§14.8/14.10/14.12。四线程实际加密入队验证顺序；ACK 数不能表示游戏已应用。 |
| `src/session/channels/video/ch_data_video.c` | 汇编：真实 StartVideoData 0x7ae0c8–0x7ae1f4、数据时钟换算 0x7ad22c；§14.10/14.11。本地 worker/短包防护及音视频真机验证。 |
| `src/session/frame_stats.c` | 汇编：Save 0x7f4b68–0x7f4cb8，首项加时钟偏移、后项 delta；§14.4/14.10。聚合快照及堆缓冲为本地并发修复。 |
| `src/session/frame_stats.h` | 汇编：Save 0x7f4b68–0x7f4cb8，首项加时钟偏移、后项 delta；§14.4/14.10。聚合快照及堆缓冲为本地并发修复。 |
| `src/session/packet.c` | 汇编：GetStreamTimestamp 0x802ab0–0x802ac4；13 字节头保持不变，本地 metadata 不序列化；短包/CRC 边界测试。 |
| `src/session/packet.h` | 汇编：GetStreamTimestamp 0x802ab0–0x802ac4；13 字节头保持不变，本地 metadata 不序列化；短包/CRC 边界测试。 |
| `src/session/retransmission.c` | 汇编：可靠发送 0x7f8b04、累计 ACK 0x7f94b8、NACK 0x7f9634–0x7f9878；§14.1/14.11/14.12。无 supersede/giveup，保留缺口直到确认。 |
| `src/session/retransmission.h` | 汇编：可靠发送 0x7f8b04、累计 ACK 0x7f94b8、NACK 0x7f9634–0x7f9878；§14.1/14.11/14.12。无 supersede/giveup，保留缺口直到确认。 |
| `src/session/session.c` | 汇编：连接 ID 检查 0x7faff0 与 Unconnected 豁免 0x7ff660；未知数据待真实配置 0x7ad1d0；§14.10–14.13。停止/销毁顺序以 C 生命周期验证。 |
| `src/session/session_pri.h` | 接口：状态/诊断/时钟所有权；字段在本地传递，非 wire 布局；§14.4、14.10–14.13。 |
| `src/session/window.c` | 汇编：构造首 ID=0（0x7f8720）、动态窗口 0x7f7270/0x7fd21c、水位 0x7fa14c；丢首包/回绕/分片/丢 NACK/扩容测试。 |
| `src/session/window.h` | 汇编：构造首 ID=0（0x7f8720）、动态窗口 0x7f7270/0x7fd21c、水位 0x7fa14c；丢首包/回绕/分片/丢 NACK/扩容测试。 |
| `tests/CMakeLists.txt` | 验证代码：按上述协议 oracle 更新；测试通过仅覆盖具体输入与并发路径，不作为 Android 行为的独立来源。 |
| `tests/session/CMakeLists.txt` | 验证代码：按上述协议 oracle 更新；测试通过仅覆盖具体输入与并发路径，不作为 Android 行为的独立来源。 |
| `tests/session/control_hid_admission.c` | 验证代码：按上述协议 oracle 更新；测试通过仅覆盖具体输入与并发路径，不作为 Android 行为的独立来源。 |
| `tests/session/retransmission_state_machine.c` | 验证代码：按上述协议 oracle 更新；测试通过仅覆盖具体输入与并发路径，不作为 Android 行为的独立来源。 |
| `tests/session/test_disconnect_destroy.c` | 验证代码：按上述协议 oracle 更新；测试通过仅覆盖具体输入与并发路径，不作为 Android 行为的独立来源。 |
| `tests/session/test_frame_stats.c` | 验证代码：按上述协议 oracle 更新；测试通过仅覆盖具体输入与并发路径，不作为 Android 行为的独立来源。 |
| `tests/test_hid_report_batch.c` | 验证代码：按上述协议 oracle 更新；测试通过仅覆盖具体输入与并发路径，不作为 Android 行为的独立来源。 |
| `tests/test_hid_report_replace.c` | 验证代码：按上述协议 oracle 更新；测试通过仅覆盖具体输入与并发路径，不作为 Android 行为的独立来源。 |

本次为修复上述调用链而扩展的文件包括 `src/hid/manager.*`、`src/ihs_timer.*`、`src/base.c`、`src/session/clock.*`、`frame_crypto.c`、`channels/ch_data.*`、`ch_control_audio.c` 及新增回归测试；其依据见 §14.10–14.13。主程序 `client/main.c`、`client/media.c` 的停止/加入与日志限额属于 Switch 运行时约束。

### 14.15 重复断开与报告长度的本地并发约束

**证据：** `test_disconnect_destroy` 在立即销毁前调用两次 discovery disconnect，
ASan 报告 `DisconnectTimerEnd` 写入已释放的 channel。第二次 Start 覆盖第一任务的句柄，
channel deinit 只取消后一任务，TimerDestroy 仍执行前一任务的 end callback。
因此 discovery 的断开任务也必须使用同一 owner 的原子发布/取消，重复请求不创建第二任务。
此问题由真实 C 执行反例建立，与 Host 锁键的关系未经证明。

`HandleDeviceStartInputReports` 原来在设备锁外更新 reportHolder.reportLength，而媒体线程
在设备锁内读取该长度并生成报告。长度更新应移入 `IHS_HIDDeviceStartInputReports` 的
同一设备锁内，与 provider 初始报告生成构成一次操作。这是本地数据竞争修复，
不改变 StartInputReports 的线上消息或响应语义。

### 14.16 发送类型与非 HID 控制消息的补充核验

**直接调用证据：** `CStreamFrame::Send 0x7f3118` 将 bool=true 分派到可靠 Send，
false 在 `0x7f314c` **尾调用 b** 到 SendUnreliable。静态列表中的日志
`0x7a7430`、认证 `0x7a7d08`、控制 `0x7a7e00/0x7a7e70`、帧事件 `0x7a8638`、
统计 `0x7a8c0c`、日志上传 `0x7a8e94/0x7a8fac/0x7a9034`、debug dump `0x7ac7c0`、
ClientHandshake `0x7acf1c` 均传 true。`SendDataLost 0x7abe2c` 传 false；
麦克风 `0x7a8ab8` 读取协商状态字节。ACK/NACK 走 channel 的独立反馈路径。
因此不能把“数据丢失通知使用不可靠发送”泛化为“HID/统计应改成不可靠”。
本地 `ch_stats.c` 可靠发送、`ch_data.c` 不可靠 DataLost 的选择与此相符。
这里列举的是可见静态调用，并非证明动态调用不存在。

**接收行为证据：**

- `OnSetQoS 0x7add24–0x7add30` 把 use_qos 左移一位后传给 transport；
  `CStreamTransportUDP::SetQOS 0x802288/0x8022b8` 调用 setsockopt 设置本地网络选项，
  不是 HID 使能消息。本地仍只记录该消息，这是沿用上游的 QoS 能力差异，
  不能直接把 Android 的 socket 常数照抄为 Switch 常数，也没有证据将其称为锁键根因。
- `OnSetTargetBitrate 0x7aebf8–0x7aec28` 保存目标码率并通知 decoder/player 回调；
  `CStreamPlayer::SetTargetBitrate 0x7c9df4` 是空实现，standalone H.264 decoder
  `0x7b1234` 则可向加速后端转发。本地已有 setTargetBitrate 回调；不是要求回复
  一条隐藏的控制确认。常规可靠 ACK 仍由传输层处理。
- `OnVideoEncoderInfo 0x7aee94–0x7aeeac` 只保存编码器说明字符串，没有解码器重建
  或控制回复。本地只记录该字符串；不能由 NVENC 字样推断编码器故障。
- `OnControllerConfigMessage 0x7afcec–0x7afd00` 转发 player 虚方法，
  本二进制中的基础 player 实现 `0x7c9e04` 直接 ret；重定位 `0xc44560` 引用该实现。
  这不足以建立“必须额外发送 ControllerConfig 才能使 HID 生效”的说法。
  完整的 UI 配置构造链和派生类型覆盖仍不能仅凭此叶函数宣称已穷尽。

### 14.17 实机输入与版本归属的证据

2026-09-08，用户游玩后反馈：“我玩了一会，非常好，似乎 20s 卡死消失了”。
对应 NRO 为 §14.13 的 `6c0e9b44…80ab9f8`；PC 侧退出摘要记录串流 738630ms，
接收/解码 41687 帧、显示 41510 帧，首帧 1712ms。保存的输入采样最后记录
28729 批 HID 发送，1 个正在等待确认的包年龄 3ms，全程观测的最大确认延迟 146ms，
没有 giveup、supersede 或发送失败。用户的操作反馈是游戏生效的证据；ACK 数据
只能旁证可靠传输，不能单独得出相同结论。

**结论边界：** 此次约 12 分 19 秒游玩没有复现原症状，支持修正版改善了问题。
未做逐项回退对照，没有同轮 Host 解密日志，因此不能把根因唯一归到 NACK、
报告顺序或某一项修复，也不能保证所有网络条件下永不复现。
nxlink 日志记录退出原因为 `hotkey:vol_up+sticks`，且诊断线程在 IHS_Quit 前结束；
不由 PC 侧日志推断 Switch 的最终屏幕状态。
用户随后另外确认此次退出恢复正常，并指出旧版有时退出报错。这是本轮退出行为的
真机正面证据，支持清理修正有效；它不提供旧版异常的调用栈，不能唯一定位到某个清理点。

游玩期间另以离线反例修正了 §14.15 的重复断开 UAF 和报告长度锁。
含这两项后续修复的构建 SHA-256 为
`74d1cf53606e6dff4cb57bcb1bca3c03f5a4f4a594f833e68ffb9a29b9d38bc2`；
29 项测试在普通、ASan/UBSan、TSan 配置下均通过。该构建与上述已实测构建不同，
不能把前者的完整运行时验证归给后者。

## 20. 游戏封面与主机图标（2026-09-08）

本节复核对象为同一 Android v1.3.32 arm64 `libmain.so`，不把符号存在本身等同于功能已验证。
ELF SHA256：`50e1d3147d5d47b71ef1970e1867a2fe4f3e1ecf2ea6153f927fac88b88ea38e`。

### 20.1 Evidence：商店图片下载与缓存

- `CAppImages::GetStoreItem(uint32)` @ `0x75ea0c` 构造 StoreBrowse GetItems 请求，写入
  appid；`0x75eb60` 设置数据请求的 include_assets_without_overrides（field 15）。随后
  序列化 protobuf、Base64/URL 编码，经 `CWebRequestManager::BStart` 发请求。
- URL 格式常量 @ `0x370c2d` 为
  `%s/IStoreBrowseService/GetItems/v1?input_protobuf_encoded=%s`。
- `CAppImages::OnStoreItem` @ `0x75fd00` 拼接资源 URL：国际域名常量 @ `0x3a3e4c`
  为 `https://shared.steamstatic.com/store_item_assets`，中国域名 @ `0x390607` 为
  `https://shared.cdn.steamchina.eccdnx.com/store_item_assets`；从 assets 取 URL 模板与
  header 字段，将 `${FILENAME}` 替换成文件名，再异步请求。
- `SaveImage` @ `0x760020` 经 BSaveCacheFile 保存；`GetImagePath` @ `0x75fa04` 和
  `GetImageInfoPath` @ `0x75f92c` 使用 `app_image_%u.jpg` / `app_image_%u.txt`。
- `LoadImage` @ `0x75f698` 从缓存读取，经 IMG_Load_IO 解码并创建 SDL 纹理。
  本次静态调用索引中，直接调用者为 `CreateStartupBackground` @ `0x75f1c8`，
  后者由 `CStreamPlayer::InitStartup` @ `0x7b6794` 调用。
- `SetStreamingActivity` @ `0x7b7160`、`SetLaunchedActivity` @ `0x7b7140` 以及
  `SetActivity` 的 `0x7c5440` 调用 AddAppID，证明图片缓存与游戏活动关联。

Conclusion：官方确实存在“游戏活动 ID → Steam 商店元数据 → CDN 横版图片 → 本地缓存 →
启动背景”的路径，不是保存串流末帧。此调用链不能证明用户记忆中的首页卡片一定采用
同一图片，也不能排除其他页面使用截图；本次没有确认“断开时截图作为游戏卡片”的路径。

### 20.2 Evidence：主机直接发送的是窗口图标

`remoteplay.proto` 的 CSetIconMsg 包含 width、height、image。
`CStreamClient::OnSetIcon` @ `0x7ae4bc` 校验图片至少 width×height×4 字节，
传给 `CStreamPlayer::SetIcon` @ `0x7c5804`，后者创建 surface 并调用 SDL_SetWindowIcon。
IHSlib 当前 `src/session/channels/ch_control.c` 对 k_EStreamControlSetIcon 直接 break。

Conclusion：主机有直接发送位图的协议，但这条已经确认的用途是窗口图标，不能把它
当成高清封面接口。GetTouchIconData 属于触控配置，CDebugDumpMsg.screenshot 属于调试消息；
字段名称不能作为游戏卡片图片来源的证据。

### 20.3 Evidence：公开接口读请求实测

2026-09-08 在开发机对同一路径使用 input_json 参数，仅请求 appid=413150、
context(language=schinese,country_code=US)、include_assets_without_overrides=true，
没有发送 Steam 登录 Cookie 或 Web API key。返回 success=1、Stardew Valley，以及：

- asset_url_format：`steam/apps/413150/${FILENAME}?t=1786554168`
- header：`header.jpg`
- library_capsule：`library_600x900.jpg`
- library_hero：`library_hero.jpg`

按返回的模板拼接 header 地址后，HEAD 返回 HTTP 200、image/jpeg、58853 字节。

Conclusion：该游戏的元数据当前可匿名读取；不能由单个应用成功推出所有游戏、地区和
未来接口行为都一致。接口是客户端内部使用方式，不按公开稳定 SDK 契约假设。
素材类别的官方说明：[Steamworks Library Assets](https://partner.steamgames.com/doc/store/assets/libraryassets)。

### 20.3.1 Evidence：header 字段包含相对目录

2026-09-08，用户报告 GIRLS MADE PUDDING 与 Palworld 新卡片有标题但持续没有封面。
对 appid=3337210 和 1623730 使用相同匿名 GetItems 请求，均返回 success=1：

- 3337210：header 为 `08a8d3df458f6b3ec9cf32d7faf2c87101598623/header.jpg`。
- 1623730：header 为 `6912f19c43a95ff5fe514eedd35e68bf12335459/header.jpg`。
- 按各自 asset_url_format 拼接后，实际 GET 均为 HTTP 200、image/jpeg，
  响应分别为 56568 和 69631 字节。
- 将两份实际 JSON 输入 5d9fa1a 的 `sl_artwork_url`，均返回 false；
  原因是 header 的字符白名单不接受斜杠。

Conclusion：header 是相对资源路径，不能限制为无目录的单个文件名。原先仅以
`header.jpg` 为样例的校验过严，可以直接复现这两款游戏的封面失败。
允许相对目录后仍固定 Steam CDN 与对应 AppID 根路径，拒绝绝对路径、父目录、
协议地址及查询／片段注入。这一证据只定位资源解析，不推断其他真机网络请求的结果。

### 20.4 NSteamLink 接入设计边界

现有 runtime activity 回调已经得到 gameid/name，UI 将历史按 host/account 保存。
封面可以单独按验证过的 Steam AppID 缓存，主机切换仍只展示该主机/账号原有游戏列表。
不要把非 Steam 快捷方式的 64 位 gameid 直接截断后拿去查询商店，也不把公开商店结果
冒充用户的完整游戏库。当前“最近游玩”源自实际串流活动记录，不是已实现的主机游戏库枚举。

推荐横版封面适配现有卡片：先显示缓存或占位，后台有界请求；成功后替换纹理，不改变焦点
与触摸命中，不阻塞发现/配对。下载失败保留名称及占位，不弹对话框。工作线程可停止、可 join；
图片字节/尺寸/缓存量需限制。自定义主机封面、非 Steam 游戏图片与局域网离线首次取图不在
已验证的商店路径能力之内；窗口图标接收可作为独立备选研究，不自动截取串流画面。

## 21. 视频停止、活动变化与会话结束的区别（2026-09-08）

Evidence：同一 v1.3.32 arm64 libmain.so，静态反汇编 /tmp/slink/main.disasm：

- OnStopVideoData @0x7ae278：解析 CStopVideoDataMsg；成功后 @0x7ae2c4 清除
  client+626 的视频状态位，@0x7ae2cc 调用 IStreamDecoder::OnStreamStopped，
  @0x7ae2e0 析构 client+40 的视频解码器，@0x7ae2e4 清空指针。此分支不销毁
  client+32 音频解码器，也不写 client+256 会话状态。
- OnSetActivity @0x7aef08：@0x7aef5c 读取 activity，@0x7aef64–70 按 has_gameid
  选择 64 位 gameid 或旧 appid，@0x7aef80 向 player 委托完整 activity/id/name。
- SetActivity @0x7c5290：@0x7c53e4 保存 activity 到 player+496；根据活动类型更新
  文字、控制覆盖层和电源管理。@0x7c5428–40 只有 activity==Game(2) 且标准 AppID
  才加入封面缓存；没有在 activity 变为 Desktop(3) 时调用 Disconnect/StopRequest。
- remoteplay.proto 的 EStreamActivity：Idle=1、Game=2、Desktop=3、
  SecureDesktop=4、Music=5；它不是视频结束原因枚举。
- OnThink @0x7a5ff8：分别检查并处理音频/视频解码器，缺少视频解码器时跳过视频处理；
  state==6 调用 HandleStreaming @0x7a7140。后者发送帧反馈和 KeepAlive；
  此函数没有“显示帧数 10 秒不变就断会话”的分支。
- OnStreamDisconnected @0x7b00d0：当原会话 state==6 时，@0x7b014c–54 设置 state=7
  并清除状态位，进入会话停止路径。与 OnStopVideoData 的仅视频清理有明确区别。

Conclusion：StopVideoData(53) 是明确的视频停止消息，允许音频与会话继续存在；
不能将它、SetActivity(98) 和会话 StopRequest(129)/Disconnect 混为一谈。
当前 fork 原已接收 StopVideoData 并移除视频通道，但应用无独立的显式停止状态，
仍会触发无帧 watchdog。SetActivity 原只上报非零且有名的游戏 ID，丢失活动类型、
空 ID 和旧 appid 回退，因此旧日志无法恢复完整语义。

接线规则：解析并保存明确视频停止状态，StartVideoData 清除它；该状态下禁止无帧
watchdog，恢复视频时重新给足等待窗口。完整活动回调保留 activity/id/name；
只有 Game 活动写入最近游戏。状态日志记录 StartVideoData/StopVideoData 和完整
SetActivity，不再要求新增收包计数实测。保留原有完整会话结束处理和清理顺序。

边界：以上确认了官方处理及本地缺口，不能倒推出 8e918e0 旧日志未记录的 activity 值，
也不能宣称该次真机必定收到过 StopVideoData。用户确认退出游戏后声音来自其他程序，
该观察与“视频停止但音频可能继续”的模型相容，不等同于抓到具体结束包。

### 21.1 直启退出复现与视频流替换核对

Evidence：ae61751 真机日志 `/tmp/nsl-ae61751-device.log` 中两次串流均为：

- 第 81/193 行：SetActivity activity=2 gameid=2358720。
- 第 86/199 行：StartVideoData(channel=4, codec=4, size=1280x720)。
- 第 123/238 行：SetActivity activity=3 gameid=413080 name=。
- 第 135/250 行：本地 watchdog，idle_ms=10004/10006，video_active=1，host_stop=0。
- 这两段从游戏转 Desktop 到 watchdog 清理之间，没有记录 StopVideoData、
  第二个 StartVideoData 或明确主机会话停止；video lifecycle: stop 在清理后才出现。
- 用户观察 Switch 先变黑，电脑也在黑屏返回 Steam；其他程序声音仍经串流播放。

Conclusion：最新日志确认的是 Desktop 活动，不能再把 413080 仅当作未知游戏 ID。
这次报错确由本地无画面 watchdog 发起；显式 StopVideoData 的修正未覆盖这条路径。
日志只覆盖到本地断开，不能证明无限等待后主机也绝不会恢复视频，也不能证明未记录的
包从未发出。黑屏实机观察不因本地 video_active 仍为 1 而被否定。

Evidence：官方同版本 ARM64：

- OnStartVideoData @0x7ae074：@0x7ae0bc–e0 停止并析构旧视频解码器；
  @0x7ae0e4–ec 保存消息中的新通道；@0x7ae1d8 按新配置 StartVideoDecoding。
  不需要先收到 StopVideoData，不为桌面和游戏各保留一条等待中的固定视频流。
- SetLaunchedActivity @0x7b7140 保存 launched ID 到 player+488；
  SDL_main @0x75cd08 调用它。SetActivity @0x7c5290 的当前活动另存 player+496/+504。
- BHandleEvent @0x7b8238–3c 在 SDL 事件类型 0x100（Quit）才跳到
  @0x7b8ad0 检查 launched ID；这不是主机游戏退出通知。
- SendQuitRequest @0x7b9d88 根据 launched ID 和另外的模式/退出状态位选择
  Disconnect 或 SendStopRequest，不能由此推导“Desktop 活动自动结束”。

Conclusion：官方有视频通道替换能力，也确实分别保存“启动意图”和“当前活动”，
但以上调用链没有证明直启游戏在 Desktop 活动时自动断开。NSteamLink 的
ch_control_video.c 同样移除旧视频通道并使用新 StartVideoData 创建通道；runtime.c
没有按桌面通道 ID 等待的逻辑。当前实机片段也没有观察到通道替换。

设计边界：直启结束回 NSteamLink 首页、Steam 入口保留串流，可以作为产品策略，
但必须有独立的游戏结束证据，不能只使用 SetActivity(Desktop)、无帧时长或 ID 变化。
可核对的协议候选是发现响应 games_running；它表示主机是否有运行中的游戏，
并非目标游戏的进程退出事件。当前 fork 没有向调用者保留 has_games_running，
且开流时停止周期发现，因此首页缓存的 false 或缺省 false 均不能用于立即结束。
“主机是否在直启结束时停止捕获但保持会话”仍是待验证的主机策略，不能冒充官方结论。

### 21.2 主机运行状态作为直启结束的补充依据

Evidence：2026-09-08 开发机对当前 Steam 主机 10.10.10.166:27036 发送三次
单播 Discovery（仅查询状态，不进行配对或开流）。仅接受对应地址、正确 magic 和
Status 消息类型后解码，三次相同 client_id/instance_id 的响应分别含：

| 主机 timestamp | has_games_running / games_running | has_remoteplay_active |
| --- | --- | --- |
| 1788878389 | true / false | false |
| 1788878390 | true / false | false |
| 1788878392 | true / false | false |

Conclusion：当前主机实际支持带时间戳的“有无游戏运行”状态；remoteplay_active
未提供，不能把其缺省 false 当作会话结束。这次只读查询不是游戏退出瞬间的抓取，
不能证明 games_running 的退出更新延迟、切屏表现或所有类型游戏的跟踪准确度。

官方附加核对：CServerManager::Update @0x79890c 接收发现消息，并在
@0x798ab0 调用 RequestStatus；HandleBroadcastMsgStatus @0x79ebdc
更新 CServerInfo，发生变化时 @0x79ec88 调用 delegate。此路径没有直接根据
游戏结束断开串流的分支。CStreamTransportClient::OnServerOffline @0x7d4e58
是空返回。不能将本文提出的组合判定称为已还原的官方自动退出算法。

可实现策略：原始直启意图 + 已收到目标 Game 活动 + 当前 Desktop 活动 + 同一
主机新鲜、显式、稳定的 games_running=false，才允许自动正常回首页。
这是 NSteamLink 的产品收尾策略，不把 Desktop 定义成进程退出。状态只反映
主机是否还有游戏，不提供逐个 AppID 的运行列表；其他游戏仍在运行时不能用它
确认目标游戏已结束。缺字段、缺时间戳、主机实例改变或查询不通均保留未知状态。

### 21.3 取消启动后立即重连的官方事务隔离

Evidence：同一官方 ARM64：

- StartStreaming @0x798d94：state==5 且目标主机相同时 @0x798dc0–d4 直接
  返回，避免同一在途请求重复创建；新请求 @0x798e90 生成随机编号，
  @0x798ea0 保存到 manager+512。
- SendCancelStreamingRequest @0x799ac4：@0x799b54 读取原编号，
  @0x799b64 写入 CMsgRemoteDeviceStreamingCancelRequest.request_id，
  @0x799b80–84 发消息类型 10 到目标主机。
- StopStreaming @0x79987c：按状态分别取消 authorization 或 streaming；
  @0x799980–8c 转空闲并清除目标/账号/请求编号。此路径没有等待 cancel ACK
  的分支，不能宣称 Steam 已在此刻撤销启动游戏的所有副作用。
- HandleStartStreamingProgress @0x79e788：@0x79e790–98 要求编号非零且
  等于当前编号；不匹配走忽略日志。
- HandleStartStreamingResponse @0x79e828：@0x79e884–8c 同样核对编号。
  不匹配进入 @0x79e94c；若 result==InProgress(5)，@0x79e96c–b4
  构造取消消息，使用迟到响应自身的 request_id（@0x79e97c），再次取消旧请求。
  其他不匹配结果返回，不把旧 success 接到新事务。

Conclusion：官方既有本地请求隔离，也有带编号的主机端取消，并处理取消消息
丢失或迟到的后续 InProgress。请求编号保护的是启动事务，不代表 games_running
状态查询也携带同一编号；两类消息不能混用其关联保证。

本地对照：UI B 在连接页增加 generation 并进入 STOPPING；收到 worker 的
STOPPED 前 A 不会启动新请求。execute 在替换 active 前 join/destroy 旧 client，
UI 拒绝旧 generation 事件，IHS streaming response 有 request_id 比较。
但是 stop_client 只有 AuthorizationCancel，没有 StreamingCancel；fork 当前也
没有对应 API。StreamingResponseVisit 还在 request_id 校验前更新 lastMsgTime/
lastMsgType，意味着旧响应虽不成功连接，却能干扰当前请求的超时计时；
IHS_ClientStreamingCallback 忽略来源地址。

Conclusion：当前 B/A 不会必然把旧 success 直接接成新连接，但主机端旧启动请求
没有被明确取消，不能以本地 generation 推出完整安全。主机旧请求与新请求冲突
的具体表现（Busy、继续启动等）尚未通过这一操作序列实测。

## 22. 局域网串流 Request 报文与发送场景核对

范围：discovery.proto、remoteplay.proto、hiddevices.proto 中全部名称含 Request
的协议项，以及 GetCursorImage/GetTouchConfigData/GetTouchIconData 这类实际查询。
补查与连接生命周期相关的 Disconnect、Pause/Resume、KeepAlive 和协商。
不将 APK 中商店 HTTP、Steam 云端 CM/RPC、VR 等所有命名为 Request 的消息
都当作局域网客户端必发项。本表是静态协议参考，不代表所有路径完成真机验收。

证据基线：官方 Android 1.3.32 arm64 libmain.so（SHA256
50e1d3147d5d47b71ef1970e1867a2fe4f3e1ecf2ea6153f927fac88b88ea38e）；
本地 ae61751 / ihslib 38d842b。地址均是官方虚拟地址，非文件偏移。

### 22.1 启动、配对与会话请求

| 报文 | 官方发送/使用场景和证据 | 本地对应及结论 |
| --- | --- | --- |
| AuthorizationRequest（发现 3） | SendAuthorizeDeviceRequest @79a490、BCreateAuthorizationRequest @79c594；配对授权阶段 | client/authorization.c 定时发送 KeyEscrow 路径，已有；不因开流就重复配对。官方还有密钥交换分支，不能宣称所有认证变体齐全 |
| AuthorizationCancelRequest（9） | SendCancelAuthorizationRequest @7999b8；StopStreaming 在授权状态调用 | AuthorizationCancelVisit 已发送，runtime stop_client 已调用；不是本轮漏发项。取消消息没有 streaming request_id，不能照搬开流编号策略 |
| StreamingRequest（5） | StartStreaming @798d94 建编号，SendStartStreamingRequest @799328 使用原编号重试；同主机在途请求去重 | client/streaming.c 有随机编号和重复发送；stream_interface 固定 BigPicture 属请求配置差异，不能凭名字改变其主机行为 |
| StreamingCancelRequest（10） | 取消原 request_id；迟到 InProgress 再取消其旧编号，详见 §21.3 | 缺发送/API；只停止本地 client 不等于撤销主机启动请求，必须补齐事务级取消 |
| ProofRequest（7）→ProofResponse（8） | 主机发 challenge，HandleStreamingProofRequest @79e1c0 校验目标 client_id；有 request_id 时比较。@79e234–40 处理 update_secret，@79e4d4 SHA256、@79e510 保存密钥 | 已响应普通 challenge；忽略源地址、未检查目标 client_id，且无条件比较 request_id，丢失“可选字段不存在”的兼容语义。没有 update_secret/updated_secret 处理；属于条件认证兼容缺口，不能无证据直接轮换现有凭据 |
| AuthenticationRequest（控制 1） | StartAuthentication @7a7b7c，握手后/握手分发路径发送 HMAC 会话认证；不是配对 PIN | ch_control_authentication.c 已发送，不能用配对或开流请求替代；本轮未发现整条漏发 |
| DiscoveryPingRequest（会话发现 1）→PingResponse（2） | OnPingRequest @7acc20 收到探测后复制探测信息并按尺寸回包；不是首页 UDP 发现请求 | ch_discovery.c 已解析并回 PingResponse；没有证据需要客户端周期性额外发 PingRequest 才能结束游戏 |
| StopRequest（控制 129） | SendStopRequest @7abb4c 仅 streaming 状态发；菜单 stop_game 使用它，见 §22.2 | 已发，但 session.c 的通用 IHS_SessionDisconnect 无差别发送，场景不等价于官方；须拆开停止游戏与停止串流 |
| QuitRequest（控制 83） | SendQuitRequest @7abbe0 有 streaming 门槛和发送实现；静态直接调用索引未找到有效产品调用者 | 本地未发送，但缺乏应发场景证据，不补。CStreamPlayer::SendQuitRequest 实际可能调用 StopRequest/Disconnect，函数名不能当报文名 |
| VirtualHereRequest（102） | SendVirtualHereRequest @7aaf20；调用者 OnDeviceAvailable @7bce58，在设备共享启用且服务状态需要时 @7bcf14 发 | 当前无 USB-over-network/VirtualHere 功能；不应在普通 Switch HID 连接时补发 |
| ControllerConfigMsg.RequestConfigsForApp（子类型 0） | 存在枚举及 SendControllerConfigMessage @7abb30，未找到本次二进制的直接业务发送调用 | fork 只解析丢弃，配置编辑未实现；不能把枚举存在等同启动必需 |
| ControllerConfigMsg.RequestActiveConfig（子类型 4） | 同上；官方 player OnControllerConfigMessage @7c9e04 是空返回 | 同上，不自动添加请求 |
| HID DeviceRequestFullReport | 主机→客户端恢复完整手柄报告，HandleRemoteHIDMessage @7c6be8 统一分发 | control_hid.c 已调设备 requestFullReport 并立即发送完整报告；不是客户端主动请求主机的游戏结束消息 |

### 22.2 StopRequest 的菜单语义与错误发送范围

Evidence：SetupMenubarElements @773e40 使用相对字符串表 @446694，
逐个写入 overlay+88+i*8；解码表得到 +160=menu_stop_streaming，
+168=menu_stop_game。BOnAction @77465c：

- 匹配 +160 后 @774878–80 调 CStreamClient::Disconnect。
- 匹配 +168 后 @774888–8c 调 CStreamPlayer::SendStopRequest；
  player @7baf5c 转调 client SendStopRequest，最终发送控制 129。
- CStreamClient::Disconnect @7a7acc 调 CStreamConnection::Disconnect，
  清理会话并 ResetConnection，此函数不发送控制 129。

Conclusion：官方明确分开“停止串流”和“停止游戏”。本地通用断开无差别
发送 StopRequest 与之不一致。可证明发送场景错误；不能仅凭静态代码宣称
用户每一次断开都实际杀掉了游戏，主机最终行为还取决于会话和主机实现。
尤其不能在收到主机结束、自动返回、网络异常或取消新请求时用通用 StopRequest
补偿未知旧状态。保留游戏的断开应使用 transport Disconnect 及有界清理；
停止游戏应有独立、明确的产品动作。

### 22.3 查询及相邻生命周期消息

| 消息 | 官方场景 | 本地结论 |
| --- | --- | --- |
| GetCursorImage（66） | SetCursor @7c5cb0 缓存未命中时 @7c5d30 请求指定 cursor_id | control_cursor.c 已有按回调缓存结果查询；runtime 只注册 activityState，未接光标呈现，属于功能未接线，不是视频结束缺包 |
| GetTouchConfigData（111） | SetTouchConfig @7c66e8 → SendGetTouchConfigData @7ab698 | 手机虚拟触控配置功能未接；普通物理 HID 不需要强行请求 |
| GetTouchIconData（115） | player GetTouchIconData @7baf64 → client @7ab748，为触控图标取资源 | 本地未实现虚拟触控布局，不补发；不是游戏封面 |
| Discovery/Status | RequestStatus @79a278，manager Update @798ab0 周期调用 | 首页已广播和单播已保存主机；开流停止查询。为直启结束补充主机状态是本产品策略，不是假设官方靠它自动退出 |
| ClientHandshake / NegotiationSetConfig / NegotiationComplete | StartAuthentication、OnNegotiationInit @7ad698、OnNegotiationSetConfig @7adb28 分阶段处理 | 现有认证/协商模块已发送；未发现整个必要阶段漏发。能力字段应只宣告实际支持项 |
| KeepAlive（9） | HandleStreaming @7a7140、SendKeepAlive @7a8744，独立于新视频帧 | ch_control_keepalive.c 已首次即发并周期发送；黑屏时不应额外启动第二个保活循环 |
| Pause / Resume（122/123） | client @7b02bc/@7b0384；SDL 生命周期事件触发。Resume 还通知 transport，并分别发送音视频 DataLost | 应用尚未实现保留会话的暂停/恢复协议；只在实现此能力时成对接入，不能把启动取消改成 Pause。缺口需与 Switch 生命周期单独验收 |
| VideoDecoderInfo / DataLost | @7aacf0 / @7abd4c；解码器描述、媒体恢复反馈 | video/ch_data_video.c 和 ch_data.c 已有发送，不是整体漏发；不能用反馈请求替代游戏结束判定 |

### 22.4 RemoteHID 的逐请求分发

主机发送 CHIDMessageToRemote，客户端返回 CHIDMessageFromRemote 或输入报告。
官方 RunHIDDeviceMessageThread @7c6a0c 解析后 @7c6b50 调 HandleRemoteHIDMessage
@7c6be8；后者 @7c6c60–6c 将请求编号写入回复。不能要求 Switch 反向发送
DeviceOpen 等主机指令，也不能认为所有指令都要同一种 ACK。

| 主机命令 | fork control_hid.c |
| --- | --- |
| DeviceOpen | 有 HandleDeviceOpen 和对应结果回复 |
| DeviceClose | 有 HandleDeviceClose，关闭设备 |
| DeviceWrite | 有处理及结果回复 |
| DeviceRead | 有处理及数据/结果回复 |
| DeviceSendFeatureReport | 有处理及结果回复 |
| DeviceGetFeatureReport | 有处理及数据/结果回复 |
| DeviceGetVendorString | 已有处理及字符串/失败回复（撤回初次审计的漏看结论） |
| DeviceGetProductString | 已有处理及字符串/失败回复（撤回初次审计的漏看结论） |
| DeviceGetSerialNumberString | 有处理及字符串回复 |
| DeviceStartInputReports | 有处理，开启报告 |
| DeviceRequestFullReport | 有处理，发送完整报告 |
| DeviceDisconnect | 有设备断开处理 |

官方 @7c6d10–1c 分别把命令 8/9 分派到 @7c6f34/@7c71c8，
对应 proto 的 VendorString/ProductString。实施时完整重读 control_hid.c，
发现原来已有这两个分派及处理函数，初次审计受截断输出影响漏看；明确撤回
“这两种查询被静默忽略”的结论，不重复添加已有实现。
其余“有处理”表示路径存在，
不代表所有设备返回值/编码/线程时序已完成逐字节一致性验证。

### 22.5 跨请求的接收校验

StreamingResponseVisit 在 request_id 校验前修改 lastMsgTime/lastMsgType；
StreamingProgress 本身也没有独立匹配后再更新的分支。旧消息或不相干消息
可能延长新请求等待，这是源码可见的时序缺口。StreamingCallback 和
AuthorizationCallback 都忽略来源地址；后者没有开流那样的 request_id 可
用于替代来源校验。必须先检查目标主机、当前事务与消息字段 presence，再
更新计时/状态或回调。认证成功仅凭回调上下文指向当前目标，并不足以证明
该响应来自当前目标。此结论不要求改变现有配对 PIN / connect PIN 语义。

### 22.6 接线修订与兼容边界

- 通用断开只使用传输 Disconnect；worker 等有界断开重试结束再 join，
  不在发送之前立即 interrupt。无差别 StopRequest 及其 ACK 等待状态已移除。
- 启动事务取消立即撤销其 timer owner，保留 8 条、60 秒有效的取消编号；
  已取消 InProgress 按原编号重发取消，至少间隔 250ms。已消费为会话的
  成功请求单独标记 Established，之后不再把会话断开当作启动取消。
- runtime 保留 client 接收 socket，取消的 timer/回调先被同步隔离，再修改
  active generation。STOPPING 仍等待 worker 完成；不等待不存在的取消 ACK。
- 接收前校验来源 IP/端口、目标 client_id、可用的 instance_id 及请求编号；
  仅有效 Proof/Response/Progress 更新等待计时。Proof 的可选编号按 presence
  处理。终态响应只消费一次。
- 当前 KeyEscrow 客户端使用安装级共享 secret，未实现官方按主机保存的轮换
  密钥链。ProofResponse 明确携带 updated_secret=false，使用原 secret 回答
  challenge，不伪称已更新、不覆盖其他主机配对。主机要求轮换时是否接受
  此兼容响应仍需对应主机证据；不能宣称实现了完整自动密钥轮换。
- 主机状态 presence/timestamp 透传；直启观察必须先有目标活动后的画面，
  并观察到主机运行游戏，再在 Desktop 接收两份递增时间戳的明确 false。
  旧时间戳不计入、缺字段清确认、活动切换清确认，新连接重置全部观察。
  Steam 入口不自动结束；Desktop/SecureDesktop 不触发游戏无帧 watchdog。

风险边界：主机级 games_running 不能识别同时运行的其他游戏；没有明确字段/
运行基线时保守保持连接。该策略不是已逆向出的官方游戏自动结束算法。
