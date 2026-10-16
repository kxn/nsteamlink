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

### 1.1 官方客户端→host 发送入口清单（静态范围）

方法：枚举 `CStreamClient::SendControlMessage(EStreamControlMessage, MessageLite const&)`（0x7a7d90）
的直接调用点，逐点提取 w1 类型常量与所属函数。
【更正，见 §28】该 ELF 有 35 个 `bl` 和 1 个尾调用 `b` 到 `c0e110`；
绕开此函数的路径至少还有 AuthenticationRequest 和 ClientHandshake 两处。
撤回旧文“发送全集／只有一个绕开点”的完整性声明；静态直接调用清单不覆盖任意间接调用。

| 类型 | 消息 | 发送函数（0x7axxxx） | 备注 |
|---|---|---|---|
| 1 | AuthenticationRequest | StartAuthentication (0x7a7b7c) | **不走 SendControlMessage**；在 0x7a7ce4–0x7a7d0c 构造 control/type=1、Put(false)、Send(true) |
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

**在上述静态发送入口未见构造点**：50/51/52/53（Start/StopAudio/VideoData）、
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
（9 在 channel 的 HandlePacket 被忽略，但更早的 connection 层会处理断连，见 §27.2；10 为不可靠窗口 NACK）。

### 9.1 发送侧：重传永不放弃

- `Send`（0x7f89dc）：全局字节预算检查（超限返回 2）→ 填包头
  （data[0]=5 类型、data[1]=重试计数清零、data[2..3]=conn+12、data[4]=通道号）
  → `AddToOutgoingPacketWindow(+0x70)`（分配包号入窗）→ 立即 `SendReliablePackets(now)`。
- `SendReliablePackets`（0x7f8ac4）：按预算批量遍历发送窗口。
  【更正，见 §29.5】撤回旧文 `包龄 ≥ 超时` 的等号：已有发送计数和非零发送时间时，
  触发条件是包龄**严格大于** `c + floor(c/4)`，其中
  `c = clamp(conn+744, 65, 3276)`；计数为 0 或发送时间为 0 另走立即尝试分支。
  **重试计数 data[1] 只计数不作放弃决策，
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
| 6 | FEC | 独立类型 11、系统式 RS 编解码及组恢复，详见 §26 | 字段 25 默认 false，类型 11 在解析器被拒绝 | 明确的抗丢包能力差异；与具体故障的因果关系未证明 | — |

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
  ——配置字段 25 默认 false，但不能以此否认抗丢包能力差异，也不能替代实际 host 配置/抓包证据；更正及完整 FEC 路径见 §26。
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
| AuthorizationRequest（发现 3） | SendAuthorizeDeviceRequest @79a490、BCreateAuthorizationRequest @79c594；配对授权阶段 | client/authorization.c 定时发送 KeyEscrow ticket，并带 auth_key（X25519 公钥 XOR SHA256(配对码)）与 request_id；response 的密钥交换、device_token 校验和 AuthorizationConfirmed 已按官方实现（Linux x86_64 1.3.32 @0x18b110，详见 STEAM_REMOTE_PLAY_AUTH）；不因开流就重复配对 |
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
- 配对密钥交换得到的 secret 按主机保存在 profile 的主机记录，开流前选用；
  旧版 KeyEscrow 配对的主机继续使用安装级 secret。ProofResponse 明确携带
  updated_secret=false，使用该主机当前 secret 回答 challenge，不伪称已更新、
  不覆盖其他主机配对。主机要求轮换（update_secret）时是否接受此兼容响应
  仍需对应主机证据；不能宣称实现了完整自动密钥轮换。
- 主机状态 presence/timestamp 透传；直启观察必须先有目标活动后的画面，
  并观察到主机运行游戏，再在 Desktop 接收两份递增时间戳的明确 false。
  旧时间戳不计入、缺字段清确认、活动切换清确认，新连接重置全部观察。
  Steam 入口不自动结束；Desktop/SecureDesktop 不触发游戏无帧 watchdog。

风险边界：主机级 games_running 不能识别同时运行的其他游戏；没有明确字段/
运行基线时保守保持连接。该策略不是已逆向出的官方游戏自动结束算法。

### 22.6 显式结束游戏的本地接线

Evidence：§22.2 的 `menu_stop_game` 调用控制 129，且发送函数具有 streaming
状态门槛。`IHS_SessionStopGame` 只在 Connected 时将该空 protobuf 消息放入可靠
控制队列；返回成功只代表入队。普通 `IHS_SessionDisconnect` 不发送 129。

本地产品策略：串流菜单确认“结束游戏”后保持会话接收与重传，等待明确主机结束，
或来自同一 IP/client/instance 的两条递增主机时间戳、明确 gamesRunning=false
的发现状态，再断开并返回首页。请求前已知时间戳作为下界；未知时第一条只建下界。
这不是对官方菜单完整退出时序的复刻。60 秒只作为本地等待上限，不作为游戏结束的证据；
该等待期间不触发普通画面超时。没有强杀进程，也不复用启动取消或 QuitRequest。


### 22.7 结束确认延迟与错误页隔离（2026-09-10，#27）

Evidence：用户在 #27 新评论观察到游戏先退出，Steam 大屏模式稍后关闭，客户端确认接近后者；
原 15 秒超时经常略早于大屏退出。该观察不能单独确定对应哪条通知报文。
复核官方 Android 1.3.32 `/tmp/slink/main.disasm`：SendStopRequest @7abb4c 的
@7abb68–90 只在 state=6 发空 CStopRequest(129)，不返回游戏进程状态；
OnSetActivity @7aef08 的 @7aef54–80 委托 activity/id/name；OnStreamDisconnected
@7b00d0 的 @7b014c–54 切换会话停止态。§21 的 StopVideoData 仅停止视频。
本地 `remoteplay.proto` 的 CStopRequest 为空，未定义与它配套的 StopResponse。

Conclusion：在已核对的消息和官方调用路径中，没有证明可用 Desktop、视频停止或可靠包 ACK
提前确认游戏进程退出。保留明确会话结束/两条新鲜无游戏状态的确认依据，不盲加消息。
“主机要等大屏关闭才发确认”的具体时序仍待真实报文证实，不作为新的协议保证。

本地策略撤回 15 秒失败上限，改为 60 秒，允许 B 停止等待并断开；不是撤销已发送的结束请求。
确认与超时同轮发生时确认优先，清理时保留 watch 至 worker join 完成，销毁 session 前读取
host-stop，避免丢失清理期间到达的完成事实。这个检查只覆盖客户端实际收到的证据。
结束失败保留操作类型；会话已销毁时不显示连接“重试”，也不能由迟到/直接重试动作启动游戏。
返回首页后用户仍可主动重新启动。成功结束和取消都使该操作的迟到 UI 事件失效。

## 23. 画质偏好与带宽配置（Android 1.3.32）

### 23.1 官方预设的证据

材料：同 §1 的官方 Android 1.3.32 ARM64 split 中
`libshell_arm64-v8a.so`，SHA-256
`15b2d79881eef0c47ed2f96c17d1d60a5f42d3285abcf9f512cfffdac5b238a2`。
用 `aarch64-linux-gnu-objdump -d -C` 按下列符号/地址复核。

【证据】`CreateStreamingConfigFastPreset` (`0xc85b74`) 清空配置后设置
`quality=1`、HEVC 和 unreliable FEC，再调用保留部分用户设置的辅助函数
(`0xc85868`)。该函数没有写入固定码率或固定帧率。
`CreateStreamingConfigPreset` (`0xc8562c`) 的 preset=1 分支清空配置后调用
同一辅助函数；preset=2/3 分支设置 `quality=3`、HEVC、unreliable FEC、
`desired_bitrate_kbps=0`，并分别写入 1920×1080 / 3840×2160 的视频限制。
尺寸常量位于 `.rodata` 的 `0x4cdd70` / `0x4cdc20`。

字段定位交叉核对：配置对象 `+148` 是 quality；`OnBitrateChanged`
(`0xc909d8`) 写配置 `+152`；`OnHEVCChanged` (`0xc90ffc`) 写 `+105`；
`OnUnreliableFECChanged` (`0xc911a8`) 写 `+113`。
`CPanelStreaming::OnPresetClicked` (`0xc9182c`) 直接调用上述 preset 工厂并保存设置。
这里的 **EStreamingConfigPreset 与协议 EStreamQualityPreference 是不同枚举**，
不能把 preset=1/2/3 当作 Fast/Balanced/Beautiful 的映射。
辅助函数保留硬件解码、音频、输入等部分设置；因此上述写入也不是所有设备最终配置的完整清单。

【结论】没有证据支持本项目旧有的“流畅=4M、均衡=6M、清晰=10M”是官方 profile。
协议本身明确分离画质偏好（字段 1）与带宽请求（字段 6），也分离分辨率、帧率、
编解码器能力。官方工厂包含超出当前 Switch 接线范围的设置，不整套移植。
此前“尚未定位官方 preset 生成代码”的判断由这里的 shell 库证据补充；
仅检查流媒体核心 `libmain.so` 不足以判断 UI preset 行为。

【待验证】Host 对各画质偏好的具体编码器参数选择及实际画质/延迟收益；
不得根据枚举名宣称 Fast 会发送更高帧率，或 Beautiful 必然增加输入延迟。

### 23.2 本项目配置契约

- UI 均衡/流畅/清晰显式映射到协议 Balanced=2 / Fast=1 / Beautiful=3。
  IHSlib 提供独立公开枚举；零值及非法输入回落 Balanced，不暴露 protobuf 类型。
- 带宽限制独立选择 4 / 6 / 10 / 20 Mbps，新安装默认 6 Mbps。
  这些是本项目的手动带宽选项，**不是冒称官方的码率预设**。
- 所有画质共用现有 H.264、1280×720、60 fps 请求；不随画质开启 HEVC、
  unreliable FEC 或修改渲染/解码时序。本变更不实现自动带宽或运行时 message 99。
- 开始连接时将画质、码率复制进命令快照；会话使用这份快照。
  串流时保存设置只影响下次连接，不并发修改当前协商配置。
- profile v3 存储独立码率。读取 v2 时保留设备身份、密钥、配对主机和偏好，
  将旧偏好对应的 6/4/10 Mbps 迁移为独立码率；后续保存采用 v3。
  文件头、长度、版本、校验和或范围不合法仍报损坏，不重建身份。
  迁移保留旧码率，但旧 Fast/Beautiful 从此真正发送相应偏好，行为并非完全不变。
- 协议测试解密实际 NegotiationSetConfig 并反序列化，交叉检查各画质与独立
  码率、分辨率、帧率、编解码器；存储测试覆盖三种旧偏好和配对身份迁移。

## 24. 视频丢失、关键帧同步与不可靠通道反馈（2026-10-16 独立复核）

### 24.1 证据身份与方法

从仓库根目录 `Steam Link_1.3.32_apkcombo.com.xapk` 重新解包
`config.arm64_v8a.apk!lib/arm64-v8a/libmain.so`，SHA-256 仍为
`50e1d3147d5d47b71ef1970e1867a2fe4f3e1ecf2ea6153f927fac88b88ea38e`。
本节地址属于这个 Android ARM64 ELF；IHSlib 注释引用的 `streaming_client`
`0x205xxx` 地址来自另一参考程序，不能混用或据此宣称两版所有分支完全相同。

用 `aarch64-linux-gnu-objdump -dC`、`nm -DC`、`readelf -Wr` 复核函数、分支和
虚表重定位；直接读取 ELF 内嵌 FileDescriptorProto，未以旧文档的“已验证”标签
代替原始证据。原始输出保存在忽略的 `build/video-recovery-re/`；这是静态分析，
不包含新的 Switch 测试或 Windows Steam host 响应测量。本项目对照基线为
`v0.3.0`（主仓 `1a06981`，IHSlib `04688d1`）。

### 24.2 重请求约 100ms；关键帧到达时立即解除等待

【证据】`CStreamDecoderVideo::DecodeFrame @0x7b2000`：

- `0x7b2074` 检查视频标志 bit 4；关键帧路径 `0x7b20b4–0x7b20d8`
  调用清理 pending 的虚函数，清零对象 `+404/+405` 的两个字节，并以新片段序列号
  重设 `+416`。虚表 `0xc44340` 指向 `FlushPendingData @0x7b2a68`；
  Standalone 虚表 `0xc44118` 指向 `0x7b124c`，它先调用相同的基础清理，再清理后端。
- `0x7b20f8–0x7b2150` 在收到后续视频数据时检查等待时间，超过阈值则发送
  空 packet 列表的 `SendDataLost(video)`，更新最后请求时间。
- `0x7b2488–0x7b2494` 初始化阈值为 `0x1999 = 6553`。
  `GetStreamTimestamp @0x802a88` 的 `0x802ab4–0x802ac4` 采用 16.16 秒；
  因此阈值为 `6553 * 1000 / 65536 = 99.9908ms`，不是 200ms 或 1–2 秒。

【结论】这版官方客户端在持续收包时约每 100ms 重请求；该检查由收包驱动。
对照基线 v0.3.0 的 `ch_data_video.c:313–334` 使用 200ms。二者在关键帧标记到达时都立即
解除等待，没有在此处额外等待一个重试周期；但标记属于视频片段，完整组装、
后端解码和显示仍是必要条件，不能把“看到关键帧标记”视为已恢复显示。
该函数没有重试次数上限，不能由此推断整个官方会话不存在其他超时。

### 24.3 序列缺口与组装积压不是同一种等待

【证据】官方对象 `+404` 与 `+405` 是两个独立状态位；下列名称只是依据分支行为
重建的含义，不声称恢复了原始 C++ 成员名：

| 路径 | 官方 ARM64 行为 | 本项目 v0.3.0 行为 |
|---|---|---|
| 视频序列缺口 | `0x7b22e4–0x7b2348` 设置 `+404`；`0x7b216c` 在该位非零时丢弃后续普通片段，等关键帧 | 设置 `waitingKeyFrame`，丢弃后续非关键帧片段 |
| pending 片段时间跨度过大 | `CheckOverflow @0x7b2854`，常数 `0x2666 = 9830` tick（约 150ms）；`0x7b2974` 只设置 `+405`，并请求同步 | 同为约 150ms，但直接设置相同的 `waitingKeyFrame` |
| 仅 `+405` 非零且序列连续 | `0x7b2154–0x7b2170` 只用 `+404` 阻止提交，因此仍能进入 pending；同时继续约 100ms 的同步请求 | 一律在 `waitingKeyFrame > 0` 时跳过片段 |
| 关键帧 | 清理旧 pending，清零两个状态位，按新序列继续 | 清理旧 pending，清零等待，按新序列继续 |

【结论】“官方所有恢复路径都立即停止接收普通视频，等关键帧”不成立。
对照基线 v0.3.0 把序列缺口和组装积压合并为严格等待，相比这版官方更保守。
官方仍接纳片段不证明所有片段都能显示；`OnThink @0x7b24dc` 的
`0x7b2540–0x7b2570` 检查 slice 范围连续，`0x7b2588/0x7b2644` 检查
FrameFinish，完整帧才进入 `0x7b2738–0x7b2750` 的后端解码调用。

【假设／待验证】本项目在纯积压且参考链仍有效时，可能不必要地停止视频并等待
关键帧，从而放大一次短抖动。没有故障窗口日志或对照实验，不能将其定为用户
报告的一两秒停顿的根因；也不能把缺参考帧后的普通帧一律当作可安全显示。

### 24.4 关键帧恢复反馈与传输窗口反馈必须分开

【证据】官方 `SendDataLost @0x7abd4c` 在 `0x7abe0c` 构造数据类型 2，
`0x7abe2c` 以 `Send(connection, false)` 发送；`CStreamFrame::Send` 的
`0x7f3118/0x7f3140–0x7f314c` 将 false 路由到 `SendUnreliable`。
前述关键帧路径传空 packet 列表，报文中没有 GOP 或关键帧周期参数。

【证据】不可靠传输另外具有接收窗口反馈：

- `CStreamChannel::HandlePacket @0x7f9250` 在 `0x7f9330–0x7f9364`
  将类型 3/4 的视频等数据放入不可靠接收窗口，同时标记需要更新状态。
- `UpdateUnreliableState @0x7fa3b0` 负责窗口交付、缺口处理及反馈；
  `0x7fa79c/0x7fa7cc` 构造包类型 10，`0x7fa7e4/0x7fa82c` 写时间回显和
  交付水位，`0x7fa89c` 将窗口位图范围限制为 320 包，`0x7fa920` 发送。
  这不是逐视频帧的“成功渲染 ACK”，也不是可靠控制通道的类型 7 ACK。
- `HandlePacket @0x7f9310/0x7f93bc` 将类型 10 送入不可靠状态的
  `HandleNackPacket @0x7f95dc`。该通用处理器在 `0x7f985c` 释放已确认包，
  `0x7f9880–0x7f98d0` 对位图缺失且满足包龄条件的包清零发送时间；
  `SendUnreliablePackets @0x7f9054–0x7f9084` 会重发这些零发送时间的包。

【证据】对照基线 v0.3.0 的 IHSlib 中，`IHS_SessionPacketTypeUnreliableNack = 10` 只出现于
`src/session/packet.h` 枚举；`ch_data.c` 的下行窗口实现没有构造这种反馈。
`ch_control.c` 的 ACK/NACK 属于另一可靠窗口；视频 `ReportVideoStats` 的每秒
帧结果报告也是另一条路径，不能当作类型 10 的替代实现。

【结论】目前存在“官方有不可靠窗口反馈，而本项目未接线”的确定性实现差异。
不能简单描述成“渲染慢了，所以没有及时 ACK”；官方窗口反馈本身并不以实际
显示成功为前提。此 Android 客户端的通用发送端证明了这种反馈可驱动补包；
本次没有反汇编 Windows host，也未实测 host 对本项目发送类型 10 的响应。

【假设／待验证】缺少类型 10 可能使可修补的视频片段缺口更容易升级为视频序列
缺口和关键帧等待。这比仅调整关键帧重试间隔更值得核对，但不是当前卡顿根因证明。

### 24.5 内嵌协议没有显式关键帧间隔字段

【证据】同一 ELF 文件偏移 `0x3e5474` 的 FileDescriptorProto 长 `21560` 字节，
SHA-256 为 `a8a97cc76440224048e02d7605f6427b5cc48868f3be0789f4f99bd37aceb626`。
从 wire 数据解析出 106 个顶层消息。`CStreamingClientConfig` 的字段到 35，
包含 quality、码率、帧率、编解码器与 `enable_unreliable_fec`；
`CStreamingServerConfig` 的字段到 13；`CStreamDataLostMsg` 只有 `packets=1`。
没有显式 GOP 长度、关键帧间隔或 I/P 帧比例字段，与本项目 proto 对照一致。

【结论】在这版官方协议与上述客户端调用链中，没有发现可以协商“每 N 帧一个
关键帧”的接口。不能外推为 Windows host 没有内部 GOP 策略，也没有证据支持
“默认每一两秒必有关键帧”。更密的关键帧与传输补包是不同的恢复手段。

### 24.6 解码错误的本地接线边界

【证据】官方 `FinalDecode @0x7b1088` 失败时记录帧结果，后端存在的分支
`0x7b1154–0x7b1168` 请求 DataLost；后端不可用分支 `0x7b1188–0x7b118c`
请求 ResetVideoDecoder。Android 后端 `0x906a7c/0x906a9c` 也有重置请求。
`HandlePendingResets @0x7a61e4–0x7a620c` 在实际 reset 后再请求 DataLost。
因此“所有解码失败都无条件连续发两次请求并重置”不是该 ARM64 版本的统一规则。

【证据】v0.3.0 `sl_media_video_submit_tracked` 将 `sl_video_submit=false`
统一映射为 `IHS_StreamVideoSubmitError`；IHSlib `SubmitFrame` 对 Error 断开
session，只有 ReportLost 才进入恢复分支。应用没有从该入口返回 ReportLost。

【结论】D-057 所述恢复存在于库内，不等于正式应用的所有解码失败都走该恢复。
这项差异可影响断流行为，但单独不能解释保持会话的一两秒停顿。

## 25. 视频恢复策略的调用链、边界与原始指令验证（2026-10-16）

### 25.1 对策略建议的证据更正

本节继续使用 §24.1 的同一 ARM64 ELF。撤回把“先补包、积压继续、缺口等待、
解码失败分类、保持上一帧”整张建议表统称为已经完整还原的官方策略：
官方存在相应分支，但等待预算、反馈时序、不同后端的错误分类和物理显示结果
必须分别取证。尤其不能把“资源／设备错误才断开”当作已证明的通用分类规则，
也不能把组装层约 150ms 阈值直接当成传输窗口的丢包等待期限。

以下结论来自实际函数、调用者、常量初始化与虚表；§25.7 的模拟执行只验证
被选中的原始指令分支，不替代真实 Steam 会话或 Switch 解码／显示测试。

### 25.2 接收窗口：先等缺包，但预算由通道与 RTT 共同决定

【证据】`OnStartVideoData @0x7ae074` 在 `0x7ae11c–0x7ae128` 给主机指定的
视频 channel 调用 `SetChannelMaxRecvDelay(channel, 6553)`；音频启动
`0x7ade40–0x7ade4c` 也设置同一值。`SetChannelMaxRecvDelay @0x7fbc98`
在 `0x7fbcac` 写入 channel `+28`。这覆盖构造时的默认 65 tick，不能仅凭
`CStreamChannel` 构造函数把活动视频通道等待解释为约 1ms。

【证据】`CStreamPacketWindow::BInsertPacket @0x7f7230` 的
`0x7f73cc–0x7f73e4` 存储包头 sendTimestamp；`0x7f7404–0x7f7434`
向窗口前面的槽位回填时间。因此窗口包龄不是“从本机这次循环开始”的墙钟时间。
`PopHeadOfPacketWindow_WithRef @0x7f743c` 的 `0x7f7474–0x7f7494`
在头包缺失或头部为孤立续片时不交付；`0x7f74bc–0x7f74f8`
还要确认头包声明的后续传输分片全部存在，才合并交付。

【证据】`UpdateUnreliableState @0x7fa3b0` 先在 `0x7fa470–0x7fa4b0`
尝试交付可用的完整传输数据，再于 `0x7fa590–0x7fa680` 扫描过期缺口。
在正常正值 RTT 下，截止点可按下式重建（实际代码保留 32-bit 回绕和有符号比较）：

```text
T(ms) = floor(ms / 1000) * 65536 + floor((ms % 1000) * 65536 / 1000)
cutoff = newest_slot_sender_timestamp
         - channel_max_recv_delay_ticks
         - T(trunc((average_rtt_ms + 2) * 0.5))
```

RTT 字段位于 connection `+732`；`ProcessTimestamp @0x7f9a2c` 把 RTT 样本加入
connection `+640` 的统计对象，`PingStats::OnSampleAdded @0x7fc7b4`
的 `0x7fc7cc–0x7fc7e8` 将 16.16 平均值转为毫秒浮点、写对象 `+92`，
即 connection `+732`。这证明上式 RTT 的单位，不依赖成员名猜测。

【结论】活动视频通道的基础等待约 100ms，另加约半个 RTT（含源码中的 2ms
修正与截断）；以窗口内发送时间跨度决定何时放弃，不能说“固定等 100ms／200ms”。
例如 average RTT=10ms 时，边界为 `6553 + 393 = 6946` tick（约 105.99ms）；
模拟执行中恰好等于边界仍保留缺口，超过一 tick 后前进窗口。相同 8000 tick
跨度在 RTT=10ms 时被放弃，在 RTT=60ms 时仍保留。

### 25.3 类型 10 的反馈、补发与退休时序

【证据】`UpdateUnreliableState` 的 `0x7fa700–0x7fa778` 同时检查反馈截止时间
和乱序宽限；第一个可用后继包的 wire 计数字节恰为 1 时，要自其接收时间等待
65 tick（约 0.992ms）；不足时重新置 dirty，后续 update 继续检查。其他计数值
不走该项宽限。计数不能泛称为“首次发送”，详见 §25.12 的更正。`0x7fa970–0x7fa9b8` 在发送后以 RTT 派生值设置下一次反馈期限。
这里使用 connection `+744` 的平滑 tick 值，经约 1–50ms clamp 后取四分之一、
再至少取 65 tick；它与关键帧请求约 100ms 的定时不是一回事。

【证据】类型 10 的包布局由 `0x7fa79c–0x7fa920` 构造：

| 字节位置（含 13B 包头） | 实际用途 |
|---|---|
| `0` | 类型 10，即不可靠通道 NACK |
| `7..8` | 位图起点：首个可用后继包的 packet ID |
| `13..16` | 对端发送时间的回显 |
| `17..18` | 首个未修复缺口之前的连续水位，不能误用位图起点 |
| `19..` | 最多 320 包的占位位图，低位先行 |

模拟输入：head=100，包 100/102 缺失、101/103 存在，官方原始指令输出
位图起点 101、水位 99、位图 `05`。`HandleNackPacket @0x7f95dc`
对这一反馈释放 101/103，把满足包龄条件的 100/102 标为补发。
`0x7f9764–0x7f9780` 组合本机 RTT 截止点与反馈回显；实际取较新的截止点，
不是盲目将所有缺失位立刻重发。`0x7f983c` 的整字节零值跳过、无位图的
fallback 与回绕比较亦是实际实现的一部分，不能只移植“0 丢失／1 收到”的口号。

【证据】补发和新包发送分阶段：

- `Connection::Update @0x7fc108` 的 `0x7fc3a8–0x7fc3b0` 先调
  `SendUnreliablePackets(false)`；它不扫描已发送包的补发标记。
- `0x7fc3d0–0x7fc40c` 再按轮转起点对 channel 调
  `SendUnreliablePackets(true)`；`UpdateLowPriority @0x7faa38` 也传 true。
  真正扫描零发送时间、调用 socket send 的位置是 `0x7f9000–0x7f9084`。
  因此 NACK 处理器只是标记补发，不是同步进行一轮无限重传。
- `SendUnreliablePackets` 入口 `0x7f8cf4–0x7f8d9c` 在发送前退休过期包。
  常数 `0x7f90cc = 13107` tick（约 200ms），再加
  `2 * T(trunc(average_rtt_ms + 2))` 的保留余量。RTT=10ms 时合计 14679 tick
  （约 223.98ms）；原始指令边界验证中，相等仍可补发，再老一个 tick 则退休。

【结论】补包是一条有反馈限频、包龄检查、调度阶段和退休期限的完整路径。
单独新增类型 10 报文或缩短 DataLost 重请求间隔，不等价于实现官方恢复。
这里证明的是官方客户端内的通用协议实现；Windows Steam host 是否按相同条件
补包、实际链路是否来得及补齐，仍需 host 证据，不能从客户端汇编直接推出。

### 25.4 组装积压、序列缺口和主机通知

【证据】§24.3 的两个状态位已经用实际 `DecodeFrame` 指令交叉验证：
`+405=1/+404=0` 且序列连续时到达组装准入点 `0x7b2170`；同样状态下出现
新序列缺口则设置 `+404=1`，从 `0x7b2448` 返回。严格等待时普通数据即使序列
连续仍丢弃。关键帧先清除两个状态，重设序列，再进入相同准入点。
这些结果只证明“进入组装”，不等于通过解码或已经显示。

【证据】`CheckOverflow @0x7b2854` 首先要求两个等待状态均未置位、pending
节点至少两个；在节点记录的帧时间跨度严格超过 9830 tick 时请求 DataLost，
只设置 `+405`，不设置 `+404`，也不在此清空所有 pending。
它不检查“本机距离上次显示已过去 150ms”，也不是自动丢弃所有过时已解码帧。

【证据】`0x7b2988–0x7b29b8` 另计算 pending 两端的 frame ID 跨度；
跨度大于或等于对象 `+412` 的记录值时，还调用 `SendVideoOverflow(first,last)`，
再保存跨度。它可在未达到 150ms 时发生；相等时也可以报告，不能写成“只在新峰值报告”。
`SendVideoOverflow @0x7abc90` 对应控制消息 148。项目 v0.3.0 的业务代码没有
发送这条消息，只有生成的协议类型。主机收到 148 后如何调整编码，本次未取证。

【结论】此前“积压继续处理”必须限定为序列连续、分片完整、解码后端仍能处理；
官方并没有许可显示缺损片段或任意缺参考帧的普通帧。其积压响应也包含主机通知，
不能认为仅拆出两个本地 bool 就已经完整对齐。

### 25.5 解码错误：已查明具体触发，尚无 FFmpeg 错误码映射

【证据】`CAndroidAccel::BDecodeFrame @0x906570` 的
`0x9065f8–0x906614` 在 BSubmitFrame 成功时交出 dummy frame；失败时
`0x906618–0x906630` 返回 false、结果 7（DroppedReset）。这里的“成功”可以
是异步提交成功，不保证硬件图像已出队，因此不能把 FinalDecode 的返回当物理显示时刻。

| 官方触发条件 | 实际处理与地址 |
|---|---|
| 后端存在，BDecodeFrame 返回 false | `FinalDecode 0x7b1134–0x7b1168` 记录失败帧结果并请求 DataLost；这一分支本身不直接 Disconnect，也不无条件 Reset |
| 后端不存在 | `0x7b1188–0x7b118c` 请求异步 ResetVideoDecoder(false) |
| Android 编码参数尺寸／Surface 发生需重置的变化 | `BSubmitFrame 0x906988–0x9069a4` 判断，`0x906a5c–0x906a7c` 更新参数并请求 Reset |
| 无法取得输入 buffer index | `0x9069e0–0x9069e8` 的 MediaCodec dequeue 最多等待 200000 微秒；返回负值走 `0x906a88–0x906a9c` 请求 Reset |
| 输入 index 存在，但 getInputBuffer 返回空 | `0x906a0c/0x906aa8–0x906ac0` 发致命错误通知 |
| queueInputBuffer 返回非零 | `0x906b84–0x906ba0` 记录错误并返回失败，进入上层相应反馈路径 |

【证据】`NotifyFatalDecoderError @0x7c9cec` 构造 SDL 用户事件类型 `0x8000`、
code=3（`0x7c9d00–0x7c9d1c`）；`CStreamPlayer::BHandleEvent`
的 `0x7b8308–0x7b8348` 对 code=3 设置 fatal 标记并 Disconnect。
这补齐“致命通知最后是否真的断开”的调用链，不仅以函数名称作判断。

【证据】ResetVideoDecoder(false) 设置 reset 请求；`HandlePendingResets`
的 `0x7a61e4–0x7a620c` 执行实际 Reset 后再发 DataLost。
`IStreamDecoder::Reset @0x7671e4` 会停准入、唤醒并 join 自有解码线程、清队列、
调用 StopDecoding、重新 StartDecoding/线程。`StopDecoding @0x7b1fbc`
设置严格等待状态。该过程不是“只切一个等待标志”，也没有静态证据保证它瞬时完成。

【结论】已证明官方区分局部失败、重置和 fatal，但不能据此为 Switch 的
FFmpeg/NVTEGRA 直接制定“某个 AVERROR 都应该重试／都应该断开”。
对照基线 v0.3.0 的 `sl_video_submit` 的 false 混有身份／所有权失败、分配失败、解码失败，
必须先分清错误来源才能映射。此前建议中的通用错误分类是工程设计要求，
不是已经逆向出的 FFmpeg 对照表。

### 25.6 关键帧恢复与呈现的边界

【证据】关键帧分支立即清等待，但后续仍有组装范围／FrameFinish 检查和后端提交。
`IStreamPlayer::GetNextVideoFrame @0x767fe0` 在 `0x768000–0x76802c`
持续取可用帧，并以结果 6（DroppedLate）结算被更新帧替代的旧候选，最终交出最新候选。
`FlushVideoStream @0x7681ec` 会清理排队及暂存 frame 引用
（`0x768244–0x7682c8`），不能描述为“官方 reset 始终保留最后一个 AVFrame”。

【结论】没有在关键帧准入分支发现额外固定 1–2 秒门槛；但解码器输入等待、重建、
异步输出及呈现调度是独立边界。“下一个完整可用关键帧之后应能恢复”合理，
“关键帧标记到达就立刻显示”或“必然保持同一物理画面”不由这些指令证明。
本项目保留 current_frame 是自己的显示／资源策略；Switch Surface 生命周期和
损坏恢复不能照搬 Android MediaCodec 的所有权操作。

### 25.7 可复核性与仍未证明的事项

`scripts/audit-steam-video-recovery.py` 用 Unicorn 加载哈希固定的原始 ELF，
直接执行官方分支，并拦截外部依赖；没有把重写的 C/Python 恢复算法当作官方代码。
36 个断言场景覆盖准入状态、关键帧清理、100ms 重请求边界、活动视频窗口的
RTT/包龄边界、乱序宽限、反馈水位/位图、补发标记、补发阶段与退休边界、
积压 150ms 边界与消息 148，以及 FinalDecode 的反馈／重置／交付分支。

```sh
python3 scripts/audit-steam-video-recovery.py \
  --binary build/video-recovery-re/libmain-arm64.so \
  --output build/video-recovery-re/emulated-branches.json
```

输入库按 §24.1 从已有 XAPK 解包；脚本需要 Python `unicorn`，不作为产品运行依赖。
日志／socket／分配／锁／部分窗口 helper 和后端行为使用替身；例如窗口 Pop 在反馈
测试里返回“尚不可交付”，Advance 只模拟水位前进，后端 decode 的成功／失败由
场景输入控制。因此这 36 项不是完整传输集成、真实硬件解码或显示验证。

【未证明】Windows host 的实际补包响应与时限；这些差异是否造成用户的一两秒卡顿；
Switch 上 FFmpeg 错误分类、reset 的正确资源顺序及实际耗时；恢复期间物理显示结果。
软件输入、退出、音频不被诊断阻塞仍是本项目既有运行时约束，不能冒称为这次已测得的
官方时延保证。静态和指令仿真证据不构成上述未证明事项的验收。

### 25.10 安卓是否自行判断参考帧依赖

【证据】同一 SHA-256 固定 ELF 的 `CAndroidVideoDecoder::BSubmitFrame @0x906660`：
`0x90673c` 枚举 NAL，H.264 分支 `0x9067a8–0x9067b8` 只有 type 7（SPS）
进入 `h264_new/read_nal_unit/CalculateVideoSize`；`0x9068d0–0x906934` 释放临时
解析器，收集 type 7/8（SPS/PPS）作为参数。普通 slice 不进入此解析路径。
尺寸或 Surface 变化在 `0x906988–0x906aa4` 触发 ResetVideoDecoder；
`0x906b80` 的 queueInputBuffer 最后一个 flags 参数为 0。
这说明此处并未从每个 slice 重建跨帧参考关系；不能把“官方会解析 H.264”
等同于“官方在网络接收层判断缺失的是参考帧还是可丢弃帧”。

【证据】输出两条显示分支是同一个 MediaCodec 的 VideoSurface / Texture 展示方式，
不是两个解码后端。`BRenderFrameVideoSurface @0x908494` 用零 timeout dequeue，
按输出 presentationTimeUs 查输入 frameId、选择/丢弃过时输出；Texture 分支
`0x908e04` 首次等待 200000us 后继续零 timeout dequeue、丢弃时间戳不匹配的输出。
`BHandleOutputBuffer @0x9080c4` 处理 buffer index、format/buffer-change 与 release
返回值。上述函数中未发现按参考帧损坏标记决定恢复的分支。此结论仅覆盖列出的包装层，
不覆盖闭源设备 MediaCodec 内部的 DPB / 错误隐藏。

【结论】本客户端不另造 H.264 参考链分析器。先对齐已证实的传输/组装状态；
FFmpeg 返回 AVERROR_INVALIDDATA 或输出显式 AV_FRAME_FLAG_CORRUPT / decode_error_flags
时才作为可恢复码流损坏反馈，上层不将该结果等同于“后端已重建”。
身份校验、资源分配与输出所有权失败仍为致命错误。关键帧入口清理 FFmpeg 内部缓存，
保留显示/GPU持有的外部 AVFrame 引用：本机与 Switch 的 avcodec.h 对
avcodec_flush_buffers 明确约定调用方引用仍有效。硬件实际恢复能力仍需真机验证。

本实现的额外资源边界（项目策略，不声称是官方常数）：软同步时 pending 最多
256 个片段，含已组装部分的编码数据最多 2MiB；超限清理 pending 并转为严格等待，
以防主机不响应时无限积累。完整帧的 transport continuation 必须类型/序号一致，
不能把另一帧的 head 拼成缺失的 fragment。媒体反馈使用单独的可 join worker，
只持有短时 windowLock，不等待解码、不使用全局 timer 锁，不输出逐包日志。
退出先置 interrupted 并唤醒两个 worker，join 后才销毁 window/cond/mutex。

传输续片 ordinal 的来源：同一 ELF `AddToOutgoingPacketWindow @0x7f6f94` 在
`0x7f7018` 给 head 写入续片数；`0x7f7024` 从 ordinal 0 开始，
`0x7f7034` 每次加 1，`0x7f7090–0x7f70bc` 将续片类型置为 4/6，
`0x7f70f8` 写入 ordinal，`0x7f7160` 使用窗口下一个 packetId。
这为接收端拒绝错类型/错 ordinal 的跨帧拼接提供发送端证据；不声称官方
PopHeadOfPacketWindow 本身做了同样的额外检查。

初始丢包：`CStreamChannel` 的 `0x7f86f8–0x7f870c` 将 unreliable 的收发窗口
ClearAndRestartWindow(0)，与 reliable 的 `0x7f8720–0x7f8734` 相同。因此新建媒体
通道也从 packetId 0 建立接收水位，首个包丢失时不能把第一个续片当作新的起点。
项目固定容量窗口溢出（含前跳超过容量）后 ReleaseAll 再锚定当前包属于本项目资源
恢复策略；不声称与官方动态窗口的容量管理完全一致。

### 25.11 VideoOverflow 比较单位与实现更正

【证据】`CheckOverflow 0x7b2988–0x7b29b8` 读取两个 uint16 frameId，
以 32 位有符号运算计算 `lastId - firstId + 1`，与对象偏移 `+412` 保存的
上次范围比较；相等也发消息。`0x7b29b8` 无论是否发消息都会保存这次范围。
`FlushPendingData 0x7b2bc8` 将此记录清零。

【更正】撤回把此前 PR 实现描述为已完整对齐消息 148 的说法：`6c5f695`
误把成员偏移 `+412` 写成时间增量常数，以时间跨度作了比较。正确单位是
包含两端的 frame ID 范围，且应在抑制一次报告后也更新记录。§25.4 的逆向
记录支持上述更正；原来的生产实现测试没有覆盖“小时间差、相同/缩小帧范围”边界。

### 25.12 接收反馈与包龄的逐指令更正

【证据与更正】`0x7fa750–0x7fa770` 比较的是 wire 计数字节**恰好等于 1**，
不能解释成通用的“首次发送”语义；`SendUnreliablePackets 0x7f8f08–0x7f8f2c`
在 socket 发送之后才增加计数，零初始化的首个包在这条发送路径上携带 0。
撤回 §25.3 中“首次发送宽限”的解释，保留实际判断 `counter == 1` 和 65 tick。

【证据】`HandleDataPacket 0x7f9434–0x7f9444` 仅在新发送时间更晚时更新回显，
旧包/补包不能令它倒退；`UpdateUnreliableState 0x7fa3d0–0x7fa3e4` 先消费 dirty，
只有期限/65 tick 未到的 `0x7fa774–0x7fa778` 重新置 dirty。一次成功反馈后，
没有新输入不会自动周期性再发同一 NACK。位图长度在 `0x7fa898–0x7fa8d0`
为 `ceil(min(tailExclusive-base,320)/8)`，不是固定 40 字节。

【证据】`BInsertPacket 0x7f73d0–0x7f7430` 的包龄时间是独立槽位元数据：
当前槽仅在未赋值或新时间更晚时更新；向前回填时仅覆盖 0 或比当前时间更晚的
槽位，且**不以该槽是否持有 packet 为界**。真实 header.sendTimestamp 不能
被这个包龄元数据替代。此前实现“直接改写前面的空槽直到遇到已收包”不足以
复现此规则，会在带有不同发送时间的乱序/重传后推迟过期处理。

【证据】`DecodeFrame 0x7b22e4–0x7b2338` 在软同步期间遇到新序列缺口时设置
严格等待，但不额外重复发送初始 DataLost、不重置上次请求时间；顶部按已有
请求时间决定是否重试。该时间依据 32 位 16.16 stream tick 的有符号差与
6553 比较，不是本地整毫秒计时。

### 25.13 补齐后积压的完整帧不能依赖新包触发

【证据】`OnThink 0x7b27dc–0x7b27f4` 在提交一帧后依据 pending count 将
返回值设为 1（仍有 pending）或 -1（空）；`RunDecodeLoop 0x766e30–0x766e48`
把返回值用作等待 timeout。因此还有 pending 时，后续 think 可在约 1ms 后运行，
不依赖再收一个视频包。原始指令用两个完整 pending 节点验证，连续 think 交付
61/62，分别返回 1/-1；该案例的 append/backend/链表释放和诊断函数为替身，
证明的是调度控制流，不是 H.264 或原始链表实现正确性。

【结论】本项目在补齐较老帧后也要继续提交 pending 中已完整的后续帧。项目在
同一个可中断 worker 中排空可组装帧，不另起官方的 1ms think 调度；这是明确的
调度实现差异。单帧失败仍按 ReportLost 继续，致命错误或 interrupted 则停止排空。

### 25.14 证据边界与实现差异矩阵

以下范围限定为本节固定 SHA-256 的 Android ARM64 客户端及本项目媒体恢复路径，
不代表全套 Steam 协议、Windows host 或 MediaCodec/NVTEGRA 内部已经等价还原。

| 核验对象 | 原始证据／本地入口 | 结论与边界 |
|---|---|---|
| 类型 10 的头、水位、回显、位图 | UpdateUnreliableState；DataBuildFeedback / WindowMediaFeedback | 比较完整输出字节；位图可变长度且最多 320 位，水位和 base 独立 |
| wire 计数、dirty、重反馈期限 | §25.12；DataBuildFeedback | counter==1 才额外宽限 65 tick；成功发送后要新输入才重新激活；RTT 期限和回绕有同输入对比 |
| 包龄与完整传输帧 | HandleDataPacket / BInsertPacket / PopHead / Advance / UpdateUnreliableState；window.c | 执行这些原始函数，比较发送时间、帧字节及交付后的窗口头；限本项目容量以内 |
| 视频准入与恢复请求 | DecodeFrame、FinalDecode；DataReceived / SubmitFrame | 同输入比较严格/软同步、6553 tick 边界、关键帧及后端失败反馈；原始视频 slice 组装和实际 codec 不在这组对比内 |
| 积压范围消息 148 | §25.11；CheckPartialOverflow | 帧 ID 的有符号含端点范围；相等可报告，较小范围也保存；不是时间阈值加 412 |
| 接收窗口交付、退休与反馈的调度顺序 | UpdateUnreliableState 0x7fa470–0x7fa6fc；DataThreadWorker / FeedbackThreadWorker | 官方同一次 update 先交付/退休再构造反馈；本项目两个 worker 在 windowLock 下各自取快照，允许不同先后顺序。F/U 分步对比不能证明并发交错的反馈序列完全相同 |
| 已完整 pending 的后续处理 | §25.13；DataReceived 的排空循环 | 官方仍有 pending 时约 1ms think；本项目在同 worker 中排空，不等新包；调度方式不同 |
| 帧损坏的判断 | §25.5/25.10；video_pipeline.c | FFmpeg 明确 INVALIDDATA/损坏标记是项目映射，不是从 MediaCodec 逆向出的错误码对照表 |
| 后端重建 | Android 输入 buffer 超时/参数变化/Surface 变化与 Reset 调用链 | 项目未等价实现这些异步重建分支；FFmpeg flush 不等于销毁/重建 MediaCodec；不能照搬 200ms 输入 timeout |
| 视频标志 bit 6 的内容模式变化 | OnThink 0x7b2648–0x7b26f8 / CheckContentMode 0x7b2804 | 官方存在依据该位及已记录模式请求 Reset 的分支；其完整语义未确认，项目未据此新增重建逻辑，不将它解释为缺参考帧标记 |
| 关键帧清理／显示引用 | FlushPendingData / FlushVideoStream；video_pipeline.c | 官方在关键帧片段入口清后端；项目完整关键帧提交前 flush，并保留外部显示/GPU 引用；时机与所有权不同，硬件行为待真机 |
| 窗口容量与坏分片 | §25.10；window.c | 官方动态窗口；项目视频固定 2048 槽、积压 256 片段/2MiB，溢出重新锚定，并增加 continuation 类型/ordinal 检查；这些是明确的项目策略 |
| 项目身份／所有权及坏数据防护 | frame ticket、帧 ID/ordinal、解密返回值检查 | 属于项目防护策略，不声称原版拥有相同检查及错误分类；未以此推导官方会接受坏密文 |
| 客户端发送方向的不可靠缓存 | §25.3 的 SendUnreliablePackets / HandleNackPacket | 官方有保留及补发；本次只移植主机到客户端的接收反馈，DataLost 仍 queue(false)，没有给客户端所有 outgoing unreliable 包实现同样缓存 |
| FEC | 官方 SendUnreliableFEC / HandleFECPacket；本地 packet enum/接收分派 | 未实现官方 FEC 路径，本次不能宣称覆盖 FEC |

可复核方式：父仓 `scripts/compare-steam-video-recovery.py` 将相同输入交给固定
ELF 原始指令和编译后的 `ihs-media-oracle` / `ihstest_decoder_loss --oracle`。
289 组输入含随机乱序、位图长度、回绕、包龄与视频准入边界。F 步骤在双方冻结
帧交付，只核反馈快照；U 步骤真实执行原始 PopHead/Advance 并比较帧字节与窗口头。
allocation/refcount/锁/memcpy/memset/socket 等外部函数为替身；socket 仅复现已核对的
发送时刻时间戳写入，CRC 连接选项关闭。视频软/严格状态在本地由真实片段建立，
原始准入函数从对应已知状态开始；未将这个边界包装成完整视频组装端到端证明。

导出的 `third_party/ihslib/tests/session/recovery_oracle.json` 只保存原始指令的
输入、输出和 ELF 哈希，不从本地实现生成期望值；普通 CI 用
`check_recovery_oracle.py` 复播，不需要分发 ELF 或安装 Unicorn。实现对比与
原始指令分支测试是两类证据，不能用其中一个替代另一个。实际线程调度及毫秒级
条件等待仍可能使发包时刻晚于逻辑 deadline；不承诺逐微秒相同的物理时序。

RTT 对比向双方注入相同的 mean/smoothed 值，只证明给定 RTT 下的预算计算；
不证明实时 RTT 采样、平滑与时钟拟合全过程等价。线程调度允许反馈先于本地
交付/退休，故即使每个冻结快照的输出一致，也不能据此推导完整网络轨迹一致。

## 26. FEC：协商、线格式、编码与交付（Android 1.3.32 原始指令）

### 26.1 证据身份与启用条件

本节继续使用 §24.1 的 `libmain.so` SHA-256；shell 的 SHA-256 见 §23.1。
区分“协议声明”“实际存在的客户端通用传输实现”“Windows host 的运行策略”：
前两者可由这些材料证明，第三者不能仅由 Android ELF 推出。

【证据】从同一 ELF 的 `0x3e5474` 文件偏移读取 FileDescriptorProto：
`CStreamingClientConfig.enable_unreliable_fec` 是字段 **25**、optional bool，
显式 default 为 **false**。它与 `CNegotiatedConfig.reliable_data` 不是同一个开关。
`OnNegotiationInit 0x7ada6c–0x7ada9c` 把本机 streaming_client_config 复制进消息 4 的响应；
`SetStreamingClientConfig 0x7b0220–0x7b0264` 在相应会话状态且调用参数允许时
还能用消息 **99** 发送 CSetStreamingClientConfig。

【证据】shell `CreateStreamingConfigFastPreset 0xc85bb4–0xc85bd4` 设置
quality、HEVC、配置 `+113` 的 FEC 值和对应 hasbit；`0xc85868–0xc85b70`
保留旧配置的 helper 不覆盖 `+113`。字段定位与 `OnUnreliableFECChanged`
（§23.1）一致。这证明 FEC 有产品配置入口，不只是未使用的枚举；不证明任意
用户的最终配置、任意 host 均已启用，也不证明预设使用固定冗余百分比。

【证据】`CStreamConnection::SendUnreliable 0x7fbbc8–0x7fbc00` 依据
connection `+11` 选择 `SendUnreliableFEC` 或普通 `SendUnreliable`。
`SetChannelFECPercentage 0x7fbcbc–0x7fbcdc` 只把传入整数写 channel `+32`；
它自身不设置 connection 的启用位。百分比、启用位和客户端配置字段是不同层的量。
该 ELF 的 channel 构造 `0x7f865c` 初始百分比为 0；仅调用百分比 setter 不足以启用 FEC。
**尚未证明** Windows host 如何把配置字段映射到实际启用状态、如何选择/调整百分比。

【本地源码】对照 IHSlib `5fe67f4`：`ch_control_negotiation.c` 用
CSTREAMING_CLIENT_CONFIG__INIT 且不写字段 25，因此请求的语义为默认 false；
`packet.h` 的 type Max=11、`packet.c` 拒绝 `type >= Max`，故类型 11 在包头解析
阶段就失败。新增类型 10 NACK 并没有带来 FEC 能力。正常遵守该配置的 host
预期使用非 FEC 路径，但没有该用户的配置/抓包，不能把此预期称为实际 host 证据。

【更正】撤回 §13.2b 以“未协商所以 host 不应发送”就将 FEC 缺口视为不重要的
推论。配置兼容与抗丢包能力是两回事：即使 host 正确回落普通路径，本项目仍缺少
官方可用的一整条纠错机制；是否造成原反馈中的停顿仍是待验证假设。

### 26.2 类型 11 的线格式及分组单位

【证据】`SendUnreliableFEC 0x7f9104–0x7f9144` 写类型 **11**、连接 ID 和
channel；`CFECOutgoingQueue::AddPacket 0x7f798c–0x7f79a0` 增加独立的
uint16 group ID；`0x7f7a64–0x7f7a70` 写分片序号及 8 字节元数据。
以下位置包含通常的 13 字节传输包头，数值为 little endian：

| 偏移 | 大小 | 含义 |
|---|---|---|
| 0 | 1 | 类型 11；bit 7 仍为外层 CRC 标志 |
| 1 | 1 | 此路径初始化为 0；不是数据/冗余分片类型位 |
| 2–4 | 3 | src/dst connection ID 与 channel |
| 5–6 | 2 | shard index，数据在前、冗余在后，从 0 开始 |
| 7–8 | 2 | 本 channel FEC 分组序号，不是视频 frameId |
| 9–12 | 4 | 通常的 stream send timestamp，由 socket send 填写 |
| 13–16 | 4 | 原始传输消息 payload 的字节数 L，不含 13B 头 |
| 17–18 | 2 | 每个 shard 的字节数 S |
| 19–20 | 2 | 冗余 shard 数 m；数据数 k 由 ceil(L/S) 得到 |
| 21… | S | 一个 shard，尾部不足补零 |

【证据】原始 `AddPacket 0x7f793c–0x7f79c0` 在正常非负百分比、有效 MTU 下：

```text
W = 13 + L
S = min((W + 10) & ~15, (MTU - 25) & ~15) & 0xfff0
k = ceil(L / S)
m = ceil(k * FEC_percentage / 100)
若 k + m > 255：m = 0，仍发送数据分片
```

`0x7f7a1c–0x7f7b90` 为 k+m 个 shard 建包；前 k 个复制原 payload 并补零，
余下由编码器填写。保护单位是**一次交给 SendUnreliable 的传输消息 payload**，
不是任意相邻 UDP 包混成一组，也不能直接等同于一整个最终显示帧。
`CStreamFrame::Send 0x7f3118–0x7f314c` 连接到此通用发送入口；视频自身另有
slice/FrameFinish 组装层。FEC 不是从 H.264 参考帧推算丢失的图像。

MTU 来自 `CStreamPacket::s_nMTU @0xf34d48`，本 ELF 数据初始化值为 **1024**；
§28.2 补齐 ServerHandshake 运行时赋值，范围限制为 512～1472。
FEC 测试中 1500/64 是显式注入值，不能冒称官方默认值。
`Socket::Send 0x7ff280–0x7ff2bc` 在 connection `+10` 要求时另加 CRC 标志及
4B CRC32C；CRC 是外层完整性检查，不是冗余编码的一部分。

### 26.3 编码不是任意 Reed–Solomon 库可互换

【证据】`AddPacket 0x7f7c10–0x7f7c90` 构造系统式编码的冗余系数矩阵，
然后调用真实 `reed_solomon_encode @0x7f6b7c`。逆元表在 `0x4640e8`，乘法表在
`0x4641e8`；原表的 65536 个乘法条目全部符合 GF(256) 模多项式 **0x11d**，
255 个非零逆元也经独立域运算验证。冗余行 i、数据列 j 的系数是：

```text
coefficient[i][j] = inverse[(m + j) XOR i]
0 <= i < m, 0 <= j < k
parity[i][byte] = XOR_j GF_multiply(coefficient[i][j], data[j][byte])
```

这是一种确定的 Cauchy 系数布局。相同 k/m 的另一种 RS/Vandermonde 布局未必
产生相同 parity；将通用库名字相同当作 wire 兼容证据不成立。
`scripts/fixtures/steam-fec-reference.json` 保存原始指令生成的 k=3/m=2/S=32
完整分片字节（位于 socket timestamp/CRC 加工之前），供独立实现核对。

### 26.4 接收、重建与普通不可靠窗口是不同路径

【证据】`CStreamChannel::HandlePacket 0x7f9314–0x7f932c` 将类型 11 送入
`HandleFECPacket @0x7f9940`。`BAddPacket @0x7f7fcc` 的入口检查包括：

- group ID 与最近已交付 group ID 的**有符号 16 位差**必须大于 0；支持回绕。
- payload 至少 9B；L 非负、S 非零；index 小于本组 k+m。
- shard 实际长度必须恰为 `8 + S`（去掉通常 13B 头以后）。

`0x7f8024–0x7f805c` 只保留一个活动组。不同 group 到来会 Reset 未完成组；
入口只对“最近已交付组”做上述新旧判断，并不另外保证新包比当前未完成组更新。
原始指令已验证：组 1 未完成→组 2 未完成→晚到的组 1，可把活动组替换回 1。
不能将此描述为支持多个乱序 FEC 组的接收窗口。

`0x7f8304–0x7f834c` 记录收到分片并计数，达到 k 后检查数据分片是否齐全；
数据已齐全即交付，不额外等 parity。缺数据则调用
`ReconstructData @0x7f84dc`→`reed_solomon_decode @0x7f609c`。
`0x7f8404–0x7f8428` 更新最近交付组并 Reset。
本接收队列的这些函数没有“再等 100ms 请求相同 FEC shard”的定时分支。

`HandleFECPacket 0x7f9974–0x7f998c` 把重建结果直接交给 connection player 回调，
**不插入普通类型 3/4 接收窗口，不经过类型 10 NACK 的窗口补包流程**。
重建保留 type 11 和组序号；`CStreamFrame::SetPacket 0x7f2c44–0x7f2cdc`
依据 channel/消息信封解析实际媒体 frameId、timestamp、input mark，而不要求
外层 type 改成 3。项目若只放行 type 11 并塞进普通 window，既不能重建，也会
混淆两套序号；本地 ReceivedFrame 的 type 3 断言也需要明确的集成边界。

【接收实现防护边界】`0x7f830c–0x7f8320` 在该原版中无独立的去重计数条件；
`0x7f85fc` 的 decode 返回值在调用链中没有被用于抑制交付。原始指令案例重复
送入同一数据 shard 三次（k=3，仅 1 个唯一 shard），会触发重建/上交，且结果
不等于原 payload。这是受控输入下的原版行为证据，不是实际用户故障证据，
也不是建议新实现照抄。独立实现应按唯一 shard 计数、验证同组元数据一致性、
限制内存/乘法长度并检查解码成功；这些防护需要明确记录为实现策略。

### 26.5 发送生命周期与恢复能力边界

【证据】`CFECOutgoingQueue::SendPackets 0x7f7dd4–0x7f7dfc` 在 socket 返回
1 时把该包放回队首并结束本轮（`0x7f7e28–0x7f7e3c`）；成功发送后释放该包。
这处理的是本地发送暂不能完成，不是收到对端缺片反馈后的重传缓存。
发送成功后重复调用不会再次发送该组；不能给它套用 §25.3 普通不可靠包的
约 200ms+RTT 保留机制。更不能描述成“FEC 失败后必然自动重传同一组”。

【结论】在有效、不同的 shard 条件下，k 个数据 shard 加 m 个冗余 shard，
收到其中足够的 k 个可恢复原传输消息；无需重传往返。3+2 的 10 种“两处丢失”
组合及反向到达顺序均由原始编解码指令恢复出逐字节相同数据。
丢失超过 m、整个组丢失、未完成组被替换，均不能由 FEC 保证恢复。
即使传输 payload 恢复，视频完整组装、参考链、后端解码和显示仍是独立条件。
20%/50% 是审计注入的发送参数，不是已逆向出的 host 实际默认冗余率。

### 26.6 复核方式与证据限度

```sh
python3 scripts/audit-steam-fec.py \
  --binary build/video-recovery-re/libmain-arm64.so \
  --output build/video-recovery-re/fec-audit.json
```

脚本需要 Python unicorn、protobuf，执行固定 SHA-256 的原始
AddPacket/BAddPacket/Reset/ReconstructData/HandleFECPacket、RS encode/decode、
媒体信封解析以及发送/路由分支。71 个断言案例包括配置描述符、GF 表、线格式、
丢片边界、乱序、组回绕/替换、重复、坏长度、总分片上限和本地发送重试。

packet constructor、allocation/refcount、CUtl 容器、socket、路由目标等使用
显式替身；RS 编解码并未替换成 Python 模型。发送队列使用受控 ring 布局。
这不是原版内存安全证明，不是本地 FEC 实现的对齐测试；没有 Windows host、
实链路、Switch 性能、码流解码/显示证据。host 的百分比选择、实际配置生效链和
强丢包时的策略不能用这些案例替代。

## 27. 传输协议的分层证据边界

### 27.1 协议支持与项目支持必须分别陈述

下表对照同一 Android ELF 与 IHSlib `5fe67f4`，不是以 protobuf 字段存在来
宣称相应运行机制已实现。§9/13 等较早审计的历史实现列不自动代表此版本现状。

| 路径 | 官方证据 | 项目差异／证据边界 |
|---|---|---|
| 普通不可靠接收 3/4 → 反馈 10 | §25，HandleDataPacket/UpdateUnreliableState | 有生产函数差分；F/U 冻结快照不证明并发全轨迹等价 |
| 普通不可靠发送 → 反馈 10 → 有限保留补发 | §25.3，SendUnreliablePackets/HandleNackPacket | 客户端 outgoing 包未完整接入这种缓存、标记、调度与退休；不能用可靠控制包重传代替 |
| FEC 类型 11 | §26，独立队列与 RS 编解码 | 配置未启用、解析器拒绝 11、无组恢复；是一整条能力缺口 |
| 可靠媒体 5/6 | OnNegotiationInit 0x7ad710 与通用可靠窗口 | 项目媒体只接纳 3/4，故明确协商 reliable_data=false；不应冒报相同能力 |
| 可靠控制/统计 5/6 → 7/8 | §14 的证据及本地 ch_control/retransmission | 已有独立实现，但本次未对所有 ACK/NACK、发送预算和并发轨迹做与 §25 同等级的穷举对比 |
| 配置 25、运行时消息 99、channel 冗余百分比 | §23/26 | schema、配置工厂、发送/接收机制不等于 host 生效策略；host 默认值/自适应规则仍无直接证据 |
| CRC、连接 ID、地址、类型分派 | §27.2 及 Socket/Connection/Channel 分层 | §29 补充真实 CRC 指令及握手→后续数据序列；完整 flags 来源与真实连线仍不由这些断言证明 |
| RTT、时钟与发送时机 | §25.2–25.3、25.14 | 给定 mean/smoothed RTT 的预算已对比；实时采样/时钟拟合和操作系统唤醒时序不是同一证明 |
| 媒体完整性 → 解码恢复 | §24–25 | 平台后端、内容模式位及 GPU/显示生命周期不能由传输层一致性推出 |

### 27.2 对类型 9 的分派范围更正与连接 guard

【证据与更正】§9 中“9 在 HandlePacket 被忽略”只能指
**CStreamChannel::HandlePacket**。`CStreamConnection::HandlePacket`
在 `0x7fad38–0x7fad3c` 更早拦截类型 9，经
`0x7faf08–0x7faf40` 验证 src/dst ID 和对端地址；连接 state=1 时
`0x7fafd8–0x7fafe8` 调用 Disconnect。因此撤回将类型 9 泛化为全链路忽略的
解释。包类型 9 与控制消息编号 9（KeepAlive）也不是同一层的枚举。

【证据】普通连接数据的 `0x7faff0–0x7fb028` 检查 ID/地址；
`0x7fb02c–0x7fb064` 在 connection `+10` 要求 CRC 时拒绝未带 CRC 标志的数据；
`0x7fb094–0x7fb09c` 把合法 channel 限定为小于 32。CRC 计算/比对及剥除尾部在
更早的 `Socket::HandlePacket 0x7ff4c8–0x7ff550`；不能把只验证 CRC 标志的
connection 分支当作已经验证 CRC32C 算术。

```sh
python3 scripts/audit-steam-transport-dispatch.py \
  --binary build/video-recovery-re/libmain-arm64.so \
  --output build/video-recovery-re/transport-dispatch.json
```

16 个原始指令案例分别验证类型 9 的 connection/channel 差异、连接状态、
错误 ID/地址、CRC 要求位、类型 7/8/10/11 的路由与 channel 上界。地址比较
结果、统计、目标处理器及 Disconnect 动作为替身；不模拟真实断连资源清理。
本节对实际执行的函数层次作出限定，不构成整套 Steam 协议等价实现的声明。

## 28. 控制入口与传输状态规则的横向核对

### 28.1 审计范围与消息清单

【证据范围】同一 SHA-256 固定的 Android 1.3.32 ARM64 ELF；本地实现对照
IHSlib `5fe67f4`。下述案例执行原始指令，替换平台依赖，不是仅搜索 protobuf
名称，也不是 Windows host 或 GitHub 所有历史版本的行为证明。

`HandleIncomingPackets @0x7a6368` 在 client state=2/3/4/6 的所有 byte 编号
0～255 上共执行 1024 次。到首个 On handler 或 protobuf 构造器即停止，故证明
**入口选择**，不证明 payload 被接受或 delegate 完整执行。实际入口为：

- state 2：ServerHandshake(7)。
- state 3：AuthenticationResponse(2)。
- state 4：NegotiationInit(3)、NegotiationSetConfig(4)。
- state 6：40 个非默认分派入口，清单保存在 fixture。

`OnStreamPacket @0x7acfa8` 另对 state 6/control channel 的全部 256 编号以及
5 个 state/channel 边界执行验证：KeepAlive(9) 在该层提前消费；RemoteHID(106)
提前交给 delegate；其他控制消息排队进入前述分派。state 0/7 丢弃数据；媒体
channel >=3 要求 state=6。crypto 的成功结果、信封构造及最终动作在这些案例中
为替身，不能拿入口扫描证明加密、媒体解析或 HID 的所有状态语义。

【本地源码差异】`ch_control.c` 的顶层 `IHS_SessionChannelControlOnMessageReceived`
缺少下列 12 个 state 6 入口；脚本从当前源码重算差集，而不是硬编码本地缺项：

| 编号 | 消息 | 所属功能 |
|---|---|---|
| 74 | OverlayEnabled | 叠加层状态 |
| 89 | SetGammaRamp | 色彩/gamma |
| 103 | VirtualHereReady | USB 转发 |
| 110/112/116 | TouchConfigActive / SetTouchConfigData / SetTouchIconData | 触摸配置及资源 |
| 121 | SetFlashState | 窗口提示状态 |
| 126 | ToggleMagnification | 放大显示 |
| 132 | RemotePlayTogetherGroupUpdate | 远程同乐组信息 |
| 136 | ShowOnScreenKeyboard | 屏幕键盘 |
| 145 | VRConnectionReady | VR 连接 |
| 146 | SetCursorScale | 光标缩放 |

这些多是 §13 已提及但未接入的界面/外设功能，不应包装成 12 种新发现的抗丢包
协议。相反，有 `case` 也不代表行为对齐，例如本地 OnSetQoS 只记录日志；官方
`OnSetQoS 0x7add24–0x7add30` 实际调用 transport SetQOS，参见 §14.16。
也不能将上述差集直接解释为 Steam 大屏底栏闪烁的原因。

【更正】§1.1 原来的完整性声明不成立。全量反汇编中，对
`SendControlMessage@plt 0xc0e110` 有 35 个 `bl` 和 1 个 `b`；尾调用在
`SendControllerConfigMessage 0x7abb44`。此外 `StartAuthentication` 的
`0x7a7ce4–0x7a7d0c` 直接构造 control/type=1 信封、Put(false)、Send(true)，
和 ClientHandshake 一样绕开该函数。§1.1 已补消息 1 并撤回“全集/只有一处绕开”
的说法；这不改变 pairing authorization 与 streaming connect/security PIN 的
区别，认证语义仍以 STEAM_REMOTE_PLAY_AUTH.md 为准。

### 28.2 ServerHandshake 的 MTU 是运行时限制值

【证据】`HandleIncomingPackets 0x7a64cc–0x7a64f0` 取 ServerHandshakeInfo
的可选 int32 字段 mtu（字段 1），先按有符号数限制下界 512，再限制上界 1472，
写 `s_nMTU @0xf34d48`；`0x7a64f8` 随后调用 StartAuthentication。
省略该可选字段时 protobuf 值为 0，走同样的限制后得到 **512**。
10 个原始指令案例覆盖 −1/0/511/512/1024/1472/1473/1500/9000 以及字段省略。
这里始终提供有效的 required info；没有将 malformed/missing info 等同于省略 mtu。

【本地源码差异】`ch_control.c::OnServerHandshake` 有 mtu 就原样保存，否则取
1500；`channel.c` 再用该值减传输头和 CRC 计算分片容量。既无上述上下界，也没有
相同的缺省结果。仅从 ELF 初始数据值 1024 推断最终会话 MTU 会遗漏这条路径。

【结论】这是可定位的分片参数差异。【待验证】过大的包在特定链路上可能产生
IP 分片等影响；没有该用户抓包，不能断言此差异造成下行停顿，也不能把修改
客户端上行分片自动等同于修复 host 下行。

### 28.3 发包限速与通道调度

【证据】`CTrafficShaper @0x7fe348` 的构造值为不可靠类 **12,500,000 B/s**、
可靠类 **625,000 B/s**；这是构造值，不是任意运行会话的最终有效带宽。
`BCanSendPacket @0x7fe38c` 先去掉 CRC bit，再将类型 3/4 归到 deadline `+8`，
5/6 归到 `+12`；7/10/11 在此函数直接允许，不受这两个 deadline 限制。
它只证明本层规则，不证明 FEC 不受其他层/系统发送能力约束。

`SentPacket 0x7fe3f0–0x7fe480` 按实际包长推进相应 deadline。
在正 rate、正常包长范围内，可写为以下 stream tick 规则（65536 tick/s）：

```text
若 rate == 0：deadline = packet_timestamp
否则：
    deadline = max_by_signed_wrap(deadline, packet_timestamp - 65)
               + trunc((wire_bytes << 16) / rate)
```

加减结果为 uint32；比较用带符号差处理回绕，不能直接用无限精度整数 max。
`Socket::Send 0x7ff244–0x7ff274` 做准入，`0x7ff33c–0x7ff3c4` 更新已发送预算。
`Socket::SetBandwidthLimit @0x7ff1d0` 写不可靠类限额，不等同于改两类所有限额。
66 个原始指令案例验证两类不同 deadline、等号准入、零 rate、空闲后的 65 tick
追赶上限、已有预算保留、uint32 回绕，以及 7/10/11 对该函数的绕行。

【证据】`SetChannelPriority 0x7fbc68–0x7fbc8c` 写 channel `+20` 并标记
connection `+376` 待重排。`HandleStreamStarting 0x7a7070–0x7a708c` 将控制
channel 1 设为 2、统计 channel 2 设为 −1。Connection Update 的实际排序调用在
`0x7fc338–0x7fc358`，按优先级降序；第一轮每通道依次执行接收状态更新、
SendReliablePackets、SendUnreliablePackets(false)、FEC SendPackets。
`0x7fc3d0–0x7fc410` 第二轮从轮转索引出发执行 SendUnreliablePackets(true)。
此处 bool 的具体发送/保留行为与 §25.3 连读，不能把两轮简称为相同的 FIFO 出队。
三个案例使用真实排序及调度指令，验证三通道顺序和三个轮转起点；通道函数本体
为事件替身，不测试并发/系统背压下的整体公平性。

【本地源码差异】`session.c::IHS_SessionQueuePacket` 将初发包 append 到统一
sendQueue，`SessionSendWorker` poll 首项；该初发队列没有同样的通道优先级排序和
双类 deadline 整形。本地可靠重传定时器、媒体反馈 worker 和 HID 合并仍是各自
机制，不能凭它们存在就视为已拥有官方连接级调度。是否有实际输入/反馈饥饿仍需
负载日志；不能从调度差异直接推算会卡一两秒。

### 28.4 连接超时、暂停及 CRC 协商

【证据】静态初始化 `0x7fe284` 设置 connect retry=6553 tick、RTO 最小/最大
65/3276 tick、普通连接超时 **15×65536 tick**、暂停超时 **180×65536 tick**。
`Connection::Update 0x7fc43c–0x7fc4c0` 按 connection `+8` 选择超时，比较
uint32(now−last_receive@+52)，**达到**阈值即进入超时分支，state 0/1 会调用
Disconnect。原指令断言覆盖 state 1 下两个阈值各自的前/等于/后边界。
`Pause @0x7fb990` 设置暂停字节；`Resume @0x7fb99c` 清除它，并以 connection
当前 `+48` 时间刷新 `+52/+56`，也有原指令断言。

这是 Android 客户端的连接级计时，不是视频缺包等待、关键帧请求周期，更不是
Windows host 会在 15 秒或 180 秒执行某动作的证据。本地 `session.c` 的接收
socket timeout 为工作线程定期检查退出服务，不等同于此状态化连接 deadline；
该版本没有找到对应的暂停/恢复计时规则。

【证据】`HandleConnected 0x7fbf10–0x7fbf58` 仅在 connection state=0、包长
恰为 **17B** 时接受，记录对端 ID、将该包的 CRC 标志写 connection `+10`，再处理
时间戳并通知连接成功。长度指 Socket 校验/剥除 CRC 尾部之后，不能误认成线上
含 CRC 总长必须 17B。12 个原始指令案例覆盖 state 0/1、16/17/18B、CRC bit 0/1；
时间戳处理和连接成功回调为替身，CRC 算术不在这些案例内。

上行 `SendConnectPacket @0x7fb84c` 的 4B cookie 是字符串 Connect 的 CRC32C；
`HandleConnect 0x7fbd68–0x7fbdc8` 接受旧式无 cookie 形式，拒绝不足 4B 的非空
cookie，验证 cookie 成功时才设置连接 CRC 要求位。后续数据的“要求 CRC 却未带
CRC 标志即拒绝”见 §27.2。这属于传输连接协商，不是 pairing/security PIN。

【本地源码差异】`ch_discovery.c::OnConnectACK` 有连接 ID/阶段检查，但没有同样
的 4B body 长度约束，也未持久化 peer 协商的 connection CRC 要求；`packet.c`
会校验**已带** CRC 的包，不代表拒收“按此连接要求本应有 CRC、实际未带”的包。
这是一项握手/完整性策略差异，不是已证实的媒体损坏来源。

### 28.5 包类型与底层 transport 不能混为一谈

【证据】实际调用 `GetStreamPacketTypeName @0x7fe318` 得到 0～11 的类型名，
12 为 UNKNOWN；更进一步，对 `Connection::HandlePacket` 和
`Channel::HandlePacket` 各自的类型 12～127 运行原始指令，共 232 个案例均未进入
媒体、ACK、NACK、FEC 等目标处理器。结合既有 0～11 分派证据，在这两个分派器和
固定 ELF 范围内，没有找到编号大于 11 的隐藏媒体包入口。这不证明未来版本、
其他输入层、其他 backend 也没有自己的消息编号。

同一 ELF 另有 `CStreamTransportUDP`（Send/Recv `0x802754/0x80286c`）、
`CStreamTransportUDP_SNS`（UpdateState `0x800c28`）、
`CStreamTransportSDR`（UpdateState `0x8011f0`、信令 `0x801754`），以及共用的
SteamNetworkingSocketsBase Send/Recv `0x800224/0x8002c0`。
这些是更下层的承载/连接路线；不能把 SNS/SDR 内部的确认、拥塞或信令编号直接
填进本节 13B 头的 channel 协议。此处记录边界与地址，不冒充完成 SNS/SDR 内部
协议逆向，也不证明原报告用户实际选择了哪条 transport。

### 28.6 可复核产物及未覆盖内容

```sh
python3 scripts/audit-steam-protocol-inventory.py \
  --binary build/video-recovery-re/libmain-arm64.so \
  --output build/video-recovery-re/protocol-inventory.json
```

脚本需 unicorn、protobuf 和 aarch64-linux-gnu-objdump；复用固定 ELF 的审计装载器。
分组案例数为控制分派 1024、快速入口 261、MTU 10、连接超时/恢复 7、整形 66、
排序/轮转 3、Connected 12、未知传输编号 232；另复跑装载器的 36 个恢复断言和
既有 16 个分层分派断言。`scripts/fixtures/steam-protocol-inventory.json` 固化原版
已处理的控制入口、MTU、常量、构造带宽、类型名和轮转结果；运行时只比较，不自动
改写期望值。本地缺项另外从源码计算，不写进“官方期望值”。

【边界】不是“协议已全部逆向”的证明：host 配置生效/自适应冗余率、可靠窗口的
全边界、时钟/RTT 拟合、真实背压并发、所有控制 payload/delegate、SNS/SDR 内部及
平台解码/显示仍没有同等覆盖。新发现的状态/调度差异、已知 FEC/发送缓存能力缺口
与原用户故障的因果关系保持待验证；本节本身不改变生产协议流或开启任何配置。

## 29. 局部机制的条件复播与证据边界

【就绪判断更正】撤回“这批核心分支已经足以开始整体实现”的判断。
本节案例证明给定状态/输入后的局部行为，不能一概证明真实会话由谁建立这些状态。
特别是 FEC 的配置请求、host 实际启用、运行中切换/回退和在途数据过渡尚未连成
闭环；不能由 RS/接收器可复播，或消息 99 存在，就认定生产启停策略已经明确。
后续实现就绪必须逐项核对真实上层触发和状态传播，不能用案例数量替代。

### 29.1 测试入口和状态的含义

【证据范围】继续固定 §28 的 ELF 与 IHSlib `5fe67f4`。本节把“函数存在”细化为
**输入层 → 前置状态 → 条件 → 动作/状态变化 → 反例**。fixture 的 `observed`
是原始指令结果，不是本地实现的期望生成器。未取到上层触发证据的能力不能用一个
setter 的单元测试冒充已经接线。

| fixture group / 入口 | 输入与替身边界 | 可检验的结果 |
|---|---|---|
| connected、crc_requirement、crc_policy / Socket::HandlePacket | 完整 datagram；真实 CRC32C、Socket HandleMessage、Connection HandlePacket/Connected；地址比较与最终 transport 为替身 | 握手状态、CRC 要求、后续数据准入、断连动作、last receive |
| mtu / HandleIncomingPackets | 已可靠重组的明文传输包；真实 frame 构造/信封提取/分派；按原版描述符用 Python 解析 protobuf 并填已知布局 | 是否解析、是否改变 MTU、是否进入 StartAuthentication |
| lifecycle、pause_resume / SDL event、Client::Pause/Resume | 真实事件分派和本地状态分支；控制发送/DataLost 为动作记录器 | 动作顺序、次数、client/connection 暂停位、时间刷新 |
| send_budget / Socket::Send | 包、时钟、两类 quota、模拟 transport 返回值；真实准入、CRC、预算扣除 | 是否真正尝试发送、返回码、blocked 标志及两个 deadline |
| fec_ingress / Socket::HandlePacket | §26 原版字节向量选择的完整分片；真实 connection/channel/FEC/RS 路径 | 交付数、恢复 payload；不含视频解码 |
| reliable_retry / SendReliablePackets | 已存在的单包发送窗口及 RTT/时钟快照；Socket send 只记录并模拟时间戳写入 | 等号边界、首次尝试、计数饱和、窗口保留 |
| reliable_ack / Channel::HandlePacket | ACK wire、发送窗口；真实 ACK 与 Advance；时间戳处理及对象引用为替身 | 累计退休、空槽跳过、回绕/半区间比较 |
| timestamp / ProcessTimestamp | echo、peer send、now 与统计快照；采样队列仅记录样本 | 接受/拒绝、最小/平滑 RTT、是否产生 offset 样本 |
| control_actions / OnSetQoS、OnSetTargetBitrate | 解密后的 control payload；真实 handler；protobuf 解析、最终 delegate/SetQOS 为替身 | 必需字段、对象存在条件、更新值与动作参数 |

数值状态分层不能混用：client `+256` 的 2/3/4/6 对应握手/认证/协商/串流；
connection `+16` 的 0/1/3 对应连接中/已连接/关闭状态。client 的暂停标志
`+19` 与 connection 的暂停标志 `+8` 也是两个状态，不应合成一个无条件切换。

这些复播输入属于各自声明的层。`reassembled_plaintext_packet` 不是可直接发送给
已加密 Steam 会话的 UDP 包；控制编号 7 也不是传输 ACK 类型 7。所有时间除明确
写 ms/us 的字段外，使用 uint32 16.16 秒；对计时应比较回绕差，不能换成 epoch ms。

### 29.2 MTU 与连接 CRC 的具体输入

**MTU 正常触发**：client state=2，control channel=1，消息编号 7，
CServerHandshakeMsg.info 存在且 protobuf 解析成功。以传输头后开始的明文为例：

```text
07 0a 00                  # info 存在，mtu 可选字段省略 → 512
07 0a 03 08 a0 0b         # info.mtu=1440 → 1440
07 0a 03 08 a8 46         # info.mtu=9000 → 1472
```

首字节是 control type，后续是 protobuf；不附 protobuf 长度前缀。
本节脚本使用完整包中的实际 channel/type 经原始 frame 构造器提取这些字段，
不再仅从 MTU clamp 中间地址起跑。`mtu_missing_info`、`mtu_bad_proto` 无效解析
不改 MTU且不启动认证；state=3、channel=2、消息=9 的反例不进入该握手分支。
required info 缺失不能解释为“mtu 省略”，后者是有效消息。

**CRC 正常触发**：连接 state=0、本地 ID=12，收到来自匹配地址的 Connected
（transport type=2、dst ID=12、src ID=34），剥除 CRC 后长度恰为 17B，
即 13B 头 + 4B echo。wire bit 7 决定接受后 connection 的 CRC 要求；
若置位，Socket 先校验完整包尾 CRC32C，校验失败不能进入连接 handler。
fixture 保存 3/4/5B body、CRC 开关的正反例，以及先握手后送第二包的完整序列。

**后续数据**：类型 3 等普通数据要求匹配双方 ID/地址、channel<32；连接要求
CRC 而包未带标志时，不进入 channel，也不刷新 last receive。已带但 CRC 错误
则在更早的 socket 层拒绝。错误 ID/地址若未匹配其他连接，Socket 可能回复
类型 9，不能一概期望“所有拒收都完全静默”。

**特殊路径反例**：类型 9 在 connection 的 CRC 要求检查之前分派；ID/地址匹配
且连接已建立时，即使该连接要求数据 CRC，未带 CRC 的类型 9 仍能进入 Disconnect。
但若类型 9 自己带了 CRC，错误 CRC 仍被 Socket 拦截。`crc_policy_*` 验证两种连接
要求 × 类型 3/9 × 无/正确/错误 CRC。不能在实现中把普通数据的要求机械移到所有
包之前，再宣称和原版等价。新增的防护策略若选择不同处理，必须单独注明。

**接线边界**：IHSlib `packet.c` 处理字节校验和剥尾；`ch_discovery.c::OnConnectACK`
处理连接接受；`session.c` 接收分派在普通 channel 路径施加连接要求。MTU 的应用
位置是 `ch_control.c::OnServerHandshake`，分片容量消费者在 `channel.c`。
官方 MTU 是进程全局值；项目若保留每 session 存储，应明确这是多会话隔离选择。

### 29.3 暂停恢复必须由生命周期边缘触发

【证据】`CStreamPlayer::BHandleEvent 0x7b8248–0x7b8254` 对 SDL 事件 **0x103**
调用 Client::Pause；`0x7b85ac–0x7b85b8` 对 **0x106** 调 Resume。
本地 SDL2 头 `SDL_events.h` 对应 WILLENTERBACKGROUND / DIDENTERFOREGROUND，
不是 DIDENTERBACKGROUND(0x104) 或 WILLENTERFOREGROUND(0x105)。四种事件均有
原始指令对照。不能由“游戏暂停”“打开 Steam 大屏菜单”推导出这些生命周期事件。

Client::Pause 的可实现条件/顺序（`0x7b02d8–0x7b0338`）：

1. client 已暂停则直接返回，重复后台事件不重复发送。
2. connection 存在且 state=1 时：若 client state=6，先发送空 CPauseMsg(122)；
   然后调用 connection OnStreamPaused，设置其暂停位。
3. 无论 connection 是否存在/已连接，首次调用最终将 client 暂停位置 1。
   非串流 client 状态不发送 122，但已连接的 connection 仍可被标记暂停。

Client::Resume 的条件/顺序（`0x7b03a0–0x7b0420`）：

1. client 未暂停则直接返回，重复前台事件不重复发送。
2. connection 存在且 state=1，先 OnStreamResumed：清 connection 暂停位，
   用 connection 当前 update 时间刷新 last receive 和 last echo。
3. 若 client state=6，依次发送空 CResumeMsg(123)、SendDataLost(audio=0, empty
   frame IDs)、SendDataLost(video=1, empty frame IDs)。这不等于直接调用两次
   后端 Reset，不能凭函数名改成销毁音视频解码器。
4. 最后清 client 暂停位；即使 connection 已不存在，也清该本地状态。

`pause_resume` 的 32 个输入覆盖两种动作、暂停位 0/1、connection 不存在/0/1/3、
client state 2/6；fixture 保留动作有序列表。`lifecycle` 再从真实 SDL 事件进入，
验证上层接线。§28 的 15/180 秒只规定持续无有效接收时的连接 deadline；仅调用
Pause、仍持续收到合法数据，不应凭空在 180 秒断开。

【项目接线证据】Switch `events.c::sl_events_next` 已把 applet 焦点变化转成上述
0x103/0x106；`application.c` 也调用 `sl_runtime_foreground`，但该函数只原子保存
foreground。原版消息/连接时钟动作尚未由此证明存在。实现应在**前后台变化边缘**
向 session worker 交付动作，保留重复事件幂等性；不在每次主循环重复发包，不在
渲染/输入热路径同步阻塞。是否触发系统暂停及唤醒后的实际时序仍需设备验证。

### 29.4 限速、优先级与 FEC 的可触发边界

**Socket 预算触发**：先把包 timestamp 改为当前时间，再检查所属类 deadline；
当前时间小于 deadline 的类型 3/4/5/6 返回 1、置 socket blocked 标志，
**不调用 transport**。到达等号即可尝试。类型 7/10/11 不进这两个额度检查。
transport 若自己返回非零，函数原样返回且不推进该类 deadline；这与整形拒绝是
两条分支，后者置 blocked，前者不因此置 blocked。

成功发送（返回 0）后才按 §28.3 推进 deadline。打开 connection CRC 时，实际
Socket send 先写 bit 7 和 CRC 尾；本层整形用 packet 长度字段计算，不因加尾而
自动多计 4B。45 个 `send_budget` 案例覆盖类型 3/5/7/10/11、deadline 前/等于/后、
transport 返回 0/1/2，并校验真实 CRC 指令输出和两个额度的变化。完整类型 4/6
对应关系另由 §28 的类表案例验证。

**优先级的真实上层来源**：串流启动 `HandleStreamStarting` 将控制=2、统计=−1；
`StartMicrophoneStream 0x7a8990–0x7a899c` 取 client `+627` 麦克风 channel，设为
1；`StopMicrophoneStream 0x7a8b34–0x7a8b4c` 在该 channel 非零时设回 0。
setter 标记 connection 待排序，下次 Update 才重排，而非收到任意数据包就排序。
第一轮更新/发送全部通道，第二轮才从轮转起点扫描不可靠补发；不能在 NACK handler
里无界同步发完。三轮转测试见 §28 fixture；阶段选择与包龄/退休输入见 §25。

**限额 setter 与 host 码率消息不应合并**：OnSetTargetBitrate(94) 解析成功后写
client `+664`，通知可选 delegate/observer；`CStreamPlayer::SetTargetBitrate
@0x7c9df4` 在这个 ELF 是 ret。尚无此消息调用连接限额 setter 的上层证据。
SetQoS(87) 则要求 use_qos 必需字段、UDP 对象和 connection 均存在，向实际 UDP
SetQOS 传 `use_qos << 1` 和连接地址。12 个 `control_actions` 验证字段缺失与对象
存在/缺失；测试 delegate 是替身，不声称完成所有 observer 的调用链。

**FEC 接收触发**：匹配的活动连接收到 type=11、channel 有效，先走独立 FEC
分组检查；收到足够的不同 shard 后重建/交付。5 个 `fec_ingress` 案例从 Socket
进入真实 connection/channel/FEC/RS，不再仅直接调用 BAddPacket：3 个数据片齐全、
缺 1/2 数据片但总计足够 k、仅有 2 片、重复同一片 3 次。最后一个保留原版错误
交付的反例，不能把它作为项目必须照抄的成功行为。

这些案例的 connection outgoing FEC 启用位始终为 0，仍可接收恢复；不能拿发送
启用位拒收这条接收路径。§26 的三组量仍须分开：配置字段 25 请求 host 行为、
connection outgoing 启用位选择自身发送路径、channel percentage 决定自身冗余量。
向后两者注入测试值能触发发送器，不证明 UI/host 会把它们设成那些值。未取证的
Windows 激活/自适应规则不能靠猜测补成默认 20%/50%。已知 wire 证据可支持隔离的
接收器原型/差分研究；它不是生产集成就绪判断，启停控制、过渡与互通仍需证据。

【配置动态性证据限度】`SetStreamingClientConfig 0x7b021c–0x7b0264` 在 bool
参数 bit 0 为 0 且 client state=6 时发送消息 99，否则仅更新/通知/保存本地配置。
`OnSetStreamingClientConfig 0x7af0cc–0x7af10c` 解析成功后复制收到的配置、通知
delegate 并保存；该 handler 本身没有设置 connection outgoing FEC 启用位。
这证明串流中有配置更新请求和接收路径，不证明 host 会把其中字段 25 立即生效，
也不证明 host 根据网络状况要求客户端开启、自适应切换阈值或双方存在确认流程。

### 29.5 可靠重传、累计确认及时间戳采样

【更正】§9.1 的等号描述撤回。真实 `SendReliablePackets 0x7f8b04–0x7f8b88`
对已有发送计数、非零发送时间的包使用：

```text
c = clamp(smoothed_rtt_ticks, 65, 3276)
retry_threshold = c + floor(c / 4)
可重传 iff signed_wrap(now - last_send) > retry_threshold
counter == 0 或 last_send == 0：跳过包龄条件，立即尝试
发送成功：counter 加 1，达到 255 则保留 255；不按次数退休
```

例如 smoothed RTT=65 tick，包龄 80/81 不重传、82 重传；smoothed=1000 时，
1250 不重传、1251 重传。33 个 `reliable_retry` 覆盖 RTT clamp、严格边界、
counter=1/255 与三个立即尝试反例。Socket send 是显式替身；真实预算拒绝/发送
失败另在 `send_budget` 验证，不能据此称重传线程调度逐 tick 等价。
本地 `RetryTicks` 数值公式相同，但 `retransmission.c` 转成向上取整毫秒 deadline
后由 timer 判断；精度/调度不同，不能把数值公式相同写成触发时刻完全一致。

**累计 ACK 触发**：类型 7 进入可靠 state 的 HandleAckPacket；包头 sequence 是
累计确认号，13…16B 是 echo。先计算 `int16(ack - head + 1)`，正值时按已占用范围
长度截断推进；随后继续跳过已有空槽。8 个 `reliable_ack` 验证旧 ACK、确认一/多
包、越过 tail 的截断、旧 ACK 也可清理已有空头槽、65535 回绕及 32768 半区间。
不是任意巨大 ACK 都按无限精度“大于 head”处理；空槽推进也不是接收端丢弃缺洞。
这些是合法长度 ACK 的证据，新增 parser 的短包防护不能冒称原版全面具备。

**时间戳触发**：ACK/NACK/Connected 等合法分派调用 ProcessTimestamp(echo,
peer_send, receive_now)。`0x7f9a60–0x7f9a68` 只拒绝比已记录 echo 老**超过 130
 tick** 的值；老 130 tick 恰好允许，并可把 last echo 更新到较小值。这不是普通
接收窗口保留 newest sender timestamp 的逻辑，两者不能共用一个“只增不减”规则。
正 RTT 参与最小值；采样 RTT 钳为非负，已有平滑值时取 `(old+sample)/2`。
只有 RTT≤minRTT+65 的样本进入时钟 offset 队列：min=935、RTT=1000 可进，1001
不进。offset 使用 `peer_send - echo - trunc((now-echo)/2)`；负数保留 uint32 位型
和 int32 解释区别。最小 RTT 的慢速上调与更新时间也由案例记录。

9 个 `timestamp` 验证 echo 旧/新边界、未来 echo、平滑、offset 准入及 min 更新。
PingStats/TimeOffsetStats 的容器在此为样本记录器，**没有证明完整 3s/10s 窗口
淘汰、均值更新与线程轨迹等价**；实现实时统计时仍须单独核对那些容器。

### 29.6 实现接线与验收资产

```sh
python3 scripts/audit-steam-protocol-triggers.py \
  --binary build/video-recovery-re/libmain-arm64.so \
  --output build/video-recovery-re/protocol-triggers.json
```

181 个场景及所有具名输入保存在 `scripts/fixtures/steam-protocol-trigger-reference.json`。
脚本比较固定原版参考，不自动改写期望；另复跑原有 36 个恢复与 71 个 FEC 案例。
普通实现测试可直接消费 JSON 的 `input` 和 `observed`，无需分发官方 ELF：

- packet/连接层测试用 mock transport 注入 `datagrams`，检查是否交付/发包及状态；
  地址比较替身需同时设置为 fixture 指定的匹配/不匹配结果。
- control 层先建立 fixture 的 client 状态，再提交 `reassembled_plaintext_packet`，
  检查消息/状态动作；不得绕过接线只调用 clamp 后声称已验证控制分派。
- lifecycle 测试注入 SDL 事件并检查有序动作列表；计时测试注入假时钟及明确的
  last receive/echo/RTT，而非靠真实 sleep 赌定时分支。
- 发送测试准备占用窗口、counter/last_send、两类额度和 transport 返回值；区分
  “没有调用底层”“底层失败”“已发但未确认”“收到 ACK 退休”。
- FEC 验收必须检查恢复 payload 的逐字节内容与唯一交付数；原版 duplicate 反例
  属于兼容性观察，项目防护应另设“重复片不增加唯一计数、恢复失败不交付”判据。

这些是可运行的原版触发契约和后续实现的对照资产，不是未实现功能的本地通过
证明。§28 的 12 项 UI/外设入口仅有路由清单，尚不具备各 delegate 的完整语义；
SNS/SDR 内部、Windows host 配置策略也不在本节的实现契约内。不得以场景数替代
这些层的证据，也不得宣称静态复播已经证明真实链路和物理显示。
