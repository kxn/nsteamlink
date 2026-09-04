# Steam Link Android 客户端协议逆向参考（v1.3.32 / libmain.so）

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
  接收计数器 CStreamClient+0x88（+136，同样自增）。**seq 不上线**，由两侧各自维护，
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
（仅接受 type==1，OnDataPacket；扩展头 +48 u32 字段被减去 conn+848 基准 = 流内相对时间戳，
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
| 1 | 重传放弃 | 无放弃，重传到 ACK/NACK 确认（0x7f8ac4/0x7f94b8/0x7f95dc 全路径） | 3s 放弃（D-039），放弃=从发送窗口除名 | **自创行为，官方不存在**；放弃在 host 接收窗制造永久洞，host 只能等它自己的放弃计时（观测 ~20s）后才恢复 | 不再出现"重传 25 次后放弃"；卡死时长消失或 <1s 级 |
| 2 | NACK | 收到洞即发扩展 NACK（掩码），收到 NACK 快速重发（0x7f9d0c/0x7f95dc） | ihslib 无 NACK 机制 | **缺失整个快速恢复通道**；host 只能靠自己的重复 ACK/计时发现洞 | tcpdump 可见我们发出的 type-8 NACK 包 |
| 3 | 在途限制 | 无（窗口制，ACK/NACK 驱动滑动，掩码覆盖 ≤320 包） | 单在途（D-040）+ 100ms 心跳 | **自创行为**；单在途把"高频 delta 容忍丢失"变成"串行等待" | 输入包速率/在途数与官方 pcap 对齐（31/s 批量、无 1 包往返） |
| 4 | ACK 语义 | 累计 ACK+空槽跳跃+周期重发+时间回显（0x7f94b8） | ihslib window.c 自实现 | 行为需逐项核对（互操作已通，疑似大体一致） | host ACK 延迟统计正常（≤99ms 已观测） |
| 5 | 接收窗口交付 | 只弹连续头部，无弃洞（0x7f9d0c 第 1 步） | 同构 | 一致 | — |
| 6 | FEC | 不可靠通道带 FEC（SendUnreliableFEC 0x7f90e4、CFECOutgoing/IncomingQueue） | 未实现（enable_unreliable_fec 未协商） | 待评估（视频/音频下行方向，与输入卡死无直接关系） | — |

**P0 因果模型（推断，待 P0 修复实验证实）**：卡死 = 我们丢一个上行可靠包
→ 我们 3s 后放弃（洞永久化，行为 1）→ host 接收窗头部滞留、按序 apply 停止（行为 5 同构）
→ host 无我们的 NACK 协助（行为 2），只能靠自身计时放弃洞（~20s，host 侧，非本二进制可证）
→ 恢复。官方在同样丢包下：NACK 回环 ~1 RTT 愈合，永远不会触发 host 的长计时器。
修复方向 = 对齐行为 1+2（去掉放弃、补 NACK 回环），行为 3 一并对齐（官方无单在途）。



### 9.4 窗口结构与我们传输层的逐项对照（P0.5，2026-09-04）

`CStreamPacketWindow`（0x7f7230/0x7f76f4/0x7f9bb0）：+0=count、+4=mask、+8=head(u16)、
+10=连续交付水位(u16)、+16=槽表、+24=时间戳表。
`Advance(n)`：推进 head 逐格释放被跳过的槽（引用计数→析构），水位跟随 head；
`ReleasePacketByID(id)`：ID 在 [head, head+mask] 内→释放该槽（**head 不动**，洞原地释放，
由后续 ACK 的空槽跳跃自然收紧）。NACK 掩码覆盖上限 0x140=320 与窗口容量一致。

| 项 | 官方 | ihslib fork（retransmission.c/channel.c） |
|---|---|---|
| 重传节奏 | 超时 = f(srtt)：`(srtt+2.0)×0.75` 钳制（0x7f95dc），运行时常量 | 5ms tick，25ms 起倍增封顶 100ms |
| 放弃 | **无**（重传至 ACK/NACK 确认） | `RETRANSMISSION_GIVE_UP_MS=3000`，放弃=退休（D-039） |
| ACK | **累计**（连续交付点 data[7..8]）+ 周期重发 + 时间回显（RTT 对时） | 逐包 ACK（packetId+fragmentId+body 时间戳） |
| NACK 发送 | 洞检测→扩展 NACK：首洞序号+连续交付点+320 包占位掩码，限频 | 仅单包校验失败时发（ok=false），无窗口状态报告 |
| NACK 接收 | bit=1→ReleasePacketByID；bit=0→超时则强制重发 | （session.c 有分支，语义未对齐官方掩码协议） |
| 窗口 | 320 容量环形窗口，累计 ACK 滑动+原地释放 | 自实现 window.c |
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

- 每数据类型一个 240 槽环形 `CFastFrameStats`（120B/槽，槽 0 = frameId）；
  遍历未发送帧：帧未完成（+88==0）→ `RecordFrameComplete(type, id, 6)` 标记 Cancelled 照报；
- 逐帧 `CFastFrameStats::Save(CFrameStats*, full=1, conn+848)`——**时间戳减 conn+848
  （连接基准）**，CFrameEvent.timestamp 为 16.16 定点秒的连接相对值；
  数据通道扩展头 +48 字段的减 conn+848（§4）同单位同基准；
- 网络样本取自连接统计：srtt(conn+732)、conn+1152/+1000（×系数 0x3A83126F≈2^-10，
  【推断】µs→定点秒换算）、丢包 = conn+1252×100.0/conn+1248；
- `CFrameStatsAccumulator.Calculate()` 后追加最多 20 条 accumulated_stats
  （EFrameAccumulatedStat：FPS 等）；
- 发送节奏：`HandleStreaming`（0x7a7140）内 `now - last > 0x10000`，**单位即定点秒
  → 精确 1.0 秒一次**；`TriggerDebugDump`（0x7ac6b4）前置一次强制 flush。

### 9c.4 我们的问题定位（network≈58518652ms 失真）——2026-09-04 复核定案

官方侧证据链（全部反汇编复核）：
1. `Plat_RelativeTicks`（0x90b0e4）：`clock_gettime(CLOCK_MONOTONIC)`，基准累加
   `tv_sec × 1e9 + tv_nsec`（立即数 0x3B9ACA00=1e9）→ tick = **纳秒**；
2. `Plat_RelativeTickFrequency`（0x90b1c8）：同初始化路径，`csel x19=1e9` → **freq = 1e9 tick/秒**；
3. `GetStreamTimestamp`（0x802a88/0x802b14）：`(ticks/freq)<<16 | ((ticks%freq)<<16)/freq`
   → **16.16 定点秒**，65536s 回绕；
4. 帧事件时间戳再减连接基准（`CFastFrameStats::Save(..., conn+848)`）→ **流内相对 16.16 定点秒**。

我们侧证据（ihslib fork 源码）：
- 现状 `IHS_SessionPacketTimestamp`（packet.c:134）= `CLOCK_REALTIME` 毫秒截断 u32，
  注释声称 "matching the official client's GetStreamTimestamp"——**该注释与反汇编矛盾，作废**；
- 历史版发的是 "1/65536-s ticks"（注释自述）= 恰恰是 16.16 定点秒的**绝对值**（未减连接基准），
  同样失真（~58.5M）。

**失真机制（修正后的结论）**：host 用它自己的流内相对时钟求差。官方客户端发
"16.16 定点秒 − 连接基准"；我们无论发绝对 16.16 秒刻度（v1）还是 epoch 毫秒（v2），
与 host 的流内时钟都不同基不同源（v2 还把 CLOCK_MONOTONIC 换成了 REALTIME），
差值自然爆炸。**修复 = 完整复刻：CLOCK_MONOTONIC → 16.16 定点秒 → 减去"连接建立时刻
的同单位值"。单位、基准、时钟源三者都要对齐，缺一不可。** 这也解释了前两次修复
（v1 刻度、v2 毫秒）为何都失败：两版都只改了单位、没改基准。

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
| 14 | → | 帧反馈 | ch2 **明文**可靠 | CFrameStatsListMsg{data_type=1, stats=2, accumulated=3, latest_frame_id=4}；1.0s；时间戳 16.16 定点秒减 conn 基准（§9c） |
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
| 5 | frame_stats.c | 事件时间戳=上述毫秒值 | conn 基准相对 16.16s（0x7a847c Save 第 3 参） | **MISMATCH** |
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

### 13.3 结论

16 项 fork 行为裁定：**MATCH 1 项、PARTIAL 1 项、MISMATCH 12 项、未验证 0 项**（三项
"未验证"已于 2026-09-04 二轮逆向闭环：#11 system_info、#12 KeepAlive、#15 StopRequest）。
MISMATCH 集中在四处自创机制（#1放弃、#6单在途/coalesce、#4/#5时间戳、#2缺NACK）
——与 §9.3 修复清单完全对应，无新增矛盾。业务代码缺口 = 触摸（#17）。
官方 KeepAlive 周期=10s、进入 Streaming 立即首发；Stopping 态不处理任何入包。



1. host 侧"弃洞"计时的确切时长与条件（host 非本二进制，只能黑盒观测；P0 因果模型预测：
   客户端补齐 NACK+取消放弃后，该计时器应永远不会被触发）；
2. `SendUnreliable` 在官方客户端的实际使用者（数据面候选：ACK/日志/统计）——
   找到 `bl c11000 <SendUnreliable@plt>` 的全部调用点即可闭环；
3. OnSetQoS/OnSetTargetBitrate/OnVideoEncoderInfo 客户端处理逻辑（收到后做什么）
   ——影响我们对 host 下行消息的响应面；
4. CStreamingClientHandshakeInfo / CStreamingClientCaps 其余字段取值（Android 官方值）；
5. KeepAlive 周期（SendKeepAlive 的调度源：OnThink 定时器参数）；
6. ControllerConfigMsg(137) 官方载荷构造（0x7abb30 只做转发，构造在调用方——
   CStreamPlayer/UI 层，需沿 xref 上溯）。

## 11. 与既有文档/决策的关系

- 本文件更正 OFFICIAL_INPUT_RE.md §5（CLIENT: 方向）、§8 候选路线 B、§15/§16
  （Send bool 映射方向、"官方输入可能走不可靠通道"猜测）；
- **不推翻**：R1 delta/full 自适应规则（0x7d035c 反汇编独立成立）、R2/R3/R5/R6 的
  发送节奏与时序观测、R7 host 日志量差异本身（仅其方向解读）、D-039/D-040 传输层修复；
- 候选路线 B 缩水为"补 ControllerConfigMsg / GetTouchConfig 族 + VideoOverflow"，
  其优先级需要结合第 9 节问题 3（host 下行处理逻辑）重新评估后再立项。
