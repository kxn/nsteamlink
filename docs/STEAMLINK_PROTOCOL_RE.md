# Steam Link Android 客户端协议逆向参考（v1.3.32 / libmain.so）

> 范围补充：§30–31 纳入哈希固定的 Windows x86/x64 Host 和跨二进制互通。
> §32 回到官方 Android shell/core 核对 FEC 的用户入口、测试推荐与配置生效链。
> §33 定义本项目 type 11 接收和手动设置接线；§26–27 对旧 IHSlib 的缺口描述
> 仍限各段标注的历史提交，不能再解释为新接收器继续拒绝 type 11。
> 早期章节的地址/不存在声明限于各自样本，不作为所有官方版本的协议全集。

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
（仅接受 type==1，OnDataPacket；扩展头的frame timestamp、input-received timestamp及
transport send timestamp减去conn+848的peer−local时钟偏移，换算为本地时间，详见§52。
撤回旧文“扩展头第12字节域是流时间戳”的错误字段定位）；channel==1 为控制通道；channel==0（发现/Ping）
由 OnPingRequest 处理。控制通道内 type==9（KeepAlive）静默消费，type==106（RemoteHID）
内联转 IStreamPlayer 虚表槽 10，**其余控制消息经 ThreadInterlockedIncrement 引用计数后
推入 CStreamQueue<CStreamPacket*>（CStreamClient+0x2a0），由 HandleIncomingPackets
（0x7a6368）按类型分派（Setup 类型直接比较；50..147 走 0x4474f8 跳转表）**。

## 5. Negotiation 深挖【已验证】

`OnNegotiationInit`（0x7ad698）从 host CNegotiationInitMsg 读取：

| InitMsg 字段 | 官方处理 |
|---|---|
| reliable_data (bool) | **无条件字节复制bool值**进自身CNegotiatedConfig.reliable_data；撤回“含输入hasbit回显”的说法，输出hasbit独立置位，详见§47 |
| supported_audio_codecs | 顺序扫描，取首个Raw1或允许的Opus3；enable_audio_uncompressed时跳过Opus；无匹配显式记0，详见§48 |
| supported_video_codecs | 顺序扫描，按客户端解码能力掩码 0x330（位4,5,8,9 = H.264/HEVC/AV1/Pyrowave，再过
  `CStreamDecoderH264Standalone::BAvailable` 能力检测）或Raw1，取首个为 selected_video_codec，详见§48 |
| supports_remote_hid | 真 → 置 enable_remote_hid=1（NegotiatedConfig hasbit 0x8） |
| supports_touch_input | 真 → 置 enable_touch_input=1（hasbit 0x10） |
| os_type / gaming_device_type (int32) | 存入 CStreamClient+8/+12 |

随后的 `CNegotiationSetConfigMsg`（0x7ada1c 起）三段整体 CopyFrom 后发送（type 4，加密+可靠）：
`config` ← CStreamClient+0x120（CNegotiatedConfig，成员对象：上述选择结果）、
`streaming_client_caps` ← +0x160（CStreamingClientCaps：supported_video_codecs 内联构建——
恒追加1/Raw视频，再按 BAvailable 逐个追加 4,5,8,9）、
`streaming_client_config` ← +0x1c8（CStreamingClientConfig，来自 Load/SetStreamingClientConfig）。

**实现契约（§48更正）**：通用可靠接收及完整协商生产已有官方客户端原指令对照，
本地按host的bool值写reliable_data，并独立显式置presence。撤回此前用“host宣告false时
真机无异常”弱化硬编码false差异的论证。平台只声明实际解码能力；Raw视频及其他未实现
codec仍是明确差异，不能以H264/HEVC子集对照代替全能力一致性。

## 6. 会话建立序列（client 视角）【已验证（函数级）/时序待动态确认】

```
会话MTU探测: Unconnected type0 / message1 → OnPingRequest；首页主机发现为独立协议（§43更正）
连接:  CStreamConnection 建立 (OnStreamConnected: state→2, 记 GetStreamTimestamp→+0x278)
握手:  → ClientHandshake(6, 明文, 可靠) 载荷 CStreamingClientHandshakeInfo(成员 CopyFrom)
       ← ServerHandshake(7, 明文) → StartAuthentication (0x7a7b7c)
认证:  → AuthenticationRequest(1, 明文) [PlayNextRecordedInput 域内的站点为回放路径,
       真实发送点在 StartAuthentication 调用链]
       ← AuthenticationResponse(2, 明文) → 派生密钥
协商:  ← NegotiationInit(3, 加密) → OnNegotiationInit → → NegotiationSetConfig(4, 加密)
       ← NegotiationSetConfig(4)（host 确认）→ OnNegotiationSetConfig（仅audio/video
         两个codec各有Assert；非debug下仍CopyFrom并进入Starting，详见§49）
会话:  → NegotiationComplete(5) (HandleStreamStarting) → HandleStreaming
       （正常Starting先记时间，首个KeepAlive须严格超过10秒；详见§50）
```

## 7. 音视频编解码能力（客户端侧）【已验证】

- 音频：`IsSupportedAudioCodec`——1（Raw）恒真；3（Opus）当 CStreamClient+0x238 == 0；
  解码器 CStreamDecoderRawAudio / CStreamDecoderOpus。
- 视频：`IsSupportedVideoCodec`——掩码 0x330（4,5,8,9）走
  `CStreamDecoderH264Standalone::BAvailable`，1（Raw视频）恒真；旧H264标注撤回，见§48。
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
2. ACK：连续收包水位变化（+42 u16）即置 +41 标志，到期后发 ACK（§45）
   （data[0]=7、data[4]=通道、data[7..8]=连续交付点、+56 区 data[13]=时间回显；
   长度 17 字节级——与 pcap 观测 21B 同量级，UDP 连接头另计）；
   **撤回原“另有周期性重发 ACK”结论**：完整构造器、HandlePacket和Channel::Update
   的原指令执行证明没有新接收事件就不重复ACK；旧包重到会重新置待确认标志，
   反馈到期前会延后。初始水位0导致首次单独交付ID0不发ACK。详见§45；
3. NACK：扫描接收窗口 (lastAcked..next)，发现空槽且满足速率条件
   （全局 [f47000+2444] 参与限频）→ 构造扩展 NACK（含占位掩码，窗口覆盖上限 0x140=320 包）
   发给对方。

### 9.3 与我们（ihslib fork）的逐条对照

| # | 项 | 官方（地址） | 我们当前 | 差异判定 | 真机判据 |
|---|---|---|---|---|---|
| 1 | 重传放弃 | 无放弃，重传到 ACK/NACK 确认（0x7f8ac4/0x7f94b8/0x7f95dc 全路径） | 3s 放弃（D-039），放弃=从发送窗口除名 | **自创行为**；放弃制造永久洞，但 Host 的 20 秒恢复机制未证实 | 不再出现"重传 25 次后放弃"；卡死时长消失或 <1s 级 |
| 2 | NACK | 洞后有老包且反馈到期才发扩展 NACK（§45）；收到 NACK 触发候选重发（0x7f9d0c/0x7f95dc） | ihslib 无 NACK 机制 | **缺失整个快速恢复通道**；host 只能靠自己的重复 ACK/计时发现洞 | tcpdump 可见我们发出的 type-8 NACK 包 |
| 3 | 在途限制 | 无（窗口制，ACK/NACK 驱动滑动，掩码覆盖 ≤320 包） | 单在途（D-040）+ 100ms 心跳 | **自创行为**；单在途把"高频 delta 容忍丢失"变成"串行等待" | 输入包速率/在途数与官方 pcap 对齐（31/s 批量、无 1 包往返） |
| 4 | ACK 语义 | 累计收包水位+旧包重到触发+限流+时间回显（§45；撤回周期重发） | ihslib window.c 自实现 | 行为需逐项核对（互操作已通，疑似大体一致） | host ACK 延迟统计正常（≤99ms 已观测） |
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
| ACK | **累计**（连续收包水位 data[7..8]）+ 旧包重到触发 + 时间回显（§45，撤回周期重发） | 逐包 ACK（packetId+fragmentId+body 时间戳） |
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
- 网络样本取自连接统计：srtt(conn+732)、conn+1152/+1000（×float32系数
  0x3A83126F=0.001f）、丢包 = conn+1252×100.0/conn+1248。撤回旧“≈2^-10／
  µs→定点秒”的系数及单位推断；这些参数还需按实际collector逐一确认来源；
- `CFrameStatsAccumulator.Calculate()` 后扫描0..18共19种 accumulated_stats（撤回旧“最多20条”）
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
| 0 | →/← | 会话MTU探测 Unconnected(0) | ch0 明文 UDP | CDiscoveryPingRequest/Response；实际应答回显request对象，见§43，不能与首页发现合并 |
| 1 | →/← | Connect(1)/ConnectACK(2) | 明文 | 见 12.0 |
| 2 | → | ClientHandshake(6) | ch1 明文可靠 | CClientHandshakeMsg.info = CStreamingClientHandshakeInfo（network_test 等） |
| 3 | ← | ServerHandshake(7) | ch1 明文可靠 | CServerHandshakeMsg.info = CStreamingServerHandshakeInfo |
| 4 | → | AuthenticationRequest(1) | ch1 明文可靠 | CAuthRequestMsg{token=1(HMAC, 见 AUTH 文档), version=2, steamid=3} |
| 5 | ← | AuthenticationResponse(2) | ch1 明文可靠 | result；密钥协商完成（STEAM_REMOTE_PLAY_AUTH.md） |
| 6 | ← | NegotiationInit(3) | ch1 **加密**可靠 | CNegotiationInitMsg{reliable_data=1, supported_audio=2, supported_video=3, supports_remote_hid=4, supports_touch=5, os_type=6, gaming_device_type=7} |
| 7 | → | NegotiationSetConfig(4) | ch1 加密可靠 | 见 §5：config.reliable_data=回显宿宣告；audio=宿列表首个∈{1,3}；video=宿列表首个过 0x330+BAvailable；enable_remote_hid/enable_touch=宿宣告；caps=CStreamingClientCaps（video_codecs 恒 1 + 逐个 4/5/8/9）；streaming_client_config=本机配置 |
| 8 | ← | NegotiationSetConfig(4) | 同上 | host 确认（与本地不一致则 Assert） |
| 9 | → | NegotiationComplete(5) | 同上 | 空消息。状态→Streaming |
| 10 | → | KeepAlive(9) | ch1 加密可靠 | 空消息；正常Starting记时间后严格超过10秒发送；last=0是特殊分支，见§50 |
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
3. ACK：累计收包水位变化或旧包重到置pending，反馈到期发送并回显时间。
   **撤回原“1s内周期重发”要求**，完整客户端执行结果见§45。
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
撤回将last=0的立即发送分支当正常首发策略的结论；完整启动调用链见§50，其他裁定按§14具体边界理解。



1. host 侧超时的确切时长与条件：本二进制不含 Host 实现，不能证明存在所谓
   “弃洞”机制，更不能证明修正客户端后它“永远不会触发”；
2. `SendUnreliable` 的直接静态调用已追到 frame 分发与其调用者，见 §14.16。
   旧稿只搜索 `bl` 会漏掉尾调用 `b`，且不能由包装函数数量推断实际发送者；
3. OnSetQoS/OnSetTargetBitrate/OnVideoEncoderInfo 的接收行为见 §14.16；
4. CStreamingClientHandshakeInfo / CStreamingClientCaps 其余字段取值（Android 官方值）；
5. KeepAlive 首发不能只读last=0分支；正常Starting设时间及严格10秒边界更正见§50；
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
此外 `needed==0` 直接返回会在16位ID回绕处漏发NACK；0是合法包号。
本节只证明confirmed字段；§45进一步以真实客户端证明NACK base应为缺口之后
第一个已存在包，本例是102，不能继续把首个缺包101当作官方base。

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
因此可靠**发送方RTO**与Android调度时刻并非逐tick相同；可靠接收反馈改由
接收worker的Update驱动，详见§45。

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
| `src/session/channels/ch_control_negotiation.c` | 汇编：完整OnNegotiationInit 0x7ad698与原C++ SetConfig生产，§47–48；reliable值/presence、codec顺序及重复Init有固定对照。Raw视频等未实现能力与平台system_info单列。 |
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
`CPresetWidget` 构造函数 `0xc85d70` 的 UI 文本进一步将 preset=1/2/3
对应为 **Default / Enhanced 1080p / Enhanced 4K**；原指令复播与推荐入口见 §32。
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
本节 Android 样本本身**不能证明** Windows host 如何映射该字段及选择百分比。
新增 Windows x86/x64 的实际赋值、调用者和版本差异见 §30；不要再把这项历史
证据缺口理解为所有已取证样本都仍未知，也不要把 Android 的 connection 布局套到新 host。

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
| 普通不可靠发送 → 反馈 10 → 有限保留补发 | §25.3，SendUnreliablePackets/HandleNackPacket | §38接入普通缓存、标记、双轮调度与退休；不以可靠控制重传或FEC队列代替 |
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

【实现边界，见§38】统一sendQueue承担跨线程生产者交付；sender接入发送窗口后，
初发尝试和周期Update使用通道优先级、两类deadline和两轮不可靠发送。旧版“本地
只有FIFO且无整形”的描述不再代表当前实现。接收状态更新/媒体反馈仍由独立worker
执行，上行FEC队列、Connect重试和墙钟执行仍有独立边界；不能据此称整个官方
Connection::Update已等价。是否存在实际饥饿或一两秒停顿仍需负载/设备证据。

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
这里记录的是本节取证时的缺口。§30–31 后续加入两版 Windows host 的真实
控制链和跨二进制反例，并未恢复“整体实现就绪”的判断。

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
这只是本节 Android 证据的限度；两个 Host 的实际生效与切换反例见 §30–31。

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
本地普通可靠包由发送worker按通道调用16.16严格边界，见§37–38；`ProcessAt`
毫秒入口仅保留兼容用途。5ms timer只唤醒sender，后者还进行约1ms有界等待；
实际调用时刻仍不同于官方连接Update，不把条件相同写成墙钟逐tick一致。

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

## 30. Windows Host：FEC 激活、发送模式与版本差异

### 30.1 样本身份与可复核来源

【证据】从 Valve 官方更新 CDN 获取 manifest、校验 manifest 里的归档 SHA256，
再提取 `SteamUI.dll`。实际 streaming server 位于此 DLL，不能因为在
`steamclient.dll` 找不到 FEC 字符串就判断 host 不支持。

| 样本 | 清单版本 | 归档 SHA256 | DLL SHA256 |
|---|---|---|---|
| PE32 x86，基址 `0x3a000000` | `1769731672` | `8b712b2a3412a9066b7725f4e1c5cef9a7ca5b187b6585a5b92d25d09df0ba62` | `0cad7c69ace13e802be17beb06df299f7f733f01b4450a74bc68709494b21ddb` |
| PE32+ x64，基址 `0x13a000000` | `1791918634` | `2378aa4845fea7b08d3cc33a88db240db20e33cf8bb934f7f4037d89a1bac1e9` | `1b9457943205dc3af0bd53463ba331cbd2a381388699705c02271aac7a2b1252` |

来源是 [win32 清单](https://client-update.steamstatic.com/steam_client_win32)、
[win64 清单](https://client-update.steamstatic.com/steam_client_win64)，归档固定为
[bins_win32](https://client-update.steamstatic.com/bins_win32.zip.23e34a6d4b10596a44561a5100dac5585d2517da)、
[bins_win64](https://client-update.steamstatic.com/bins_win64.zip.0ed643edc3bd395674066241d556cd970f4bdc19)。
清单会更新，审计按上述内容哈希固定，不把较老 win32 包冒称为当前 win64 行为。

x86 embedded FileDescriptorProto 位于文件 `0xaaaad0`，长度 20634，SHA256
`eee83a5c4445e8fb1e394c600c0371ef99ac69062422002c74c7768c154c6bd8`；
x64 位于 `0xd55800`，长度 21827，SHA256
`9e7fd2cc5ce5496049014c8dc2195c9fcece4ef5b931b0cee684d084ecde53a4`。
两者字段 25 均为 optional bool、default=false。GF(256) 65536B 乘法表和 256B
逆元表与 §26 Android 表逐字节一致；x86 VA=`0x3aa2a3f8/0x3aa3a3f8`，
x64 VA=`0x13acb1580/0x13acc1580`。表一致之外，§31 还验证实际发包和恢复字节。

### 30.2 配置从哪里进入 Host

【证据】Android UI 的 `OnUnreliableFECChanged @0xc911a8` 更新配置 `+113`
和 hasbit，尾调用 `CShellApplication::SaveStreamingSettings @0xc99a98`；该保存
函数序列化/写设置文件，没有在函数内直接更改活动 connection。Fast preset
会预先写 true，故不能把“先观察到丢包”当作 FEC 的必要前提。
保存文件到串流核心启动/初始协商的完整静态链、其他预设与测试推荐条件见 §32；
不能据 Host 接受运行时消息 99 反推客户端 checkbox 自动发送 99 或主动重连。

客户端 `OnNegotiationInit @0x7ada6c–0x7ada9c` 将本地配置放进消息 4；
`SetStreamingClientConfig @0x7b01c4` 的串流中发送条件见 §29.4：client state=6、
bool 参数 bit0=0 才发 99。**协议/API 可更新，不等于该 UI checkbox 必然立即热更新。**

| 实际入口 | x86 | x64 | 已执行的前提与动作 |
|---|---|---|---|
| 初始消息 4，`CNegotiationSetConfigMsg` | dispatcher `0x3a16a4a0` → handler `0x3a16c870` | `0x13a1eca00` → `0x13a1ef170` | host state=6；required `config` 存在且 protobuf 有效；复制 `streaming_client_config` 后 apply |
| 运行中消息 99，`CSetStreamingClientConfig` | handler `0x3a16a882` | dispatcher 的 `case 99`，调用 `0x13a47cd90` | host state=7/8；解析成功才 CopyFrom → apply → 可选 delegate |
| Host 本地配置 setter | `0x3a171470` | `0x13a1f4d70`（静态调用链） | 先复制并 apply；x86 原指令复播还验证 bool=false 且 state=7/8 时向 client 发 99，bool=true 抑制发送 |

Host state 与 Android client state 是不同枚举，不要因为数字不同修改会话顺序。
x86 的消息 99 跳表索引从 80 开始，`0x3a16b138[99-80]=2`，
`0x3a16b0ec[2]=0x3a16a882`，不是只凭相邻字符串给 handler 命名。

【结论】这是客户端设置/请求驱动的实际接线，不是通过向 connection 人工写 flag
模拟“已启用”。两个固定 host 样本均能在运行中接收并应用字段 25。
这些 receive handler 没有发送 FEC 专用的接受/拒绝/回显消息；这不否认可靠控制
通道本来存在的传输 ACK，也不证明所有 delegate 都不会另发其他消息。

【证据】CopyFrom 先 Clear 再 Merge；x86 `0x3a388a60` 调用
`0x3a371460/0x3a38a0c0`，x64 `0x13a47cd90` 调用
`0x13a4620d0/0x13a47e420`。消息中给了一个不含字段 25 的空 config，
会恢复 false，**不是保留原值的局部 patch**。x86 坏 protobuf 不执行 apply、保留
上次值；固定案例区分省略字段的有效消息与字节截断的无效消息。

### 30.3 x86：连接级发送开关和固定冗余率

【证据】apply `0x3a171e40` 的 `0x3a17228b–0x3a172298`：

```text
connection = server[+0x18]
if connection != null:
    connection[+7] = server[+0x165]  // config(+0x11c) 的 bool(+0x49)
```

`SendUnreliable @0x3a166b70` 要求 connection state=1，读取该 byte；true 时
构造 type 11，取 channel `+0x18` 比例，调用 `AddPacket @0x3a163a30` 和
`Drain @0x3a1668f0`；false 时走 type 3/4 发送窗口。

真正的 percentage setter `0x3a167200` 只有两个已定位的直接调用者：
`StartAudioData @0x3a1715d0`（消息 50）在 `0x3a171856` 传 5，codec=3
（Opus）改为 0；`StartVideoData @0x3a171880`（消息 52）在
`0x3a171b06` 传 5。channel 构造 `0x3a162b40` 的默认比例是 0。
这里的 5 是 **5%**，不是每 5 片补一片，也不是以前审计注入的 20%/50%。

【结论与边界】已定位的音视频初始化采用上述常量，没有找到这些调用者按丢包率
改成 20%/50% 的证据；不能把这个有限的静态范围扩大成所有 host 都绝无自适应。
连接开关 true、Opus 比例 0 时仍用 type 11，只生成数据片，不额外生成 parity。
字段 25、选择 type 11 的模式、生成多少 parity 必须分别建模。

x86 apply 只赋 flag，不重置普通窗口或 FEC 队列；真实开关后分别 drain 已排队的
旧类型仍能发出。FEC → 普通 → FEC 不重置 FEC group ID。§31 明确区分此行为
与新 x64，不把“保留在途/排队数据”写成跨版本统一策略。

### 30.4 当前 x64：逐通道模式、Pyrowave/type 12 和模式清理

【证据】`ApplyConfig @0x13a1f5c10` 尾部读取 server 的 current video channel
`+0x2fe`、current codec `+0x248`、config FEC bool `+0x201`，调用
`SetChannelMode @0x13a1e82b0`：

```text
codec == 9 (Pyrowave) : mode = 2
否则 config.enable_unreliable_fec == true : mode = 1
否则 : mode = 0
```

`GetChannel @0x13a1e5b60` / constructor `0x13a1e31d0` 给新 channel 的
`+0x20` mode、`+0x24` percentage 均置 0。`StartVideoData @0x13a1f5580`
先分配 channel ID 再 apply，因此真实启动 H.264(4)/HEVC(5)/AV1(8) 时会将该
**视频通道**设为 0/1，Pyrowave(9) 则设为 2；`0x13a1f583c` 调用比例 setter 传 5。
`ChannelSend @0x13a1e7ad0` 实际读取 mode：0 → 普通 type 3/4，1 → type 11
和 RS，2 → type **12** 原始队列（`0x13a1e7800`），不是 type 11 的一种 shard。

【更正】“传输编号 12…127 没有入口”只成立于 §28 的 Android ELF，撤回其
可能被理解为所有官方版本 wire 全集的说法。此 x64 的 socket assert 接受
`type < 13`（`0x13a1f6c10`），确有 type 12 发送路径。

另一个实际模式来源是 host state=5 的消息 8（网络测试）：dispatcher
`0x13a1ecc68–0x13a1ecc74` 将 channel **3** 设置为 mode 1；该入口的调试线程
未在本节仿真中启动。不能由“field25=false”否认测试会话存在 FEC 包装。

x64 `StartAudioData @0x13a1f4f00` 仍给 Opus 0、其他音频 5 的 percentage，
但它没有设置音频 channel mode。固定新连接上的音频案例实际得到 mode 0、
type 3；不能用 percentage=5 推断音频已走 FEC，也不能把视频 mode 当作连接全局位。
复用 channel 的既有模式还须按实际先前状态解释。
该 percentage setter `0x13a1e8240` 的已定位直接调用点是视频的
`0x13a1f583c` 和音频的 `0x13a1f519d`；未发现这些调用者按丢包率改变比例。
这仍是固定样本的静态直接调用范围，不是任意版本/任意间接调用不存在的证明。

【证据】`SetChannelMode` 只有在新旧 mode 不同时调用
`ResetPreviousMode @0x13a1e5ab0`，再写新 mode：

| 旧 mode | 真实清理动作 |
|---|---|
| 0 | 清普通发送/重传状态；`ClearWindow @0x13a1e52b0` 将两个窗口重启到 sequence 0 |
| 1 | `0x13a1e7220` 释放旧 FEC 发送队列的 packet 引用 |
| 2 | `0x13a1e72d0` 释放旧 raw 发送队列的 packet 引用 |

重复设置同一 mode 不清队列。codec=9 时只开关字段 25 不会离开 mode 2，也不会
清 raw 队列。视频 channel ID 按 3…31 分配，超过 31 回到 3；StartVideo 停用
旧 channel 的优先级后在新 ID 上 apply，不因 codec 变化就清理所有旧 channel。
真实连续 29 次重启到 H.264，复用原来 Pyrowave 的 ID=3 时才触发该 ID 的 raw
队列清理。模式清理不是“在途网络包撤回”，接收端仍须能分类到达的旧类型。

【协议清单差异】x64 descriptor 相对 Android 样本增加 config 字段 36…40
（Pyrowave 相关参数）、`CStartVideoDataMsg.colorspace=6` 和
`CVideoFrameHeader`（frame_id/timestamp/codec/pixel_bits/YUV/colorspace/亮度/尺寸）。
两者已有字段 35 `enable_video_pyrowave`，故不能说 Pyrowave 这个 codec 名称到
x64 才出现。本项目 `ch_control_negotiation.c` 仅选择/声明 H.264 或可选 HEVC，
没有声明 codec 9；新增 descriptor 名称不等于必须让 Switch 支持该编码器。
相对 Android 的 codec 枚举，此 x64 descriptor 还移除了 VP8/VP9 的枚举项，不能
把任一旧客户端的枚举表当作所有 host 的编码能力声明。
从 codec=9 的 StartVideo API 到 type 12 已验证；其完整编码器选择、GPU payload、
codec 私有 parity/interleave 与新增 frame header 不属于这里的 type 11 接收契约。

## 31. Host 发包与 Android 接收的交叉验证、实现约束

### 31.1 原始指令复播与边界

```sh
python3 scripts/fetch-steam-host-audit.py \
  --output-dir build/video-recovery-re/official-host
python3 scripts/audit-steam-host-fec.py \
  --binary build/video-recovery-re/official-host/win32/SteamUI.dll \
  --output build/video-recovery-re/host-fec-activation.json
python3 scripts/audit-steam-host64-fec.py \
  --binary build/video-recovery-re/official-host/win64/SteamUI.dll \
  --output build/video-recovery-re/host64-fec-activation.json
python3 scripts/audit-steam-fec-interoperability.py \
  --host32-binary build/video-recovery-re/official-host/win32/SteamUI.dll \
  --host64-binary build/video-recovery-re/official-host/win64/SteamUI.dll \
  --android-binary build/video-recovery-re/libmain-arm64.so \
  --output build/video-recovery-re/fec-interoperability.json
```

需要 Python `unicorn`、`pefile`、`protobuf`；Android ELF 的取得/身份见 §24。
DLL 及归档保留在 ignored build 目录，不提交/再分发。固定参考分别为
`steam-host-fec-reference.json`（52 场景）、`steam-host64-fec-reference.json`
（37 场景）和 `steam-fec-interoperability-reference.json`（12 场景）。
脚本只比较固定参考，不在普通运行时生成或改写期望。

【证据】两个 Windows harness 执行原版的 frame 提取、protobuf parser、
generated CopyFrom、server dispatcher、apply、stream/channel 构造/设置、
RS/FEC 和队列处理，不再以 Python protobuf 替代 wire parser。
Python 只根据同一二进制内 schema 构造具名输入。
替身是分配/释放、OS 锁、日志/消息名、时钟、最终 socket send，以及出站
控制消息的加密和可靠发送；x64 还替换与 FEC 无关的平台 ID/码率上限查询。
`AssertFailed` 在 harness 中直接令案例失败，不通过吞断言使错误路径“通过”。

交叉脚本把 **Windows 实际生成的 datagram 字节**交给 Android 原版
Socket → Connection → Channel → Window/FEC/RS。地址匹配、分配、引用计数等
仍继承各 harness 的替身；没有认证会话、真实网络、视频解码、物理显示和并发证明。
它会额外复跑既有 36 个恢复断言及 71 个 Android FEC 案例作为基础装载审计。

### 31.2 5% 保护的对象和可恢复范围

【证据】两个 Host 经消息 99 和 H.264 StartVideo 的真实发包，对于相同输入，
type 11 的 header/meta/shard/parity 字节相同。MTU=1500、L=3000 时
S=1472、k=3、m=1，共 4 片；送给 Android 原版接收器：全到达、丢中间一片、
parity 先到都各交付一份**逐字节正确**的原 payload，丢两数据片则不交付。
这证明 5% rounding 后的实际保护能力，不是把审计注入的 50% 当作默认。

| 输入 L，MTU=1500 | k | m=`ceil(k*5/100)` |
|---|---|---|
| 100 | 1 | 1 |
| 3000 | 3 | 1 |
| 29440 | 20 | 1 |
| 29441 | 21 | 2 |

【结论】5% 是按传输组的 shard 数向上取整，并不保证每组恰好 5% 开销。
保护单位来自一次 SendUnreliable 的分组，不能未经上层 packetizer 证据就等同于
“一整个视频帧”。丢片数不超过 m 且总计有 k 个不同有效 shard 才可能恢复；
整组都丢、超预算、组被替换、或参考图像本来已损坏，不由 FEC 自动解决。
该用户“一两秒卡顿”的因果关系仍无设备日志支持。

### 31.3 动态开关的跨版本反例

【证据】交叉场景从新通道普通 sequence=0 开始，先交付 N=1 或 3 份普通
payload，再通过真实消息 99 开 FEC、交付一组，然后再用 99 关 FEC：

- x86 后续普通 sequence 从 N 继续，Android 原版继续逐份交付。
- x64 进入 FEC 时清旧普通窗口到 0，切回普通后也从 0 发。Android 保留的普通
  接收水位为 N，前 N 份被判为旧序号；发送到 sequence=N 时恢复交付。

这不是仅观察一个 Reset 函数后的猜测：固定 fixture 包含 Host 生成的每个
sequence、Android 接收水位和实际交付数。payload 为确定性字节，不声称已复现
H.264 参考依赖或真实 Steam UI 的热切换流程；客户端 UI 仅保存设置的路径见 §30.2。

【结论】撤回“消息 99 可更新配置，所以运行中可以随时无缝开关 FEC”的推论。
Host 接受字段、发送器已切模式、对端接收水位兼容，是三项不同条件。
这里已经出现实际跨版本反例，不能以“旧队列保留/清掉即可”代替对端状态同步。
也不能把这当成现有用户停顿的根因：当前本项目并未请求字段 25=true。

### 31.4 接线约束

依据上述直接证据，type 11 接收实现的边界为：

- 先具备独立 type 11 分组/RS 和唯一 shard 计数，再按 §32 官方设置来源在初始
  协商携带字段 25；不以“实现了接收能力”为理由强制该字段恒为 true。
  不在包头 parser 尚拒绝 11 时先发 true；不以本机 outgoing flag 拒收 host 的 11。
- 启动时按本机能够实现的 codec 宣告能力。H.264/HEVC 的 type 11 与 Pyrowave
  的 type 12 分开；未知类型/codec 保持明确的不支持路径，不把 12 当 11 猜着解。
- 配置收到/发送使用完整配置语义；省略字段会恢复默认。发送反馈、连接 ACK、
  FEC 开关和比例不合并；5% 由这里的 Host 决定，不自创一个客户端协商 percentage。
- 不据丢包率自行热切字段 25，也不因收到 99 就重置本地全部接收序号。
  §31.3 的反例只否定无条件无缝切换的推论；它不证明官方主动重连、重建通道
  或重置对端水位。动态行为须追到官方客户端实际触发/处理入口，不能自行补一套策略。
- FEC 失败后仍按已核对的媒体序列/关键帧恢复处理完整组，不向 decoder 投喂
  未补齐 payload；保留 §26 原版重复片错误交付的反例作为项目必须防护的输入。

这些约束限定 type 11 的接收/启动声明及已取证控制链，不恢复整体协议、所有
平台/版本或生产集成的就绪判断。SNS/SDR、Pyrowave 私有编码、真实背压和 Switch
解码/显示不被这些指令复播代替。

## 32. 官方客户端 FEC 策略：设置、测试推荐与启动链

### 32.1 材料与结论更正

【证据】官方 Android 1.3.32 ARM64 同一安装包内的两份库：

| 材料 | SHA-256 | 本节用途 |
|---|---|---|
| `libshell_arm64-v8a.so` | `15b2d79881eef0c47ed2f96c17d1d60a5f42d3285abcf9f512cfffdac5b238a2` | Qt 设置页、预设、连接前网络测试、保存/启动参数 |
| `libmain.so` | `50e1d3147d5d47b71ef1970e1867a2fe4f3e1ecf2ea6153f927fac88b88ea38e` | 读取设置、串流核心的消息 4/99 |

【撤回】“中途改变 FEC 就重建会话”是项目侧的建议，没有官方客户端入口证据，
不作为官方策略或实现要求。§31.3 的 Host/Android 交叉反例也不能证明官方这样做。
同样，具备 FEC 接收器不意味着官方默认恒开，不能据此把初始字段 25 强制改为 true。

本节的“官方”明确限定为以上客户端样本。UI 中已有入口的静态链与原指令复播，
不扩大为所有官方平台/版本、不存在任意间接调用的证明，也不等于实机抓包。

### 32.2 用户入口与预设的实际 FEC 值

【证据】`OnUnreliableFECChanged @0xc911a8` 将 QString 新值转为 uint，
以 `value != 0` 写 panel+313（config+113），置 hasbit `0x4000`，尾调用
`SaveStreamingSettings`。`OnPresetClicked @0xc9182c` 在点击对象不是当前活动
预设时，读 widget+48 的预设编号，执行工厂 → Save → UpdatePresetState。
点击当前活动预设直接返回。

`CPresetWidget::CPresetWidget @0xc85d70` 明确包含下表三个 UI 名称。
工厂和保留 helper 的地址为 `0xc8562c/0xc85b74/0xc85868`。

| 实际入口 | FEC 结果 | 相关配置 |
|---|---|---|
| 手动设置 FEC=0 / 非 0 | false / true，并显式置字段存在位 | 保存用户选择 |
| preset=0 | 保留输入值 | 不 Clear；不对应本节三个有名按钮 |
| preset=1，Default | false，字段不存在 | Clear 后的默认 quality=Balanced(2) |
| preset=2，Enhanced 1080p | true | quality=Beautiful(3)、HEVC、1920×1080 限制 |
| preset=3，Enhanced 4K | true | quality=Beautiful(3)、HEVC、3840×2160 限制 |
| `CreateStreamingConfigFastPreset` | true | quality=Fast(1)、HEVC；是网络测试推荐的工厂，不能等同于 Default 按钮 |
| 没有设置文件 / ResetStreamingSettings | false，字段不存在 | 配置默认值；Reset 还保存结果 |

helper 保留硬解/音频/输入/窗口等部分字段，**不覆盖 FEC**；所以不能声称工厂
设置 true 后又被旧 FEC=false 恢复。预设的其他 codec 字段不代替 Switch 能力探测，
不能为了复制 FEC 策略宣告本机没有的 HEVC/4K 能力。

### 32.3 哪种网络测试会推荐、什么时候保存

【证据】`SetPanelStateNetworkTest @0xc7029c` 读取已保存的
`desired_bitrate_kbps`，决定 panel+272 的测试 mode：

| 带宽设置 | mode | panel+600 的测试目标 kbps |
|---|---|---|
| -1，自动，quality=1/2/3 | 2 | 10000 / 15000 / 30000 |
| 0，无限制 | 2 | 250000 |
| 明确正值，例如 20000 | 1 | 该正值 |

这个分支由带宽设置决定，不是由 FEC 开关决定。表内值是客户端给测试的目标，
不是本项目应固定使用的串流码率。`CNetworkTest::StartNetworkTest @0xcaa778`
发送消息 8；其中字段 5 叫 **bandwidth_test**，取 `mode == 2`，不是 FEC 请求位。
Host 为测试设置 FEC 的另一个入口见 §30.4，不能混成正常会话字段 25 的自动调整。

【证据】`HandleNetworkTestComplete @0xc71078` 先将 recommendation
（panel+704）清为 0，再区分测试模式。mode=2 的 `0xc711dc–0xc71468`：

| 测试结果 panel+596，kbps | 当前 quality | recommendation / 对话框 |
|---|---|---|
| <100000 | 已为 Fast(1) | 0，不推荐修改 |
| <100000 | 不是 Fast(1) | 1，询问是否优化为 low bandwidth |
| ≥100000 | 已为 Beautiful(3) | 0，不推荐修改 |
| ≥100000 | 不是 Beautiful(3) | 2，询问是否优化为 high quality |

单位由同一函数的 `"Streaming bandwidth test successful up to %1 Mb/s"` 与
`value / 1000` 交叉确定；因此 100000 对应 100 Mb/s。该值所在成员还由
`CNetworkTest::OnSetTargetBitrate @0xcab700` 从 `CSetTargetBitrateMsg.bitrate`
记录；不能把这个门槛改写为实测丢包率或所有网络质量的总评分。

mode=1 的丢帧/网络波动评分经 `CNetworkStats::GetResult @0xca930c` 选择结果
说明，不写 recommendation=1/2，也不直接保存 FEC；复播包含零丢帧、轻微丢帧、
10% 丢帧和完全没收到帧。不能从“网络结果不好”泛化出必然开启 FEC。

【证据】结果页把 `finished(int)` 连到
`OnNetworkTestComplete(int) @0xc72164`。有推荐时显示 OK/Cancel；只有
`result == 1` 且 recommendation=1/2 时，才 Load → 应用预设 → Save：

- recommendation=1：`CreateStreamingConfigFastPreset`。
- recommendation=2：`BCanDisplay4KVideo` 为真选 preset=3，否则 preset=2。
- 取消，或 recommendation=0：不改/保存配置；既有 FEC=false 可以继续保持 false。

确认值也来自此客户端自身：`CPanelDialog::accept @0xc7ec28` 发出
`accepted` 和 `finished(1)`；`reject @0xc7ec60` 发出 `rejected` 和 `finished(0)`。
不是仅凭 Qt 常规约定把数字 1 命名为“用户确认”。

之后关闭结果页、保存网络统计。处于连接流程（panel+208=3）时，清掉本次测试
标志 panel+212，再回 `SetPanelStateConnecting`；另一个入口（=2）返回应用状态。
这是连接前测试结果页的流程，**不是运行中改变 FEC 强制断线重连**。

### 32.4 保存值如何进入串流、消息 99 能证明什么

【证据】保存/启动/核心链如下，各地址仍分别属于各自库：

1. shell `SaveStreamingSettings @0xc99a98` 序列化 config，向 storage path 的
   `streaming_settings.bin` 调用 BSaveFile；其完整成功/失败分支没有调用活动
   CStreamClient、发送配置消息或启动重连。
2. shell `StartStreaming(QStringList) @0xc98f08` 重新 Load；
   `BUpdateStreamingSettingsForCodec @0xc9d7f8` 补 codec capture limit，
   不改 FEC。随后 helper `0xc9de50` 构造
   `streaming_client --settings <storage>/streaming_settings.bin ...` 参数。
   `0xc99780–0xc9980c` 保存启动参数、标记 s_bStreaming 并退出 shell Qt 主循环。
3. core `SDL_main` 的 `--settings` 分支 `0x75b588–0x75b63c` 调用
   `SetSettingsFile @0x7a5a28`；无指定路径时 `0x75c418–0x75c484` 使用同名文件。
   setter 调 `LoadStreamingClientConfig @0x7a5a50`，解析到 client+456。
4. core `OnNegotiationInit @0x7ada6c–0x7ada9c` 把这个配置复制入消息 4。
   Host 如何接收并应用字段 25 已在 §30 的原指令案例中独立验证。

【证据范围】固定 core 的 LoadStreamingClientConfig 直接调用点只有
SetSettingsFile；SetSettingsFile 的两个直接调用都在 SDL_main。
已枚举 `SetStreamingClientConfig @0x7b01c4` 的 13 个直接/尾调用，涉及 Init、
桌面/窗口尺寸、缩放、降低视频分辨率、性能浮层、麦克风和 player delegate；
这些已定位调用不是“丢包率触发 FEC 开关”的入口。这个范围不覆盖未知间接
调用或其他版本，不能把未发现说成全局不存在。

运行时消息 99 仍是官方真实配置通路，不能删除：client state=6 且 bool bit0=0
才发送；incoming 99 CopyFrom/通知 delegate/保存，见 §29.4。**完整配置中的 FEC
应跟随已有值**；改变窗口、麦克风等其他字段时，不应因省略字段 25 意外关闭 FEC。
API 能更新配置不能推导为 UI 热切换；也没有客户端证据支持项目主动添加
“丢包自动开关、自动重连、收到 99 就清全窗口”的策略。

### 32.5 原始指令复播与边界

```sh
python3 scripts/audit-steam-client-fec-policy.py \
  --binary build/video-recovery-re/libshell-arm64.so \
  --output build/video-recovery-re/client-fec-policy.json
```

需要 `unicorn`、`pyelftools`，材料 SHA 在入口固定校验。
`scripts/fixtures/steam-client-fec-policy-reference.json` 固定 73 场景：
10 个预设、3 个手动 FEC、9 个测试 mode/目标选择、9 个 100000 边界/quality、
4 个固定码率丢帧评分、12 个预设点击、缺文件/Reset 各 1、24 个确认/取消回调。
所有场景都从相应完整官方函数入口进入，未替换推荐条件、preset 写值或
generated config 构造/复制/Clear；不是直接注入 recommendation 后就宣称触发链完整。
确认回调的 recommendation 输入由独立结果页场景核对。

替身为 Qt 渲染/字符串值/平台能力、分配/析构、已完成的 protobuf 进程初始化、
空 repeated limit 容器操作、文件输入/保存边界，以及后续连接/页面切换。
预设的嵌套 resolution limit 构造仍执行原版指令。完整 Save/启动参数/core Load
链在本节为静态反汇编证据，**不是本脚本的端到端文件/wire 测试**；也没有真实
Qt 事件循环、Steam 认证会话、并发、Switch 解码或显示的证明。

## 33. 类型 11 接收与用户设置的接线契约

### 33.1 接收边界与官方策略

`third_party/ihslib/src/session/fec.c` 独立处理 §26 的传输组，
`packet.h` 明确命名类型 11，未知类型 12 不进入 FEC。包头拒绝未知类型的旧实现
与官方连接保活顺序存在差异，撤回“包头直接拒绝即对齐”的含义，修正见 §34。raw datagram 经
SessionRecvCallback 的地址/连接 ID 检查后进入媒体 channel；早到的 type 11
与普通媒体一起等待 Start*Data 确定 channel 身份，不猜 codec。

- 一条 channel 一个活动 FEC 组，以最近已交付组为水位，uint16 差为 1…32767
  才接纳。不同有效组替换未完成组，包括晚到的旧未完成组；不自行增加多组窗口。
- 从 L/S 计算 k，检查完整的 8+S 字节 shard body；按唯一 index 收集。
  系统数据全到即交付；缺数据且有 k 个不同 shard 才执行同一 GF(256)/Cauchy
  码字的恢复。实现只求解缺失数据列，不改变官方系数、数据分片或 parity 字节。
- 输出沿用首个有效 shard 的传输 header（type=11、组 ID 和时钟），媒体 frame ID
  仍由内部信封解析。FEC 不进入普通类型 3/4 窗口，不推进普通水位、更新时间回显
  或产生类型 10 NACK；FEC 序号和媒体 frame ID 也不混用。
- 组替换、未达恢复门槛或解码失败不交付不完整 payload；不增加同组 shard
  重请求定时器，不据失败自行切字段 25、清普通窗口或重连。

独立 C 实现从多项式 0x11d 生成乘法/逆元表，没有复制二进制表或依赖一个仅名称
相同的通用 RS 库。parity 非零的 k+m≤255；m=0 不进 RS，支持包含 65536 个数据
shard 的 16 位 index 全范围（index=65535），不能把 index 当有符号 fragment count。

### 33.2 有界资源与明确的实现差异

以下是本项目的边界，不能标为原客户端逐指令等价：

- `IHS_FEC_MAX_PAYLOAD=2MiB`，拒绝零长、过大、无效 index、坏 shard 长度及
  同组元数据变化。输入先校验再替换组；失败分配不交付。parity 组上限约束也限制
  矩阵尺寸，m=0 的总 shard 数最多 65536。
- 按唯一片计数，重复片不改变已存数据或满足 k；检查恢复成功才交付。
  这是对 §26.4 原版重复计数错误的有意防护，不复制其错误 payload 上交行为。
- 重建结果通过既有媒体 worker 消费；不在收包线程调用 decoder。受 windowLock
  保护的完成 FIFO，项数≤windowCapacity，分配字节（含节点）≤windowCapacity×2048。
  超预算淘汰最旧完整项；单项超预算或分配失败直接释放。这是线程桥的背压资源策略，
  不是 Steam 的额外网络补包算法。视频后续帧 ID 的断裂仍由既有恢复层处理。
- worker 停止/唤醒/join 后才释放 FIFO、活动分组、GF 表、接收窗口及锁。
  不增加 detach 线程，也不把 stop 后的 packet 留在组或 FIFO 中。

### 33.3 手动开关、默认值与持久化

应用 **设置 → 网络纠错** 对应官方 `OnUnreliableFECChanged` 已取证的保存入口。
默认关闭；改动保存为 profile v5 的 `unreliable_fec`，由启动 command 交给 runtime，
配置回调赋给 `IHS_SessionConfig.enableUnreliableFec`。首次协商 true 时显式写字段 25；
false 时使用 optional 默认值。串流中改设置只保存供下一次用户正常连接使用，
不由设置动作主动重连。该开关不设置百分比，也不是接收 type 11 的本地准入开关。

旧 v2/v3/v4 配置迁移的 FEC 值为 false；v4 的设备身份、逐主机授权密钥、画质和
码率逐字段迁移。不能把旧结构 padding 解释成新开关，也不以升级为由重新生成密钥。
现有画质偏好仍与 FEC 独立：Fast quality 枚举不等于 §32 的 FastPreset 工厂。
§32 的官方增强预设/网络测试推荐不由这个手动开关代替，也不因支持接收而隐式应用。
运行时完整配置 99 和它的产品触发仍按 §29/§32 的契约分别核对。

### 33.4 验证入口和证明范围

```sh
cmake --build build/desktop -j4
ctest --test-dir build/desktop --output-on-failure
python3 scripts/check-steam-fec-receiver.py \
  --receiver build/desktop/third_party/ihslib/tests/session/ihs-fec-oracle
python3 scripts/audit-steam-fec-interoperability.py \
  --host32-binary build/video-recovery-re/official-host/win32/SteamUI.dll \
  --host64-binary build/video-recovery-re/official-host/win64/SteamUI.dll \
  --android-binary build/video-recovery-re/libmain-arm64.so \
  --native-receiver build/desktop/third_party/ihslib/tests/session/ihs-fec-oracle \
  --output build/video-recovery-re/production-fec-interop.json
```

`fec_official_vectors` 用固定官方 k3/m2 全片字节验证 2-erasure 的全部 60 种幸存
顺序和全片的 120 种排列，并覆盖不足 k、重复、元数据冲突、组回绕/替换、CRC、
类型 12 不交付 FEC 及 m=0 超过 255 片/完整 16 位 index。期望来自官方固定向量，不用
本地编码器生成 parity 再证明自身正确。
坏元数据和 m=0 的大分组边界由测试构造，不冒充官方发送器导出的字节向量。

跨二进制脚本在既有 12 场景之外，将其中 8 个 Windows 5% FEC 场景的真实发包字节
同时交给本地 receiver，对照官方 Android 的恢复 payload；原版配置 parser/apply、
发包及 RS 仍执行，不把手写 codeword 当作 Host 发包证明。

`fec_channel` 从 raw datagram 进入 session，覆盖早包缓存→添加 channel→媒体
信封→真实 worker 的 dataFrame 回调，解码阻塞时 FIFO 上限、无 FEC NACK、普通
sequence=0 未被 FEC ID 消耗及 stop/join 清理。回调为受控消费者，**不是 H.264
图像解码或屏幕显示**。`client_capabilities` 解密真正排队的消息 4，核对 false/true
字段 25；UI 测试核对保存/command、迁移和不主动重连，不能合称认证会话实测。

CTest、sanitizer、Switch 交叉构建分别证明对应的 CPU 路径、内存/并发检查和构建
兼容性；不能据此声称 Switch 上的纠错时延、负载下输入/显示、所有协议策略或原用户
停顿已经验证。普通发送缓存/补发、可靠媒体、完整配置更新、MTU/CRC/暂停/调度
等契约依然独立于 type 11 接收，不以这个接线覆盖其他层。

## 34. 官方连接准入、MTU 和生命周期的生产契约

### 34.1 证据来源和接收时间的先后顺序

【证据】本节依据官方 Steam Link Android 1.3.32 ARM64 `libmain.so`，SHA256
`50e1d3147d5d47b71ef1970e1867a2fe4f3e1ecf2ea6153f927fac88b88ea38e`。
沿用 §28–29 的 Socket/Connection 原指令复播；新增 `transport_lease` 八个输入，
原有 181 个 input/observed 保持不变。固定参考保存完整 datagram，原版地址比较、
channel 查找、delegate 回调和最终网络 I/O 的替身范围仍然适用。

`Connection::HandlePacket 0x7fae30–0x7fae64` 的 Connected 专门分支先刷新
`last_receive`，随后 `0x7faefc` 才调用 HandleConnected。后者在
`0x7fbef4–0x7fbf58` 检查 state=0、去 CRC 后总长=17B，成功才设置 peer ID、
CRC 要求并通知连接完成。**刷新连接计时与完成握手是两件事**：已匹配的短/长包和
重复 Connected 仍可刷新时间，但不能重复握手。普通数据在
`0x7fb094–0x7fb09c` 检查 channel<32，之后才在 `0x7fb0d8` 写接收时间。

Socket `HandleMessage 0x7ff660–0x7ff6f0` 将 channel=0 的 type0 直接交
`HandleUnconnectedPacket 0x7fbd14`，该函数只转发 delegate，不刷新连接时间。
§29 已核实 type9 在普通数据 CRC 要求之前分派；它自己带 CRC 时仍须通过算术校验。

【结论】普通未知编号 12–127 虽然没有媒体处理入口，只要通过地址/ID、channel
和连接 CRC 要求，仍会刷新连接时间。撤回将“没有处理入口”扩大为“Socket 可在
包头直接拒绝”的解释。`packet.c` 现在解析七位编号并验证 CRC；`session.c` 完成
连接准入和刷新后丢弃未知编号，**不把 type12 当 FEC 或可解码的视频**。
八个新增原版场景涵盖重复 Connected 的 3/4/5B body、channel31/32/255、未知12、
discovery。channel31 在官方 harness 中有查找替身，本地没有该通道，因此这组只
比较连接时间和不重复握手，不拿替身的 channel 回调数量冒称生产媒体交付一致。

### 34.2 MTU 和 Connected CRC 的接线

| 官方条件与动作 | 项目生产入口 |
| --- | --- |
| state2 + control7 + 有效 required info：optional int32 mtu（省略为0）有符号限制到512–1472，再开始认证；`0x7a64cc–0x7a64f8` | `ch_control.c::OnServerHandshake` 经真实可靠重组和 protobuf parser 进入；错误状态/消息/通道/缺 required info 不应用 |
| Connected 去尾 body 恰4B，连接尚未建立；记录 peer ID、CRC bit、echo 并开始 ClientHandshake | `ch_discovery.c::OnConnectACK`；重复包不再次开始握手 |
| 已协商 required CRC 的普通数据不能无 CRC 进入；错误 CRC 在 Socket 更早拒绝 | `session.c::SessionRecvCallback` + `packet.c`；type9 单列，不套普通数据条件 |
| 发送时按连接要求附 CRC | `IHS_SessionSendPacket` 在最终填头/CRC 前补 suffix；保留调用者原有 CRC 标志 |

MTU 初值1024来自同一 ELF 初始化；握手缺字段得到512，不再取1500。
项目保留每 session 的 MTU，官方该值是进程全局；这是明确的存储范围差异。
connectionState、MTU、双方 ID、CRC 要求由接收路径更新，又被发送/重传路径读取，
以 C11 atomic 保存；接收时间/暂停状态由接收 worker 拥有，不给 UI 线程直接修改。

`check-steam-transport.py` 把固定官方输入交给 `ihs-transport-oracle` 的真实收包
入口，不直接调用 clamp。MTU 的10个值另外排队4000B受控明文，核对生产分片数量、
每片线上长度和完整字节；较大测试 frame 显式扩充 fixture 缓冲区，不改变生产包上限。
CRC 测试从 Connected 进入，再实际序列化一个未预置 CRC 的上行包，核对要求位、
长度和 CRC32C。这里没有声称所有发包构造入口或时间戳统计都已逐条等价。
上行附 CRC 的官方来源是 `Socket::Send 0x7ff1dc`，§29.4 的45个原指令预算场景
亦执行了该分支。撤回此处原先按CRC要求位选择分片容量的实现假定：Socket测试
没有证明入窗分片的计算规则。§42的原指令全链确认，无论该位为0/1，普通分片
容量均为MTU−17；预留空间和是否真的发送CRC是两个独立决定。

### 34.3 暂停、恢复和连接 deadline

【证据】官方 `Client::Pause 0x7b02bc` / `Resume 0x7b0384` 与
`OnStreamResumed 0x7fb99c` 的条件和顺序见 §29.3；普通/暂停15/180秒阈值
见 `Connection::Update 0x7fc43c`。`SendDataLost 0x7abd4c` 发送空 frame IDs
的 type2 媒体信封，audio/video channel ID 来自 client 字段；Start* 前初始为0，
不以 decoder 对象存在为发送前提。

`application.c::event` 仅由 SDL 0x103/0x106 逐事件发布协议前后台边缘，不把桌面
window focus/minimize 或 SDL 0x104/0x105 额外推导为协议 Pause/Resume。Switch 的
焦点适配仍由 `events.c` 合成0x103/0x106；实际系统行为须设备验证。
`sl_runtime_foreground` 将前后台变化写入 atomic generation，偶数为前台；重复值
不生成事件。runtime worker 按序将变化交给 `IHS_SessionSetForeground`，接收
worker 的 `lifecycle.c` 执行动作。同一轮间快速后台→前台保留两条边缘；UI 热路径
没有网络发送、锁等待、decoder reset 或日志。新 session 按当时前后台状态初始化，
不向新连接重播此前其他会话的历史事件。

生产动作保持原版顺序：

- 首次 Pause：已连接且串流时排队122；标记 connection paused；最终标记 client paused。
- Resume：已暂停且连接仍成立时清 connection paused，用连接**上一轮 update 时间**
  刷新 last receive/echo；串流中依次排队123、audio DataLost、video DataLost；最终清
  client paused。没有相应媒体 channel 时使用初始 channel0，不销毁解码器。
- 接收循环 update 用 uint32(now−last_receive) 比较15或180乘65536，达到阈值即
  发起本地断连；不会将本地超时写成 HostRequestedStop。

这里刷新的是 `clock.lastEcho`，即后续 `ProcessTimestamp` 准入实际使用的水位，
不另存只供展示的副本。官方 constructor `0x7fb28c–0x7fb290` 也用当前时间初始化
该水位；项目在 TransportBegin 时初始化。Resume 后构造旧 echo 验证−200被拒、
−130边界接受；这只核对水位衔接，不代表统计窗口淘汰和均值过程已全部等价。

这些动作在既有接收 worker 的 recv 轮询中执行，没有新建脱离生命周期的线程。
每个 worker 每轮最多处理32条边缘，积压留到下一轮；这是项目避免热路径阻塞的
执行机制，不宣称与官方 SDL 主循环的墙钟调度逐 tick 等价。socket 的10ms轮询
不是连接超时。旧接线曾复用约1.1秒的重复断连timer；该做法与官方分层不同，
按§40的Disconnect/Close契约撤销，接收超时改走连接层、下一Update通知并停止worker。

接收错误退出路径先 Interrupt 唤醒发送队列，再 join send worker，避免空队列下
无限等待。session Destroy 继续停止/join timer 和媒体 worker，再释放各自依赖。
应用现有视频首帧/空闲 watchdog 与这里的连接 deadline 分属不同层，没有把它们
解释成官方15/180秒策略。系统真正暂停线程后的时序仍需 Switch 设备证据。

### 34.4 验证契约和边界

```sh
python3 scripts/audit-steam-protocol-triggers.py \
  --binary /path/to/official/libmain-arm64.so \
  --output build/video-recovery-re/transport-official-recheck.json
python3 scripts/check-steam-transport.py \
  --receiver build/desktop/third_party/ihslib/tests/session/ihs-transport-oracle
ctest --test-dir build/desktop --output-on-failure
```

官方原指令189个场景与固定参考比较；本地连接入口98组包括官方 Connected/CRC/
MTU/Pause/Resume/lease 参考、10个MTU边界及实际分片、发送 CRC、deadline前/等于/
后、uint32回绕和快速前后台事件。最后一类及资源边界是受控构造输入，不冒充实机
网络事件。Pause/Resume 核对真正排队的消息编号、加密空 protobuf 和 DataLost 顺序；
本地最终断连动作为记录替身，时间和媒体消费者也受控，不是屏幕渲染证据。

`transport_worker` 另行启动真实收发 worker，合成 Connected 后使虚拟时间依次走到
阈值前一tick/阈值，经过真实断连 timer、回调和 join；分别覆盖前台/后台。第三个
输入模拟致命接收错误，验证发送 worker 被唤醒且两线程结束。它不使用外部 Steam
主机，不把 CPU 测试当作真实会话抓包。

本节只定义这些连接分支。完整配置99、调度整形、发送缓存、可靠媒体及完整 RTT/
时钟采样窗口仍需各自的官方客户端证据和接线验收，不能从这里推导整体等价。

## 35. 官方客户端完整配置值与消息 99 的双向契约

### 35.1 原指令来源与字段映射

【证据】仍固定 Android 1.3.32 ARM64 main，SHA256
`50e1d3147d5d47b71ef1970e1867a2fe4f3e1ecf2ea6153f927fac88b88ea38e`。
`audit-steam-client-config.py` 使用同一包的嵌入 schema 构造输入，但不代替其解析：
queued packet → 原版 CStreamFrame 构造/Get → 原版 C++ ParseFromArray、
IsInitialized、CopyFrom、序列化及 client dispatcher 均实际执行。
34 个独立字段输入还记录原版 parser 对对象内存的写入差异，避免按成员邻接猜字段。

| 字段 | 官方 C++ config 值偏移 | has 位 / 默认值 |
| --- | --- | --- |
| enable_unreliable_fec（25） | +113 | has word +16 的 bit14；false |
| enable_hardware_decoding（7） | +156 | bit28；true |
| enable_input_streaming（11） | +159 | bit31；true |
| enable_audio_streaming（10） | +158 | bit30；true |
| enable_video_streaming（9） | +157 | bit29；true |
| enable_performance_overlay（8） | +104 | bit8；false |
| enable_microphone_streaming（15） | +106 | bit10；false |
| windowed（27） | +115 | bit16；false |

【撤回】把播放器读取 config+156 的分支解释成 windowed 的临时推断不成立。
原版 parser 实际把 hardware decoding 写到+156，windowed 写到+115；后续 decoder
reset 的判断必须用这一映射。它也不能作为“切换 FEC 会重置 decoder”的证据。

### 35.2 本地 setter：复制、通知、保存，然后按条件发送

【证据】`CStreamClient::SetStreamingClientConfig 0x7b01c4–0x7b0290`：

1. CopyFrom 输入到 client+456（`0x7b01f4`）；这是完整值，不是 patch。
2. delegate 存在则调用 vtable+128，传存储值及 bool 参数的 bit0
   （`0x7b01f8–0x7b0210`）。
3. 调用 SaveStreamingClientConfig（`0x7b0218`）。
4. 仅 bool bit0=0 且 client state=6，才构造 CSetStreamingClientConfig，复制
   **原输入引用**并发送99（`0x7b021c–0x7b0264`）。其余状态依然复制/通知/保存。

setter 的 bool 不是 FEC 值，也不是 host 接受结果。固定案例包含 ABI 值0/1/2/3，
2 的 bit0=0、3 的 bit0=1；普通 C/C++ bool 调用者只应传规范0/1，本地 bool API
只对照这两者，不拿 C 的 true 宣称可以模拟非规范 ABI 值2。

【证据】`SaveStreamingClientConfig 0x7a5b34–0x7a5c20` 先检查 client+144
文件名指针及首字节。为空则返回；非空时 SerializeAsString 完整配置，按
ByteSizeLong 把原始 protobuf 字节放入 CUtlBuffer，再调用 BSaveFile。文件不带
99 编号、外层 CSet 消息、传输头或额外长度前缀。写失败只 Warning，不回滚配置。
该文件 I/O 过程的证据是反汇编；配置审计中的 Save 调用是记录替身，不是磁盘测试。

### 35.3 接收 99：缺字段回默认；delegate 可能产生后续动作

【证据】queued dispatcher 只在 client state=6 进入
`OnSetStreamingClientConfig 0x7af08c–0x7af13c`。原版 Get/ParseFromArray 成功，
且 required config（及嵌套 required mode 宽高）满足后，CopyFrom → delegate(bool=true)
→ Save。坏 protobuf、缺 required config、无效嵌套 mode 都保留旧值、不通知、不保存。
空 **config** 是有效值，会把已有 FEC=true 恢复 false，已有 input/audio/video=false
恢复各自默认 true；空 **外层消息** 缺 required config，是无效值。两者不能混同。

【结论】§29.4 的“接收 handler 自身没有设置 connection outgoing FEC”仍成立；
不能把它扩大成“接收99绝不会再发送控制消息”。实际
`CStreamPlayer::SetStreamingClientConfig 0x7c5504–0x7c55ec` 的九个正反例显示：

- overlay 比较实际值（包括省略后的 false），变化则更新播放器统计浮层状态。
- hardware decoding **has 位存在**且值与播放器旧值不同，调用
  ResetVideoDecoder(false)。该字段省略时不以默认 true 强制触发此分支。
- microphone 实际值变化：有旧 audio stream 则销毁，shutdown microphone encoder，
  修改当前 config 的 microphone 字段/has 位，再 SetStreamingClientConfig(false)，
  最后 BOpenMicrophone。嵌套 setter 会再次通知/保存，并在串流中发送99。
  外层接收 handler 返回 delegate 后还会保存一次。
- 仅 FEC 改变的输入不触发 decoder reset、麦克风重开或嵌套99。

例如 incoming config 的 microphone=true，从旧 false 变化时，原指令动作依次是
notify(true) → microphone shutdown → notify(false) → save → send99 →
microphone open → save。最终 send99 保留同份完整配置中的 FEC；这不是 FEC ACK。
麦克风设备的实际打开、音频转换器和 codec 重置均为尾部替身，只证明条件及动作顺序，
不证明设备操作成功。不能因不存在麦克风外设而删掉协议/API分支，也不能假装 Switch
已实现这些 Android 播放器行为。

### 35.4 生产完整值、所有权和协商复用

`session/client_config.c` 在 base 的递归锁下保存 owned CStreamingClientConfig，
通过 protobuf-C pack/unpack 深复制字符串、嵌套/重复结构及 unknown fields。
`IHS_SessionSetStreamingClientConfig` 接受独立的完整 protobuf 值；接收99以
localOnly=true 调用同一应用逻辑，核心不会无条件回显、重连或清接收窗口。
input/audio/video 状态按完整值的有效默认值刷新，并以 atomic 提供给其他线程。

库 callback 顺序为 clientConfigChanged → saveClientConfig → 条件发送99。
callback 字节只在调用期间有效；持久化消费者必须复制后排队，不能在 RX worker
同步做文件/设备操作。delegate 可以递归调用配置 API；保存取 delegate 返回后的
当前值，发送则取本次 API 的独立输入。这与官方 setter 传独立输入对象时的行为
一致；该 serialized-value API 不暴露 C++ 内部对象的可变别名。
`GetStreamingClientConfig` 返回所需长度，目标容量不足时不写入。

初始协商从存储的完整值深复制出本次配置，再应用既有 configuring callback 的
显式选择；复用 FEC、未知字段、重复 limits、hotkey，以及未被修改的60000/1001
帧率和−1码率。旧 IHS_SessionConfig 是精简的、以平台请求参数为主的接口；其默认
请求字段不等于 Android 硬件能力，不能将此包装层称为完整官方 UI。
控件配置不在 worker 间共享裸 proto 指针，session Destroy 在各 worker/timer 结束
后释放 owned proto。protobuf 赋值宏包装为单语句，保证条件分支同时约束 has/value。

控制 frame 允许保存多包 payload，之后由 channel 按 MTU 分片；packet 缓冲区仍按
单包处理。这修正了“整份配置必须小于2048B”的隐藏断言。4096B hotkey 的实际接收、
API发送和初始消息4均核对了分片→重组→解密后的完整内容，没有用 setter 镜像代替。
可靠队列资源/调度和发送失败策略仍属于独立契约，不据此声称所有发送边界已等价。

### 35.5 验证范围

```sh
python3 scripts/audit-steam-client-config.py \
  --binary /path/to/official/libmain-arm64.so \
  --output build/video-recovery-re/client-config.json
python3 scripts/check-steam-client-config.py \
  --receiver build/desktop/third_party/ihslib/tests/session/ihs-client-config-oracle
ctest --test-dir build/desktop -R 'client_config|client_capabilities' --output-on-failure
```

固定参考包含111个原指令场景：36个 setter、32个 queued receive、34个逐字段
parser/接收和9个实际 player delegate。对象静态初始化采用原始标量默认值；
allocator、libc++字符串存储、packet refcounts、文件/最终网络调用和设备动作是
明确替身；protobuf 初始化错误的诊断文本格式化也排除，但 IsInitialized 拒绝分支
实际执行。回调记录复制消息头后用原版 serializer 读取保留的对象；fixture 不做
销毁/释放等价验证。官方二进制不入仓，SHA固定在脚本入口。

生产对照使用其中86个适用于核心层和规范 bool 的官方输入，另加3个无效 API输入
及5个初始协商复用/默认值输入，共94组。Native incoming 从实际CRC datagram进入真实
session、可靠窗口、加密/解密和控制解析，消息字节来自固定官方 plaintext fixture；
加密输入由受控测试会话构造，不冒称真实 host 抓包。输出从真实 sendQueue 重组并
解密后比较字段 presence、重复顺序、nested及unknown，不依赖 Python protobuf 包。

`client_config` 额外验证 delegate 递归替换、保存与发送输入的区别、容量不足不写、
session 销毁后的应用自有快照，以及4000次写入与并发读取/解析，停止后 join reader。
这些是项目内存/并发验证，不代替原版播放器行为的生产验收。

完整文件保存/重载的实际应用入口、文件故障和 UI 视图契约见 §36；本节 callback
计数不代替那些文件证据。overlay/hardware/microphone及窗口事件的设备副作用与
配置存储分属不同层。§32的手动 FEC 保存策略仍适用，不把库 API 可发送99扩大成
checkbox 热切换；配置值覆盖不等于所有播放器/设备行为均已验证。

## 36. 完整设置文件与应用持久化边界

### 36.1 原版 Load/Save 的完整入口

【证据】`audit-steam-client-settings-io.py` 从同一 SHA 固定的官方 Android main
执行 `SetSettingsFile 0x7a5a28`、`LoadStreamingClientConfig 0x7a5a50` 和
`SaveStreamingClientConfig 0x7a5b34`。共27个固定案例覆盖7个加载输入、18个
文件名/写入结果/配置值组合及2个 setter→load 输入。
C++ protobuf parser/CopyFrom/SerializeAsString/ByteSizeLong 和分支仍执行原指令；
BLoadFile/BSaveFile、CUtlBuffer 与 libc++ 内存存储是明确适配器，没有执行 Android
文件系统的真实读写或断电耐久性测试。

- SetSettingsFile 先替换文件名字符串，再直接调用 Load；不发控制消息。
- Load 调用 BLoadFile；返回 false 时不解析、不改变当前 config。成功读取零字节
  是有效空 protobuf，恢复完整默认值。这里没有 delegate、Save 或99调用。
- Save 仅在文件名非空时执行。写的是完整 config 的原始 protobuf，不带控制编号、
  CSet 外层、传输头或长度前缀。写失败 Warning，内存配置不回滚、不主动断连。

【证据／明确差异】Load 直接把 ParseFromArray 的目标设为 client+456。
原版输入 `c8 01 00 80` 先把 FEC 改成 false，然后遇到截断 varint 并 Warning，
不会回滚；单独 `80` 失败后也已清成默认值。因此不能把原版文件加载失败描述成
“事务性保留旧值”。项目文件 loader 先解析独立候选，所有读取/关闭/恢复步骤成功
才替换当前值；失败保留旧完整配置，并不自动覆盖损坏的源文件。这是明确的坏文件
防护差异，不冒称与原版异常路径逐字节等价。

### 36.2 文件、兼容 profile 和初始协商

`stream_settings.c` 在平台数据目录中使用 `streaming_settings.bin` 作为完整配置
来源。首次缺文件时从现有 profile 的画质、码率、FEC 选择迁移，保留既有用户选择；
不把旧 profile padding 当作新配置，也不重建设备身份或逐主机配对密钥。
已有有效文件（包括空文件）优先于 profile 中那三个历史字段。

应用启动时 preview 为 UI 提供视图，不保存新配置；若有可恢复备份，loader 可恢复
其文件名。runtime worker 在创建 session 前加载完整值，随后调用
`sl_stream_settings_apply_limited`，再注册 session callbacks、建立连接。
因此读取文件本身不触发 delegate、Save 或99；初始消息4由 §35 的完整值路径构造。
应用先在独立的本次 session 副本应用 H.264、1280×720、60fps 请求限制，
不改写完整文件/cache；60000/1001 等未超限分数不被取整。configuring callback 再限幅，
不再用每条 UI command 的旧默认值覆盖 FEC/quality/bitrate。
这些平台请求限制是项目能力边界，不是 Android Default 预设的数值复制。

完整配置省略字段仍采用 protobuf 默认语义，例如省略 bitrate 是−1自动、overlay
是false；不能因字段缺省就注入旧包装层的15 Mbps、overlay=true或hotkey="auto"。
显式提供空配置和只带FEC的配置均核对消息4与存储结果没有这些额外字段。未调用
完整配置 API 的兼容调用方仍走既有精简接口默认值，二者不能混为一谈。

配置中的 unknown fields、嵌套/重复 limits、字符串、分数帧率及有符号码率保留在
完整文件中。profile 的 bitrate 字段继续占32位，以相同比特表示 int32；不再把
菜单外的值强制归一化到6000。四个手动菜单选项的验证仍与“完整配置可以携带任何
int32”分开；自动−1、无限制0及其他数值在 UI 显示当前值而不假装选择了6 Mbps。
这不改变 profile v2/v3/v4/v5 的身份、校验和及密钥迁移语义。

### 36.3 Save 回调、UI 编辑和先后顺序

生产 session 的 saveClientConfig 已注册到 `client_config_saved`。接收线程只将
借用的 protobuf 字节复制进单项 mailbox，再唤醒 runtime；没有文件写入、fsync、
设备操作或 session 重入。mailbox 合并的是待落盘快照，不合并核心层的收包、
delegate 或控制消息动作。配置文件和 cache 的读取/解析/写入归 runtime worker。

UI 保存只按最后一次实际显示/提交的视图判断变化，修改画质、码率、FEC 中实际
变更的字段；语言、声音、主机列表和配对身份的保存不会重建完整 proto。
完整99与 UI 编辑按生产者顺序应用，各编辑字段分别记录序号：

```text
UI FEC=true → 完整配置 FEC=false → UI quality=Beautiful
最终 FEC=false、quality=Beautiful
```

不能把两个 UI 编辑共用最后一个序号，否则旧 FEC 编辑会因稍后的画质编辑而错误
覆盖完整配置。同理，更晚的完整配置会完整覆盖更早的 UI 选择，不自创“profile
永远优先”或“省略 FEC 就保留”的规则。

设置视图通过持久 snapshot 提供给 UI，不占用可能拥塞的通知队列。提交编辑时
发布 revision；待提交的 UI command 和旧 revision 不能把控件改回旧值。UI 真正
接受新视图后 ACK 它作为下一次编辑的基准，才能识别“先看到 true、再改回 false”
这种值恰好等于更早旧快照的编辑。revision 是项目内线程交付标记，不上协议线，
不与 Steam 时间戳或消息序号混用。

设置页手动更改依然只更新保存值，不调用活动 session 的配置 API；串流中的 FEC
不会因此热切、按丢包率自适应、清窗口或重连。当前 session 保留其现值，下次
正常连接从完整文件/cache 取值。后续收到更晚的完整配置仍按其正常覆盖语义保存。

### 36.4 文件发布、失败和退出

文件保存用临时文件、flush/fsync、rename 发布；Horizon 不能替换目标时，先保留
backup 再发布，失败尽量恢复旧文件。加载只在主文件不存在时恢复有效 backup。
这是本项目的文件发布/恢复机制，原指令 I/O 适配器不证明 Android 底层也如此。
写入/关闭/发布失败保留内存配置和旧磁盘记录，仅记录错误，不新增协议响应或断连。
坏文件不被启动流程自动覆盖；有效空文件则按原版默认值加载。

退出时先停止并 join session 等生产者，再 drain 最后一次配置/编辑并保存，之后
runtime worker 才结束；销毁 settings mutex、待保存字节和 owned proto 发生在
runtime join 后。没有新增 detached thread。启动 preview 位于首次 UI 渲染之前，
运行时文件 I/O 不在渲染、输入或 session 收包热路径上。

### 36.5 证据和验收入口

```sh
python3 scripts/audit-steam-client-settings-io.py \
  --binary /path/to/official/libmain-arm64.so \
  --output build/video-recovery-re/client-settings-io.json
python3 scripts/check-steam-client-settings-io.py \
  --receiver build/desktop/app/nsl-stream-settings-oracle
ctest --test-dir build/desktop \
  -R 'nsl-stream-settings|stream_settings_official_vectors|nsl-native' --output-on-failure
```

Native file oracle 消费27个原版案例中适用于应用固定文件名的13个输入，实际读取/
写入临时目录、经过 session apply/Get 取出配置；11个正常/失败写入契约与原版对照，
另2个失败 parser 输入明确断言“原版部分改动／项目保留旧值”两侧结果。
其余空文件名 guard/SetSettingsFile 证据不被冒称是本产品任意路径 API 的验收。

`nsl-stream-settings` 覆盖关闭/发布失败、Horizon rename 行为、backup恢复、零字节/
坏文件、超过单包的配置所有权及磁盘重载、unknown/nested/repeated/分数fps、
本次请求限幅不改源配置/自动码率/未超限分数fps、
手动 FEC 保存不修改受控串流状态（无主机连接）的当前 session、不排队99、逐字段时序、旧UI快照、
4000次跨线程发布以及生产者 join。大字符串长度为4096B，不把测试生成的数据称为
官方真实会话。profile 读回与 UI 投影同时核对身份/密钥未改变。

`nsl-native` 在真实 runtime/discovery worker 中完成两次取消/退出，证明旧 UI
快照不覆盖完整文件；再通过真实 SAVE command 修改、关闭 runtime、重新从磁盘读取，
核对FEC/画质/码率及unknown保留。SDL用dummy设备，没有认证主机或Switch显示证明。
原版播放器 overlay/hardware/microphone 的设备动作不因文件持久化而自动获得验证；
它们与调度、发送缓存、可靠媒体和统计窗口分别有独立协议契约。


## 37. 发送窗口、失败事务与连接调度

### 37.1 客户端来源与完整执行边界

【证据】同一官方 Android 1.3.32 main ELF（SHA256
`50e1d3147d5d47b71ef1970e1867a2fe4f3e1ecf2ea6153f927fac88b88ea38e`）中，
`audit-steam-outgoing.py` 不再把 channel sender 和 Socket::Send 都替换为事件：

| 入口 | 地址 | 本节执行/适配范围 |
|---|---|---|
| SendReliablePackets | 0x7f8ac4 | 原始候选扫描、RTO、失败停止、发送计数 |
| SendUnreliablePackets | 0x7f8cbc | 原始退休、新包cursor、补发阶段和计数 |
| HandleNackPacket | 0x7f95dc | 原始包龄/echo/位图/水位分支，随后真实sender |
| Socket::Send | 0x7ff1dc | 原始时间戳、双类准入、CRC与成功后的预算更新 |
| Connection::Update | 0x7fc108 | 原始排序和两轮调度；两类sender本体均执行 |

199个固定场景含18个发送/预算/transport组合、42个可靠RTO/计数场景、16个不可靠
退休/补发场景、39个NACK/顺序边界场景、8个可靠失败时序、4个连续连接更新、
3个优先级重设、66个排序输入和3个实际GetChannel场景。GetChannel的分配/构造
适配器与这些新增分支的准确范围见§38。窗口存储是按本节前置状态预置的ring；Advance/Release只执行请求的释放并
维护存储，原版引用计数/销毁、接收消费者、空FEC队列、统计、最终transport及静态
初始化注册是明确适配器。排序、sender、Socket预算和CRC不是模型替身。

原版二进制不入仓，固定参考保存input/observed；本地测试不需要ELF或Unicorn。
这些受控ring与最终I/O替身不证明原版完整分配机制、系统背压或真实网络公平性。

### 37.2 初发入口与预算失败的区别

【证据／静态反汇编】`CStreamChannel::Send 0x7f89dc` 和
`SendUnreliable 0x7f8bd8` 在各自发送mutex下，先设置普通包类型、零发送计数、
连接/channel标识，调用 `AddToOutgoingPacketWindow 0x7f6f94`，再立即调用对应
sender（不可靠传false）。因此“全部初发只在下一次Connection::Update排队发送”
不符合该客户端。AddToOutgoingPacketWindow以当前时间写入头、按window tail分配
连续packet ID并处理分片；本节只静态核对该入窗/分片入口，不将预置ring当成其执行验收。
§42另从实际控制调用者/Frame::Put接通该入口和真实window插入，覆盖普通可靠发包。

【证据／原指令】sender→Socket::Send会先写本次尝试的timestamp，再检查deadline。
未到预算时返回1、置blocked、不调用transport；到达等号可发送。进入transport前
清blocked，transport返回非零时不增加预算。0成功后才推进对应deadline并增加
packet发送计数（255饱和）；CRC实际字节也在本路径核对。预算按不含额外CRC尾的
packet长度计费，类型7/10/11绕过这两类deadline；这些规则仍以§28–29的类表为准。

sender遇非零结果停止本channel当前扫描，不继续跳过失败包发送后面的包；返回1
在sender出口归一化为0，其他非零原样返回。Connection::Update不因一个channel
的sender返回非零而跳过其他channel。不能将“API没有报告失败”解释成已上网，
也不能让一次本地失败消耗整批待发包的计数或期限。

### 37.3 可靠包失败、RTO和项目接线

【证据】已有计数的可靠包在失败的Socket尝试中也已改写timestamp，但计数不变。
例如retained count=1、smoothed RTT=100时：失败当次只尝试窗口首包；下次update
可以尝试后面的旧包，首包在age=125仍不重传、126才再尝试，wire count仍是1。
count=0则无包龄限制，下一次update可再次尝试，仍发0；成功后才存为1。

【撤回旧实现等价推断】原项目 `IHS_RetransmissionProcessAt` 在I/O前为全部到期
候选增加计数、推进deadline，并在失败后继续发送同channel后续包。其公式/正向
成功案例不能证明与本节失败事务相同。生产路径现以“实际尝试→按结果提交”处理：
失败不加计数、同channel本轮停止、未尝试项不变，其他channel继续。pending对象
在快照期间持有独立引用；ACK可移除其窗口所有权，不造成悬空指针；已观察到ACK
的后续快照项跳过。I/O期间的新NACK通过generation保留，完成发送不覆盖更晚反馈。
这是多线程交付机制，不冒称原版单线程Update也有相同的并发实现。

发送worker按通道调用 `IHS_RetransmissionProcessChannel`，普通可靠类型5/6直接使用：

```text
c = clamp(smoothedRTT, 65, 3276)
delay = c + floor(c / 4)
count==0 或 timestamp==0 或已标NACK：可尝试
否则：int32(timestamp + delay - now) < 0 时可尝试
```

保留uint32回绕和严格负号判断；RTT每次处理只取一次快照，不能在候选计数和填充
之间读取变化的估计而越过分配容量。旧 `ProcessAt` 毫秒入口为独立兼容入口，不再
代表生产普通可靠包准入。5ms timer只负责唤醒，不在timer线程直接发包；worker
自身进行约1ms有界等待。条件精度不证明墙钟执行逐tick等价。
Connect类型1不属于普通可靠窗口；专用连接调度、生产入口和独立对照见§39。
不能用普通可靠包的RTO断言替代连接握手重试验证。

### 37.4 不可靠窗口与连续轮转的契约

【证据】新包从 `m_nUnreliableSendCursor` 扫至tail；失败位置保留为下一次新包
起点，成功后才前进。已发送包只在bool=true阶段扫描，timestamp为0才尝试。
NACK只标记/释放，不同步重发；先普通阶段再补发阶段，实际缺包与位图释放结果、
16位packet ID回绕均在同一fixture内执行。

退休使用window保存的入窗时间，而非Socket重写的最后尝试时间，按§25的200ms
加RTT保留量检查。边界相等保留，超过一tick退休。已标记的旧包若补发遇预算/本地
失败，Socket仍将零timestamp改成本次时间；它不会因计数未增加而自动在下一次
补发扫描重试，需要后续NACK重新标记（可靠包另有RTO）。不能擅自把两者统一成
“所有失败永远保持待立即重试”。

【证据】Connection按优先级降序排列，第一轮逐channel先接收状态更新、可靠
sender、不可靠false、FEC队列，第二轮从cursor扫描不可靠true。连续执行还确认
原版轮转值允许暂存等于channel数N：3通道存储值为1→2→3→0→1，而非模3的
1→2→0→1；扫描时值N映射回起点0。因此不能仅用三个合法起点的单次结果推出
长期轮转实现。本节两种priority组合均连续执行5次Update，并保存实际报文顺序。
此轮转细节属于原版行为，未据此推断必然出现肉眼停顿。

### 37.5 验证入口与精确覆盖范围

```sh
python3 scripts/audit-steam-outgoing.py \
  --binary /path/to/official/libmain-arm64.so \
  --output build/video-recovery-re/outgoing.json
python3 scripts/check-steam-outgoing.py \
  --receiver build/desktop/third_party/ihslib/tests/session/ihs-retry-sender-oracle
ctest --test-dir build/desktop \
  -R 'reliable_sender_official_vectors|retry_sender|retransmission_state_machine' --output-on-failure
```

可靠重传oracle消费199个官方场景中50个可靠RTO/失败输入：实际session retained packets
进入生产tick准入和Socket序列化，逐字节比较CRC、timestamp、packet ID、wire计数
及各轮发送数量/停止位置。仅时钟与最终UDP I/O为替身；预置retained状态记录前次
成功/失败初发，不把该准备步骤冒称实际联网发送。其余149个缓存/整形/发送阶段、
排序与factory场景由§38的生产oracle消费；两类oracle的精确比较字段分开列明。

`retransmission_state_machine` 额外覆盖失败不越过同channel后包、其他channel
继续、ACK释放当前/后续snapshot和I/O中新NACK不被覆盖。`retry_sender` 用真实
pthread使ACK发生在send callback等待期间，并在4000次生产tick处理期间并发修改
RTT；结束后join再销毁。它们是项目所有权/线程验证，不替代官方策略来源。

FIFO交付后的窗口/整形/发送阶段接线见§38；接收更新和媒体feedback worker仍
不同于原版Connection::Update，不将发送阶段对照扩大成整个连接循环的墙钟等价。
真实认证会话、系统背压时序、Switch输入/解码显示及用户原始停顿因果均无本节证据。


## 38. 普通发送缓存、整形与发送worker

### 38.1 官方入口、实际factory与排序反例

【证据】§37的sender/Socket/Connection Update链仍是策略来源。补充执行
`GetChannel 0x7fba34`：已有slot直接返回；请求新ID时逐个补齐0…ID的缺slot，
每次构造标记dirty。请求3→1→7→0与0→31→31均固定为原指令输入，32/255不构造。
分配与channel构造为适配器；请求边界、循环、存储、复用和dirty由原指令执行。
`HandlePacket 0x7fb164–0x7fb1c0` 在CRC/ID/范围准入后、channel分派前调用该factory，
所以未知type也可以创建传输channel，而不是只有Start*Data才创建。

【证据】SetChannelPriority改变的是channel内的key和dirty。下一次Update从原始
slot表重建排序视图，不能沿用上次已排序顺序作为稳定排序输入。3/16/32通道的
实际setter→连续Update均核对。24个及以上元素会走另一排序分支；32通道存在
同key次序变化，普通稳定排序无法复现。

`outgoing_sort.c` 专门处理至多32个ID，使用LLVM libc++19算法实现参考，许可见
third_party/README；其行为标准仍是官方客户端`0x7fd464`的执行结果。66个输入
覆盖0/1/2/3/4/5/23/24/25/31/32长度、正反序、全等、重复key和int32极值；不因
ELF中出现不同clang版本字符串就宣称全部函数来自某一工具链。没有使用第三方
Remote Play实现或Host支持某API来反推客户端排序策略。

组件sender/排序fixture可以直接预置channel表，包括不符合真实factory创建顺序的
合成表；生产oracle同样预置该组件前态。实际GetChannel的密集前缀另有独立输入，
不把预置表测试当成整个上层创建链的执行证据。

### 38.2 队列交付、序号与真实保存的包

`sendQueue`只负责把生产者数据交付给既有sender线程。普通不可靠3/4进入owned
发送window，保存完整header/payload和独立入窗时间；立即尝试false阶段。初发
发送失败或预算不足时保留原包，cursor停在失败位置。可靠5/6在公开给worker前
已注册owned待确认包；§44将可靠初发改为完整frame交付后一次激活该batch，
与RTO共用扫描。未交付的未来batch保持未激活，timer不提前发送、ACK不提前退休。

可靠/不可靠各自的16位ID计数归connection/channel所有；移除并重建媒体channel
对象不重置它们。NEXT只作为入队请求，实际排队时分配ID；整帧分片在queue mutex
下连续分配/发布，不能在两个线程分别“准备frame”时先各占一个head，随后把
续片交叉插入。autoPacketId只是本地元数据，不上线；显式ACK/NACK等引用ID保留。
可靠control的加密序列仍受原sendLock保护，与传输packet ID是不同序列。

cache采用64起始、二次幂增长的ring并保存独立created数组，选择性释放保留该
slot时间、Advance才清除。跨65535增长重排和payload所有权有本地测试。累计跨度
到模糊的16位半区间之外拒绝，分配失败不转移原body；这是项目资源/坏输入防护，
不把原版EnsureCapacity的断言/异常当成已经复制的故障策略。

### 38.3 type10准入、标记和退休

type10经实际datagram CRC/连接准入后进入缓存NACK处理，transport已连接才应用；
不把它交给音频/视频decoder或普通接收window，也不因callback未知就丢掉反馈。
新channel注册遵守0…ID的factory前缀，合法未知type只建立传输状态后仍忽略payload。

NACK先检查旧feedback timestamp（0为原版sentinel），再保存本次timestamp；
1…5B坏body没有位图动作，但已消耗该时间水位。因此一个较新的坏NACK仍可使
随后的旧有效NACK被忽略；不能把检查长度提前后声称异常分支完全相同。
完整body先处理连续水位/已有空head，再按非零bitmap字节扫描到最高set bit；
1选择性释放已发送packet，0只把足够老且已有计数/非零timestamp的包标为0。
最后处理base之前的包。cutoff采用本机RTT准入与echo的较新者。

【证据／边界】header-only fallback用的是两个零扩展ID的signed int32减法，
不能擅自换成int16回绕比较。head=65534而base=2时该差为负，不标记；其他字段
如连续水位与cursor准入仍各自使用原来的int16规则。新增16个base前/等于/尾后/
半区间与两侧回绕输入，以及3个零sentinel/旧feedback/坏body时序，都实际执行
原NACK→普通阶段→补发阶段。

退休和重发条件沿用§37：入窗时间超过200ms加RTT保留量才Advance，等号保留。
旧包只有true阶段且timestamp=0才尝试；失败的Socket仍会写timestamp，不保证
下次立即重试。新包失败则cursor不前进，后续false/true阶段仍可重试该位置。
现有clock平均值供这些公式使用；完整PingStats/TimeOffsetStats采样窗口另见§29.5，
不能把固定RTT输入对照算成整个统计过程等价。

### 38.4 双类预算、优先级与worker执行

Socket序列化入口采用§28构造默认限额12,500,000/625,000 B/s，3/4与5/6各有
独立deadline。每次尝试先stamp，未到deadline返回1、不调用UDP；成功才扣预算，
空闲后最多追赶65tick。按不含CRC额外尾部的packet长度计费，CRC本身实际生成。
bool旧入口仍表示发送成功；内部保留0/1/2供sender控制，EAGAIN/EWOULDBLOCK与
硬错误都不会消耗成功额度。不把host消息94擅自接到预算setter。

初发交付后周期发送按priority降序：每channel可靠发送→不可靠false，再从轮转
位置执行所有channel的不可靠true；保留N暂存值的轮转规则。首次协商完成入口
按官方HandleStreamStarting将控制1设2、统计2设−1；麦克风Start/Stop入口设1/0。
channel优先级只改dirty，下一次Update重建，不逐packet重排。

可靠timer不再与sender同时直接发送，它只唤醒sender。sender在无交付数据时
有界等待约1ms；持续有数据也按至少65tick间隔执行周期发送。撤回旧可靠初发
“逐项尝试”的接线：§44改为每个完整可靠frame触发一次扫描；3/4路径另计。
序号/整帧发布只持queue mutex，不持Base/socket锁；缓存、注册、排序和socket事务
由Base锁序列化，避免生产者持control sendLock再等待socket锁的倒置。没有新增
线程、detached worker或文件I/O。停止/join现有收发/媒体生产者、销毁timers后，
才释放待发队列、cache和锁；NRO显示/loader属性仍须独立设备证据。

这是发送阶段的接线：官方同Update内的接收状态更新，本项目仍由原媒体/feedback
worker执行；上行FEC队列和Connect类型1的100ms专用重试亦有独立契约。不能把
本节称为整个Connection::Update、系统背压、网络时序或所有发送模式均已等价。

### 38.5 验证入口与比较字段

```sh
python3 scripts/audit-steam-outgoing.py \
  --binary /path/to/official/libmain-arm64.so \
  --output build/video-recovery-re/outgoing.json
python3 scripts/check-steam-outgoing-engine.py \
  --receiver build/desktop/third_party/ihslib/tests/session/ihs-outgoing-oracle
ctest --test-dir build/desktop \
  -R 'outgoing|reliable_sender_official_vectors' --output-on-failure
```

199个原指令场景由两个生产oracle消费：50个可靠RTO/失败场景见§37；149个发送
引擎输入包括80个逐轮wire/预算/阻塞/轮转及不可靠head/tail/cursor/retained内容
对照，66个sort和3个factory比较ID顺序。已释放slot不读取原版残留对象字节；
私有可靠window metadata和原版接收消费者动作不在此oracle比较字段内。
NACK输入在本地从真实CRC datagram进入生产session，不直接调用缓存setter。

`outgoing`测试4个线程同时准备并发布多分片frame、两类序号独立、跨65535的100包
ring增长和销毁。`outgoing_worker`启动实际收发线程，验证预算拒绝仍缓存、一次
EAGAIN后wire计数仍0、真实type10重发同ID/payload且计数为1、过期后不再补发；
受控时钟/recvfrom/最终sendto是替身，完整跑两次并join。既无认证Steam主机，
也无Switch串流/解码/显示或原用户停顿因果证明。

## 39. 官方客户端 Connect 的独立重试契约

### 39.1 原指令证据与触发链

证据固定为本文件既有SHA256的Android官方`libmain.so`，不是Steam host API。
`scripts/audit-steam-connect.py`实际执行客户端`BConnect @0x7a7808`的UDP分支，
进入`Create @0x7faaf8`、connection constructor `@0x7fb23c`、
`Connect @0x7fb62c`、`SendConnectPacket @0x7fb84c`和Socket Send `@0x7ff1dc`。
内存分配、packet基础构造/引用计数、socket构造、transport激活/最终I/O、统计
构造/记录、client delegate为明确替身；connection构造、状态写入、packet header/
cookie填充、CRC32C和Socket序列化执行原指令。

【结论】新的connection构造时CRC要求为false，`BConnect`没有提前打开它。
线上首发为17B：type=1、count=0、local ID、destination/channel/fragment/packet
ID均0、新发送时间戳、`CRC32C("Connect")=c7 3d 8f 3c`。这4B是body cookie，
不等于设置CRC header bit并在尾部再附4B。撤回“首发Connect强制CRC尾部与官方
相同”的隐含假定；原本`SessionInitialized`传`hasCrc=true`属于本地差异。
Connected恰4B body才记录peer/CRC并进入已连接transport，见§34的完整入包校验。

【证据】`Connect @0x7fb6dc–0x7fb700`设state=0、lastConnect=0并立即首发；
`BConnect @0x7a79f4–0x7a79fc`忽略该首发返回值，返回true。
`Update @0x7fc190–0x7fc1b8`只在state=0进入专用重试：lastConnect为0，或
uint32(now−lastConnect)≥6553时，新建Connect并尝试发送，随后无条件写入本次
Update时间。返回码0/1/2均遵循这一规则；不是普通可靠包RTO、指数退避或count递增。
首发不更新lastConnect，因此首次Update可立即重发；now=0的sentinel和uint32
回绕均保留原行为。Connected之后的state=1不再进入此分支。

【证据】同一次Update先执行上述发送，再在`@0x7fc43c`检查15/180秒接收租约。
达到边界的连接可以先发一个Connect，再调用Disconnect；不能把超时检查搬到
专用重试之前。`Disconnect @0x7fb724`只有state=1时发送一个type9，随后转state=2；
连接尚未建立时不发送type9，下一Update在delegate仍存在时通知closed并转state=3。
上层Close可能先清delegate，不能概括成所有路径都回调closed。这与本地现有
旧Discovery disconnect timer的多次type9及延迟收尾有差异；§40以独立证据/生产
对照替换该路径，不能用Connect重试对照冒称断连生命周期已等价。

### 39.2 固定案例与范围

固定参考`scripts/fixtures/steam-connect-reference.json`保留35个原指令场景：
9组首发/重试（起点0、普通、回绕×发送返回0/1/2），6组Connected长度/CRC guard，
6组15/180秒边界及下一Update，2组超时后迟到Connected，12组四种transport状态下
主动Disconnect/发送结果。
Connected测试入口从已剥CRC的HandleConnected执行；完整datagram CRC与地址/ID
guard仍由§34的原指令及生产oracle覆盖。这里不证明真实Steam应答时间、Switch
运行时延迟，也不证明原截图停顿由Connect引起。

### 39.3 生产接线与比较范围

`lifecycle.c::TransportSendConnect`构造新的17B初始包直接经Socket序列化，不进入
普通retransmission tracker。`SessionInitialized`在receive worker初始化连接ID、
CRC初值并首发；该worker的TransportUpdate执行6553tick周期尝试，再检查接收
deadline。lastConnect由Update而非Socket采样时间写入，失败不改变规则。
Connected的4B guard成功后阶段转Handshaking，自然停止Connect；超时已发生时
迟到的Connected不能启动ClientHandshake。移除旧毫秒重传和伪discovery ACK退休。

`connect_oracle.c`运行真实初始包序列化、receive worker Update及完整Connected
datagram入口，消费23个官方参考场景，比较每轮wire/action顺序、lastConnect、CRC
与transport阶段，且Connect始终不占可靠窗口。最终Disconnect清理为替身，原版
下一Update的closed回调不在比较范围，12个主动Disconnect案例也未计入本地对齐。
源代码的session握手枚举与官方transport状态不同，oracle明确将Handshaking及以后
映射为transport connected，将timedOut映射为closing；这不证明完整关闭状态机。

`connect_worker`实际启动现有收发线程：首发EIO→首次Update EAGAIN→6552tick不发
→6553tick重发→3B Connected拒绝后继续重试→4B Connected停止；完整执行两次、
join收发线程并销毁session，时钟/最终UDP I/O受控。此CPU集成测试不需要也不等于
Switch hbmenu两次启动验证。

```sh
python3 scripts/audit-steam-connect.py \
  --binary /path/to/official/libmain-arm64.so \
  --output build/video-recovery-re/connect.json
python3 scripts/check-steam-connect.py \
  --receiver build/desktop/third_party/ihslib/tests/session/ihs-connect-oracle
ctest --test-dir build/desktop -R 'connect|transport_worker' --output-on-failure
```

## 40. 官方客户端 Disconnect、Close 与上层停止

### 40.1 原始调用链与证据边界

证据仍为固定Android官方客户端ELF。`audit-steam-disconnect.py`执行Connection
Disconnect `@0x7fb724`、Close `@0x7fbce0`、Update `@0x7fc108`、Client Disconnect
`@0x7a7acc`、HandleStreamStopping `@0x7a7238`、ResetConnection `@0x7a527c`，
以及实际Socket入包/CRC/HandleMessage/Connection HandlePacket的type9路径。
内存分配、packet基础构造/引用、空client队列、缺省空decoder/设备指针、统计、
地址比较和底层transport销毁/I/O为明确替身；未执行平台解码器、真实socket销毁。

【证据/结论】连接层Disconnect仅state=1发送一个全新type9：count、channel、
fragment和packet ID均0，source/destination使用该连接两端ID，CRC由连接协商位
决定。即使底层返回1或2，也不重试；state0/2不发，state3保持3，其他转state2。
重复调用state2不再发。Update遇state2先通知仍存在的delegate，再清peer地址/ID、
获取新的local ID并进入state3；回调看到的是关闭前的state2和旧两端ID。

【证据/结论】上层Client::Disconnect先调用上述Disconnect，仅client state6/7
进入HandleStreamStopping（停止音视频decoder、外设/统计消费者），随后ResetConnection。
ResetConnection调用Close，Close再次调用Disconnect后清connection的socket和delegate；
第二次Disconnect此时为state2，不会重复发type9。随后Update不能再通知已清的delegate。
撤回“上层主动退出必然等下一Update的closed回调”这一概括；底层断连与上层关闭需
分别实现，不能加一个统一1.1秒等待或type9循环来近似。

【证据/结论】对端type9先通过Socket CRC（有CRC时）、两端ID和地址校验，按
`HandlePacket @0x7faf08–0x7fafec`刷新接收时间；只有state1才调用Disconnect。
该类型不要求已经协商CRC的连接也必须带CRC，但有CRC却错误仍在Socket拒绝。
收到有效type9并不是StopRequest(129)，没有证据从这里推断host游戏进程已经退出。
本项目可保留“host请求结束transport”的UI事实，不能据此生成129。

【证据】`Connection::Send @0x7fb9b4`和`SendUnreliable @0x7fbb58`都只在state1
进入channel；其他状态返回3。关闭后的生产者不能继续由sender发普通数据。
这不表示Socket低层对任何type9发送再加一次“必须state1”检查；Disconnect本体
先送一次goodbye，再改状态，Close再清socket。

【证据】`TransportUDP::BInit @0x802580–0x8025a0`对fd执行F_GETFL并把O_NONBLOCK
位并入F_SETFL；`TransportUDP::Send @0x802754`只尝试一次sendto，完整长度才算成功。
Android errno EAGAIN/EMSGSIZE/EBADF/其他分别返回1/2/3/4，EINTR也没有内部循环。
因此“只发一个goodbye”还要求发送本身非阻塞，不能在应用退出路径等待socket写缓冲。
本地POSIX backend的接收保持有界阻塞，发送使用每次MSG_DONTWAIT实现同样的出站
非阻塞语义；这不是整个UDP BInit/BWait/IPv6路径与原版等价的结论。

【证据】`GetNextConnectionID @0x7fab70`全进程共享计数，首次取非零的rand()%255
（1～254），随后按1…255回绕跳过0；构造和退休都会分配。项目使用自有entropy
provider供给同范围初值，用atomic CAS保证相同的进程内序号策略，不声明libc
PRNG状态、随机样本与官方相同。

### 40.2 接线约束

本项目session认证阶段与官方transport四状态分开：Connecting映射0、Handshaking
至Connected映射1，另存closing/closed。普通主动退出选择上层Close语义；接收超时
与入站type9选择连接层Disconnect，下一Update再通知并停止现有workers。应用
disconnected回调是项目API，主动Close可以通知应用收尾，不冒充已清除的官方delegate。
Stop/join producer、收发线程、销毁依赖的顺序由现有runtime保证；不能在timer线程
持全局timer锁做跨线程join，也不能在关闭后仍由heartbeat/feedback发送数据。

### 40.3 实现和验证投影

`shutdown.c`把transport四状态与认证阶段分开，用Base锁串行化一次goodbye与
socket脱离。周期sender和初发交付在同锁内检查状态，queue/整帧发布在关闭时拒绝
继续入窗，控制生产者不会将“已经在关闭”升级为另一次上层Close。正式关闭后
Socket入口拒绝发送；退休保留不可变host配置，用addressCleared表示连接地址已清。
`connection_id.c`实现进程内非零递增分配，初始Connect和退休分别消费ID。

接收超时/type9调用TransportDisconnect；下一receive Update在清ID之前通知应用、
退休并interrupt。主动SessionDisconnect选择Client Close语义，同步尝试一次goodbye
并停止现有worker；应用回调在finalized通知一次。无worker的项目API回调可以同步
发出，它是应用收尾通知，不能冒充被Close清除的官方transport delegate。
finalized不持Base/socket/timer锁停止heartbeat、join sender；Destroy再停止/join
媒体和应用拥有的生产者，最后释放timer/cache/socket依赖。没有新增线程或timer。
启动尚未完成时取消会在两个初始化检查点保持关闭，不重开连接；未创建sendThread
时不调用SDL的非空ThreadJoin。资源清理与官方平台decoder析构不能混称逐指令等价。

固定参考138场景：连接层重复Disconnect 24、原始Close 8、上层Client Disconnect
32个client/transport状态组合、入站type9的ID/地址/CRC与两种接收时刻48、退休后
越过15秒期限8、ID分配/回绕4、UDP BInit系统调用2、UDP发送错误/CRC 12。
上层状态交叉组合属于人工前置状态，不表示所有组合在正常UI均可达。

生产oracle消费其中136个：逐轮比较wire、transport状态、关闭/ID动作先后、
lastConnect/lastReceive、CRC要求、逻辑socket/delegate存在性及UDP返回码。
其中32个上层组合仅比较transport投影，排除原版stats_stop/save、transport析构
替身与client枚举；项目应用通知另验仅一次。GetNextID为单独依赖，关闭oracle
使用固定12适配；另4组直接调用生产allocator，核对260个连续ID与首次零余数重取。
预置计数器案例使用初始化/预热建立相同前置状态，不比较随机来源内部状态。
两个BInit案例只有原版syscall轨迹，没有纳入生产协议等价数量。

本节发送准入对照限关闭阶段。旧内部Queue曾在首次未连接阶段接受部分调用再由
actor抑制发送；该差异由§41的独立准入/调用者对照纠正，不能倒过来用本节结果
代替该证据。完整收发Update与播放器消费者不在本节的等价范围。

`disconnect_worker`实际收发线程覆盖12次关闭：并发8个退出请求及控制生产者、
peer无CRC断连、15秒超时，协商CRC开/关、goodbye EAGAIN且不重试；另32次启动即
取消。核对一次goodbye、一次通知、先回调后清ID、关闭后不再有普通wire，收发均
join。`connection_id`以4线程分配40000次检查计数器无零/连续分布并跨IHS_Quit保留。
`udp_send`控制最终sendto，验证MSG_DONTWAIT、完整长度、EAGAIN/EINTR各仅一次尝试，
保持接收阻塞属性。它们不证明真实内核拥塞、Switch显示/loader或真实Steam会话。

```sh
python3 scripts/audit-steam-disconnect.py \
  --binary /path/to/official/libmain-arm64.so \
  --output build/video-recovery-re/disconnect.json
python3 scripts/check-steam-disconnect.py \
  --receiver build/desktop/third_party/ihslib/tests/session/ihs-disconnect-oracle
ctest --test-dir build/desktop -R 'disconnect|connection_id|udp_send' --output-on-failure
```

## 41. 发送准入、控制调用者与失败分类

### 41.1 官方客户端证据

`audit-steam-send-admission.py`执行固定ELF的Frame构造`0x7f2af4`、Frame::Send
`0x7f3078`、Connection::Send/SendUnreliable `0x7fb9b4/0x7fbb58`和Client
SendControlMessage `0x7a7d90`。protobuf Put、普通加密、channel查找/返回值与析构
为明确替身；本节测试准入/调用者动作，不把这些替身当作真实窗口、wire或protobuf。

【证据/结论】Frame::Send的connection为空返回3；connection存在但state不是1，
两种Send均在进入channel前返回3。该返回不能占用packet ID、跟踪窗口或发送队列。
client控制调用者的明文分支`0x7a7e04`与加密分支`0x7a7e74`都没有检查Send返回值，
随后直接析构/解锁；channel返回0/1/2/3/4时，当前client和connection状态均不改变。
临时Socket失败的retained窗口与后续RTO见§37，不能把“初次没写出去”改为强制断连。

【证据】控制类型1/2/6/7走明文分支，其他类型先获取channel并递增64位加密序列，
再调用加密和Frame::Send。因此即使连接此时未建立、最终被返回3拒绝，加密序列
仍已消耗；不能为了提前返回在Client准备消息之前增加transport guard。

【证据/独立项目防护】另8例实际执行BEncrypt `0x7f342c`，在HMAC或AES helper返回
false时原版未改写原始payload，而上层仍调用Frame::Send。state1可把原始payload
交给channel。这里的helper失败是故障注入，不是正常Steam会话的观测。
本地继续保留加密/分配失败不发布payload的防护；这些本地资源/密码错误与普通
transport返回码分开，不能把此防护冒称已复制原版失败行为。

### 41.2 实现边界

内部queue/frame准入使用结果0（已接纳）、2（本地frame边界拒绝）、3（未连接）、
4（本地分配/加密/保留失败），原bool API保留为“已接纳”含义。它不是原版同步
Channel::Send的Socket返回值：项目sender actor负责实际发送并按§37保留/重试。
控制调用者只把明确的本地资源/密码故障交给项目关闭保护；2/3不再由bool false
概括为断连。完整frame在分配ID之前检查连接状态，消息准备/加密序列的时机不变。

### 41.3 对照范围与触发

固定参考170例：Frame::Send的4个transport状态×两种发送方式×5种channel返回
40例、null connection 2例，控制调用者的4状态×类型1/2/6/7/8/106×5返回120例，
以及HMAC/AES失败×4状态8例。channel发送是结果注入点，不包含真实窗口/RTO，
正文不能据此宣称这些不可能正常共存的client/connection组合均由UI可触发。

生产oracle消费前162个契约投影：相同transport状态下的准入、拒绝不消耗ID、
加密准备/序列消耗、control不因ordinary socket返回码断连。生产侧真实protobuf/
加密/排队后单独执行Socket和NoteInitialSend，核对0..4分类、未退出与可靠保留；
bool已接纳不冒充官方同步Frame返回码。不同合成payload不比较wire；窗口保留的
官方原指令证据仍在§37的独立sender对照，不把channel替身说成已执行窗口。

2个本地保护案例分别注入加密失败、reliable Track分配/保留失败，要求不发布明文/
不继续使用可能出现ID空洞的连接。这些保护会关闭transport，是保留的项目差异，
没有计入162个普通契约等价数量。官方8个crypto故障例未做相同行为的生产实现。

`send_admission`还从真实packet入口验证拒绝时buffer仍归调用者、独立Unconnected
discovery准入、本地frame边界在ID分配前返回2，2不触发关闭。
`send_admission_worker`两次启动真实收发线程：先提交被拒绝的握手消息，再正常
Connect；实际ClientHandshake经历EAGAIN/EIO/EMSGSIZE/EBADF四次失败后第5次成功，
期间无断连/ID变化/计数增加，再接收真实ACK退休并停止/join。只有时间与最终UDP
I/O受控；它证明项目发送actor的恢复接线，不证明全收发循环墙钟时序等价。

既有媒体/反馈/HID队列测试明确把transport设为已连接再运行其组件；涉及首次
Connect的测试继续从未连接状态启动，不能把公共fixture统一改成已连接来绕开准入。

```sh
python3 scripts/audit-steam-send-admission.py \
  --binary /path/to/official/libmain-arm64.so \
  --output build/video-recovery-re/send-admission.json
python3 scripts/check-steam-send-admission.py \
  --receiver build/desktop/third_party/ihslib/tests/session/ihs-send-admission-oracle
ctest --test-dir build/desktop -R 'send_admission' --output-on-failure
```

## 42. 客户端控制生产者到实际报文字节

### 42.1 官方证据和推导范围

【证据】固定Android 1.3.32 ARM64 ELF（SHA256同§41），执行
`CStreamClient::SendControlMessage 0x7a7d90` 或 `OnStreamConnected 0x7ace2c`，
经真实Frame构造/Put `0x7f321c` / Resize `0x7f2ef8` / Send `0x7f3078`，
Connection::Send `0x7fb9b4` / GetChannel `0x7fba34` / Channel::Send `0x7f89dc`，
进入 AddToOutgoingPacketWindow `0x7f6f94` / BInsertPacket `0x7f7230`，
再由可靠sender `0x7f8ac4` 和Socket::Send `0x7ff1dc` 形成最终wire。
CRC32C仍执行 `0x8e1610`。`s_nMTU`的GLOB_DAT `0xc806c8`指向`0xf34d48`，
不以未重定位的GOT零值替代实际MTU。

【证据】Channel::Send `0x7f8a58–0x7f8a6c` 清空13B头再写type5、两端ID和
channel，因此不会从Frame携带强制CRC位。Socket按connection+10添加CRC。
在ID12/34、timestamp1000000、message6含空required info的受控输入下：

```text
CRC=false: 05 00 0c 22 01 00 00 00 00 40 42 0f 00 06 0a 00
CRC=true:  85 00 0c 22 01 00 00 00 00 40 42 0f 00 06 0a 00 86 78 6f c6
```

【证据】AddToOutgoingPacketWindow `0x7f6fec` 无条件减17计算body容量，
`0x7f6ff8` 在body<=容量时不分片；大于时head.fragment=(body−1)/容量，
后片type6、fragment从0起、packet ID连续，head的packet长度缩到MTU−4。
因此CRC=false的满片线上比MTU少4B，CRC=true满片恰为MTU。

【证据】可靠sender `0x7f8bcc–0x7f8bd0` 把Socket返回1变成0；其他非零值
保留。包已入窗，失败不增加count，不退休。撤回把§41注入的Channel结果1直接
等同于真实可靠Socket结果1的推论；§41本身只证明上层如何处理给定Channel返回，
没有执行本节实际映射。项目bool队列准入和最终Socket结果仍分开比较。

【证据】空channel表前态下，实际OnStreamConnected构造message6并可靠发送，
经真实GetChannel只创建0、1密集前缀。channel构造器是显式内存布局适配器，
不执行其全部初始化。
本地协议消费者预建0/1/2同时注册outgoing，不能据GetChannel独立用例宣称上层
创建时机已相同；本节仅记录此差异，不将wire对照计为factory时机等价。

### 42.2 固定向量与替身边界

`audit-steam-control-wire.py` 固化78例：CRC两值×MTU512/1024/1472×6个body
边界36例、真实控制调用者类型1/2/6/7×Socket返回0..4×CRC两值40例、
OnStreamConnected两例。检查完整wire、Frame返回、真实window tail和创建顺序。
protobuf的ByteSize/Serialize输出是显式适配器：控制例提供空消息或required空info
的确定字节，frame边界例提供不解释schema的受控字节。原指令负责Put写入位置、
envelope、分片及后续所有报文决策，不把序列化替身称为已执行完整protobuf。
内存、channel构造器、mutex/refcount、destructor、统计和最终transport同样为适配器。
没有加密例，不能把此处明文全链推广到crypto实现或所有上层调用者。

生产oracle执行真实control/handshake生产入口及真实protobuf-c、frame队列/保留、
分片和Socket；只有时钟/最终UDP受控。边界frame输入与原版Put输出相同的字节，
不比较不存在的protobuf语义。wire/ID投影不包含全worker调度、factory创建时机、
真实网络认证或Switch解码显示，亦不证明用户停顿的因果。

```sh
python3 scripts/audit-steam-control-wire.py \
  --binary /path/to/official/libmain-arm64.so \
  --output build/video-recovery-re/control-wire.json
python3 scripts/check-steam-control-wire.py \
  --receiver build/desktop/third_party/ihslib/tests/session/ihs-control-wire-oracle
```

## 43. 统计消息与会话MTU探测应答的生产入口

### 43.1 官方客户端来源

【证据】固定Android ELF的 `SendStatsMessage 0x7a8bbc–0x7a8c64` 构造channel2
Frame，Put(message,false)，Send(connection,true)。它使用§42的同一可靠入窗/
分片/Socket链，不能用本地ch_stats的“单个可靠packet”替代。原指令的CLogMsg
受控序列化输出在MTU512/1024、空/边界/2048B字符串下核对完整wire；CRC=false时
type5头不带bit7，较长消息切成5/6和连续ID。单包Socket失败仍按§42映射/保留。

【证据】`OnPingRequest 0x7acc20` 先构造request于`x29−0x28`（sp+88），成功
Frame::Get后构造response于sp+56，并把sequence/接收长度写到sp+80/sp+84。
但 `0x7accf8` 传给Frame::Put的x1为`x29−0x28`，即request本身，不是response。
原指令执行时分别记录两个构造器返回位置、ByteSize所用对象和未使用的response
字段，确认线上type2的protobuf第二字段回显request.packet_size_requested。
不能因schema把该field2命名为packet_size_received，就推断实际线上填写接收长度。
这可能是该固定版本的实现疏漏（hypothesis），其wire行为本身是直接证据。

【证据】应答使用Frame ctor(0,2)、Put(...,true)的4B protobuf长度前缀；非零
requested触发GetWriteArea/memset(0xFE)填到请求的packet长度，之后
`Frame::SendUnconnected 0x7f3160` → `Connection::SendUnconnected 0x7fbc04`
清空13B头再走真实Socket。两端ID/channel/fragment/packet ID为0、不建channel，
CRC仍由connection+10决定；因此开启CRC时最终线上长度是requested+4。
OnPingRequest忽略SendUnconnected的结果，成功解析分支返回true；EAGAIN不会
进入可靠窗口或自动重试。这里的input frame已剥CRC，不把它称为完整Socket入包。

【更正】§6/§12早期把此OnPingRequest与UDP27036首页广播串成一条链的概括
撤回。此处是会话Unconnected type0、discovery message1/2的MTU探测，不能与
独立的首页主机发现协议合并。§7表格已有此分层说明，以这里的对象/线上证据为准。

### 43.2 对照的范围

§42的audit追加统计40例、discovery22例，原78个input/observed保持不变。
统计32个成功多片/边界输入另加8个单包错误输入；discovery覆盖CRC两值、请求
长度0/64/1024/1472和Socket成功/EAGAIN，另以6例省略sequence/requested或两者
验证presence原样保留。总140个生产wire/ID对照。protobuf parser/ByteSize/serializer、
构造器、内存/refcount和最终UDP为显式适配器；真正选择哪个protobuf对象、
response字段写入、padding、信封及发送链均执行原指令。无真实网络测试UI。

本地oracle从真实stats入口或实际discovery channel回调进入，使用protobuf-c
解析/序列化、真实queue/retention/分片/Socket，核对wire和该通道的next ID。
它不证明首页发现、解析失败/畸形小requested的所有路径、全部stats用户触发，
或fragment初发失败时整个actor与官方同步sender的动作顺序。
后者不能仅凭重传阶段测试宣称相同：这里记录的81846be/IHSlib437d763旧worker
仍直接初发后续FIFO项；§44以整帧事务替换该接线，明确追加初发/续发对照。

### 43.3 独立的真实C++ protobuf核验

【证据】`audit-steam-discovery-protobuf.py` 另用已重定位ELF和原版生成的
CDiscoveryPingRequest/Response构造器、真实Frame::Get/parser、ByteSize/serializer、
Frame::Put/Resize与padding复播5例：两字段存在(requested=0/64)、都省略、只保留
sequence、只保留requested。不是复用§43.2的protobuf输出适配器。
每例在真实Put调用记录传入对象相对SP偏移88，并截取final SendUnconnected之前
的Frame正文（4B长度+protobuf+padding）；5例都确认序列化的是原request对象。
内存/libc存储和最终SendUnconnected为适配器，input Frame/packet布局预置，
没有执行完整网络入包，也未把没有执行的header/message-byte/CRC写入算进来。

这5个独立正文向量与§43.2的相应CRC=false报文、生产真实discovery回调三方对照，
不把5例再计作新增的完整wire输入。原140例仍保留各自的适配器/字段边界。

```sh
python3 scripts/audit-steam-discovery-protobuf.py \
  --binary /path/to/official/libmain-arm64.so \
  --output build/video-recovery-re/discovery-protobuf.json
```

【证据／未对齐范围】§42导出的原指令Sender，以CLogMsg字符串1000B、MTU512、
CRC=true从真实SendStatsMessage进入；Socket返回1或4时均只尝试head，window tail
为3。81846be/IHSlib437d763时生产`ihs-control-wire-oracle 1 512 3 3 1 1000`
（或错误码4）的FIFO投影却尝试
3片，首片字节与原版相同。这是初发事务次序差异，不是CRC/分片字节差异。
该oracle不启动worker，不能据此宣称负载/墙钟下真实worker序列已取证；现有worker
逐FIFO项直接初发的接线也不能被重传阶段“失败停止扫描”用例替代。§44的独立
事务对照覆盖整帧入窗、失败停止及后续Update/新Frame触发，不沿用此旧FIFO投影。

## 44. 可靠整帧初发事务与后续触发

【证据】固定Android客户端的Channel::Send先完整执行AddToOutgoingPacketWindow，
再调用SendReliablePackets；该扫描在第一个非零Socket结果停止，Socket返回1映射为
Channel返回0，包和后续片留在同一窗口。§43的真实worker探针已证明原FIFO逐片
初发与此不同。`audit-steam-initial-send.py` 从真实SendStatsMessage/Frame入口
构造1000B字符串、MTU512的三片消息，固化64例：CRC两值、失败位置0/1/2、
Socket错误1..4，以及下一次sender Update、新Frame、成功前缀ACK后Update。
ACK只确认已成功发送的前缀（失败位置0不构造此场景）。

【证据】初轮只尝试0..失败位置；下一次sender扫描跳过尚未超过RTO的已成功片，
从count=0的失败位置继续。新Frame的Send先扫描旧窗口，再发新增ID3，不把它
排在旧失败片之前。ACK确认前缀后，失败片和未发送片仍可继续。时间仅增加1tick，
未达到125tick的RTO，因此不能将原本的初发绕行解释成正常RTO触发。

真实client/Frame/Connection/Channel/入窗/Socket/CRC及ACK分支执行原指令；
protobuf输出、channel构造器、window释放、时钟feedback、分配/refcount/mutex/
统计和最终UDP是显式适配器。Update案例调用真实可靠sender组件，不冒称完整
Connection::Update，也不把受控ACK/固定clock称为真实主机或墙钟延迟。

【设计约束】生产者必须在queue mutex保护下准备完整可靠frame后再公开；分配/
保留失败不能公开残缺batch。每帧仅一个初发扫描触发，后续片不是新的Frame触发。
发送worker先将该batch全部激活，再使用既有窗口的统一初发/RTO扫描；失败停止
该通道本轮，剩余片仍为count=0。尚未由worker接收的其他batch不得被提前发送。
ACK在I/O期间仍允许退休，持有引用的snapshot不得在ACK后写回已退休项。
此交付机制不是官方同步API/主循环的墙钟执行复制；本节只核对帧事务和触发顺序。

生产接线使用仅由queue mutex保护的staging队列，成功后整体公开；失败则销毁暂存
body并撤销未激活的retained登记。head携本地batch长度，continuation不再单独触发
扫描；该元数据不上协议线。worker先取完整batch，释放queue mutex后才持Base锁，
一次激活ID区间并调用与RTO相同的可靠扫描；生产者不新增反向等待Base锁。

【证据／边界】HandleAckPacket `0x7f9554–0x7f9560`按实际window tail截断确认。
尚未由worker激活的producer准备记录不属于该窗口；累计/选择确认不能提前退休
未来batch。初发I/O中的ACK仍能退休已激活项，引用snapshot之后不复活它。
`initial_send`验证未来帧不提前发送/确认、staging分配失败、第二片Track/queue-item
失败回滚。`retry_sender`分别在初发和重传I/O中并发ACK全部snapshot项。
`initial_send_worker`真实收发线程完成24组CRC×失败位置×errno的Connect/三片恢复/
累计ACK/stop/join，固定时钟避免将旧成功片的RTO误当初发恢复。

本地资源故障不能与Socket返回码4混用：整帧准备失败不公开残片，Control沿用既有
关闭保护，Stats也在释放producer锁后关闭，防止ID已消耗后继续使用有缺口的连接。
这是明确项目防护，不把原版分配故障路径宣称为已复现；64个普通写错误输入不会
触发这条关闭保护。既有140个wire向量改由真实worker transaction步骤消费，仍与
原版相同；Socket分类另有§40–41独立对照，不由此oracle重述输入errno冒充返回值。

```sh
python3 scripts/audit-steam-initial-send.py \
  --binary /path/to/official/libmain-arm64.so \
  --output build/video-recovery-re/initial-send.json
python3 scripts/check-steam-initial-send.py \
  --receiver build/desktop/third_party/ihslib/tests/session/ihs-initial-send-oracle
ctest --test-dir build/desktop -R 'initial_send|retry_sender|control_wire' --output-on-failure
```

【线程约束】整帧dispatch与独立RTO入口共享扫描时，锁序统一为Base→sendLock→
retained状态锁（快照期间），I/O时不持retained状态锁。TSan在“先dispatch、后独立
RTO Socket回调”的受控输入中检出了原混合入口的潜在Base/sendLock反序；没有观察
到真实死锁，不能把warning称为设备故障。共同Process入口对有session的扫描先持
Base，调用者已持Base时递归进入；无session的独立窗口测试保留原锁域。


## 45. 官方可靠接收事件、反馈节流与线包

【证据】`audit-steam-reliable-feedback.py` 固定执行本文件相同SHA的Android
1.3.32 ARM64客户端，真实入口为Channel构造器`0x7f8630`、
HandlePacket `0x7f9250`和完整Channel::Update `0x7f9c9c`。
可靠更新`0x7f9d0c`、BInsert `0x7f7230`、PopHead `0x7f743c`、
Advance `0x7f76f4`以及Socket/CRC均执行原指令。142个固定案例覆盖CRC两值、
连续/重复/分片/乱序、ACK到期边界、RTT钳位及32位clock回绕、
Socket结果1..4、位图1/7/8/9/319/320/321位，以及旧时间戳和混合缺口年龄。

【适配器边界】真实构造器完成后只预分配空RX环的存储，逻辑头尾仍由真实Clear
初始化；真实BInsert/PopHead/Advance操作该环。分配/refcount/释放、mutex/queue
构造、帧上交delegate、统计、诊断和最终UDP为显式适配器；空FEC发送器按空操作
适配，不由此证明实际FEC发送策略。时钟和Socket错误受控。
输入为Socket已接受后的通道包，不冒称原始UDP接收、完整Connection::Update、
实际主机应答、真实解密或设备渲染。某些首包有缺口案例触发原版“increasing”诊断；
探针保存原文、让非debug release路径继续，不能把诊断报告为客户端必然崩溃。

【结论：初始状态与ACK】构造器将dirty/+40、pending/+41、ACK水位/+42和
peer时间/+44、接收时间/+48清零，deadline/+104设为构造时间。
HandlePacket对5/6置dirty；只有peer时间为0或新的有符号时间差大于0，才同时更新
peer时间与该包的本地接收时间。相同/旧peer时间不刷新接收时间。
已经在窗口头之前的重复包置pending；仍留在窗口内的重复片不置pending。
Update只在dirty时进入，先清dirty并上交所有完整连续帧，再扫描连续**收包**水位。
水位变化置pending；pending且达到deadline才发送累计ACK并清pending，否则重置dirty。
因此单独收到并交付ID0仍保持初始水位0，不发ACK；ID0重到或之后ID1推进才会发。
ACK body是`peerTimestamp + GetTimestamp() - peerReceiveTime`，不是接收包ID的独立确认。

【结论：NACK】缺口只在已观测的头尾范围内判定。header.packetId是第一个缺口
**之后的第一个已存在包**；body依次是未经elapsed调整的peerTimestamp、累计水位u16、
从该base起的presence位图。位图长度为`ceil(min(tailExclusive-base,320)/8)`，
不是固定40字节。base及后面任一已存在包的本地接收年龄严格大于65 ticks，就满足
缺口年龄条件；不能只检查base，也不能把年龄扫描截到320位内。
一个Update允许先ACK再NACK；二者共用本轮进入时的deadline。只要尝试了任意反馈，
下一deadline设为`updateNow + max(clamp(smoothedRTT,65,3276)/4,65)`（整数除法）。
缺口太年轻或还未到deadline时保留dirty，后续Update继续检查。
成熟NACK尝试后不自行重置dirty；没有新接收时不会周期重发NACK。
Socket返回1..4同样清除此次ACK pending/成熟缺口dirty，并推进deadline；新接收事件
才能再次触发反馈，发送方自己的可靠RTO是独立恢复入口。
包头CRC初值清零，由Socket根据连接的CRC协商状态添加。

【更正与设计约束】撤回旧§9.2的周期ACK说明，撤回旧控制实现“无新输入必须每5ms
重复NACK”的测试断言；§14的窗口水位证据本身不能证明每包立即ACK或初始0必须ACK。
可靠接收应将入窗事件和Update分开，所有上交/解密仍在接收worker执行；
调用应用delegate时不新增持有Base传输锁的约束。反馈状态/Socket段使用Base→
receiveLock的统一锁序，避免收包锁反向等待Base。
反馈应在该Update中通过已设为nonblocking的Socket直接尝试，避免发送FIFO排队期间
ACK回显时间与实际发包时间脱节；Socket失败不另造反馈重试策略。
本地接收超时设为1000微秒，避免原10ms空闲阻塞推迟反馈；这只是唤醒粒度，
不能将操作系统实际调度保证为精确1ms。真实收发worker测试覆盖CRC×ACK/NACK
首轮失败×四种errno共16组：接收、交付、到期边界、空闲不重复、重复包重触发、
补洞和stop/join；Poll只记录交付并验证回调仍属于接收线程，没有替换真实Poll。
本地内存耗尽仍沿用显式关闭保护，不冒称官方故障分配分支已执行。
平台worker的轮询粒度不等同于官方墙钟调度，固定clock对照只能证明相同事件/Update
输入下的状态和线包；完整Connection各通道顺序与真实网络时延必须分开核验。

```sh
python3 scripts/audit-steam-reliable-feedback.py \
  --binary /path/to/official/libmain-arm64.so \
  --output build/video-recovery-re/reliable-feedback.json
python3 scripts/check-steam-reliable-feedback.py \
  --receiver build/desktop/third_party/ihslib/tests/session/ihs-reliable-feedback-oracle
ctest --test-dir build/desktop -R 'reliable_feedback' --output-on-failure
```

本地oracle仅控制时钟和最终UDP，并在真实Poll返回后记录未解析帧。
初始状态及每个Receive/Update后的dirty、pending、水位、peer/local时间、deadline、
窗口头尾、完整帧body和完整线包均与官方fixture比较；只有诊断assert文本不属于
本地协议状态，明确排除。配置/传输层旧oracle分别补上显式通道Update，
不把已入窗但尚未交付的输入误算成配置接收完成，也不额外重复Connect Update。


## 46. 通用可靠通道、客户端消费与通道构造边界

【证据】`audit-steam-reliable-channels.py`接续§45的固定官方Android客户端。
输入通过真实Connection::HandlePacket `0x7facfc`进入真实GetChannel/ctor和
Channel::HandlePacket/Update；可靠窗口/ACK/NACK/Socket/CRC执行原指令。
交付不再停在虚delegate：执行真实OnStreamPacket `0x7acfa8`、Frame构造与
SetPacket `0x7f2b98/0x7f2bac`、HandleIncomingPackets `0x7a6368`、
HandlePendingDataPackets `0x7aff74`和
OnDataPacket `0x7ad148`。100例覆盖CRC两值、channel0/2/3/31、客户端state0/2/6/7、
错误消息类型，以及有效媒体头在已配置/未配置时的区别。

【结论】可靠传输状态属于通用channel，不属于Control消费者。即使上层忽略
channel0/2的未知消息，接收窗口和ACK/NACK仍正常推进。客户端state0/7不消费
帧；媒体类型1要求state6，尚无匹配audio/video消费者时保存完整packet；匹配时
先规范化时间戳，再RecordFrameReceived，最后调用decoder的OnReceiveFrame。
先收到ID1、后补ID0时，两个帧按0→1上交，保留各自transport发送/本地接收时间。
因此不能用Stats消费者Noop替代可靠接收，也不能把已重组帧重新送回transport窗口。

【证据】GetChannel `0x7fba34`只在请求新ID时创建缺失的0..ID前缀，构造时间决定
§45的初始反馈deadline。控制/统计消费者预建不证明官方transport channel已创建。
§42的140个真实生产入口已记录factory：discovery不用channel，Handshake创建0/1，
Stats创建0/1/2；加密控制在Frame准入前GetChannel，明文Frame在连接准入后GetChannel。
生产者创建transport状态不能反向等待持Base的sender；factory/发送排序快照可由
queue mutex保护，Socket I/O时不得持queue mutex阻塞生产者。

【边界】队列append、最终decoder入口、统计记录、地址比较、空FEC发送器、分配/
refcount/释放、mutex、诊断与最终UDP为明确适配器；接收环预分配空存储。
真实HandleIncomingPackets从队列取帧并执行未知消息的丢弃分支；真实OnDataPacket
执行未配置缓存和已配置时间转换。没有实际decoder、真实Steam主机或完整应用主循环。
固定状态可独立于连接状态设置，是函数边界验证，不冒称每个组合均由实际UI触发。
平台的异步decoder交付和完整Connection循环顺序必须与本节逐事件结果分开核验。

【证据／更正】共享HandleNackPacket在`0x7f9614–0x7f9624`以lastTimestamp=0
为哨兵，并在任何body长度校验之前存入新header时间；短畸形体也消耗水位。
可靠通道原实现的独立haveTimestamp位和先拒绝短体的顺序与原版不同。
新向量同时执行首次畸形后较旧有效NACK、首次时间0后0xffffffff的反例，
从Connection入口核对到后续原版可靠sender的实际wire，不能只测字段setter。
另有媒体三片缺口与补洞、未配置完整帧到消费者注册后原始pending处理函数的案例。
临时vector CopyArray、pending存储预分配及最终decoder仍是显式适配器，未调用真实设备。

生产接线将32个protocol可靠状态放在session中，独立于consumer的创建/替换；
入窗、累计/选择确认、NACK及反馈复用§45机制，可靠媒体完整帧复用decoder worker
的完整帧FIFO；等待消费者的帧带完整标记，注册后直接上交而不重新入窗。
消费者预建不再注册outgoing；明文Frame和加密控制按上述各自实际时机触发factory，
初始deadline也跟随该逻辑构造时刻。queue锁只保护factory/排序快照，不包围Socket。
临时资源失败沿用明确项目关闭/有界队列保护，不冒称原版内存耗尽分支已等价执行。

本节媒体数据采用有效完整头，peer−local offset固定0；实机codec、非零offset的
跨层转换、完整应用循环与协商声明不能由这些数据头样本自动推出。
本节当时`reliable_data=false`仍是声明差异；后续§48完整协商生产对照更正此声明。
完整decoder契约仍独立于通用可靠接收状态机。原§14.11/§24中“只接纳3/4”说明由此更正：5/6可以重组并
交给consumer，但不能仅凭本节宣称完整协商和设备消费已经与Android相同。

```sh
python3 scripts/audit-steam-reliable-channels.py \
  --binary /path/to/official/libmain-arm64.so \
  --output build/video-recovery-re/reliable-channels.json
python3 scripts/check-steam-reliable-channels.py \
  --receiver build/desktop/third_party/ihslib/tests/session/ihs-reliable-channels-oracle
ctest --test-dir build/desktop -R 'reliable|control_wire' --output-on-failure
```

Native oracle从实际session wire回调进入，逐事件比较完整反馈wire、原始交付帧、
客户端最终忽略/媒体回调、pending内容、factory前缀和NACK时间水位。
真实媒体worker消费队列，终端dataFrame只记录头/载荷，不替换重组或FIFO；
pending同单元内dispatcher调用另在真实data handoff处观察，GNU wrap不冒充内部调用拦截。
控制§45的142例保持原结果，§42的140例另比较完整factory列表；五个独立C++ protobuf
输出比较继续保留。真实收发worker在channel0/1/2/3/31执行CRC×ACK/NACK失败×四种errno
共80组，验证非控制反馈、到期边界、重复输入、补洞和stop/join。
历史`audit-ihslib-control.sh`探针补上明确的连接前态、激活窗口、Receive→Update和
最终Socket/clock替身，不再从旧FIFO接口推断反馈发生；仍保留诊断buffer canary。


## 47. reliable_data值与presence的直接C++核验边界

【证据】`audit-steam-negotiated-reliable.py`使用同SHA官方客户端的真实
CNegotiationInitMsg/CNegotiatedConfig构造器、Frame::Get与原C++ protobuf parser，
执行OnNegotiationInit `0x7ad698`到`0x7ad720`。`0x7ad6fc/0x7ad710`
无条件读取已解析bool值并复制；`0x7ad704–0x7ad71c`将目标hasbits独立OR 5。
初始codec选择尚未继续，目标partial config由原C++ ByteSize/serializer生成：

| 输入protobuf | 输入hasbits | 目标reliable_data | 目标hasbits | 此处partial config |
|---|---:|---|---:|---|
| 空 | 0 | false | 5 | 08001000 |
| 0800 | 1 | false | 5 | 08001000 |
| 0801 | 1 | true | 5 | 08011000 |

【结论／撤回】§5原“含hasbit回显”的表述没有依据，现明确撤回。该地址复制的是
值；缺省false与显式false在这个checkpoint的输出相同，输出presence不是输入presence。
不能再将输入字段省略直接等同于目标config字段省略。

【边界】这是完整解析器后的初始复制checkpoint，使用已解密明文Frame；codec选择、
最终SetConfig的原始调用者/序列化wire、真实主机协商及decoder均不在此3例范围。
停止点及分配/libc为显式适配器；不把partial config当作最终协商报文，亦不由此
宣称协商声明和完整媒体模式已对齐。

```sh
python3 scripts/audit-steam-negotiated-reliable.py \
  --binary /path/to/official/libmain-arm64.so \
  --output build/video-recovery-re/negotiated-reliable.json
```


## 48. 完整NegotiationInit生产与编码能力语义

【证据／撤回】直接读取固定ELF的内嵌remoteplay.proto descriptor，
EStreamVideoCodec的1=Raw、4=H264、5=HEVC、8=AV1、9=Pyrowave。
撤回旧§5/§7“1/H264”的说明，不能把音视频消息的type1或Raw视频codec1当H264。
`OnNegotiationInit`对Raw1直接选中，对4/5/8/9调用BAvailable；caps顺序为Raw1，
再按BAvailable追加4/5/8/9。当前平台H264/HEVC外的codec能力不因看到这个分支就可冒报。

【证据】`audit-steam-negotiation.py`执行完整OnNegotiationInit、原C++构造/
parser/CopyFrom/serializer、SendControlMessage、Frame::Put/Send至最终Connection
send边界。输入是已解密Frame；BAvailable、GetChannel、加密和Connection最终发送
是显式适配器，捕获的是已定型的明文frame body，不是加密UDP线包。
三个复制checkpoint不再被当成完整协商；完整生产案例覆盖codec顺序、Raw音频开关、
可靠字段presence/值、重复Init、host元数据、临时limit清除与坏protobuf。

【结论】完整SetConfig明确写reliable_data（缺省false也有presence），selected audio/
video即使None0也显式出现。音频按host顺序取首个Raw1或Opus3，enable_audio_uncompressed
为true时跳过Opus；enable_audio_streaming=false不删除解码能力。视频按host顺序取
Raw1或BAvailable允许的4/5/8/9。Codec能力与HEVC请求偏好分开；caps的音视频数组也
不能改成偏好排序。Native库的H264/HEVC子集不支持Raw视频1，是明确能力差异，相关source
案例不计入Native等价；不能把过滤后的计数宣称覆盖了Raw/AV1/Pyrowave。

重复Init会覆盖reliable/selected codecs，但remote HID/touch仅在host的值为true时置位，
随后false/省略不清除该成员。os_type/gaming_device_type仅在输入presence存在时更新，
显式0仍覆盖。OnInit在复制client config前清除runtime_limit，保留display/quality limit。
这些规则由完整C++生产案例执行验证，不从字段名推断。Switch应用只声明已接线的H264，库的显式HEVC能力与请求偏好分开。
平台的BAvailable、caps初始deprecated HEVC位为受控输入，不冒称执行了真实硬件探测或完整CStreamClient构造。


### 48.1 可靠环满状态与大帧约束

【证据】长SetConfig的19片生产回归中，本地已发送全部片，但测试接收环在第16片
后把满环误判成空，后续重组无法完成。通用接收也采用相同window函数，故这是实际
接收风险，不是测试需要多pump一次sender。此前引入16槽初值时没有覆盖环满边界。
`audit-steam-reliable-large-frame.py`执行官方真实ctor/BInsert/EnsureCapacity/PopHead/
Update/Socket，证明环满仍保持正确span并交付。原始EnsureCapacity `0x7fd250–0x7fd270`
将容量下限取64、再按二的幂扩展。18例覆盖15/16/17/19/63/64/65/1100片、
CRC开关和64槽满环但缺首片的ACK/NACK。该探针还逐字节重组1100×1024B，记录真实交付的
长度/SHA256和ACK，不用本地算法生成expected结果。

【设计约束】Native的物理head/tail相邻既可表示空也可表示满；tail槽仍持有packet时
不能返回size0。可靠window从64槽起增长，满环不能阻断扩容。可靠完整帧使用接收
窗口范围决定重组长度，不把control时期的1MiB临时buffer上限误当成媒体协议上限。
decoder/FEC FIFO的显式本地资源限制与此transport重组区分；本节不是内存耗尽验收。

### 48.2 Raw音频能力必须由实际播放路径支撑

【证据】同SHA官方客户端`StartAudioDecoding 0x7a7ef8`对codec1构造
CStreamDecoderRawAudio；`StartDecoding 0x7b178c`执行CAudioFormat parser，
用其中frequency/channels启动player，不能仅沿用StartAudioData外层的两个值。
`DecodeFrame 0x7b1838`读取little-endian signed16样本，转换为float（除32768）
后交给player；标量尾部和NEON分支均如此。`audit-steam-raw-audio.py`执行原始
parser/DecodeFrame，14例覆盖mono/stereo、极值/符号、向量边界及6000样本长帧，输出真实float
字节与frame metadata。player的分配、启动、提交和GetWriteArea存储为显式适配器。

【设计约束】此前应用播放端仅允许Opus，不能把库能交付Raw误称为应用能播放。
Raw能力声明必须配套解析codec_data和实际PCM播放。SDL平台仍用已验证的S16LE
设备格式；官方float输出与本地SDL队列的S16LE按精确的32768比例比较，平台音频
输出格式差异不当成网络codec差异。短坏配置、无效采样率/声道及分配失败的保护
属于本地资源/输入约束，不声称官方故障行为等价。实际声卡/扬声器仍需设备证据。


```sh
python3 scripts/audit-steam-negotiation.py \
  --binary /path/to/official/libmain-arm64.so \
  --output build/video-recovery-re/negotiation.json
python3 scripts/audit-steam-reliable-large-frame.py \
  --binary /path/to/official/libmain-arm64.so \
  --output build/video-recovery-re/reliable-large-frame.json
python3 scripts/audit-steam-raw-audio.py \
  --binary /path/to/official/libmain-arm64.so \
  --output build/video-recovery-re/raw-audio.json
ctest --test-dir build/desktop -R 'negotiation|reliable_large_frame|raw_audio' --output-on-failure
```

完整Init固定96例，Native比较其中93例；3个实际选择Raw视频/AV1/Pyrowave的案例只作
source证据。比较器仅删除caps中本平台没有的Raw视频1声明，其他SetConfig字段完整逐字节
比较，不以此过滤冒称全codec等价。Native真实可靠分片和加密发送后重组、解密再比较；
Source完整C++ Frame生产在加密/Connection发送处用适配器，故不是两端加密UDP互通证明。
嵌套limit保留/清除覆盖空repeated容器，非空decoder-limit列表不在本节96例内。
Raw音频另外从真实media start/submit走到SDL设备队列，与14个官方float结果比较，并
核对codec_data覆盖外层频率/声道；附加坏配置/不整样本保护和stop/shutdown。
这些证据不包含真实Steam认证、peer SetConfig后完整握手、物理设备解码/显示或用户停顿原因。


## 49. Host回传SetConfig与独立StreamStarting阶段

【证据／撤回】`audit-steam-peer-negotiation.py`执行同SHA官方客户端
`OnNegotiationSetConfig 0x7adb28`完整函数及原C++ Frame parser/CopyFrom/serializer。
撤回旧§6“校验整个NegotiatedConfig一致”的说明：`0x7adb78–0x7adbfc`只分别比较
selected_audio_codec和selected_video_codec，断言行2683/2684。探针显式使用
非debug环境，断言被记录但不终止；codec不一致仍CopyFrom，不能据此新增拒绝协商策略。

【结论】解析成功时只将message.config整体复制到成员，包含reliable_data、HID/touch
清零、省略/presence及unknown fields；同一消息的streaming_client_config/caps不替换
client自身配置。required config完全缺失或坏protobuf时保留旧成员/状态；required
config存在但为空则有效，可清掉旧字段。函数末尾始终return1，不能以返回1断言
protobuf解析成功。复制后state不是5时改为5（Starting），本函数不发Complete，
不改channel priority、不启动stats/player。

【证据】探针随后显式调用`HandleStreamStarting 0x7a6f9c`，执行原始状态分支、
Complete构造/SendControl/Frame Put/Send；最终明文body为05。观察到调用顺序：
network lock → state6 → SetChannelPriority(1,2)/(2,-1) → 写两处同值timestamp →
发送Complete → stats Start → 可选client/player通知 → network unlock。setter、clock、
stats及player回调本身是记录适配器，未由此证明各个被调模块内部实现。

【证据范围】固定66例：state4/5/6受控入口×缺required config、reliable三态、codec
匹配/不匹配、flags清零、unknown config和坏消息，另含显式空required config。
state5/6是直接函数入口的受控测试，不据此宣称完整网络dispatcher在这些状态必然
允许对应消息。Start是探针显式接续；真实应用循环何时调用、与Connection Update/
feedback/KeepAlive的先后仍不能由这两个单函数的拼接代替。

【实现约束】完整成员CopyFrom与Starting阶段不能省略为“收到host SetConfig就直接
忽略正文并发Complete”。另一方面，看到codec Assert也不能自行添加非debug断连。
官方状态6与本地Connected枚举的数字不相同，比较时应按阶段语义映射。
本节仅提供官方入口证据，不把现有Native协商处理宣称为这些66例等价。

```sh
python3 scripts/audit-steam-peer-negotiation.py \
  --binary /path/to/official/libmain-arm64.so \
  --output build/video-recovery-re/peer-negotiation.json
```

输入Frame从解密后开始，内存分配/进程protobuf初始化、network lock、priority setter、
时间、stats/player/client回调、GetChannel、加密及Connection最终发送均是显式适配器。
原C++字段复制和protobuf输出并未被本地模型替代；真实加密会话及设备仍不在范围内。


## 50. OnThink真实分派与正常首个KeepAlive边界

【证据／撤回】`audit-steam-negotiation-loop.py`从官方
`CStreamClient::OnThink 0x7a5ff8`进入，执行真实HandleIncomingPackets队列取出、Frame
构造/解析、OnNegotiationSetConfig、状态选择、HandleStreamStarting及HandleStreaming。
撤回§6/§9/§13.3/§14.14把`last==0`立即发送解释为正常启动首发的结论。
§13.3的表格保留历史审计背景，不能再据此称本地立即发送已经与正常官方启动对齐。
`ch_control_keepalive.c`中旧“Official立即发送”的注释也属该过度解释，不能作协议证据。

【结论】OnThink在network process/Transport Update后先排空incoming队列，再按当前
状态仅选一个阶段。state4只把Setup3/4分派到Init/SetConfig；成功peer SetConfig改为5
后，同队列后面的Setup4被忽略。原始队列中先坏PB后有效消息仍能成功；先有效后另一
有效消息则保留第一份config。state5/6时Setup4不直接进入OnNegotiationSetConfig，
因此§49受控函数入口state5/6不代表相应网络消息被接纳。

OnThink发现state5时执行Start并进入6，但该轮不再执行Streaming。
Start把两处时间都写为当前值：client+0x1c678（frame events）和+0x1f6f0（KeepAlive）。
下一轮Streaming的KeepAlive条件是last=0或signed(now-last)>0xa0000。
正常非零启动时间下，下一tick和恰好+0xa0000都不发；+0xa0001才发消息09。
不能把正常首发改成立即发，也不能把严格大于改成大于等于；只有预先state6而
last仍为0的控制案例才在第一次Streaming立即发送。

【原指令案例】30组×4个OnThink阶段，覆盖state4/5/6、网络线程开关、空队列、
有效/坏PB、两份有效及坏后有效；逐阶段输出真实config、完整明文Complete/KeepAlive
frame body、send sequence、调用记录和两处timestamp。Complete只在进入Starting的轮
发05；正常KeepAlive在严格10秒边界后发09，帧事件反馈的调用另外记录。

【边界】StreamProcessNetwork与Transport Update本身是记录适配器，因此本节证明
客户端阶段/dispatcher/KeepAlive调用链，仍不证明Connection内部RX反馈/TX同循环时序。
Input已解密，平台无decoder，network lock/refcounts/destruction、priority setter、clock、
stats/player/log回调、GetChannel、加密与Connection最终发送亦为显式适配器。
不据此声称真实认证、完整设备消费或操作系统调度等价。

```sh
python3 scripts/audit-steam-negotiation-loop.py \
  --binary /path/to/official/libmain-arm64.so \
  --output build/video-recovery-re/negotiation-loop.json
```

## 51. 接收更新中的协商阶段与保活算术契约

【证据／更正】§49–50的完整官方客户端入口支持将peer config保存、Starting和
Streaming拆开实现，不能仅调整毫秒timer。`audit-steam-negotiation-loop.py`保留原30例
并追加9例：tick0、32位回绕、连续周期、倒退和signed半域边界。原始指令
`0x7a71b8–0x7a71c0`实际检验32位`last - now + 0xa0000`的符号位，非负跳过发送；
last0另外直接发送。撤回把`signed(now-last)>0xa0000`当全32位域等价表达的说明。
通常小时间差下两式相同；半域及加法回绕边界不同，新增原指令反例已直接区分。

【设计约束】协商成员保存完整CNegotiatedConfig，包括presence、unknown、nested/repeated；
收到有效peer config只复制并进入Starting。接收更新先排空已接纳的可靠控制帧，再选择
一个阶段。Starting先置Connected、设priority和本次tick，再准备Complete并通知应用；
该次更新不再执行Streaming。已Connected的更新按原符号位算术检查KeepAlive并记录
尝试时间，不引入独立timer线程；配置分配失败采用本地关闭保护，不声称原版OOM行为。

【比较边界】Native从实际encrypted/CRC wire ingress、可靠重组及解密到peer handler，
分别观察drain后的Starting和实际Base RX Update后的状态，出站通过真实分片/加密/
retained sender后从wire重组解密。39个OnThink序列加22个state4 peer案例在CRC关/开
各比较一次。state5/6的Setup4只按真实dispatcher忽略；§49的直接入口案例不会冒充
这些网络消息可达。比较完整成员config、Complete/KeepAlive body、sequence、保活tick，
以及Starting的priority结果和connected通知。网络线程开关在Source影响适配器调用，
不宣称Native拥有同样的平台线程配置。

CNetworkStats Start、frame-events时间/统计内部、pending log、完整decoder与Connection
内部RX反馈/TX同循环排序不在本节比较内；普通sender异步队列与应用callback相对Socket
写入的先后亦不因此宣称等价。原transport/Pause oracle调用的UPDATE限定为Transport
Update，避免以单组件Source结果推断整个新增客户端阶段；完整RX阶段由本节另测。


保留现有control producer锁串行化Starting的live状态发布与Complete入队，防止并发HID
在这两者之间抢先入队；应用connected callback仍在该段锁释放后执行，不新增应用
必须持Base锁的约束。该局部producer顺序不当作Source全局network lock域的等价证明。

极端半域tick跳变案例中，Source记录Connection::Send入口，未执行内部整形器；Native
因此同时记录真实加密Frame producer边界与实际wire。通常tick范围两者均比较；跨半域
时仍逐字段比较producer/序号/保活时间，额外wire轨迹保留，但不冒称Source已证明整形后
UDP发出。Native整形器确实可能阻止该包立即写出，不能把序号增加当Socket已经发送。

```sh
python3 scripts/check-steam-negotiation-stage.py \
  --receiver build/desktop/third_party/ihslib/tests/session/ihs-negotiation-stage-oracle
ctest --test-dir build/desktop -R 'negotiation_stage' --output-on-failure
```

真实RX/send workers另覆盖CRC关/开、普通/回绕起点及正常、Complete首次EIO、KeepAlive
首次EIO/EAGAIN，共16组；保留标准ConnectACK/ClientHandshake，认证后状态为显式fixture。
实际加密peer配置进入后观察一次connected、完整配置、严格到期、发送序号与重传，最后
stop/join/destroy。冻结逻辑clock时传输整形rate设为0；EAGAIN后的可靠重传显式推进到
现有RetryTicks之后，不用保活producer再生成一条消息来替代可靠重传。


Complete准备在producer锁内返回admission结果；本地资源失败的关闭/停止消费者发生在
释放该锁之后。不能在外层锁仍持有时复用会自动Disconnect的普通Send包装器，否则
消费者可能正在等待同一producer锁。该保护是Native所有权约束，不冒称官方OOM策略。

## 52. 帧统计窗口与完整报告的原始客户端契约

【证据／撤回】同SHA官方客户端`CStreamClient`构造器0x7a5020–0x7a50d0对四个
数据类型各构造240个120B CFastFrameStats，清零各自watermark/previous-time。
RecordFrameReceived/Event/Complete、GetFrameStats及SendFrameEvents均用id模240寻址。
撤回Native frame_stats.h“128槽/按id&127即对应Steam”的注释；它是本地实现差异。
`audit-steam-frame-stats.py`实际执行CFast构造器及上述完整函数、原累加器、C++ protobuf
和Frame Put/Send，保留最终明文frame body；不是按本地代码构造预期。

【结论】只有Receive可为不同frame ID重置槽；Event/Complete在ID不匹配时直接忽略。
已有非Pending result时第二次Complete不覆盖；显示结果才更新displayed watermark，
该watermark不附加本地“只能向前”的假设。Receive同ID只更新Recv事件，保留size和
其他时间；receive早于send时原函数会连同frame-start向前平移，再记录send=receive。
构造/Reset的slot ID为0，GetFrameStats(0)的零槽语义不能由本地inUse标志改写；这些是
直接入口和构造状态的证据，不把每个受控顺序宣称为实际播放器均会发生。

报告仅遍历(reported,displayed]；匹配但未完成的帧在当时补Complete(result6)，随后
Save或AddFrameSample并Reset，无论最终Connection Send返回值如何，槽和reported
已经推进。原累加路径与明细路径二选一：full-frame-stats为真时输出明细，不再将
同帧另加时延累积；两种路径都附带当次network sample，零均值也可有count=1。

【更正】Source Save以raw timestamp0作缺省哨兵，不因Native tracked valid-mask为真
就把零时间戳作为有值事件发送。首个保留事件加peer offset，后续按已输出事件差分；
client Save(true)跳过2..12且省略frame_size，frame-start/display delta仅非零时有presence。
原统计量使用float32样本、两遍样本标准差(n−1)；不能用本地double总体方差(n)替代。
完整明细生产和均值/标准差的Native对照必须单独证明，不能从窗口索引正确推导。

【证据／结论】`CFastFrameStats::SetEventTimestamp @0x7f4838`仅对事件12/14保留
首次非零值，其他事件可覆盖；写入timestamp≤1时保存1。0是Reset/Clear留下的缺省值，
不是“有效mask为真即可原样发出0”。SetLastFrameTimestamp/SetLastDisplayTimestamp
@0x7f48c8/0x7f49c8将非正间隔钳制为0.001f毫秒。撤回本地相关“mask保留实际0”、
“重复DecodeBegin覆盖”及“完成间隔为0就保持0”的等价解释。

SendFrameEvents回绕处还有实际原指令的窄化差异：0x7a8398–0x7a83c0把FFFF+1
留在32位寄存器，槽ID仍16位；该轮candidate=65536不匹配slot0，reported推进0，
但不输出/Reset帧0。不能将其改写成“每轮先窄化后匹配”。这是固定版本的实际行为，
不从此推断媒体帧ID0无效。

`Frame::SetPacket @0x7f2bac`读取扩展头的id(+0/u16)、frame timestamp(+2/u32)、
input mark(+6/u16)、input received(+8/u32)，分别放在Frame+26/+28/+44/+48。
Frame+32来自transport header+9；+36/+40来自Packet+28/+32的本地收包元数据。
`OnDataPacket @0x7ad220–0x7ad260`仅对非零input-received减offset，而frame/send
无条件减offset，再进入原RecordFrameReceived。这纠正了§4旧字段位置，没有改造
成另一种协议。原CreateInputMark @0x7a9240跳过0，按mark&1023写入begin/sent；
绑定查询使用当前latest mark所在槽，ID相符且非未来mark才复制0/1/2三个事件并消费。
“收到的任意input mark直接照填反馈”不符合原函数；此处不声称各输入producer触发
CreateInputMark并发到线上那一段调用链已被证明。

静态调用证据另见`SendLatencyTest @0x7a910c`：state≠6直接返回0；state6内联执行同一
mark递增/跳0及begin/sent表写入，构造CInputLatencyTestMsg后调用SendControlMessage(70)。
不能因libmain里没有到导出CreateInputMark的直接BL，就断言原客户端没有生成调用者；
这里的内联代码是一个实际生产入口，但不等于所有触摸/HID/按键都会生成mark。

【证据范围】60组覆盖full开关、offset正负、2/3/8/9样本、迟到事件/重复完成、补齐
缺口、只丢帧、重复Receive、初始0、时间钳制、零哨兵、乱序显示、128/240槽别名、
16位回绕、真实input-mark查询与受控network样本。原CFrameStatsAccumulator/Save/
protobuf生产均执行；NetworkStats/bitrate collector、已设置channel/时钟/metrics、
libc分配、诊断enum名字、最终Connection发送和析构为显式适配器。未证明传输整形/
Socket、OnThink调用周期、完整Client初始化或GPU/显示时序。初始槽构造与buffer布局
有上述真实构造器静态链交叉支持，探针不冒称运行了整个客户端构造器。

六组另执行真实Frame::SetPacket与OnDataPacket，五组执行原CreateInputMark；重复事件、
零时钟Pending→Displayed、旧input mark另有四组。原45组input/observed保持不变。
`check-steam-frame-stats.py`在本节基础案例最初只将Native video ring的逐动作状态、cursor、两个delta及
明细CFrameStats的完整protobuf字节与上述原输出比较；Native输入先按原packet案例
给出的换算值调用record入口，不借此声称Native接包整链已由这些案例覆盖。Audio案例
为source-only。§53另扩展为完整报告producer/body对照；tracked ticket采集及OnThink
周期仍排除，共用encoder不等于Root实际tracked统计已全面对齐。

## 53. 客户端累计样本、float计算与报告退休契约

【证据／结论】同SHA客户端`AddFrameSample @0x7f5238`的client/source2分支以事件13、
15是否非零决定network6=(13−12)、decode7=(15−14)采样，不要求begin非零。仅result1
追加display8=(18−16)、client9=(18−13)、frame10=(18−5)；撤回本地“display=17−16”
和“frame10=相邻完成间隔”的等价解释。FPS0分别从两个delta求1000/delta（0→0），
正常取display FPS；两个rate差的平方>10000且frame FPS较小时取frame FPS。
input0非零且result1时追加11/12/13：input仅当uint32(0−2)符号位置位时取uint32(2−0)，
否则0（不能在半域边界简化成signed max）；game=uint32(5−2)，
roundtrip=uint32(18−0)；后三者的毫秒换算按unsigned16.16进行。相关getter原指令为
0x7f4354/0x7f44b0/0x7f4630，不把所有duration统一成unsigned或统一钳制。

`CStatValue::AddSample @0x7f55e0`每次float32相加并保存float样本。`Calculate @0x7f5770`
及CStatValue版本0x7f58d0在n≥2时用float(sum/n)，再两遍计算样本标准差(n−1)。
整8个样本用分别舍入的平方后按样本顺序相加；尾部使用FMADD。Stddev非零才带presence，
count1即使average0也必须输出。`AddNetworkSample @0x7f5700`追加14..18五个样本，
由SendFrameEvents在有帧退休时取当次连接快照；这是collector输出消费规则，不证明
连接各采样窗口已被Native采集。

【证据／撤回】`SendFrameEvents @0x7a8378–0x7a8394`在调用最终Connection前已Reset槽并
推进reported，0x7a863c后不检查发送结果。撤回本地“enqueue失败应重发同一旧报告快照”
及将该行为称为官方策略的解释。应用层报告数据退休与底层可靠帧被接纳后的保留重传
是两层不同的事务，不能因此删除可靠channel自己的重传。

【执行证据】原60组input/observed不变，另追加25组，覆盖2/3/7/8/9/16/17个非均匀
样本、FPS相差>100分支、缺少DecodeBegin、输入半域/unsigned差值、网络0分母/有符号
计数，以及最终Connection受控返回1/5/FFFFFFFF后的重复flush。原85组执行输出固定在
同一fixture，Native84组video逐动作比较960个状态、90份完整frame body、64条明细。
Source的完整float累加器/C++ protobuf/Frame Send实际执行；Native经公开Stage/Complete、
实际report consumer、float累加器、protobuf及StatsSend进入真实frame admission。
报告正文不再过滤network/accumulated行；这取代了§52的局部输出比较范围。

【边界】双方的网络collector输出仍是受控输入；Native完整报告的默认network快照为0，
本节不把测试setter当成真实RTT/bitrate/loss采集接线。Native正常接纳走真实可靠队列；
受控拒绝在最终Frame准入处返回，Source在Connection边界返回，不能从此证明各errno
类别/Socket/整形等价。tracked采集仍独立settle，wall-clock timer/OnThink及统计窗口
的实际触发另有契约。浮点向量的本地分配失败保护不冒称官方OOM策略。

## 54. Tracked资源记录与协议统计的衔接约束

【依据】§52–53原RecordReceived/Event/Complete按发生顺序更新240槽及previous-time，
只在SendFrameEvents遍历时采样/退休。原协议统计取消不证明底层显示资源已释放。
撤回本地将256个ticket的settle顺序/presentationSerial当作统计顺序的解释；没有显示
水位时也不能在settle中无限追加float样本。资源记录与协议窗口必须各自维护生存期。

【适配设计】公开Complete仍只读纯CLOCK_MONOTONIC、写ticket payload/完成序号并原子发布，
不取得session/统计锁。已有packet.c时间函数不依赖IHS_Init/Quit状态，晚发布不解引用session。
采集器在收下一份数据前、生成报告前及关闭epoch前，先取得已发布完成与阶段的快照；
按完成序号应用RecordComplete，保留原显示水位与前帧/显示delta规则。数据接收仍独立
记录R，资源拒绝/重复接收不能改变原record分支。采集预约/应用由独立锁串行，tracker锁
仅保护快照复制，不能持有统计锁再等待tracker。GPU ticket的Claim/READY/过期/引用
规则不由统计Reset或Cancelled更改；资源清理在协议采集之后进行。

【执行对照】在§53的85个原版案例上，两个含Pending(result0)的直接入口案例不适用于
公开ticket Complete（该资源API拒绝Pending）；audio仍为source-only。其余82例实际
调用ticket Decode/UploadStage/Complete，转入同一ring/producer：938个观察状态、
88份完整body、63条明细与原版逐项相同。另一个batched模式在事件间不做观察采集，
让多次完成累积再按序采集；只比较129个flush边界及相同88份body/63条明细。
这补充了§53对tracked collection的排除范围；不能把中间观察导致的逐次采集当作
真实批量完成的替代证据。

【资源边界】统计与资源共享clock/事件数据，不共享退休水位。1000个只丢帧序列不追加
无限float样本，下一显示帧只报告最后240槽；协议Cancelled后仍可Claim/Publish原live
ticket，旧统计不会因此复活。READY若在采集后、资源清理前发布，资源Settle必须等
stats reservation，不能先复用槽而丢失完成记录。会话关闭/IHS_Quit后的旧ticket只持CPU
endpoint，晚发布/释放不访问已销毁统计对象。这些资源检查不是官方GPU时序证明。

软件upload的已有begin/end capture在实际发生时写入ticket阶段，避免到Complete才补。
硬件zero-copy阶段、完整decoder错误/显示回调、OnThink周期、真实collector窗口与
Steam/Switch仍有独立证据边界；不从上述给定事件对照推出所有平台事件来源均一致。

## 55. OnThink中的帧统计上报时钟与消费者生存期

【官方客户端证据】同SHA Android libmain的HandleStreamStarting @0x7a6f9c，
0x7a7090取GetStreamTimestamp，0x7a7094/98将同一值写入client+0x1c678和
client+0x1f6f0。HandleStreaming @0x7a7140在0x7a7178取当前tick，随后检查
frame-events时间；last==0，或uint32(last−now+0x10000)符号位置位时，
0x7a71a8调用SendFrameEvents(type1)，0x7a71ac无条件写入now。此后才检查
KeepAlive的0xa0000阈值。因此正常非零启动不是立即上报；常规时钟范围内，
严格超过1秒才尝试，不是大于等于。零哨兵、回绕和半域边界必须按原32位运算保留。
原反汇编可由scripts/audit-steam-negotiation-loop.py的同SHA二进制重现，
本地文件为build/video-recovery-re/negotiation-stream-starting.disasm与
negotiation-handle-streaming.disasm（生成物不入库）。

【结论／撤回】撤回将视频DataStart的1000ms独立timer作为官方上报调度的解释。
此调度不以视频通道/decoder已创建为前提；空报告仍推进尝试时间，发送拒绝也不回滚。
同轮统计调用先于KeepAlive。§52–54的报告正文/采集对照不能单独证明此调度。

【本地资源适配】会话统计对象一次性持有编码scratch，由RX会话阶段作唯一正常
report consumer，在Streaming分支先发送统计再更新KeepAlive。视频停止只关闭自身
资源epoch，不销毁会话级scratch或异步取消另一个消费者正在使用的报告。会话销毁
先join RX和视频线程，再释放统计及scratch。tracked资源清理仍是本地资源策略，
安排在协议采集之后；不把资源2秒过期称为官方解码策略。真实网络采样窗口、
整个网络处理全局锁、平台decoder/显示回调仍须各自核对。

【原版执行对照】audit-steam-frame-events-loop.py执行同SHA的原OnThink、空输入队列、
Starting/Streaming、真实RecordReceived/Complete、完整SendFrameEvents、累计统计、
C++ protobuf和Frame Send。48例覆盖完整/累计模式、最终Connection返回0/5、正常
1秒精确边界、空报告、两报告间退休、与KeepAlive同轮、零哨兵、回绕、半域及state4/6。
固定输出为steam-frame-events-loop-reference.json；Native经实际会话阶段、同一
report consumer、protobuf、StatsSend/控制producer和真实可靠frame准入，逐项比较
188次阶段观察和148份完整body，包含跨channel发送顺序、时间戳、序号和reported水位。
另在既有39组真实RX/协商对照中加入frame-events时间戳比较，连接接收链不由新案例替代。

【对照边界】Source的网络process/update、锁、Stats::Start、player、加密、时钟、
网络metric collector及最终Connection发送是显式adapter。channel来自真实Frame Send
传给Connection::Send的参数，不从尚未由Connection填充的packet header猜测。
Native受控拒绝在最终frame准入处发生，仅对照退休/重试时间，不宣称其errno含义与
Source返回5相同。新案例不比较实际UDP调度/重传/ACK、网络指标窗口和decoder。

## 56. 连接与视频带宽采样器的原版窗口语义

【官方客户端证据】同SHA Android客户端的BitrateStats ctor/Record/UpdateBitrate为
0x7fcb14/0x7fcb84/0x7fccd0，PacketStats ctor/Record为0x7fcec8/0x7fcf24，
PingStats ctor/Record为0x7fc5f0/0x7fc070，VideoBitrateStats ctor/RecordPacket为
0x7b046c/0x7ac1d0。audit-steam-network-collectors.py实际执行上述构造、记录、
原CUtlQueue构造/扩容及CStreamSampleQueue::AddSample；锁/libc内存为显式adapter，
不是用Python重写窗口输出。Bitrate/Packet/Ping/Video窗口以
uint32(newTick−oldTick)>0x30000退休，
仅新增样本时推进窗口，不因读取或墙钟流逝清零。

【结论】Bitrate合并最新同tick样本，按有符号int字节值累加64位总数；使用固定3秒
分母计算float((signed64)(bytes<<3))/3，不取首尾样本的实际跨度。PacketStats只在
tick及lost标志都相同才合并，total/lost按32位加减。loss的真实caller不能由该参数
入口反推：原HandlePacket记录成功接纳的收包；成功入窗的retry>1路径及可靠窗口
PopHeadOfPacketWindow_WithRef输出的非零计数另调用PacketStats::Record(lost=true)，不能把丢帧数、NACK个数或FEC纠错片数
当作同一计数。上层触发与实际报文字节数仍须分别验证。

【证据／撤回】PingStats::OnSampleAdded @0x7fc7b4及内联版本0x7fc760先将uint32
sum/count做整数除法，再将整数tick拆成高/低16位换算float毫秒，sum也按32位回绕。
撤回本地“用float总tick/样本数再乘1000/65536等价于官方RTT平均值”的解释。
原常数RTT的sender/media对照只是受控metric输入，不能证明它们的采样公式。
Clock的真实反馈样本应共用原整数平均规则，NACK、媒体反馈及普通包退休都读同一结果。

Video RecordPacket的前三个参数，在FrameReceived内联路径对应frame+32/36/40。
队列样本四项为：本次参数3−参数2、上一frame末参数3−首参数1、本次参数1−上一
frame末参数3、上一frame累计字节；队列tick取上一frame末参数3。仅第二项>0且
第三项非负、首参数1及累计字节非零才入队。原derived值在至少10个样本
时才重算；后续窗口不足10个时保留原值。第二项加第三项计算bitrate；非零第一项
计算link值，均先float除法再乘8。低于门槛不等于立即写0。原FrameReceived中的
内联分支与RecordPacket对应，但给定原语输入不等于真实caller参数来源已对齐。

【本地资源适配边界】动态环形采样存储由所属clock/会话锁串行；关闭后释放所有队列。
分配失败保护不冒称官方OOM策略。采样器组件对照不证明Socket错误、CRC计数、
channel窗口丢弃、decoder阶段、Stats Start/Stop或真实Steam/Switch已验收。

【执行对照】固定25例共724次状态比较，包含3秒精确边界/超过1tick、同tick/不同
lost标记合并、uint32回绕/倒退/半域年龄、int字节与64位累计/32位样本分别溢出、
9/10/11/17/65个视频样本、失效输入、不足10样本后的旧值、130样本扩容。Native
比较所有队列有效样本、总数与float原始比特。PacketSample的受控padding为0，
此处比较不声称是wire padding契约。

两组另从原FrameReceived及真实Frame::SetPacket→OnDataPacket进入视频内联采集。
0x7f2ce8/0x7f2cec把packet+28/32复制到frame+36/40；不能将直接R入口手工seed的
frame+36=sent当作真实wire路径的参数。单packet案例两接收时间相同，其link样本
第一项为0；该分支与RecordPacket受控非零输入不同。Native在这些组件案例中
提供对应已归一字段，不借此声称实际Native RX/Frame元数据已接好采样。

另4例执行真实ProcessTimestamp，直达原Ping和TimeOffset的真实队列；比较echo、
minimum/smoothed RTT、min-update、offset，最后一例另比较offset样本数量和64位总和，
确认10秒等号保留、超过1tick退休。Connection字段为受控初态，实际连接构造时钟与
全32位极端值不由这些案例穷尽；GetRTTStandardDeviation/网络评分不在该比较内。

【Native clock适配】实际反馈路径改用同一Ping队列，uint32累计、整数tick平均及缓存
毫秒值由NACK年龄、媒体延迟及普通包退休共用。655与656tick两样本的平均必须是
655tick；旧655.5tick浮点平均会把NACK年龄从8ms越界到9ms、媒体额外延迟从5ms
越界到6ms。普通sender的旧10ms原版fixture是直接seed连接字段，本地oracle也明确
seed缓存10ms，不能为配合新getter而篡改该fixture输入。上述Native采样器中bandwidth、
packet和video组件仍需实际收发/组帧入口接线；报告network快照仍不能计作生产采集完成。
