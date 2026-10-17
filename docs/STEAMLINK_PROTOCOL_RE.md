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
| 无法取得输入 buffer index | `0x9069e0–0x9069e8` 的 MediaCodec dequeue 最多等待 250000 微秒（常数更正见§78）；返回负值走 `0x906a88–0x906a9c` 请求 Reset |
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
不能把另一帧的 head 拼成缺失的 fragment。媒体反馈原使用单独的可 join worker；
该调度差异由§62更正为接收批次末尾推进/反馈。解码worker只消费完整帧FIFO，
不等待解码完成才反馈；退出置interrupted并唤醒，join后才销毁window/cond/mutex。

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
| 接收窗口交付、退休与反馈的调度顺序 | UpdateUnreliableState 0x7fa470–0x7fa6fc；DataUpdateAt / SessionReceiveUpdateAt | 撤回本项目仍由两个worker各自推进/反馈的当前状态；§62由同一接收批次按priority快照先推进窗口再反馈。F/U旧分步案例不能替代新增完整Socket批次对照；发送actor全局交错仍单列 |
| 已完整 pending 的后续处理 | §25.13；DataReceived 的排空循环 | 官方仍有 pending 时约 1ms think；本项目在同 worker 中排空，不等新包；调度方式不同 |
| 帧损坏的判断 | §25.5/25.10；video_pipeline.c | FFmpeg 明确 INVALIDDATA/损坏标记是项目映射，不是从 MediaCodec 逆向出的错误码对照表 |
| 后端重建 | Android 输入 buffer 超时/参数变化/Surface 变化与 Reset 调用链 | 异步actor生命周期与已核实触发见§79–83；FFmpeg flush与backend重建分立，各SDK错误/平台producer映射仍独立；250ms常数边界见§78 |
| 视频标志 bit 6 的内容模式变化 | OnThink 0x7b2648–0x7b26f8 / CheckContentMode 0x7b2804 | 原OnThink用末片bit6与已见模式判断转换，转换请求异步Reset并门控FinalDecode，执行对照与Native契约见§83；主机侧含义未确认，不解释为缺参考帧标记 |
| 关键帧清理／显示引用 | FlushPendingData / FlushVideoStream；video_pipeline.c | §82按原首关键片段入口清protocol pending/flush backend，完整提交抑制重复flush；保留显示/GPU引用的本地所有权独立验证，真实硬件行为另验 |
| 窗口容量与坏分片 | §25.10；window.c | 官方动态窗口；项目视频固定 2048 槽、积压 256 片段/2MiB，溢出重新锚定，并增加 continuation 类型/ordinal 检查；这些是明确的项目策略 |
| 项目身份／所有权及坏数据防护 | frame ticket、帧 ID/ordinal、Source assert前置条件与容量保护 | 属于本地身份/所有权/内存保护，不声称原版采用同一错误分类；bit5解密返回值与原输出变换另按§84执行，不添加strict请求 |
| 客户端发送方向的不可靠缓存 | §25.3 的 SendUnreliablePackets / HandleNackPacket | 客户端初发/保留/ACK/NACK补发及关闭的执行对照见§52–67；DataLost的queue(false)仍是独立producer语义，不能扩展为全部outgoing的准入约定 |
| FEC | 官方 SendUnreliableFEC / HandleFECPacket；本地 packet enum/接收分派 | type11接收/恢复及配置请求见§27–32；接收能力不证明产品启用门，自身上行入口与明确边界见§71 |

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

【范围更正】上述是原扫描输入，不是“仅state6可进入通用分派”的证明。
§63核对原指令及新增状态后，通用表实际用于除2/3/4以外的状态；
入队时的state0/7丢弃与消费时的状态选择必须分开。

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
SessionRecvCallback 的地址/连接 ID 检查后进入连接持有的transport接收槽；早到的
普通3/4与type11也先推进窗口/FEC/反馈，完整数据再等Start*Data确定decoder身份，
不猜codec。旧raw datagram缓存与原版的差异及更正见§69。

- 一条 channel 一个活动 FEC 组，以最近已交付组为水位，uint16 差为 1…32767
  才接纳。不同有效组替换未完成组，包括晚到的旧未完成组；不自行增加多组窗口。
- 从 L/S 计算 k，检查完整的 8+S 字节 shard body；按唯一 index 收集。
  系统数据全到即交付；缺数据且有 k 个不同 shard 才执行同一 GF(256)/Cauchy
  码字的恢复。实现只求解缺失数据列，不改变官方系数、数据分片或 parity 字节。
- 输出使用收到的最低 index shard 的传输 header（type=11、组 ID 和时钟；§59更正旧“首片”解释），媒体 frame ID
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
- 接收循环在本轮通道收发之后，用保存的batch tick计算 uint32(now−last_receive)，
  比较15或180乘65536；达到阈值发起本地断连，见§65。不会将本地超时写成HostRequestedStop。

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

【更正】撤回“queued dispatcher只在client state=6进入”的过度结论。
§63补测并核对`0x7a6444–0x7a651c`：只有state2/3/4使用专用分派，其他状态
走50…147通用表；其中99进入`OnSetStreamingClientConfig 0x7af08c–0x7af13c`。
state0/7在OnStreamPacket入队之前丢弃新帧，但已排队后改变state的消费边界不同，
不能把两个入口合成同一guard。143例配置审计含28个新增post-decrypt queue边界案例；
不据函数边界状态注入证明相应UI启动路径可达。原版 Get/ParseFromArray 成功，
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

FIFO交付后的窗口/整形/发送阶段接线见§38；普通媒体推进/feedback的独立worker
差异由§62更正，发送actor和完整阶段交错仍不同，不将发送阶段对照扩大成整个连接循环的墙钟等价。
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
本地POSIX发送使用每次MSG_DONTWAIT实现出站非阻塞；§60将串流接收改为独立
readiness等待与非阻塞drain，discovery保留其接收适配。IPv6/全部BInit错误分支仍不
由这些结论验收。

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

接收超时/type9调用TransportDisconnect；下一Connection Update在清ID之前通知
client连接delegate并退休。随后client队列/Stopping与应用完成通知按§66分层，撤回
此处原先“立即通知应用并interrupt”的实现映射。主动SessionDisconnect选择Client Close语义，同步尝试一次goodbye
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
seed缓存10ms，不能为配合新getter而篡改该fixture输入。该组件对照本身不证明
bandwidth/packet/video的实际入口或报告快照采集；§57另定义RTT/RX/TX/received接线，
video与完整lost来源仍有独立边界；§58核对普通channel的三个lost入口，§59接通实际视频link采样。

## 57. Socket收发入口与网络采样计数

【官方客户端证据】audit-steam-network-wire.py固定同SHA，执行原Socket::HandlePacket
@0x7ff3e0→HandleMessage @0x7ff640→Connection::HandlePacket @0x7facfc及真实采样队列。
CRC由原CRC32C函数生成和验证。0x7ff4e0先把packet52减4，0x7ff54c写回后才进入
Connection；RX BitrateStats消费的是去掉CRC的header+body长度。ID/地址/所需CRC
标志/channel准入通过后，记录一个received及其字节数；未知七位type通过Connection
准入也计入，之后channel不处理该type不撤回计数。Unconnected的Socket分派另走
discovery，不由这些普通收包案例推导成Connection received。

TX执行原Socket::Send @0x7ff1dc。0x7ff2b0–bc把CRC写在packet52末尾，但不增加
packet52；最终I/O的物理长度另加4。仅transport返回0才在0x7ff31c记录TX字节，
其长度仍为不含CRC的header+body；非零返回不记。不能把物理发包长度、整形记账、
可靠发送器对返回值的后续处理或errno层级混成同一个统计输入。

【执行边界】Source Socket connection表/地址比较、连接状态和最终I/O返回值为受控
输入；channel消费者、Connect/Disconnect正文处理、未认领包的回复发送及refcount
为显式adapter。Socket::HandlePacket返回寄存器不作为接纳布尔；未认领输入可被
Socket复用来构造回复，因此只在真实Connection入口记录CRC剥离长度，不用返回后
packet52反推。组件窗口依照§56；取样入口的等价结论限于下述Native实际Parse/收发
路径对照。

【Native所有权约束】连接采样随session零初始化；RX与TX使用已有Base锁串行更新
动态队列，销毁前先停止/join全部会话和数据worker，最后释放队列。收包计数在已
通过连接准入、尚未分派正文的位置；发送计数在实际Socket成功返回之后。采样资源
失败保护是本地适配，不改变ACK/NACK、codec或发送结果语义。

【准入差异】原0x7fad50–7fad88的Connect(type1)不检查destination；仅remote ID已知
且非零时比较source ID，未知remote时不据source拒绝。Connected(type2)在
0x7fae30–7fae58只检查destination与地址，不比较source；Disconnect(type9)与普通
流量同时比较两ID。1/2/9专用分支绕过普通channel范围和“必须带CRC标志”的要求；
若实际带CRC，仍先经过Socket真实校验。本节据这些原指令及新增Socket案例纠正
Native旧“所有非discovery包检查destination、Connect始终忽略source”的统一guard。

【执行对照】96组固定案例比较172次状态：实际Socket CRC开/关、坏CRC、所需CRC
标志缺失、地址/ID/channel准入、type1..13，以及5类TX type×5种I/O返回×CRC开/关。
另有同tick、严格3秒、回绕的连续收发，并补1/2/9的source/destination/CRC/channel
分支及未知remote的type1。Native从实际PacketParse/CRC和session收到
回调进入采样，TX从实际SessionSendPacketResult经过最终I/O边界记录；比较采样队列、
总数、float比特、Connection入口长度及尝试I/O长度。RX正文可能产生的Native最终
发送在此受控拒绝，Source对应正文/回复为adapter，不以这些案例验收完整控制流程。

四组再把真实收发采样与ProcessTimestamp、原Streaming上报连接，完整/累计模式及
CRC开/关分别比较12份完整Frame body、序号、退休水位及两周期tick。包含旧RX样本
被新RX淘汰，而失败TX不淘汰其旧样本；读取RTT缓存不因墙钟超过3秒自行清零。
Native全局阶段在报告前取得实际RTT/RX/TX/packet快照，进入同一报告退休/编码consumer。
原受控network setter的独立报告案例仍有原覆盖范围，不当作该收发整链接线的替代。

【边界】此处接通RTT、RX/TX字节及received计数；视频link的接线另见§59，lost的
普通channel成功入窗retry>1、可靠Pop和不可靠过期空槽的实际入口对照见§58，
不能把此处的分母采集单独称为完整丢包策略。实际RX/TX/快照三线程各1000包检查CRC计数、同tick合并、join后销毁，
这是本地并发/生存期证据。实际全局network锁、构造时钟/极端值、CNetworkStats评分、上行FEC、
硬件/decoder、真实Steam/Switch均不由本节证明。

## 58. 丢包采样的三个客户端入口

【官方客户端证据】继续使用§24.1固定SHA的Android客户端。原
CStreamChannel::HandlePacket @0x7f9250的可靠和普通不可靠分支仅在
BInsertPacket真正插入后、wire retry字节大于1时，调用PacketStats::Record：
时间取packet+32，count=retry−1，lost=true。旧包及重复槽不产生这笔lost，
但通过Connection准入的物理包仍有§57的received样本。

原PopHeadOfPacketWindow_WithRef @0x7f743c在0x7f76c4–0x7f76d8累加
头包raw[1]，在0x7f766c–0x7f7680累加每个已消费续片raw[1]。
UpdateReliableState @0x7f9d0c将本轮所有Pop的总和在0x7f9dec–0x7f9e04
另记为lost，时间取Update参数。这个输出不是跳过的缺包数；新retry=2包
可在入窗记1、可靠交付再记2。不能凭统计直觉合并或去重这两笔官方事件。

原UpdateUnreliableState @0x7fa3b0给Pop传NULL，不记录上述交付retry总和。
0x7fa590–0x7fa680扫描过期前缀，推进时同时经过已有包和空槽，但只累计空槽；
0x7fa688–0x7fa694以Update时间另记这些空槽为lost。孤立续片的跳过不算空槽。
过期比较仍遵循§25.2；真实构造值是65tick，活动视频/音频启动会改为6553tick，
不能用未启动的generic channel默认值替代活动媒体策略。

【本地契约】窗口Add原bool表示“处理没有资源错误”，旧包/重复包也返回true，
因此lost入口必须单独取得实际插入结果。可靠交付在窗口锁外累计记录；普通媒体
过期只能计空槽，不能用原Discard的全部推进槽数代替。采样仍由会话Base锁保护，
禁止在持有reliableLock/windowLock时反向取得Base锁。FEC独立入口、早到媒体缓存、
全局调度及设备解码并不由这些普通3/4/5/6分支推定等价。


【执行对照】audit-steam-network-loss.py执行原Socket→Connection→GetChannel/
真实构造与EnsureCapacity→HandlePacket→UpdateReliable/UnreliableState→原采样队列。
52组固定输入共266次状态、12份完整统计body，与Native真实CRC RX/窗口/可靠
Update/全局上报逐项比较。覆盖retry=0/1/2/3/255、入窗前后重复/旧包、乱序续片、
多个frame交付总和、可靠600跨度真实扩容及16384拒绝、接收时间/Update时间区分、
严格3秒样本退休，以及sender回绕时6946tick保留/6947tick放弃。此边界案例先执行
真实ProcessTimestamp：656tick样本约10.0098ms，经整数毫秒截断得额外6ms。
另有只有lost、没有完整frame可交付及重复Update不新增loss的输入。

【执行边界】Source最终feedback发送、引用计数、锁、player delegate是adapter；
完整统计消息仍使用§57的加密/最终Frame准入边界。初始缺口可进入原可靠Update的
line1139 increasing诊断，fixture另保存其次数，adapter按非调试继续执行；不隐藏
为“没有assert”。Native媒体步骤使用生产worker的PollLocked入口受控驱动、独立
记录返回空槽数；不等于复制官方同步network loop。媒体有界容量保护仍遵循§33/48
已声明差异，不能以本节可靠扩容案例证明媒体动态扩容等价。

【本地线程验证】真实媒体worker在过期缺口之后仍是未完成head时，验证无需
decoder回调也发布lost；停止并join后释放。另三线程并发执行1000次实际TX、
2000次真实CRC RX（其中1000个可靠retry=2）、可靠Update及网络快照读取，
join后核对total=5000/lost=3000与有效样本。此处线程证据不能替代官方调度、
早到媒体缓存/FEC独立路由、真实Steam会话或Switch解码显示的证据。


另4组将§26固定原版向量从真实Socket送入type11接收分支，执行真实FEC队列和
RS重建：系统片0/1/2全部收到，或只有片0再靠校验片3/4恢复；CRC开关均覆盖。
三包即便retry=255，也只有received=3/lost=0，不进入普通入窗/可靠Pop计数。
随后同channel普通packetId0、retry2仍正常新入窗并交付，另记lost1；FEC组ID1
不推进普通水位。结果与Native真实FEC RX/RS/FIFO消费者的payload和计数一致。
原版直接同步delegate，Nativeoracle在同一收包action内驱动生产FIFO polling；
这是明确的线程桥适配，不据此宣称callback同步时序一致。向量不覆盖原版重复
shard错误、全部畸形输入或FEC配置启用/自动切换；配置策略仍以§32的客户端证据为准。

## 59. 视频网络采样的真实收帧元数据

【官方客户端证据】同§24.1 SHA的Socket::HandlePacket在0x7ff42c–0x7ff43c、
0x7ff558–0x7ff568中仅first(packet+28)为0才填入本次接收tick，last(+32)每次更新。
普通分片Pop的0x7f764c–0x7f7668仅在续片last无符号大于头片当前last时推进；
first为0才随之补值。first不是所有分片接收时间的最小值。真实Socket/Pop执行中：
头/续片1000000/1000002→first1000000,last1000002；续片先到、head最后到→两者
1000002；头0xfffffff0/续片16→两者0xfffffff0；头0/续片2→两者2。
撤回把Native旧int32差挑选receiveTimestamp视为该合并语义等价的解释。

FEC原BAddPacket 0x7f82a0–0x7f82dc另有不同规则：出现更低shard index时复制
其13B wire头；first只在0时取当前packet last，last无条件取当前packet last。
系统片0/1/2及片0+校验3/4真实Socket/RS执行均得到first1000000,last1000002。
不能沿用Native原firstHeader而永远只保留第一片的末接收时间。

原OnStreamPacket 0x7acfa8→Frame构造/SetPacket→OnDataPacket 0x7ad148
先归一化发送方时间，再RecordFrameReceived 0x7abeb0，最后才调decoder。
Record的0x7abf40–0x7abf58对receive早于send的情况只修正用于统计的send/frame/input
局部值；VideoBitrateStats内联使用修正后的send、本帧first/last与payload大小，
payload含7B视频头，不含传输13B、消息tag、12B数据头、CRC或FEC shard元数据。
原视频采样与帧received统计都发生于codec解析之前；不能因payload不足7B而漏采。

【本地契约】首/末接收时间是本地元数据，随完整frame/早到可靠frame与FEC FIFO
保持所有权，不序列化进UDP。实际视频RX完整帧交付入口在decoder FIFO之前记录
帧统计和VideoBitrateStats（§70更正时序）；后者归session、沿用§56队列与Base锁、关闭join后释放，
由§57全局上报快照读取link。普通分片和FEC不共用错误的末时间合并规则。


【证据／撤回】旧check-steam-fec-receiver.py的scenario人为用sequence[0]构造
预期header；这部分不是原指令输出。撤回§33.1“首个有效shard的header”的描述。
原BAddPacket的header选择和新的60种distinct shard到达顺序均支持最低index，
测试须据此修正，不能为了迁就旧预期而保留Native firstHeader的错误语义。
视频collector对照的decoder不在验收范围：Native零codec payload可在采样后进入
既有decoder/组装关闭分支。短payload采用独立会话验证其采样，不把该关闭行为
称为已经与原版decoder对齐；全decoder策略须独立取证。


【原指令与Native执行对照】audit-steam-video-network.py固定146组、2316次动作状态、
12份完整统计body。Source从原Socket、channel ctor/窗口、普通Pop或FEC队列/RS
进入真实OnStreamPacket、Frame构造/SetPacket、OnDataPacket、RecordFrameReceived
内联视频采样，再经Streaming/FrameEvents/C++ protobuf；没有用Python重写这些分支。
13份有效视频FEC向量另由原SendUnreliableFEC @0x7f90e4、AddPacket、真实RS编码及
队列发送产生，MTU64/percentage50是显式输入，wire IDs/clock受控，不冒称官方默认
或已经证明主机/客户端何时启用FEC。§26固定k3/m2向量另有60种distinct到达顺序，
核对最低index header；8组补first=0、倒退、回绕的FEC首/末时间。

Native走真实CRC RX、普通/可靠窗口、可靠frame→媒体FIFO、FEC RX/RS/FIFO及生产
complete-frame/video消费者，再采实际网络快照/完整报告。worker创建与调度改为受控
polling，Source的锁/引用计数/析构、最终feedback I/O、CNetworkStats评分、decoder、
报告加密/最终Frame准入为adapter。非data tag的固定FEC向量只到记录delegate，
不以此核对未知消息入队。Source接收tick参数、Native时钟均受控；Socket::Update
在transport读取前取tick；§60接通Native实际readiness/drain前取tick与可靠更新批次。
全局network锁、普通媒体/发送worker与完整收发同循环仍有独立差异，不能把本对照
扩大成全局墙钟时序已闭合。

覆盖CRC开关、普通3/4和可靠5/6、单包/分片/反序、同视频frame多个payload、offset、
receive早于send的统计局部修正、零哨兵、无符号回绕、frameId65535→0、3秒窗口
淘汰后不足10样本保留旧derived值。完整/累计报告比较真实video link，既不跳过
network项，也不以直接setter替代采样。0…7B视频payload各用独立会话核对decoder
长度检查之前的采样；恰好12B data header、零视频payload也记录received与0字节，
不能用旧“必须大于12B”漏掉该入口。此处不证明它们在实际decoder上的结果。

另真实媒体/视频worker接26个CRC分片、13个视频frame，与并发快照线程一起执行；
join后读取原版同输入的12个样本，totals=[120,240,11760,324]、bitrate/link float
比特=[1180512027,1236061389]。编码帧sink代替硬件decoder，所有worker停/join后
销毁session采样队列；这是本地线程/所有权证据，不是Steam认证或Switch显示证明。

## 60. Socket读取批次与接收/更新tick

【官方客户端证据】同§24.1 SHA。GetWaitMS @0x7feb7c按Socket blocked字节返回
0或2ms；Wait @0x7feb90把transport readiness bit0保存到socket+56。Update
@0x7fecd4先GetStreamTimestamp；readable时反复BReadPacket→HandlePacket(捕获tick)
→重新GetStreamTimestamp，直到Read非零；随后才逐连接调用真实Update。
即使最后一次空Read耗时增加，连接Update仍使用该Read之前的tick；无readiness
也会更新连接。本地旧“每个包之前Update一次、Parse后取receive tick”不等价。

Connection::Update @0x7fc108把该tick写+48；同一tick传给通道可靠/不可靠Update。
可靠Update的反馈资格、lost Pop样本以此tick计算，但ACK echo在0x7f9ed0重新取
当前时刻，并非统一用旧Update tick。HandlePacket的0x7f93a0把接收tick传给
HandleAckPacket→ProcessTimestamp，不能在Native解析之后再新取一次用于RTT。

【适配边界】Source真实Socket/Connection/channel/采样/反馈Socket TX可执行，
transport wait/read/write、client-update/frame delegate、refcount与构造初始时钟受控。
Native以可中断的有界readiness等待加非阻塞drain实现同一批次契约；检查退出后
由owner join再释放socket/会话。Discovery独立接收不据此改动认证/PIN语义。
Source sender和普通媒体decoder worker、全局network锁及主线程OnThink与Socket
线程之间的执行交错仍须单独验证，不把接收批次相同称为全局时序已完全闭合。


【执行对照】audit-steam-receive-cycle.py使用真实原Socket::GetWaitMS/Wait/Update、
Connection::Update、channel构造/扩容/可靠更新、ProcessTimestamp、采样队列与反馈
Socket发送/CRC，固定28例34周期状态/18份完整feedback wire。Native从生产
SessionReceiveCycle进入实际Parse/clock/window/可靠UpdateAt/发送准备；单包、同批
2/17/130包、乱序可靠分片、读/处理/最终空读分别耗时、readable=false、blocked的
0/2ms、NACK65tick边界、多个批次及ACK入站RTT均逐项相同。构造初始lastReceive/
echo受控且一致，空outgoing队列的原sender仍执行；不能以空队列证明生产TX actor
和普通媒体worker已与Source同步循环。原line1139诊断单列保存，不隐藏为零assert。

Native实际BaseWorker另用CRC开/关接同批两包；验证第二包和空Read时尚未交付，
批末统一交付/反馈。每包read7tick、parse11tick，批次tick为start+36；空Read另耗
100tick，ACK wire timestamp为start+136、echo仍按当前时刻重取，Pop lost样本用
start+36。实际POSIX loopback核对readiness、非阻塞读完两包直到empty，以及关闭；
停止/join发生在依赖释放前，不借此声明Switch loader或物理显示已验证。

旧worker脚本曾把“每包一次Update”隐含在read调用之间，现显式给出空Read边界；
精确反馈/Connect计时脚本将受控clock推进放在Wait/read之前。没有为了保留旧
worker调度的预期而改变官方批次规则。SDL fallback补同一readiness/非阻塞接口，
当前验证平台是POSIX desktop与Switch交叉构建，不冒称Windows/SDL_net已实测。

【范围与更正】普通媒体窗口/feedback的独立worker差异由§62更正；发送仍有独立
worker。decoder没有移到网络线程，也未复制Source未知fatal read行为，Native负返回仍走本地stop/join
关闭保护。停止检查可在持续drain中生效，是loader ABI所需的本地生存期保护。
两条PIN语义和Connect/Connected正文协议未因传输readiness改动而合并或重写。

## 61. 官方网络管理器的等待、锁、线程入口与主循环

【官方客户端证据】同§24.1的Android 1.3.32 `libmain.so` SHA，
`audit-steam-network-manager.py`从原函数入口执行下列调用链。证据来自客户端，
没有以Host支持的字段或本地线程设计推断官方行为。

| 入口 | 地址 | 原指令行为 |
|---|---|---|
| CStreamClient::BInit(bool) | 0x7a5df8 | 同一参数写client+16/17/18，再调用全局threaded setter |
| StreamSetThreadedNetworkProcessing | 0x7feec0 | 启动前写manager+168；running时有诊断，不据此设计热切换 |
| CStreamSocketManager::AddSocket | 0x7fe7e8 | manager+72锁内追加pending；threaded且非running才Join/Start |
| StreamProcessNetwork | 0x7fef1c | 尾调用全局manager的CheckSockets |
| CStreamSocketManager::CheckSockets | 0x7fe904 | 锁外等待，锁内追加pending、逆序更新/移除Socket |
| CStreamSocketManager::Run | 0x7fee74 | 请求priority=15，检查stop，再循环CheckSockets |
| StreamLock/UnlockNetworkProcessing | 0x7fef28/0x7fef34 | 指向同一全局manager+72 mutex |
| CStreamClient::OnThink | 0x7a5ff8 | client+16 bit0为0才调用StreamProcessNetwork |

### 61.1 等待、追加与更新的准确顺序

【原版执行结果】有active Socket时，先计算所有active Socket的GetWaitMS最小值：
全部blocked=false是2ms，任一blocked=true是0ms。仅数组第一个Socket的transport
Wait接收这个timeout，其余Socket的Wait参数均为0；并非每个Socket都独立等待2ms。
Wait调用发生在manager+72加锁之前。0…5个Socket的全部63种blocked输入组合，
覆盖优化后的成对扫描与余数扫描；readiness返回值逐Socket保存。

随后manager加锁，将pending vector追加到active尾部并清pending count，再从尾
到头执行原Socket::Update。Update=false的Socket调用析构/释放并用尾项填空位；
原Socket内部的Connection::Update也真实执行，未把整个Socket替换成事件。
没有active Socket也会加锁处理pending；没有剩余Socket时清running、返回false。

因此新加入pending的Socket本轮已进入Update，但本轮等待扫描没有包含它；在其
初始readable=false的受控案例中，本轮只执行连接更新，下轮Wait后才收包。
不能据此把“AddSocket返回”解释成它已经执行过一次网络读取。

实际接收、普通可靠窗口Pop/交付、反馈Socket Send与Connection client-update
delegate均在同一次manager锁期间发生。样本仍保留§60的两次read7+处理11：
连接update参数为start+36，最后empty read另耗100，交付和ACK wire时刻为start+136。
证明的是这些执行点的锁包围关系，不能扩大成所有producer/外部decoder均持此锁。

### 61.2 线程和主循环的触发条件

【证据】AddSocket在threaded=true且running=false时，在同一锁内调用
Join(0xffffffff)，置running=true，再Start(0)；已有running或threaded=false不走
这组调用。复播记录原Join/Start请求，平台线程函数返回受控成功，没有创建OS线程。
Run先请求ThreadSetPriority(0,15)，然后在每轮CheckSockets之前检查stop：初始
stop=true一轮也不执行；在第N次client-update delegate注入stop后，当前管理器
周期仍执行到解锁，随后返回。所有Socket自然退休也使Run结束。
stop退出不等于运行中的所有Socket已被释放；不能据此跳过另行Shutdown/join。

【证据】Think案例实际执行BInit(false/true)，核对其三处client标志和全局threaded值，
再进入OnThink。false时执行完整StreamProcessNetwork→CheckSockets→Socket/Connection，
解锁后才执行transport Update与后续客户端阶段；true时跳过这条网络处理链。
“启用网络线程后OnThink仍自行再处理一次Socket”不符合此固定客户端。

【边界】BInit参数在本节为输入，不以两值均可执行证明Android生产启动参数或所有
平台默认值。Run由审计入口直接调用；OS创建、优先级实际生效、线程间墙钟交错没有
被执行。OnThink的transport Update、日志阶段以及最终frame/client-update delegate、
refcount、析构与OS I/O是显式adapter；容器初始存储、单个存活连接和时钟受控。
其余Socket刻意没有连接，用于执行真实退休/移除分支，不作为多活跃连接的完整验证。

### 61.3 复播材料与实现约束

```sh
python3 scripts/audit-steam-network-manager.py \
  --binary /path/to/libmain-arm64.so \
  --output build/video-recovery-re/network-manager.json
```

固定`steam-network-manager-reference.json`保存123例输入与完整observed trace、
pending/active存储结果、交付payload/时间、完整反馈wire和packet samples；含CRC开关、
空管理器、0…5个Socket、pending首次更新、存活Socket位于不同位置、逆序退休、
Run连续周期/初始停止/自然退出及AddSocket首次启动/已有线程两个分支。
共执行148次CheckSockets、保留92份完整feedback wire。本节把§50曾记录为adapter的
StreamProcessNetwork接通至真实manager/Socket/Connection，不扩大其余adapter的范围。
原line1139诊断继续单列；未将其隐藏为零assert。初次探索曾由通用Core的mutex
adapter吞掉锁调用，现由此脚本显式截取实际mutex PLT，并在每个wait/read/update/
delegate/send处检查对应锁状态；fixture只保存修正后的执行结果。

【结论】§60的收包批次不是独立线程随意拼接的依据。与此官方策略对齐时，应把普通
接收窗口更新/反馈和按通道排序的周期发送纳入同一网络处理周期，并保留锁外等待与
锁内原有阶段顺序；decoder消费可通过交付队列隔离。跨通道priority/creation顺序和
初发producer调用仍以§37–38及实际调用链为准，不能把所有初发强行延后到周期尾。
本节没有改变生产实现，也没有把FEC启用条件、decoder错误处理或真实设备结果判为
等价；FEC启用仍以§32客户端设置/预设/推荐确认链及§29配置消息证据为准。

## 62. 普通媒体窗口推进与反馈归属接收批次

【官方客户端证据】同§24.1 Android客户端固定SHA。原Socket::Update先排空read，
Connection::Update按priority/creation快照逐channel执行可靠更新，再执行
UpdateUnreliableState @0x7fa3b0。其0x7fa470起先Pop并交付完整消息，再按sender
时间退休过期前缀/计空槽，最后构造类型10反馈；不是由解码器或另一个反馈线程
各自读取窗口。§60–61接通外层Socket/manager，§25/58接通内部窗口/反馈/采样。

【更正与实现】撤回§25/37/60“普通媒体仍由两个独立worker推进/反馈”的当前状态。
生产SessionUpdateAt在read批次结束后调用SessionReceiveUpdateAt，以共享的
OutgoingSnapshot取得原priority排序；每个channel先可靠UpdateChannelAt，再解析
当前audio/video消费者并调用DataUpdateAt。可靠control delegate可能替换消费者，
因此不能跨该delegate保留旧指针。窗口推进、空槽lost样本和反馈期限使用同一批次
tick；类型10直接在本轮尝试Socket Send，不排到初发producer队列之后。

普通3/4接收只入窗、更新sender时间和dirty，不唤醒解码线程抢先Pop。DataUpdateAt
先把完整消息/过期后可交付消息移入完整帧FIFO，在窗口锁外记lost；随后锁内构造
反馈、锁外发送。decoder worker只在FIFO上等待/消费，不能推进普通窗口或发反馈。
FEC仍在实际收片/RS成功时交付到FIFO，可靠完整帧仍由可靠更新交付；二者不进入
普通不可靠窗口。单独的feedback线程和cond已移除；退出仍stop→唤醒→join解码线程
后才销毁FIFO、窗口、RS、锁及会话依赖。网络采样不得在windowLock下反向取得Base。

### 62.1 整个Socket批次与priority对照

`audit-steam-receive-cycle.py`在§60的28例之后追加14例，合计42例56周期状态、
30份完整feedback wire，与Native真实SessionReceiveCycle→Parse/CRC→窗口→
SessionReceiveUpdateAt→Socket准备/采样逐项比较；不是把两侧输入都直接放在
DataBuildFeedback入口。原28例输出原样保留。

| 输入 | 原版与Native输出 |
|---|---|
| 同批普通id0/1 | 两个完整payload在批末交付，不发送无缺口NACK |
| 同批id1再id0、各有read/处理耗时 | 收完批次再交付；不因第一包的临时缺口提前反馈 |
| 普通head/continuation同批 | 保留原first/last/send元数据和完整组装payload |
| 首批缺口、后续无readiness周期、再补缺 | 64/65/66tick与dirty/期限反馈按实际原指令结果比较 |
| sender时间跨过媒体退休界限、剩余head仍不完整 | lost空槽在批次tick记录，不依赖decoder得到可解码帧 |
| ch3缺口加ch4可靠id0/1，priority分别为±10 | 同周期确实产生两份反馈；优先ch3为[3,4]，优先ch4为[4,3]，CRC开/关均比较完整wire |

Native fixture在批次返回后受控排空生产FIFO来记录payload/元数据；这是consumer
调度adapter，不把它解释成原decoder与Native decoder在同一指令位置执行。
实际BaseWorker测试另在CRC开/关各运行可靠/普通两种模式：第二次Read和最终空Read
之前无交付/普通Pop；空Read之后才推进窗口。read7+处理11各两包，批次tick=start+36，
最终空Read额外耗100，普通完整帧元数据仍来自每次Read之前的start/start+18；
不因decoder线程恰好先/后运行改变协议时间。

### 62.2 decoder阻塞、资源边界与未涵盖范围

实际媒体worker测试在dataFrame回调中阻塞decoder，仍由网络owner执行窗口补洞与
类型10同步发送。loss-only案例使decoder始终没有完整帧可消费，网络owner仍记空槽。
实际视频worker/并发快照reader使用接收批次步骤后得到§59相同13帧的采样总和与
float比特；这些编码帧sink不替代物理硬件decoder。

完整帧FIFO沿用本地有界内存保护，不声称是官方队列容量：所有完整帧共享原窗口
容量的count上限，bytes为windowCapacity×2048且至少允许一个2MiB payload及node。
满队列退休最老完整帧，普通帧不再藏在另一个待解码窗口中；blocked decoder的
混合FEC/普通输入因此按共享FIFO上限计算。该资源保护分支不纳入原版等价声明，
不据此增加DataLost、自动FEC、重连或decoder reset策略。

【边界】发送actor仍独立，原每channel的可靠更新→不可靠更新→可靠发送→不可靠
false→FEC，以及末尾轮转不可靠true不属于本节独立RX边界；组合周期见§64。全局
network锁与control处理/consumer替换的所有交错也不能由此42例推定已等价。
保持初发producer的来源约束，不将所有初发强行延后。早到媒体窗口、畸形/错误保护、
完整decoder/OS线程、Steam会话和Switch实际显示/loader均另需来源和运行证据。

## 63. 控制交付、解密与主阶段消费的边界

【官方客户端证据】同§24.1 Android 1.3.32固定SHA。OnStreamPacket @0x7acfa8在
client state0/7直接丢弃新帧；控制通道先按原明文类型集合{1,2,6,7}选择解密，
加密帧在0x7ad054–0x7ad06c先递增client+136，再执行Frame::BDecrypt。
失败也消耗该次期望序号，不因下一帧成功或更大序号而重同步。
成功后KeepAlive(9)直接消费，RemoteHID(106)在0x7ad0c4–0x7ad0d8调用delegate，
其余消息经0x7ad0e0–0x7ad0f0引用计数/真实CStreamQueue::PushItem排队。
不是等到主阶段才解密，也不是把所有控制消息都立即分派。

【更正】原§35.3“queued dispatcher只在state6进入99”撤回。原
HandleIncomingPackets的0x7a6444–0x7a6458只对state2/3/4作专门分派；
其他状态进入0x7a6510–0x7a6534的50…147通用表。其内部99 handler本身没有
state6判断。state5的队列99会复制配置；同批先收到有效peer SetConfig(4)再收到
99时，主阶段先变state5，再应用99，之后才由Starting阶段进入6。
0/7入队前丢弃新帧，不能推成“先前已排队的消息在消费时state0/7也必定被丢弃”。
补测0/1/5/7的143例配置审计含28个新增**已解密队列入口**案例；该函数边界输入
不证明相应UI或网络连接启动路径可达。主动发送99仍要求state6且bool bit0=0，
不能把接收分派边界的更正反向用来放宽发送条件。

### 63.1 Native所有权和调用顺序

ControlReceiveFrame继续在网络交付时解密/递增序号，将除9/106之外的成功消息交给
ControlHandoff。control拥有独立incoming mutex和常数时间head/tail FIFO；节点持有
type、原transport header和已解密body所有权。入队不执行普通控制handler，不把body
借给稍后已释放的Frame或栈buffer。KeepAlive不进队列，RemoteHID仍内联处理。

SessionUpdateAt先完成本轮收发周期（§64），再DrainIncoming，然后按新的状态选择
一个Starting/Streaming阶段。每次pop只持队列锁，实际控制分派在锁外执行，也不
持网络/Base锁；一条消息改变状态后，下一条按新的状态重新选择。可靠ACK可以在
普通控制动作执行之前发出。消费期间不重新递增解密序号，不再次解密body。
ControlReceiveFrame是网络入口；OnMessageReceived是较低层handler入口，直接调用
后者的测试不能用于证明网络准入或队列时序。

队列没有新增丢旧消息、FEC切换或重连期限。分配失败仍按项目已有本地关闭保护，
不把“立即在网络锁下执行handler”作为失败fallback。destroy在RX/producers停止后
丢弃未消费节点并释放body、队列mutex及sendLock，不在析构时执行协议动作。
部分初始化的Stop/Destroy允许空channel，避免新增mutex失败后清理未创建的消费者。
这些OOM/关闭保护不是从原版推导出的失败策略，不扩大正常分派的等价范围。

### 63.2 原指令对照、空控制帧与真实worker

`audit-steam-control-handoff.py`执行原OnStreamPacket、Frame构造/BDecrypt/Resize、
CStreamQueue PushItem、实际CUtlQueue增长/取出、HandleIncomingPackets及peer
SetConfig/config99解析/复制。固定53例618个状态快照、451次consumer事件，比较
每一步队列顺序、完整明文body、send/receive metadata、receive sequence、客户端
状态及完整negotiated/client config；Native从真实ControlReceiveFrame进入实际
MBED TLS解密/HMAC、生产FIFO和DrainIncoming。Source的AES-CBC/HMAC primitive由
cryptography/hashlib适配，原Frame层的长度/HMAC比较/序号/移动与Resize分支仍执行；
不能将其描述成原CCrypto密码实现的完整指令验收。

案例含合法/坏MAC/IV-only/旧序号/未来序号后下一次合法输入、plain与encrypted编号、
0…7接收状态、排队后改变消费状态、两份peer config、坏PB后有效config、Starting
期间99、17/129/257项队列增长、排空后再次入队，以及带未消费节点的Native退出清理。Source的
2683/2684 codec诊断如实单列；它们不拒绝非debug下的完整peer config，见§49。
其他terminal handler、OS mutex/refcount/析构为adapter；仅peer SetConfig和99的
完整配置消费者进入原实现，不把HID/播放器设备功能称为已验证。

空控制帧也不能在外层提前绕过解密尝试：原Frame缺少message byte时保留type0，
仍递增receive sequence，然后拒绝缺失cipher。独立的两份CRC开/关carrier向量执行
原Socket→Connection→可靠Pop，确认13B零payload载体会交给client delegate；此
delegate为adapter，与后续Frame入口案例构成两段边界证据，不冒充一次完整会话。
Native可靠交付现在也让空控制frame进入该失败分支；其他空消费者保持自身准入。

实际BaseWorker测试在CRC开/关分别接收同批空控制帧和随后sequence1的有效加密
SetInputTemporarilyDisabled。最终空Read之前无交付；ACK时已完成两次decrypt attempt，
队列只有一条普通控制动作，input状态尚未改变；Drain后才改变。handler中创建并join
一个实际线程，该线程能取得Base和incoming mutex，验证消费回调没有持这两把锁。
这是Native线程/锁生存期证据，不代表Source OS调度或Switch decoder/loader已验证。

原来的transport/client-config/protocol-evidence/peer-negotiation fixture曾隐含
“可靠Update即分派普通控制”，现显式执行DrainIncoming再观测对应源函数边界。
decrypt_attempts测试用Connected状态验证实际控制动作；在Handshaking状态发送
普通input通知本来就不属于官方专用dispatcher允许的输入。

【范围】这一步分离普通控制消费，不将周期发送actor、全局network锁与所有producer
的交错称为已对齐。RemoteHID仍是官方内联例外，其设备线程/发送锁关系须按自身
调用链核对。完整decoder、早到媒体、上行FEC实际启用、统计评分与真实Steam/Switch
仍独立取证；没有新增自动FEC或把原用户停顿认定为已修复。

## 64. 同轮接收、反馈与周期发送的时间和通道顺序

【官方客户端证据】沿用§24.1固定SHA的Android 1.3.32 libmain.so，不以主机代码
或字段定义代替客户端策略。Socket::Update @0x7fecd4先按§60排空可读数据，再以
最后一次Read之前保存的tick调用Connection::Update @0x7fc108。它在
0x7fc368–0x7fc3cc按同一优先级快照逐channel执行：可靠接收更新、普通不可靠接收
更新、可靠发送、不可靠发送(false)、FECOutgoingQueue发送；全部channel之后，
0x7fc3d0–0x7fc40c再做不可靠发送(true)的轮转扫描。每轮只在末尾推进一次rotation。
因此不能把“先更新全部RX，再由另一周期线程扫描全部TX”称为同一策略。

### 64.1 可靠RTO、NACK与实际发送时间

0x7fc36c/0x7fc390将同一batch tick w20分别传给可靠接收和
SendReliablePackets(unsigned int)；可靠sender @0x7f8ac4的0x7f8b28使用参数w1
计算到期条件，不在候选判断前重新取时钟。默认估计为0时，clamp后65 tick加1/4为
81 tick；age=81不触发，age=82触发。该数值是受控初始估计的边界，不是固定线上RTO。
最后一次空Read消耗100 tick，或前一通道实际发送耗时100 tick，也不能使另一个
可靠包在本轮由81提前变成到期。

不可靠sender @0x7f8cbc在0x7f8cf4自行GetStreamTimestamp，以新时间清理保留窗口。
Socket::Send @0x7ff1dc还会独立取实际attempt stamp，包含被budget拒绝的attempt。
故同一轮可以出现“可靠包按batch tick仍未到期，不可靠包按新时间已经过期”。
0xf479a8是局部静态初始化的__cxa_guard，0x7f90bc–0x7f90e0初始化0xf479a0为13107；
它不是开启重传/FEC的配置开关。审计通过真实首次调用执行此初始化，不预置其值。

HandlePacket @0x7f93d0尾调用共享HandleNackPacket @0x7f95dc；后者直到0x7f9938
没有调用sender。NACK先修改窗口，在后续周期发送阶段生效；同一接收批次随后到达
的ACK可先移除该包，从而不产生多余重传。旧组件审计中显式再调用sender，是单独
受控步骤，不能用来证明原客户端“收到NACK即发送”。

### 64.2 Native边界与完整字节对照

IHS_SessionNetworkUpdateAt使用一次factory/priority/rotation快照，对每个channel
依次调用可靠RX、媒体普通RX/反馈、OutgoingUpdateChannel，最后OutgoingRetryPass。
普通控制仍在网络周期后出队分派，见§63。初发producer事务保留原来的Queue/Dispatch
入口；SessionSendWorker不再独立触发周期OutgoingUpdate。新初发事务在自己的入口
调用sender，仍可能发送同channel其他到期包，不能把“取消独立周期扫描”误写为
“所有初发必须等到接收批次末尾”。legacy重传timer仍只唤醒初发队列，不执行周期TX。

`audit-steam-network-cycle.py`从官方真实Channel::Send @0x7f89dc、SendUnreliable
@0x7f8bd8建立保留窗口，执行原Socket收包/Connection整轮和真实RX/TX窗口。
固定40例76个状态，含96份初发wire、132份周期wire；与Native真实QueuePacket/
DispatchQueued、receiveCycle、网络收发/反馈及统计路径逐字节、逐状态比较。
检查完整CRC wire顺序、初发失败后的重试、可靠保留状态、不可靠head/tail/cursor/
计数/stamp、两类budget deadline、blocked、优先级顺序、rotation、时钟及采样。

向量包括CRC开/关、RTO 80/81/82、最后空Read耗时、实际write耗时、无可读输入仍推进
TX、同批NACK→ACK/ACK→NACK/NACK单独输入、混合媒体NACK与可靠ACK/重传、优先级
正负、两类budget阻塞、transport结果1…4及同channel失败不阻断其他channel、重复
NACK下跨rotation完整回绕。不以只看rotation计数的空队列案例声称公平重试；该组
实际观察到channel4/5/6的重试。被budget拒绝的attempt仍更新stamp，后续NACK可重新
标记，这一点也比较窗口状态，不能仅检查实际write次数。

Native真实双worker测试在CRC开/关分别把RX批次卡在Read中，保持初发worker运行，
确认初发可发送；再推进协议时钟并等待20ms，确认没有周期抢跑。释放Read后，同批
NACK无ACK时才重传，有随后ACK则取消；stop/join后销毁。恢复独立周期sender的
mutation会在EOF前重传并触发断言。这是Native时序回归证据，不是Source OS调度证据。

【证据范围】时间、初始连接状态、IO结果、平台mutex/refcount和交付delegate受控；
FEC outgoing队列为空。该对照不证明上行FEC的真实生产入口或启用条件，不新增按丢包
自动开启FEC的策略。全局network锁与所有初发producer/内联RemoteHID设备线程交错、
timeout/生命周期相对channel的完整顺序、早到媒体的窗口所有权/完整帧缓存、decoder、
统计评分及真实Steam/Switch会话，不能由这些受控网络周期结果推定等价。

## 65. 通道收发、连接deadline和下一轮关闭通知

【官方客户端证据】同§24.1固定SHA。Connection::Update @0x7fc108在0x7fc120先
保存传入tick；state1在0x7fc140进入§64的全部channel收发/轮转，直到0x7fc43c
才判断接收租约。普通/暂停阈值仍分别15/180乘65536，使用uint32(batch tick−
lastReceive)。达到边界时先前通道工作不会被撤销；一个到期的可靠包可以先产生
一次type5重传，随后Disconnect @0x7fb724产生一次type9并转transport state2。
Socket写失败不阻止状态转移，也不会使goodbye进入可靠重试窗口。

下一次Update在0x7fc1c8–0x7fc204对state2调用仍存在的delegate，回调时连接state
仍为2、两端ID仍为旧值；然后清地址/peer ID，分配新local ID，进入state3。
该次Update不再执行state1的通道扫描。原默认IStreamConnectionHandler::OnStreamUpdate
@0x7b0790是ret，本节直接执行它，不由该回调伪造关闭或推进时钟。

【更正/实现约束】此前SessionUpdateAt在NetworkUpdate之前调用整个TransportUpdate，
会在已达租约的这一轮提前断连，从而漏掉原版先执行的通道尝试。生产链拆为
TransportPrepareUpdate（前后台边缘、保存tick、上一轮closing退休、connecting
专用重试）、NetworkUpdateAt（state1时的收发）、TransportCheckTimeout（本轮
deadline），随后才进入client消费。保留TransportUpdate作为不含channel工作的
组件组合入口；旧transport oracle在该边界对照，不能用它代替实际receiveCycle。
CheckTimeout只处理transport0/1，state2/3不再触发新超时动作。前后台边缘排队的
本地执行机制仍按§34单列，不据此声称与官方UI线程调度完全等价。

### 65.1 实际Socket整轮对照

`audit-steam-network-deadline.py`基于§64执行真实初发窗口、Socket Wait/Read/Update、
Connection::Update、真实Disconnect/CRC和下一Update的ID退休。固定68例128状态，
84份初发/预置Disconnect wire、108份周期wire及64次关闭notice边界，与Native真实
生产receiveCycle、收发/采样、Disconnect/Finish及callback前旧ID状态逐项比较。
next local ID固定为12，证明重分配的时机及peer清零，不冒称原版PRNG状态相同。
factory排序不在closing入口凭空初始化，因此此组不比较未经过state1扫描的排序数组；
逐通道排序/完整wire顺序继续由§64的40例验证。

案例覆盖CRC开/关×普通/暂停的deadline−1/0/+1、EOF耗时跨界、write耗时跨界、
可靠budget阻塞仍可发type9、四种最终IO失败、有效可靠收包续期、同批对端type9、
初始closing时的四个client阶段及uint32租约回绕。EOF/write跨界但batch tick未到
期限的那轮只有type5、没有type9；恰到期的那轮为[type5,type9]，下一轮才有notice，
notice观察到state2和旧ID，结果为state3。上述非空顺序另有Source断言，不仅将
Native输出填回fixture。原§64的40例逐状态结果保持不变。

实际RX/initial-send双worker在§64原CRC×ACK场景外追加CRC×普通/暂停超时：Read
被阻塞时仍允许初发，EOF后到期轮先重传、再goodbye；下一轮应用notice看见closing
和旧ID，随后退休并stop/join，goodbye只一次。把deadline检查移回通道扫描前的
mutation会在goodbye处因缺少前一个重传而失败。此为Native运行证据，不外推为
Source OS线程或Switch loader/显示验收。

### 65.2 客户端主阶段与项目应用回调的区别

原CStreamClient::OnStreamDisconnected @0x7b00d0也在本节执行并单独记录Source
client阶段：受控state6进入7，0/2/7入口结果为0。回调保存transport notice后跳入
原handler，原客户端阶段赋值/日志分支实际执行；这些是函数边界案例，不能声称
所有组合均由正常UI连接可达。完整OnThink的Stopping消费、播放器通知、资源停止
与Close不由此组执行。Native应用disconnected callback用来比较transport通知的
位置及旧ID，不冒称是同一个官方client/player回调，也不把Source-only阶段记录
描述成本地已经具有相同Stopping状态机。

原OnThink @0x7a60c0–0x7a60d0在network/transport Update后直接调用
HandleIncomingPackets，再于0x7a6134–0x7a616c按client阶段选择Starting/Streaming/
Stopping。这里没有用transport state2/3跳过已经排队的控制消息；dispatcher按§63
自己的client状态表选择。§65对应实现曾有Native DrainIncoming的shutdown==0保护，不能外推为
官方正常closing的队列消费规则；§66撤回该过滤并接通客户端阶段。§63的该项本地保护也不证明超时/对端断连与上层
Stopping的组合等价；本节Source-only关闭阶段与上述原指令顺序明确限定这一边界。


【证据范围】连接初态、暂停字节、时间/读写耗时、IO结果、next ID与delegate包装
受控；锁、refcount和完整帧consumer仍为adapter，FEC outgoing队列为空。关闭这一
轮的queued control消费/后续client阶段、完整Stopping/Close/通知锁关系、全局所有
producer/RemoteHID交错、早到媒体、decoder、FEC实际启用、统计评分及真实Steam/
Switch会话不在本节等价结论内。本节没有把15/180秒租约解释为用户所见一两秒停顿。

## 66. 连接关闭、已拥有的控制队列与客户端Stopping

【官方客户端证据】仍为§24.1固定SHA。OnThink @0x7a5ff8先处理network及
StreamTransport Update，0x7a60d0调用HandleIncomingPackets，然后才在
0x7a6134–0x7a616c选择client阶段。不能用transport closing/closed替代客户端
消息准入：已排队的99在client6或7仍进入通用dispatcher。新Frame的OnStreamPacket
只以client0/7拒绝，接收入口本身没有transport2/3判断；后者是函数边界结论，
不证明任意transport/client组合均可从正常网络到达。

OnStreamDisconnected @0x7b00d0在原连接delegate回调中将client6设为7，其他
受控client阶段设0；随后Connection::Update才清peer并重新分配local ID。
HandleStreamStopping @0x7a7238的顺序为音频OnStreamStopped/析构、视频
OnStreamStopped/析构、player delegate、input析构、NetworkStats Stop/结果/保存，
最后client设0；625/626的媒体ID也清零。该函数**不调用Close或ResetConnection**。
原CStreamPlayer::OnStreamStopped @0x7b76e4为ret，本节直接执行它。主动
CStreamClient::Disconnect @0x7a7acc则先Connection Disconnect，client6/7时
执行Stopping，再ResetConnection/Close；后者才清队列和连接对象引用。

触发时机也需区分：租约到期在Connection Update的通道扫描末尾发生，下一次
Connection Update才通知client；type9若在Socket Read中触发Disconnect，紧接着
本批次的Connection Update已经能执行该通知。因此不能将两者都说成“下一次
Socket收包循环才停止”，更不能在连接delegate中立即中断client队列消费。

### 66.1 Native阶段、通知和所有权

【更正】撤回§40/65实现说明中将应用disconnected callback当成原连接delegate、
要求应用在该回调中观察旧ID的映射。连接delegate由独立
IHS_SessionClientTransportClosed表示，在清ID之前变更client阶段；应用完成通知
在Stopping中停止并join音频/视频后发出，随后停止输入，client回0。连接原语
oracle现观测真实delegate边界，原wire、旧ID时序和退休结果不因错误的应用映射
而放宽。前Streaming失败的应用完成通知仍是项目API扩展，单列为收尾机制。

TransportFinish不再提前interrupt。SessionUpdateAt在本轮network/timeout之后，
即使transport已2/3仍消费已有队列，再选择client阶段。Control Frame和Drain的
shutdown==0过滤均撤回，改以client表及明确的本地interrupt/detached保护；正常
closing不是本地取消。原0/7拒绝新Frame，与允许先前已排队的消息继续消费，两者
保持独立。配置99仍按完整值替换、通知、保存，不因关闭而合并或丢掉FEC字段。

Stopping通过原有消费者remove路径按audio→video stop/join/destroy，在Base和
incoming锁外执行；播放器完成通知之后再CloseAll输入设备。它不发送StopRequest、
重连或额外goodbye。会话owner结束时执行自己的Close/清队列/最终退休，这是平台
会话所有权收尾，不能冒称原Stopping内部调用了Close。

有RX owner时，外部/decoder线程的Interrupt只发布退出和唤醒初发队列，不并发
遍历可能正被remove/free的消费者表。RX finalized按阶段停止并join消费者，再
停止剩余channels、关闭输入和连接。主动SessionDisconnect先尝试一次goodbye，
发布closeRequested，由RX owner在消费者停止后Close/清队列；无RX owner的独立
取消API保留自身关闭保护，不以它证明完整原版UI/decoder调用栈相同。

### 66.2 原指令组合对照与实际线程验证

`audit-steam-client-shutdown.py`运行原Socket CRC/真实可靠窗口、实际控制
OnStreamPacket/Frame解密/队列、OnThink、Connection Disconnect/退休、client
OnStreamDisconnected、config99解析/复制及完整HandleStreamStopping控制流。
96例288状态覆盖CRC开关、timeout/type9/已进入closing后再OnThink三种触发、
单份FEC=true配置及连续true→false配置、audio/video/input八种有无组合。
144次控制consumer、288次配置通知/保存及144份完整wire与Native一致；媒体ID、
阶段、接收序号、队列body/顺序、完整配置与各动作相对位置逐项比较。

初始受控network步骤先将完整控制帧交给client owned队列，再让OnThink执行关闭，
模拟网络与主阶段之间的交付边界；它不是一个Source OS线程调度测量。每例明确
断言关闭时是否仍应在本轮消费99、先后stop/destroy及仅一次Stopping；原日志队列
也经真实ctor初始化，不将未初始化的零索引当作有效待发送日志。55例handoff参考
保留原53例不变，再加transport2/3的两个assembled-Frame边界，防止在接收入口又
引入同类隐含guard。这两个输入不冒称其carrier一定可由正常UI触发。

Native真实RX/initial-send/audio/video worker测试按CRC×四个场景各连续两次，共
16次：closing后消费配置、消费前退休至7、audio停止期间decoder请求取消、主动
本地取消保留消息直到Close后丢弃。前两者先通知/保存配置，再audio/video stop并
join，最后应用通知；本地取消不执行queued配置。两个实际data worker退出时取得
Base锁，应用回调另创建/join能取得Base的线程，验证join/通知不持Base；callback
还核对已无媒体消费者、通知仅一次、goodbye仅一次，随后owner join/destroy。
恢复shutdown过滤的mutation会因缺少配置通知/保存而失败。

【范围】AES/HMAC primitive、平台mutex/refcount、wait/read/final IO、decoder/input
析构本体、StreamTransport Update为明确adapter；Starting/Streaming分支本体沿用
独立证据，本组只观测它们的选择。Source NetworkStats Stop/结果/保存是Source-only
hook，未把它们说成Native已具有相同评分/文件输出；client暂停标记的组合清理及完整
ResetConnection的录制输入、pending媒体、复用状态也不由本节验收。全局producer/
RemoteHID交错、真实decoder/资源、非空上行FEC启用、统计Start/Stop评分及真实
Steam/Switch仍须各自证据。本节不证明用户一两秒停顿或菜单闪烁的根因。


### 66.3 client+19暂停标记的清理更正

【撤回与证据】原§66及Issue中将client+19笼统列为未知/未建模字段的说法不准确。
Pause @0x7b02d8/0x7b0338和Resume @0x7b03a0/0x7b0420明确读取/写入它，它就是
§29/34的clientPaused。OnStreamDisconnected的client6→7分支在0x7b0154清零此标记；
其他受控client阶段仅回0，不在该分支清它。ResetConnection @0x7a52e8也清零。
这个client标记与Connection+8的paused租约选择字节保持分立，不能通过Resume来
伪造关闭清理，从而额外发送123/DataLost或刷新echo。

在原96例之后追加CRC×timeout/type9/先closing再Think的6例paused输入，原96例
逐状态不变，共102例306状态、150份wire。明确比较入口clientPaused/connectionPaused
都为true；client6→7清clientPaused，connectionPaused仍true，未生成Resume或DataLost。
Native16次实际worker场景同时检查retire时清client暂停标记，以及本地取消在player
通知时仍保留它、到owner Close/Reset收尾后才清零。暂停时完整媒体帧的准入与解码
调度不由这6个控制/关闭案例推定等价，须按OnStreamPacket自己的数据路径核对。

## 67. 暂停期间的完整媒体帧准入

【官方客户端证据】同§24.1 Android 1.3.32固定SHA。OnStreamPacket
@0x7acfa8先拒绝client0/7；Frame构造后，channel≥3且message tag=1才进入
0x7ad00c–0x7ad01c的媒体分支：client阶段必须为6，且client+19必须为0，
才调用OnDataPacket @0x7ad148。此处读的是客户端暂停标记，不是Connection+8。
控制消息的解密/队列准入不经过这个媒体判断，不能一起在收包入口屏蔽。

【结论】判断发生在通道已取出完整媒体帧之后。普通/可靠窗口、FEC重建、
连接入包采样以及反馈维护不因clientPaused而停止；被拒绝的帧不进入
OnDataPacket、RecordFrameReceived或视频带宽采样。该判断不生成Resume、
DataLost或关键帧请求，也不构成按丢包启用FEC的策略。暂停/恢复的控制生产
及DataLost动作仍按§29/34各自的调用入口。

【执行对照】`audit-steam-media-admission.py`执行真实Socket CRC/ID准入、
普通3/4与可靠5/6窗口/Pop、type11 RS恢复、原OnStreamPacket/OnDataPacket
和视频采样。反馈另外接通真实Socket::Send @0x7ff1dc，保留ACK/NACK含CRC
的完整wire。42例570状态覆盖CRC开关、三种载体、持续暂停、末片到达前暂停/
恢复、末片到达后但Update前暂停/恢复，以及受控client5/7→6。66次
OnDataPacket frame ID和42份反馈wire，与Native生产路径及采样逐状态一致。
client phase/paused为显式受控输入，不将所有组合称为真实UI或网络可达。
通道构造时钟为1000000，数据时间从1101000起，避免用倒退时钟掩盖ACK资格。

其中FEC的重建完成在收包调用内同步触发媒体准入；普通/可靠媒体由通道Update
取出完整帧时触发。因此在末片到达后、Update前改变暂停位，FEC第二帧已经
按旧标记决定，普通/可靠第二帧按新标记决定。该差异来自真实指令输出，不能
为了统一三种载体而把所有判断挪到decoder worker。Native在完整帧交入消费者
FIFO前判断；可靠的未配置通道分支在存入完整帧pending前也先检查暂停位。
已有消费者所有权的数据不因这个新增判断被追溯清除，decoder自身暂停行为不
由本节推定。旧线程测试在Handshaking状态等媒体回调不符合此准入条件，其
解码/反馈测试输入改为Connected，不删除原有消费者/窗口/反馈断言。

【撤回与范围】撤回将旧Native“暂停时完整数据仍进媒体FIFO”视为官方等价的
解释。修改前对照明确出现paused下Native admitted=[1]、官方=[]，且Native
视频collector已推进而官方未推进；修改后两者一致。Source平台锁/refcount、
最终IO结果、decoder及CNetworkStats评分仍为明确adapter，Native线程创建用
受控polling桥接。Source pre-gate transport delegate与Native post-gate FIFO
并非同一所有权边界，本组不比较旧delivered/metadata列表，而单独比较实际
OnDataPacket/消费者入口frame ID；原§59的146例未作此投影或更改。
本组适用已配置媒体通道，不证明早到普通3/4的raw pending缓存、未知tag路由、
无decoder通道的完整pending生命周期、硬件解码/显示或全局线程交错已经等价。

## 68. 待处理完整媒体帧的快照与重新准入

【官方客户端证据】同§24.1固定Android客户端。OnDataPacket
@0x7ad170–0x7ad218检查channel是否匹配audio/video ID；不匹配时增加完整
CStreamPacket引用并追加client+744的vector，未在这里做时间归一化/帧统计。
HandlePendingDataPackets @0x7aff74在0x7aff9c–0x7affb0复制整个vector，
0x7affb8先将live count清零，0x7affec–0x7b0008逐项调用client虚函数+48，
即原OnStreamPacket。原快照仅处理一次，尚不匹配且仍准入的帧进入新的live
列表；暂停或client0/7则在本轮被丢弃，不会保留到之后恢复/串流时再显示。

OnStartVideoData @0x7ae11c–0x7ae128在已有transport channel设置6553tick
接收预算，0x7ae1f4调用HandlePendingDataPackets；没有在此创建新的接收序列
或把完整帧重新送入网络窗口。Audio的预算setter在0x7ade40–0x7ade4c。
原通道构造默认65tick与活动媒体6553tick应保持分立，不能因为decoder还没创建
就延迟整个transport窗口、纠错和反馈。

【执行对照】`audit-steam-reliable-channels.py`在原100例之后追加24例，原100例
逐状态保持不变。CRC开/关×channel3/31×六种快照条件：仍在串流且未暂停、
暂停后配置其他channel、暂停后配置匹配channel，以及受控client0/5/7下配置
其他channel。先以真实可靠窗口交付两帧，再按各个条件调用原HandlePending，
最后回到client6/未暂停并配置原channel。源client状态/暂停位/配置ID是显式输入，
不宣称所有组合都由UI可达；配置动作是原pending函数边界，不是完整Start*Data
handler或decoder设备执行。

新增160个动作状态、104次完整packet delegate进入、8次decoder终点调用及24份
完整ACK/NACK wire，与Native实际CRC RX/可靠窗口、pending/重新准入及真实媒体
worker逐项一致。总计124例648个动作状态。CUtlVector CopyArray的临时内存复制、
pending append、refcount/析构、mutex、统计和decoder终点仍为明确adapter；原
快照清空/循环/OnStreamPacket/Frame解析/时间归一化分支执行真实指令。输入时钟
偏移为0；不以此核验运行中offset变化与真实decoder采样的时序。

【本地契约／撤回】撤回把旧Native“仅从pending取匹配channel项”视为官方快照
行为等价的解释。配置其他channel的对照中，原版仍对两帧重新执行delegate；
旧Native未进入delegate。在暂停或client0/5/7下，原版清掉完整待处理帧，旧
Native却留下非匹配项，之后可能重放。Native现先取走整个live列表，使用已有
queue item的本地链接保存一次性快照，再逐个交回完整帧分派；调用delegate前
live count已清空，不在同一遍追逐重新追加的帧。模块独立编译保证golden观察的
跨文件调用边界真实存在，不用observer伪造尚未调用的delegate事件。此本地链
接不增加线程/分配，也不上协议线。

【历史范围，由§69更正】本节实现时完整pending只来自可靠媒体；普通3/4与type11
在未知decoder channel时仍缓存raw datagram，尚未成为官方的完整packet pending模型。该raw缓存
暂保留其已有投递分支，不把原始FEC shard冒充已重建帧送入可靠分派器。320项
缓存上限为本地资源约束，不是原CUtlVector策略的证明。完整Reset/中途输入回调
重入/资源失败、transport与decoder生命周期分离、全部carrier的早到窗口及真实
Steam/Switch仍各有独立证据范围；本节不证明原用户的停顿根因。


## 69. 解码器配置之前的连接接收窗口与FEC

【官方客户端证据】同§24.1固定Android 1.3.32 SHA。Socket/Connection的
GetChannel/Channel::HandlePacket/Update、普通3/4窗口及FEC接收属于连接，
不以client是否已收到StartVideo/AudioData为创建/推进条件。真实OnStreamPacket
和OnDataPacket在transport完整帧之后才执行§67/68的准入、匹配与pending。
OnStartVideoData @0x7ae128、OnStartAudioData @0x7ade4c的setter把同一通道
预算由构造默认65改为6553tick，不清除窗口序列、未完成FEC组或反馈水位。
接收过期预算另加RTT项，不能把65本身直接说成完整接收timeout。

【撤回】撤回§33和§68曾把普通/FEC原始datagram先缓存至decoder出现再处理
视为正确接线的含义。旧实现把传输入窗/重组/反馈一起延后，缓存项可能只是某个
分片；配置/替换decoder还会新建消费者所拥有的窗口/FEC。它与原版连接先接收、
完整packet才pending的顺序不同。§68的全列表快照契约不变，现适用于三种carrier。
旧protocol_evidence以非data tag99测试raw包交给新decoder，不能证明官方完整
媒体pending；该夹具改为核对传输仍收包/出窗、不会把未知tag直接交给decoder。

【本地契约】连接按channel ID持有unreliable receive槽，含普通窗口、FEC活动组、
反馈状态和通道预算；decoder只拥有获准的完整帧FIFO。媒体消费者创建/删除/
替换不销毁或重置接收槽。Start*Data先通过真实本地setter建立通道并设置预算，
再创建decoder；其接收槽继续使用已有部分帧。NetworkUpdate在原通道排序位置
推进普通窗口和反馈，无需先找到媒体消费者。FEC在收到足够shard时立即重建并
交给同一个完整帧分派器；不进入普通窗口，也不在pending重放时重新解码FEC。

完整帧沿用原传输metadata进入统一pending；快照重放同样再判断client阶段及
暂停位。普通不完整片/FEC shard不再混入pending。收到数据后可继续反馈，即使
codec配置仍未到达。接收槽由RX协议owner串行操作，释放窗口锁后才交完整帧；
decoder worker仅消费FIFO。窗口/FEC/锁在RX和消费者线程停止/join后随Session
销毁释放。这个所有权分离不证明完整ResetConnection/对象复用的每个字段已等价。
原有窗口/FEC payload、FIFO、320项pending资源界限仍是本地约束，不冒充官方限值。

【原指令对照】`audit-steam-early-media.py`固定46例498动作状态，基础42例为CRC开/关×
普通3/4、可靠5/6、type11×七种条件。包含配置前完整数据、末片前配置、暂停
期间到达、暂停后配置、其他channel配置再匹配，以及配置前出现缺口/不完整组、再次配置decoder后重复旧完整帧。
真实Socket CRC、构造器/窗口/Pop、FEC RS、OnStreamPacket/OnDataPacket、
HandlePending控制流和视频collector执行。30份完整ACK/NACK及4份goodbye wire、54次decoder
终点、完整pending的type/channel/序号/片数/发送和首末接收时间/body、普通
window head/tail及65→6553预算逐状态与Native一致。原各组golden保持不变。

配置动作是原setter+HandlePending的函数边界，phase/暂停/时钟/配置ID为受控
输入；CUtlVector快照存储/append、平台锁/refcount/析构、decoder终点与最终IO
是adapter。初始budget通过真实setter恢复为已由构造指令证明的65，接收基准
clock/构造时间受控。没有用这46例声称完整Start handler、UI可达、所有畸形/
资源失败、时钟offset在异步消费期间变化或真实硬件decoder已验证。

`early_media_real_workers`将同46份官方动作序列各运行两次，共92个独立进程
启动、136个实际消费者启动/停止。CRC RX、三carrier重组、pending、真实媒体
线程/FIFO与stop/join都运行生产代码，decoder终点核对body与54×2个frame ID，
反馈数量30×2、goodbye数量4×2，并断言decoder替换前后仍持有原接收槽。D屏障仅在原版同步
终点之后等Native消费者完成，不替代原版OS调度证明；两次桌面进程不是两次
Switch loader测试。网络真实会话、全局producer锁、完整统计/codec资源与显示
仍有各自范围，未据此判定用户一两秒停顿/菜单闪烁的根因。

【Closing边界补证与更正】另外4例经真实Socket接收peer type9，执行原
Connection::Disconnect并发一次goodbye，再在同读批次、Connection::Update
退休之前接收剩余FEC shard。CRC×clientPaused两值均覆盖，明确观察connection
为2而client仍6；未暂停时仍进入OnDataPacket/decoder，暂停时仅完成FEC而不交付。
原42例逐状态保持不变。普通通道U动作不是该组的Connection退休动作，不能据
这组声称原OnThink/Stopping已执行；退休/完整Stopping由§66独立核验。

撤回把完整帧分派器的atomic shutdown拒绝当作官方client准入条件的解释。
加入本组前Native在第一个闭合FEC处admitted=[]、官方=[1]，且视频collector
不同，实际对照能检出。完整帧分派现按client0/7、媒体client6/paused判断，并
保留本地主动interrupt/detach的所有权保护。旧reliable oracle将client7借由
Connected+shutdown模拟，现直接设置真实Stopping=7、保留独立connection1边界；
原124例输出不变。传输closing本身不代替客户端状态判断，也不推导出额外FEC
重试、关键帧或控制应答策略。

旧transport oracle本来在Source Channel::HandlePacket前停止，现将Native terminal
observer移到同一接收边界，原固定输出不变；非data的固定FEC向量仍仅比较
transport delegate，不把它们当作未知消息完整dispatcher证明。媒体测试的packet
header补齐真实channel ID，并登记实际decoder消费者；保留原窗口/丢包/反馈及
阻塞消费者断言，避免在未配置消费者的夹具里要求已经发生解码。


## 70. RX时间转换、采样与延迟消费者

【官方客户端证据】同§24.1固定Android客户端。OnDataPacket
@0x7ad220–0x7ad25c在已匹配audio/video ID之后，从connection+848取offset，
将frame-start、transport-send减去offset；input-received仅在非零时减去offset。
本地首/末接收时间不转换，32位减法保留回绕。随后0x7ad260调用原
RecordFrameReceived，0x7ad298才进入decoder。未匹配ID的完整packet先pending，
不在首次到达时固定offset；配置匹配后的重放才转换与采样。

【撤回】撤回§59把“dataFrame在codec长度检查前采样”足以当作官方接收时序
等价的含义。旧Native在媒体worker读取当前offset、归一化并采样，FIFO等待期间
的新时钟样本会改变此前到达帧的结果。新对照在第一个U后直接检出：Native
video collector仍frame0/空，原版已frame1并记录send=1100900。该差异不证明
原用户停顿的根因，但明确说明统计与decoder消费不应共用晚到的时钟估计。

【本地契约】匹配有效完整data header后，在RX准备阶段缓存一次offset，并
记录视频网络/received统计，再把原body与本地cache一起转交FIFO。消费者从原始
12B数据头生成回调header时按cache转换，标记为local，视频消费者不重复减去
当前offset或重复采样。frame/transport wire header与body仍保留原始值；cache、
local/recorded标记均不上协议线。Frame初始化、重新组装与释放清除cache，FIFO
所有权转移保留cache。pending只保存尚未匹配的原始完整packet，在重放时准备。
视频tracker的本地完成事件仍由其原路径收集，不把本节扩大为整个tracker/decoder
生命周期已对齐。Audio保留同一offset转换，完整音频采样/同步策略另有证据范围。

【原指令对照】`audit-steam-media-clock.py`固定48例618动作状态、96次官方
终点metadata。CRC开/关×普通3、可靠5、FEC11，覆盖接收后改变offset、pending后
配置、负offset、零frame/input sentinel、ProcessTimestamp更新估计，以及32位
符号边界附近回绕。T执行原ProcessTimestamp和Ping/TimeOffset采样，不把所有
变化只当作手动setter；O为明确受控的offset状态，未假称每个极值必然由真实
网络触发。12例另经真实完成标记、Streaming/FrameEvents/C++ protobuf生成
24份完整消息正文，核对report时当前offset与旧帧接收时offset的组合。plain正文
不等于最终UDP加密/发送证明，原frame/encryption准入adapter范围保持明确。

原Socket CRC、窗口/Pop、RS、OnStreamPacket、OnDataPacket、received采样及
pending重放执行真实指令；decoder终点立即复制转换后的header。D只消费这份
已记录的官方历史，供Native晚取FIFO时比较，不改变Source原decoder调用时机。
每动作直接比较RX accepted metadata、video collector、完整pending、窗口/预算、
offset及反馈；消费者D再核对先前真实终点值。没有用Python公式替代官方转换。
平台锁/refcount/vector存储、decoder本体与最终IO仍为明确adapter。

`media_clock_real_workers`对36份非report场景各运行两次，共72次实际工作线程
进程启动。首个消费者在D前不能取帧，首帧回调之后再次等待第二个D，RX期间
继续收包、执行时钟更新。核对真实dataFrame回调的144份完整metadata/body及
反馈，并stop/join后销毁Session；没有只用observer自行计算header代替真实回调。
屏障是显式Native调度输入，不是官方OS/硬件调度的证明；完整异常/短data header、
消费者替换期间的tracker事件、音频时钟同步、资源失败与真实Steam/Switch仍
属于各自证据范围。本节未新增FEC开关或重试策略。

【检测力】将消费者临时改回“消费时重新读取offset”而保留RX cache与sampling，
使用真实ProcessTimestamp更新场景，真实工作线程回调得到frame-start=1100349，
原官方终点为1100549；测试明确拒绝。恢复后72次工作线程通过。这也区分了
FIFO observer按cache自行计算与消费者实际收到正确header两种证据，不能用前者
替代后者。

## 71. 官方客户端上行FEC：产品入口与通用发送能力的证据边界

【材料】继续固定§32.1的Android 1.3.32两份客户端库及各自SHA，不使用Host
赋值或本地实现倒推客户端策略。core和shell均导出自己的Connection、Channel、
FEC队列实现；shell的网络测试与core的串流配置入口不能只凭相似名称合成一条
运行中自动调节链。这些符号的存在也不证明产品一定调用所有通用能力。

【直接调用证据】`audit-steam-client-fec-entry.py`遍历两个ELF的整个`.text`，
分别检查1,639,516和1,779,887个对齐指令位置，解出直接B/BL目标，同时枚举
所选导出函数对应PLT及`.rela.dyn/.rela.plt`引用。函数归属按真实符号范围记录，
不是只取最近的符号名称。六个关注目标共有core19处、shell6处直接调用；25处
地址、原始指令字和目标均经独立objdump反汇编核对。

| 入口/调用 | core地址 | shell地址 | 该范围内的证据 |
|---|---|---|---|
| Connection构造 | 0x7fb23c，清零0x7fb250 | 0xccb638，清零0xccb64c | `str wzr,[this,+8]`明确将包含+11的四字节清零 |
| SetChannelFECPercentage | 0x7fbcbc | 0xccbfcc | 两份库均没有直接B/BL调用者，也没有对应PLT入口或动态重定位引用；函数本身仍是导出符号 |
| Connection::SendUnreliable → Channel::SendUnreliableFEC | 0x7fbbd4 | 0xccbee4 | 两份库各只有这一处直接调用；先检查connection+11 |
| Channel::SendUnreliableFEC → OutgoingQueue::AddPacket | 0x7f9150 | 0xcc9638 | 各一处，使用channel的percentage成员 |
| OutgoingQueue::SendPackets | 0x7f915c/0x7f9cf8/0x7fc3bc | 0xcc9644/0xcca0f4/0xccc6c8 | 各三处，分别来自FEC初发、Channel::Update、Connection::Update；周期调用不等于有生产者入队 |

core的SetStreamingClientConfig另有13处直接/尾调用，地址及真实调用者完整记录在
fixture，与§32.4的Init、桌面/窗口事件、缩放、分辨率、性能浮层、麦克风和player
delegate范围一致。shell没有该core类的导出入口；其FEC设置/推荐链仍由§32的
原函数案例提供证据，不能用“没有这个同名方法”否定shell已有产品入口。

【原始指令复播】两份库各从完整Connection构造入口执行，预先将+8…+15填为
0xa5。实际内存写hook捕获构造清零+8的4B写入，+11变为0。随后分别传入
percentage=0、5、20、50、100、-1、INT_MAX、INT_MIN，执行原setter及原
Connection::SendUnreliable：setter仅保存原32位值，正常构造的gate始终为0，
都选择普通发送终点。每例再**显式注入gate=1作为能力对照**，重复setter/send，
才选择FEC终点。16例均直接观察gate内存写与终点；没有用观察者公式生成结果。

该复播的socket注册、时间、mutex、GetChannel及两个最终channel发送终点为
adapter；Ping/TimeOffset/Bitrate/PacketStats构造及Connection本体执行原指令。
连接状态1是受控前置条件，没有声称重演完整协商。GetChannel返回受控channel
存储，因此这组案例不替代§34的真实channel工厂或§26的非空RS/队列案例。
极端percentage只验证setter没有clamp，不是建议发送这些值，更不是官方产品
选择这些值的证据。强制gate分支只能证明能力，不能冒称触发条件已经找到。

【结论】官方客户端**请求对端视频FEC**的产品策略，依据仍是§32的手动配置、
预设、网络测试结果及用户确认，再经完整配置字段25进入协商/99；接收类型11
也不要求本机outgoing gate为1。客户端**自身上行FEC**另受connection+11和
channel percentage控制，不能把发送实现、周期空队列调用或Host的赋值直接
当作客户端开启策略。此处没有新增“丢包达到阈值自动开FEC”或固定percentage。

【范围】静态扫描只覆盖这两个固定ELF内的直接B/BL与指定动态重定位，不覆盖
任意间接调用、dlsym、其他库/版本、指针别名或内联写入。未见直接调用不能
改写为“永远不启用”；本节不以缺少调用者证明全局不可达，也不证明整段
产品状态机、非空上行producer或真实Steam/Switch行为等价。

```sh
python3 scripts/audit-steam-client-fec-entry.py \
  --core /data/dl/nsteamlink/build/video-recovery-re/libmain-arm64.so \
  --shell /data/dl/nsteamlink/build/video-recovery-re/libshell-arm64.so \
  --output /tmp/steam-client-fec-entry.json
```

脚本只读核验`steam-client-fec-entry-reference.json`；更新fixture必须显式传入
`--refresh-reference`，已有结果仍要求完全一致。它是官方客户端来源审计，不是
Native互操作或设备测试。

## 72. 官方Opus音频缺帧恢复与元数据契约

【官方客户端证据】同§24.1固定SHA的Android 1.3.32客户端。
`CStreamDecoderOpus::StartDecoding @0x7b134c`调用原multistream decoder create，
0x7b13d0–0x7b13d4将next ID置0、first置true。`DecodeFrame @0x7b1414`在
decoder为空时直接返回；首帧以其ID初始化next，并清first。0x7b1460–0x7b146c
按`int16(next-current)>0`拒绝旧帧，其余进入缺口循环。

0x7b14d8–0x7b15dc对每个缺失ID创建AudioFrame，timestamp沿用当前到达帧的
frame timestamp，不按采样率自行推算。非最后一帧调用原
`opus_multistream_decode_float(NULL,0,...,480,0)`进行PLC；紧邻当前ID的一帧
使用当前包payload、480、decode_fec=1。每补一帧后next按uint16递增。随后
0x7b15e4–0x7b1688先设next=current+1，再用当前包、5760、decode_fec=0正常
解码当前帧。这里的480和5760是实际每通道sample上限，不是传输tick或网络FEC
冗余百分比。它与§26的type11 RS纠错不同，不需要把配置字段25当作此codec API
分支的本地门禁。

【差异】Native旧音频submit只有payload，丢失了媒体头的frame ID/timestamp；
`stream_media_audio_submit`每包仅调用一次`opus_decode(...,5760,0)`，无法触发
上述按ID补帧。单纯增加type11接收能力不等于补齐这条音频codec恢复策略。

【错误边界】原缺口解码返回值不等于480时在0x7b15bc断言，但非调试继续路径
仍提交所分配的缓冲；当前包decode返回负值时0x7b1694断言，随后仍把负sample
数乘channels和4传给Resize。探针可记录这些原始请求，不能把分配替身产生的零
内存当作官方静音输出或要求Native提交未初始化PCM。该不安全结果的内存/播放
处理与正常恢复调用策略分开标注，不宣称错误分支的资源行为等价。

【API与构建差异】原StartDecoding在48kHz mono/stereo分别传给
opus_multistream_decoder_create的参数为`48000,1,1,0,[0]`和
`48000,2,1,1,[0,1]`；解码调用实际进入内嵌的multistream float实现0x948024。
旧Native的单流opus_decode不能视为等价：同一20ms包、480/FEC=1，单流返回480，
原multistream返回-2。原`opus_get_version_string @0x93e07c`返回
`libopus unknown-fixed`；不能据此编造一个官方精确版本号。

本机系统Opus1.5.2浮点构建即使改为相同multistream float API，在立体声连续
缺口向量仍与原输出相差最大94个S16单位。同一应用代码改用同版本的定点构建，
原36份正常/有界错误场景的有效PCM转换后全部逐字节一致；追加时间戳案例后
38份调度的固定构建对照仍全部一致。此处的构建对照定位了
该组差异，不将其泛化为所有版本/浮点优化的完整证明。Native因此固定构建未修改
的官方Opus1.5.2归档（SHA见third_party/README），保留float API，最后按已验证的
SDL S16LE格式转换；该依赖版本是本地可复现选择，不是对unknown版本的命名。
源码来源与归档SHA由[Opus官方发布记录](https://opus-codec.org/news/)交叉核对。
1.5.2上游CMake在固定点AVX2分支包含未配置头路径的float-only encoder源，本地
关闭该AVX2候选并保留SSE内核；Switch直接使用已知AArch64 NEON，不改上游源码。
BSD许可随二进制收集，不把codec库的许可/构建动作当作Steam产品策略证据。

【Native接线】AudioCallbacks追加可选submitFrame，带frame ID和本地frame timestamp；
正常完整帧在RX捕获offset，经FIFO保留，到实际audio消费者只转换一次。旧submit
仍在新回调未提供时使用。应用注册新回调，在既有audio_lock下按原ID规则依次
执行PLC、末帧FEC、当前包解码；start/stop重置next/first，不引入后台线程或新的
协议开关。有效PCM以float进入§73的官方策略jitter buffer。原本地300ms清空
SDL队列的处理已由§73替代；撤回将该保护当作音频恢复完整对齐的任何推论。
本节codec对照的观察点是jitter输入，不能拿它代替§73的缓冲/播放回调对照。

【原始执行证据】`audit-steam-opus-recovery.py`固定40例140状态，实际执行原
Start/Decode/Stop、内嵌Opus创建和完整decode。38份可比较调度覆盖mono/stereo、
10/20ms包、连续/缺一帧/缺三帧、重复旧帧、乱序、uint16回绕、首帧高ID、重启、
零/回绕时间戳及非零SILK输入；另两份记录真实坏包和空decoder的Source边界。
输入SILK数据由明确记录版本/设置的本地编码器生成，只是刺激，不是Host策略证据。
立体声单缺口另将codec入口受控改为NULL/PLC，原输出hash与真实FEC分支不同，
证明该输入实际区分了FEC数据与PLC；mono同组输出相同，不能把它也声称为独立
FEC恢复成功。counterfactual不作为客户端生产触发入口。

`opus_recovery_official_vectors`使用真实Native完整帧分派、offset cache、audio
FIFO/线程、应用恢复函数、真实固定点Opus及jitter输入。38次进程调度比较134次
实际metadata回调、168次完整codec参数/返回值、156份有效PCM，S16误差为0。
codec配置、next/first及补帧id/timestamp也逐项核对；不是只比较观察者推算的计划。
另三进程检查旧callback后备、当前坏包不提交PCM，以及暂停真实SDL设备后101份
解码产物受§73的16383-frame接纳界限约束。每个消费者stop/join后再销毁Session/SDL。

【检测力】将Native末个缺帧的fec位临时由1改为0，真实worker/codec对照在
one_gap_1_10立即拒绝：官方首个补帧id11/fec1，本地id11/fec0。该零PCM输入
单看波形可能相同，完整调用参数比较仍能发现策略差异。恢复源文件并重建后，
38份调度与三个Native控制进程均通过。

【范围】Source测试从decoder-worker函数入口进入，ID/timestamp/包体为受控输入；
player创建/提交、Frame存储、libc分配、断言显示为adapter。真实网络/FEC窗口、
完整OnStartAudioData/UI/解码线程调度、所有声道/频率、半域超大缺口资源/退出延迟、
audio统计ring与input-mark采样、jitter buffer/同步、设备声道转换及实际播放仍是
独立契约。此处未新增网络丢包自动FEC或认定原用户停顿根因。

```sh
python3 scripts/audit-steam-opus-recovery.py \
  --binary /data/dl/nsteamlink/build/video-recovery-re/libmain-arm64.so \
  --output /tmp/steam-opus-recovery.json
ctest --test-dir build/desktop -R 'opus_recovery_official_vectors|raw_audio_official_vectors' --output-on-failure
```


## 73. 官方float音频jitter与设备拉取边界

【官方客户端证据】与§24.1相同SHA的Android 1.3.32 `libmain-arm64.so`。
`CStreamPlayer::BOpenAudio @0x7bec54`实际执行构造器
`CAudioJitterBuffer<float> @0x7bf048`，再于0x7bed44–0x7bedb0覆盖参数。
`Push @0x7bf91c`、`Pop @0x7bfdd0`、`FindBestCrossfadeEndpoint @0x7ca5b8`、
`ApplyCrossfade @0x7ca798`、`UpdateStats @0x7ca928`均执行原指令；
不是用自写伪代码产生预期。SDL设备及提交、libc存储和外部sinf为明确adapter。
这条路径是官方客户端自身的播放策略，与Host何时发送网络FEC无关。

| 对象offset | BOpenAudio设置（按每通道frame计） | 触发/作用 |
| --- | --- | --- |
| +0 | floor(rate×70/1000) | priming且无fade时达到此占用才开始输出 |
| +4 / +8 / +12 | 80 / 60 / 40ms | 统计最小占用在区间外，修正量为min−60ms |
| +16 | 10ms | queued−requested不大于此值时进入欠载预判；也是溢出混合保留量 |
| +20 | 500ms | 按Pop请求frame数累计，达到后发布统计；不是墙钟timer |
| +24 | 50ms | 淡入步长1/(N−1) |
| +28 / +32 | 5 / 10ms | 扩张/收缩crossfade步长的分母N−1 |
| +36 | 1 | 无新写入期间最多一次欠载扩张尝试 |
| +60 | 16384 | 环形容量；预留一个slot，可接纳16383个frame |

【Push】正常路径只接纳free范围，保留已排队数据并累计被丢弃的输入frame数。
部分接纳后设置overrun锁存。后续输入若仍放不下，整份拒收；能放下时清锁存，
令blend=min(queued−10ms,inputCount)。blend>0时回退write，按sin²权重混合
旧尾部与新输入，再接入剩余输入，并清统计周期计数/修正量。
不存在“超过300ms就清整个队列”的分支。blend=1的原0/0浮点路径也有自然调度
对照，未把它改写成任意平均混音。

【Pop】priming不足时只累计missing并返回0，不推进读指针/统计周期，也不填充
输出尾部。达到70ms后清priming、开始50ms淡入。queued−requested≤10ms时，
若最后一frame各声道全0，或没有新写入而已达一次扩张尝试，就重新priming；
已有有效增益时按当前queued淡出。否则修正量为queued−requested−60ms，
在前max(queued−5ms,0)范围寻找声道顺序求和的符号变化作为起点。
新write与tracked_write不同会重置尝试次数；不是按frame ID或网络ACK判断恢复。

统计最小占用>80ms或<40ms时设置min−60ms修正量（边界等于40/80不触发）。
修正起点最多向前检查299次符号变化；候选目标最多再前/后检查99次。
没有符号变化返回原候选，不假定候选一定属于新到PCM。正修正做10ms收缩，
负修正做5ms扩张，均从原环形内容交叉淡化，不清整队列、不重启codec。
正crossfade完成在0x7ca8c8切换read到已前进的alternate_read；
负crossfade完成0x7ca8ac**仅清phase/step，不切read**。这两个分支不能合并。
相位、权重、插值和统计的原float/FMA舍入次序均保留。

【Native与设备边界】`audio_jitter.c`实现上述策略；解码器持续输出float，Raw
按原signed16/32768归一化。媒体SDL2设备的pull callback每次调用同一Pop，
在设备边界才转换S16/限幅/舍入，随后混入UI提示音；已移除SDL_QueueAudio及
300ms清队列。`audio_queued_bytes`是环形内占用折算S16字节，`audio_queue_drops`
是拒收的输入frame累计数，不再表示清队列次数。SDL2必须填满请求缓冲，因此
不足部分补0是本地设备adapter；官方SDL3 PlayAudio只提交Pop实际返回的部分。
原PlayAudio在本对照中设置volume=1；其他volume、SDL3自身重采样/欠载行为不
由此推成相同。超过16384-frame的本地设备请求以静音守界，不冒称原客户端策略。

callback只拿专用jitter锁，不拿audio_lock/state_lock；生产者在audio_lock下短暂
拿jitter锁Push。关闭路径持audio_lock先Pause/Close等待SDL callback退出，然后
销毁ring/codec；从不持jitter锁等待SDL关闭。原算法原子index与本地序列化临界区
的并发调度不宣称逐指令等价；callback内不分配、不打印日志。

【对照边界】`audit-steam-audio-jitter.py`的自然Push/Pop/Play调度从原BOpenAudio
进入，构造后不写policy/state。保留所有scalar/float位、完整ring hash、实际输出
float字节和分支PC；包含临界预缓冲、单frame混合、零长度、环绕、溢出拒收/恢复、
稳态占用修正、欠载淡出/扩张、静音、常量及声道抵消。Play调度额外执行原
CStreamPlayer::PlayAudio @0x7bfca4并观察SDL提交终点。固定fixture为120例9276步，覆盖8/12/16/24/44.1/48kHz及mono/stereo/八声道。
Native模块对照与实际Raw媒体→生产SDL callback对照分开；后者为90例6957步，
比较S16输出、补零尾部、占用及丢弃数。
真实SDL dummy callback另做连续start/stop，验证退出后不再访问ring；这不是Switch
或Android物理设备/loader证据。

sinf是Android系统外部数学库边界，Source探针明确使用host libm的float adapter，
Native模块采用同一host数学边界作逐字节比较；不因此宣称Android/Switch libm位级
相同。八声道及44.1kHz从受控BOpenAudio入口执行，不能反推全StartAudio协议/
codec/capability会选择这些参数；本地实际媒体仍受原有mono/stereo/rate准入限制。
音频全局统计/input-mark与时间同步、所有生产入口和真实设备调度另有独立契约。
本节不能证明用户的1–2秒停顿或菜单闪烁根因，也不新增按网络丢包自动FEC。

```sh
python3 scripts/audit-steam-audio-jitter.py \
  /data/dl/nsteamlink/build/video-recovery-re/libmain-arm64.so \
  --check scripts/fixtures/steam-audio-jitter-reference.json.gz
ctest --test-dir build/desktop -R 'audio_jitter_official_vectors|audio_playback_official_vectors' --output-on-failure
```


## 74. 音视频接收统计与共享input-mark消费

【官方客户端证据】同§24.1固定SHA的Android 1.3.32。
原`OnStreamPacket @0x7acfa8`以client0/7直接拒收，媒体只在client6且+19为0
时进入`OnDataPacket @0x7ad148`。0x7ad220–0x7ad260对非零input-received及
frame/send做原时钟转换，然后**音频和视频均调用RecordFrameReceived**；此后
才在0x7ad274/0x7ad28c检查decoder是否存在并交付。decoder消费时间不能替代
这项RX时间点。真实Frame构造/SetPacket也在此对照中执行；初始phase/channel
和完整packet是受控输入，不把它扩大成UI/Socket/所有传输生产入口均已证明。

`RecordFrameReceived @0x7abeb0`在0x7abefc按client+625选择audio/type0；
否则0x7abf24按+626选择video/type1，其他channel返回。只有video进入
0x7abf94的CNetworkStats::RecordFrameReceived和bitrate收集分支，audio跳到
0x7ac054。两种媒体都执行后续槽处理：

- 0x7ac064–0x7ac080按`client+1096+type×28812+12+(id%240)×120`选择
  独立CFastFrameStats槽。audio和video相同ID不能别名到同一槽。
- 0x7ac084相同ID只刷新event13/receive；既不改size/start/send，也不再次
  查询mark。初始Reset的ID0亦遵守这一规则；不能用inUse改写。
- 不同ID时先Reset、设id/size及event5/12/13；receive早于send时保持原
  时间平移/零input-received规则，见§52。
- 0x7ac118–0x7ac15c要求mark非0、`int16(mark-latestMark)<=0`，并且
  `inputMarks[latestMark&1023].id==mark`。它查**latest所在槽**，不按收到的
  mark另查旧槽；旧mark/未来mark不能因此误绑定。
- 匹配时0x7ac160–0x7ac194复制begin/sent/input-received到event0/1/2，
  0x7ac198只把该共享记录的id清0。begin/sent原值保留。表属于client，
  并不属于media ring；哪个媒体先匹配就消费一次。

【结论／差异更正】即使audio不发送视频FrameEvents报告，也不能跳过audio
RecordFrameReceived。原Native media_receive.c在捕获offset后直接返回audio，
会留下本应被音频消费的mark，让后到视频误绑定；反过来共用视频ring则会让
相同ID的视频被当作重复音频。撤回从“音频不报告”推导“音频接收统计无副作用”
的任何等价解释。本节只证明接收ring/共享mark和后续视频报告的契约，不把音频
decoder complete或全局CNetworkStats的其他函数补成未经取证的本地事件。

【Native契约】session内独立audioRing和既有video ring，共享1024-entry mark表
及同一统计锁。IHS_FrameStatsRecordMediaReceived按media选择槽；旧video API
委托该函数，保留既有调用方。完整帧在RX准备时对两种媒体记录，video才调用
已有network/bitrate收集；FIFO metadata继续携带捕获的offset/已记录标志。
不引入decoder时钟补录，不按收到的mark回查任意旧条目，也不清另一个media槽。
现有video report/tracker消费路径继续使用视频ring；新增audio ring不被冒充视频
明细发送。对象释放随原session统计owner，在消费者停止后进行。

【可执行对照】`audit-steam-media-input.py`执行原CreateInputMark、整个
OnStreamPacket门禁/Frame构造/OnDataPacket、接收统计、视频Complete、原报告
累加器/protobuf及最终明文body。150例996状态覆盖音视频先后/相同ID、同媒体
重复ID后新mark、240槽覆盖、0与uint16回绕、旧/未来/零mark、零时间、正负offset、
receive早于send、full/aggregate报告，以及client0/5/7或paused时音频不得消费。
完整mark记录、两种media的slot内容及138份视频报告body逐项比较；另在真实
Native network采样函数入口计数，与Source实际video-only分支PC对照。

原先126份直接OnDataPacket案例经更高层OnStreamPacket/Frame构造重播后，
除新增的准入PC计数外全部观察保持一致。Source packet refcount、锁/libc、
CNetworkStats/bitrate样本终点、最终send为adapter。Native对照执行实际完整帧
分派/RX准备、mark创建、slot和视频报告，但decoder入队为终点adapter；它不
冒称真实OS decoder线程/输入设备/Steam Host/全局统计Start/Stop或loader验收。
当前latest counter由探针明确控制，再执行真实CreateInputMark（包括FFFF→1）；
这不是证明每个输入producer均会生成这些标记。原完整协议/设备范围保持独立。

```sh
python3 scripts/audit-steam-media-input.py \
  /data/dl/nsteamlink/build/video-recovery-re/libmain-arm64.so \
  --check scripts/fixtures/steam-media-input-reference.json
ctest --test-dir build/desktop -R 'media_input_official_vectors|frame_stats_.*vectors' --output-on-failure
```

## 75. Audio Start/Stop控制分派、codec presence与同步启动

【官方客户端证据】仅使用§24.1固定SHA的Android 1.3.32 core；协议描述或
第三方客户端不充当官方策略证据。`audit-steam-audio-start.py`从原
HandleIncomingPackets @0x7a6368执行真实Frame/protobuf解析、Start/Stop handler、
factory、decoder构造/启动/停止及pending重放。BOpenAudio的设备返回值、OS线程
Start/Join与锁、包引用计数、PCM输出存储及最终IO为adapter；不证明设备、真实
OS调度或完整Steam会话。client初始phase、协商配置和线程开关是受控输入。

`OnStartAudioData @0x7add8c`的先后关系为：

1. 原Frame::Get解析成功才到0x7addd0；格式错误或缺少required channel均
   保留原decoder/channel，且不重放pending。
2. 全局网络锁内先清audio channel，停止/删除旧decoder，再写新channel；
   0x7ade40调用真实SetChannelMaxRecvDelay(channel,6553)。这不是等待关键帧
   的timeout，而是该媒体传输receiver的最大接收延迟字段，见§44/69。
3. 0x7ade80调用player BStartAudioStream(消息frequency,channels)。真实
   `BStartAudioStream @0x7bebe0`先BOpenAudio(float/2,外层rate,channels)，
   成功才SetAudioFormat。同一消息的codec_data尚未在此作为设备参数使用。
4. device成功才到0x7ade98–0x7adeb0：hasbit4存在则读消息codec，缺省才读
   negotiated config的selected_audio_codec(client+336)。**显式0不会回退**。
   negotiated config通过原type4控制分派/解析写入的路径亦执行验证。
5. 复制可选codec_data，调用`StartAudioDecoding @0x7a7ef8`。该factory只为
   Raw/1与Opus/3构造decoder；其他值走assert line606并保持decoder为空。
   不为Vorbis/MP3/AAC臆造客户端解码路径。
6. decoder指针发布后SetUseThreads(client+17)，同步执行
   `OnStreamStarted @0x7670b4`：设active、复制codec_data、虚调用
   StartDecoding，最后才按开关调用Thread::Start。它不检查该OS调用返回值。
7. 无论device成功与否，均到0x7adf14执行完整HandlePendingDataPackets，
   再解全局锁。device失败不创建decoder，不触发整个会话断开；已配置channel
   的完整帧仍经过原RX/统计，但无decoder消费。重试Start可重新创建decoder。

`OnStopAudioData @0x7adf9c`也先Frame::Get(CStopAudioDataMsg)。空protobuf是
合法stop；坏protobuf不改变decoder/channel。成功才清channel、stop/delete旧
解码器；没有Start路径的pending重放。真实`OnStreamStopped @0x767160`
先清active，线程模式下signal/join/purge队列，最后虚调用StopDecoding。该handler
及Raw/Opus停止/析构路径不调用player CloseAudio。不能把decoder停止自动解释为
立即销毁物理音频设备或清空player jitter尾部；BOpenAudio及整个player关闭路径
不在本节的设备adapter边界内。

【结论／更正范围】§48的“codec_data权威格式”仅指Raw decoder逻辑格式。
真实`Raw StartDecoding @0x7b178c`在设备已按外层字段打开后，再用codec_data
解析结果SetAudioFormat，且忽略ParseFromArray失败；没有重新BOpenAudio。
撤回将其扩大为“物理设备也必须只按codec_data打开”的等价解释。原Opus
StartDecoding @0x7b134c即使embedded decoder_create失败仍保留decoder对象、
设置format/active，缺codec时丢帧；不能把backend一切失败都归为device失败。
原client构造0x7a4f2c宽零写覆盖+17，证明构造默认线程标志0；探针强制两分支
只证明其能力，不证明产品UI/平台后来如何设置该标志。

【Native契约及边界】库的StartAudio先区分codec presence/协商回退，并验证
StopAudio protobuf。Audio start callback在控制分派调用者同步完成，才发布媒体
endpoint/重放pending；成功之后才启动joined worker；stop在worker join及队列
purge之后由teardown调用者执行。已支持codec的start失败保留channel与session，
置discardFrames而不创建消费者，后续帧仍走完整RX准备后丢弃。未知codec不创建
库消费者。video class仍沿既有worker启动接口，本节不作其factory等价声明。

本节fixture使用未提供prepare的合并backend接口，对照库的配置/consumer边界；
它没有执行实际SDL/player。§76另以可选prepare及真实应用回调表细分设备/decoder
阶段，核对未知codec的设备准备、Stop尾部及codec_create失败；不能把本节fixture
单独当作那层证明。无效Raw/PCM的安全拒绝规则见§72/76，不复制原不安全输出。Native OS线程创建失败仍保留已启动backend和待解码FIFO，匹配原代码
忽略Thread::Start失败、保留decoder/队列的结果；停止时先purge再释放backend。
既有FIFO内存/条数上限仍生效，不宣称复制原未设上限队列的耗尽行为。

【可执行对照】74个官方案例/346状态涵盖缺省/显式0/1/2/3与协商0/1/3组合、
真实peer config、device失败后重试、替换与跨channel、未配置多channel pending、
坏Start/Stop、重复Stop、phase0–7/paused，以及原线程开关0/1。原指令输出保留
device/format/factory/queue/codec实际状态；原factory选值与原解析presence/协商
字段独立核对。6个设备/unsafe边界案例只作为Source观察，不投射成本地通过。

68个案例/332状态与Native真实控制FIFO/drain、AudioCreate、完整pending、RX
准备、实际worker及stop/join逐步比较：phase/pause、channel/decoder存在、所有
数据channel延迟、完整pending packet元数据/body、交付帧id/localtimestamp/body、
配置及生命周期顺序。另强制OS Start返回失败，执行原Raw/Opus decoder
入队/Stop路径，并比较实际Native FIFO内每帧id/timestamp/body；保留decoder、
不运行worker及停止清理均有原函数对照。Native回调记录器强制start/stop在调用者、submit在worker，
并核验stop之前已join；按实际入队计数等待回调完成，不从golden输出导入预期
完成数。物理线程调度/Source队列深度不投射为Native严格等价。完整帧媒体入口
在传输重组之后，控制入口在解密之后；不能将它们表述为Socket/FEC/鉴权验收。

```sh
python3 scripts/audit-steam-audio-start.py \
  /data/dl/nsteamlink/build/video-recovery-re/libmain-arm64.so \
  --check scripts/fixtures/steam-audio-start-reference.json
ctest --test-dir build/desktop -R audio_start_official_vectors --output-on-failure
```

## 76. 音频设备与decoder分层、真实PCM Frame到player及停止尾部

【官方客户端证据】同§24.1固定SHA的Android 1.3.32 core。
`audit-steam-audio-player.py`把§75的BOpenAudio adapter下移到SDL终点，执行
原控制分派/解析、Start/Stop、Raw/Opus factory及嵌入codec、真正
`CreateAudioFrame @0x7679c4`与CStreamFrame存储、CAudioFrame accessors、
`PutAudioFrame @0x7bf8a0`、AudioFrameComplete、jitter及PlayAudio。
`IStreamPlayer ctor @0x7676a8`亦执行；它经SetPlayer要求client Idle。
初步组合探针在client6调用该ctor触发streamclient.cpp line250断言，因此不能
把那次构造当作有效产品顺序。正式fixture先在Idle执行原ctor、再进入受控6；
普通案例没有断言，未知codec仅原factory line606。CStreamPlayer其余UI/owner
字段为受控零，volume=1、线程开关=0，不把这些输入冒充整个产品初始化。

原`BOpenAudio @0x7bec54`先销毁旧+1104 stream、释放旧+1320 jitter，再按
**外层消息**设置设备format/rate/channels(+1124/1128/1132)，构造float jitter
并调用SDL_OpenAudioDeviceStream。成功后GetAudioStreamDevice/Resume；失败
仍保留新jitter、设备请求字段，但BStartAudioStream不SetAudioFormat，也不进
codec factory。它的三项SDL hints是APP_NAME/设备stream名称/role，未从这些
字符串推导未观察到的丢包、FEC或缓冲阈值。

`BStartAudioStream`成功才设置IStreamPlayer逻辑format(+16/20/24/28)，然后
Raw/Opus StartDecoding可再次设置它；**设备请求与decoder逻辑格式是两组字段**。
实际执行Raw外层24000Hz/mono、codec_data48000Hz/stereo时，SDL请求及jitter
仍24000/mono，逻辑format变为48000/stereo；反方向声道组合也执行验证。
原Opus在44100Hz的SDL adapter成功后，真实embedded codec_create失败，
decoder对象仍active，后续帧无PCM；不升级为整个会话断开，也不销毁player。

原CreateAudioFrame实际构造CAudioFrame/CStreamFrame并复制当时逻辑format、
frame ID及timestamp。实际GetWriteArea/Resize、GetFrameDataSize/GetFrameData
都执行。PutAudioFrame在0x7bf8b0读取的是**设备channels+1132**；0x7bf8d8以
`PCM float字节数/(设备channels×4)`算交给jitter的帧数，并非按decoder channels
解释；0x7bf8f8真实Push后调用player虚表+384 AudioFrameComplete。
`AudioFrameComplete @0x767bc4`执行原frame释放及next-ID/first bookkeeping；
这些Source字段保留在fixture，不声称本地app有相同内存布局或已证明所有同步/
统计消费者。记录的float PCM在原GetFrameData返回之后、原Push之前读取，
不是用另一个codec生成golden，也不是只比较量化后的S16。

原StopAudio handler/decoder Stop不关闭player。成功Opus数据经过整个原路径后
留下480帧音频，Stop后stream/jitter/环内数据仍在；Raw的非零尾部亦可在Stop后
由原PlayAudio继续取出。真实CStreamPlayer vtable+104解析到
`OnStreamStopped @0x7b76e4`，ELF symbol size=4，唯一指令RET。
`CloseAudio @0x7c0e00`在SDL audio已初始化时才销毁streams、再释放jitter、清
设备format；逻辑format不会随之清零。另执行原`Quit @0x7c80cc`从入口到
0x7c842c（CloseAudio之后）的前缀：先真实AudioFrameComplete/VideoFrameComplete、
Microphone Shutdown，再CloseAudio，480帧尾部最终释放。USB/JNI及非音频UI终点
为adapter，UI/owner字段及线程启动flag为0，随后Video/UI关闭与全函数返回没有
执行；`source_only_quit_audio_prefix`单独保留这些观察。外层UI何时进入Quit及
其余资源/线程不能由这段前缀证明，不列为完整UI owner/lifecycle验收。

【Native契约／§75应用边界细化】AudioCallbacks尾部新增可选prepare，要求
零初始化/同源码重编译。prepare在codec factory gate之前同步执行，包括未知
codec；成功才调用start，失败保留媒体映射而无decoder。提供prepare时，start/
stop只管理decoder，player/device资源由prepare重新打开或player close管理；
没有prepare的既有调用者保持合并backend接口。本地app实际回调表由
sl_media_audio_callbacks提供，runtime和对照使用同一张表。

app prepare按外层字段准备设备/jitter，成功才更新逻辑format；start_decoder再
按Raw codec_data或Opus字段建立逻辑decoder。Raw不再被Opus频率白名单限制。
Opus codec_create返回NULL仍保留decoder active语义，收到帧静默丢弃，直到新的
Start/Stop。Stop只释放decoder，保留已打开设备和jitter尾部；新的prepare先
关闭旧player，显式audio_close/媒体shutdown关闭并join SDL callback，再释放
ring。PCM Push按设备stride转换帧数；逻辑与设备格式不同也不重开SDL。

Native支持mono/stereo，使用SDL2 S16 callback；Source为SDL3 float stream。
既有§73的float→S16量化、完整callback零填充及Switch960/desktop1024设备块仍
是明确I/O adapter，不声称复制Android物理设备参数。无效/零维度、Raw错误或
未对齐输出仍安全拒绝；不复制原unsafe路径。Native内存/FIFO上限继续生效。
独立UI音效设备、mute/mix/recording、外层session/UI owner与全部平台关闭分支
不由本节的显式close动作证明。SDL callback真实线程运行的本地证据也不能替代
Switch真机、Steam联调或loader返回/二次启动证据。

【可执行对照】38例280状态：Raw/Opus与8/12/16/24/44.1/48k的适用组合、
mono/stereo、双向Raw冲突格式、None/2/4/5未知codec仍先准备设备、设备失败与
重试、真实Opus create失败、坏Start/Stop、重配置、配置前完整pending、
原OnStreamStopped空操作、重复Close、断序/旧Opus、两个非零SILK/FEC输入、缺省codec协商回退、pending后修改/正负clock offset，
以及Stop后的非零尾部播放。82份完整float PCM逐字节和ID/localtimestamp比较；
每步还比较设备请求/stream/running、逻辑格式、完整pending、jitter参数与所有
观测标量、完整ring SHA，以及原PlayAudio输出经已声明I/O转换后的实际SDL
callback S16及零尾。原packet引用计数、锁/OS调度、SDL IO/libc/host sinf为adapter。
完整帧和控制入口分别在重组、解密之后；没有把它们升级为Socket/真实Host证明。

Native执行真实控制FIFO/drain、RX准备、实际decoder worker、生产音频回调表、
app codec/jitter及生产SDL callback。按本地实际入队计数等回调完成，不从golden
喂入完成数；dummy设备保持暂停作确定性pull，另在真实dummy线程中验证三次
Stop仍继续callback、保留设备后直接prepare替换、Close后join且callback数不再增长。
prepare先join旧stream再重置共享UI mixer，避免旧callback与voice reset并发。Source线程标志是受控
0，本节不证明它在所有产品入口的设置，也不声称Native worker物理调度相同。

```sh
python3 scripts/audit-steam-audio-player.py \
  /data/dl/nsteamlink/build/video-recovery-re/libmain-arm64.so \
  --check scripts/fixtures/steam-audio-player-reference.json
ctest --test-dir build/desktop -R 'audio_player_official_vectors|audio_playback_official_vectors' --output-on-failure
```

## 77. SDL_main退出owner、窗口焦点与音频player收尾

【官方客户端证据】同§24.1固定SHA Android1.3.32 core。SDL_main导出symbol
size=4，仅0x75b3d8的B 0x75b3dc，不能用symbol size排除其后主体。
0x75cce4以4232 bytes分配CStreamPlayer，0x75ccf8保留x0到callee-saved x21，
0x75ccfc调用真实CStreamPlayer constructor，client参数为sp+0x238；随后至退出
虚调用的x21构造来源闭合。撤回把0x75cf50/58的receiver仅保留为未证实候选的
限制；这不证明该区域之外所有同offset虚调用也是CStreamPlayer。

`BOpenVideo @0x7b5c68`在CreateWindow成功后，0x7b5e30–0x7b5e6c真实读取三次
SDL_GetWindowFlags，分别保存bit6到+1784、bit9到+1785、bit10到+1786。
原`BHandleEvent @0x7b8110`对0x20e在0x7b82e4写+1785=1，对0x20f在
0x7b8b0c写0。它们对应窗口输入焦点，独立于Remote Play client+19 Pause。
字段/分支判断来自原指令；SDL枚举名称仅借[SDL官方events头](https://raw.githubusercontent.com/libsdl-org/SDL/release-3.2.0/include/SDL3/SDL_events.h)
和[window flags头](https://raw.githubusercontent.com/libsdl-org/SDL/release-3.2.0/include/SDL3/SDL_video.h)
核对，不把SDL文档作为Steam策略证据。

0x75cf80–0x75cfac按client+256循环OnThink、player virtual+408 Update，Update
bit0为0才ThreadSleep(1)。client state0退出循环，0x75cf20先Client::Quit。
接着0x75cf24读取player+1785：无输入焦点时设置g_bBackgroundShutdown=1，跳过
显式player Quit和destroy；有焦点则保留原background值。Hard/background真实
GOT relocation分别为0xc80450/0xc80458，指向g_bHardShutdown/
g_bBackgroundShutdown。退出动作如下：

| input focus | background输入 | hard | 显式virtual+416 Quit | virtual+8 destroy | background输出 |
|---|---|---|---|---|---|
| 0 | 任意 | 任意 | 否 | 否 | 1 |
| 1 | 1 | 任意 | 否 | 否 | 1 |
| 1 | 0 | 0 | 是 | 是 | 0 |
| 1 | 0 | 1 | 否 | 是 | 0 |

Player虚调用之后0x75cfc0才StreamShutdownNetworkProcessing，再
SteamDatagramClient_Kill。原CStreamPlayer析构前缀0x7b4944–0x7b4980实际执行
并抵达其Quit调用之后，确认hard跳过显式Quit并不意味着跳过析构内Quit。
§76已独立执行Quit直到CloseAudio之后，证明音频关闭效果；本节不把完整dtor/
UI/renderer/所有线程清理当作已执行。一次与重复关闭的最终音频资源效果一致。

【Native契约】sl_player_owner_decide保留focus/hard/background为独立输入。
窗口focus独立发布，不调用SetForeground，也不产生Pause/Resume。Desktop从
实际SDL键盘焦点window flags初始化，并按FOCUS_GAINED/LOST事件更新；Switch
deko无SDL window，明确以libnx application input focus作平台adapter，发布真实
APP lifecycle边沿时同步owner focus。minimized/restored与其他字段不替代owner
焦点。runtime停止session时先disconnect/join、释放session，再按owner动作收尾
音频player；正常有焦点退出不再只停decoder而遗留stream/jitter。无焦点则保留
尾部，下一prepare或最终media shutdown释放。

本地Switch session使用normal mode（hard/background process mode输入为0）；
Android的全部hard/background产品调用入口、对象移交Java/完整SDL_main返回与后续复用
没有由本节输入矩阵证明；下述hard producer对照只覆盖明确列出的函数/事件。最终NRO shutdown仍无条件释放资源以满足Homebrew ABI，
不能把Android背景对象逃逸搬成返回hbmenu时的资源泄漏。Native只把这段owner
策略投射到音频player，persistent renderer/UI对象没有冒充C++析构的全部效果。

【可执行对照】`audit-steam-player-owner.py`执行原flags读取块、完整focus事件
handler、原post-connect loop/owner分支、真实析构Quit调用前缀。480例覆盖三个
window flag组合位、五种focus事件序列、所有hard/background组合、state0和两组
脚本化phase推进、Update bit0和Sleep路径。Client OnThink/Quit与Player Update/
Quit/destroy、global network stop为声明的终点adapter；它们的wire/内部清理分别
保留既有审计范围，不把脚本状态变更当作完整网络连接。Connecting state1之前的
10秒UI等待、Init失败及全部平台启动/退出入口不在此post-connect边界中。

另8例先真实控制Start→Opus→原CAudioFrame/PutAudioFrame→480帧jitter→Stop，
再执行原owner分支；Quit/dtor音频效果adapter跳到真实CloseAudio，比较Native
生产回调/实际worker/SDL dummy的资源保留或释放、全部既有音频观测值。该adapter
连接两个独立已执行边界，不声称执行了全player Quit/dtor。Native实际runtime
stop_session另以production translation unit测试：真实test session、实际音频worker与
480帧尾部，未启动Base RX线程，Socket send为终点adapter；强制核验生产join调用
→session destroy→owner→device close，不能据此证明真实Socket线程的退出；有焦点且app
lifecycle为background仍关闭，无焦点且app lifecycle为foreground仍保留。最后
media shutdown两者均释放；不替代Switch/Steam/loader验收。

【hard标志producer证据】再执行原`TerminateSession @0x7b9a28`、完整
BHandleEvent中type0x8000/code3，以及完整`ReduceVideoResolution @0x7b9a4c`。
TerminateSession与该事件均在hard=0时先写hard=1再调用Client::Disconnect；已为1
则不重复Disconnect。事件code在SDL_Event+20，尚未证明全部事件投递入口，因此
不能把code3自行命名为某个用户操作。Disconnect在本对照为终点，不重复声称其
wire和内部工作已执行。

ReduceVideoResolution按当前player+1336/+1340的32-bit面积比较：大于
1920×1080时目标1920×1080；否则大于1280×720时目标1280×720；再低则不设置
新尺寸，hard=0时写1并Disconnect，hard已1时不重复。中间两档若config中已有
相同目标就不调用SetStreamingClientConfig；不根据hard跳过降尺寸配置。
46个source-only案例执行边界两侧、hard组合、三个旧config尺寸及低面积宽屏。
原尺寸决策、直接字段读取/写入和调用分支执行；config复制/释放为受控storage
adapter，SetStreamingClientConfig为记录终点，不证明这些case发送的protobuf或
wire。不能由这两个面积门槛推导FEC阈值，也没有据此新增本地自动降尺寸。
这些函数的全部产品caller、hard其他写入和background全部producer仍须分别取证。

```sh
python3 scripts/audit-steam-player-owner.py \
  /data/dl/nsteamlink/build/video-recovery-re/libmain-arm64.so \
  --check scripts/fixtures/steam-player-owner-reference.json
ctest --test-dir build/desktop -R player_owner --output-on-failure
```


## 78. Android decoder失败producer、事件消费与runtime limit配置

【官方客户端证据】同§24.1固定SHA Android1.3.32 core。
`audit-steam-decoder-events.py`执行原Android decoder ctor（JNI初始化为声明终点）、
完整`BUpdateDecoder @0x9079a0`、真实`BGetLowLatencyOptions @0x907b80`、
完整`BUpdateParams @0x907e80`，以及`FinalDecode @0x7b1088`→真实
`CAndroidAccel::BDecodeFrame @0x906570`→完整`BSubmitFrame @0x906660`。
CDummyFrame构造、SetFrame及对应accessors执行；IStreamDataBuffers存储、NAL边界/
参数解析结果、MediaCodec/Format返回值、SDK版本/manufacturer、JNI、OS锁及最终
frame/statistics/DataLost/Disconnect为适配终点。硬件codec没有执行，不能把提交成功
解释为已解码图像。普通H264案例的NAL扫描返回空；PPS案例仅由受控扫描终点返回
固定Annex-B PPS的边界，原参数拼接和BUpdateParams调用/缓存真实执行，未声称
验证了NAL parser或参考帧关系。

【撤回／常数更正】撤回§25.5/25.14把输入dequeue写为200000us/200ms的记录。
`0x9069e0/0x9069e4`及`0x907ec4/0x907ec8`均为低16位0xd090、高16位3，
即0x3d090=250000us；BSubmitFrame和BUpdateParams的SDK终点实收250000。
Texture输出路径首次dequeue的200000us是另一处输入，不能混用。本节不从250ms
直接推导原玩家1–2秒停顿，也不把Android SDK等待值搬成FFmpeg timeout。

【失败分支】下表区分函数内动作与外层动作；SDK错误输入受控，不证明真实设备
会因丢包触发同样的SDK返回值。

| 原始入口／条件 | 直接效果 | 已组合执行的后续 |
|---|---|---|
| BUpdateDecoder stop非零／Format分配NULL | 返回false，不发decoder通知 | 本节从该函数入口验证，完整BCreateDecoder失败处理仍独立 |
| configure最终非零 | 清ms_nLastWidth/Height，NotifyReduceResolution | 原通知投递type0x8000/code2，原BHandleEvent调用ReduceVideoResolution |
| configure成功、start非零 | NotifyFatalDecoderError并false | code3被消费后hard由0置1再Disconnect；已hard不重复 |
| BSubmitFrame input index负值 | 原ResetVideoDecoder(false)，提交false | FinalDecode记录result7并DataLost；真实reset请求字段置1，未执行完整Reset生命周期 |
| BSubmitFrame输入buffer NULL | 原fatal通知、提交false | 先由FinalDecode记录result7/DataLost，后在声明的事件消费边界Disconnect |
| BSubmitFrame queueInputBuffer非零 | 提交false | result7/DataLost；没有额外reset/fatal通知 |
| BSubmitFrame尺寸／Surface变化 | 原ResetVideoDecoder(false)并false | result7/DataLost；本节实际覆盖Surface变化，SPS尺寸解析仍是独立输入边界 |
| BSubmitFrame输入buffer容纳不足 | 原路径以零长度queue，queue成功仍交dummy frame | 仅为异步提交成功，不能称这份输入已经显示；不据此削弱本地资源/有效性检查 |
| BUpdateParams index负值／queue失败 | 返回false，原参数缓存不更新 | PPS组合案例从BSubmitFrame进入，最终result7/DataLost |
| BUpdateParams输入buffer NULL | fatal通知、false | PPS组合案例先result7/DataLost，再按code3消费断开 |
| BUpdateParams容量不足 | 归还零长度输入，false，不更新参数缓存 | PPS组合案例最终result7/DataLost，不冒充后续视频提交成功 |
| Android accel的stopped标志 | 不进入SDK，result7/false | FinalDecode DataLost |
| FinalDecode没有backend | 记录默认result5，ResetVideoDecoder(false) | 不在此直接DataLost；后续HandlePendingResets/Reset仍按各自边界取证 |

【低延迟选项实际触发】helper读取decoder+202、SDL_GetAndroidSDKVersion及缓存的
`ro.product.manufacturer`。BCreateDecoder的0x9075cc先置+202=1；Surface/Texture
准备后0x907704调用JNI boolean，0x907710把结果是否非零写回+202。
BInitJNI的0x907240/250/258把原字符串`shouldEnableLowLatencyOptions`、`()Z`
对应的method ID存到+72，恰为上述JNI调用所用成员。此绑定为原指令/字符串证据；
完整Java方法体和所有BCreateDecoder/展示资源路径没有在本节执行。

正式案例将+202作为受控入口输入，执行真实helper及manufacturer缓存初始化路径，
不再注入helper的布尔结果。覆盖9个SDK值23/24/25/26/27/28/29/30/35与5种
manufacturer输入；持续configure失败的案例实际有1/2/3/5次尝试。+202=0时
helper仍让attempt0后重试一次，不能简化成“关闭低延迟就绝不重试”。各attempt
实际写入的priority、low-latency、vendor选项及顺序保留在fixture；这些是Android
设备参数，不是网络重请求次数或FEC阈值。NDK导入的KEY_MIME/WIDTH/HEIGHT
数据变量由真实ELF relocation核对，字符串值以显式SDK符号label替代；vendor
选项字符串来自原ELF。属性值、SDK及JNI输入仍不是实机观测。

【原事件消费与完整配置】真实NotifyFatal/Reduce/Reset构造事件，原BHandleEvent
消费0x8000的code3/2/1。code1执行ResetVideoDecoder(false)，本节仅从通知函数
显式进入，不把它称为已经找到所有产品caller的错误producer。Notify/SDL_PushEvent
不等于事件已经被UI消费；fixture分别保存before、produced、after-consume。
事件投递失败的受控案例不执行消费；原Notify不检查SDK投递返回值。实际SDL/UI/
线程排程不由该动作边界证明。

ReduceVideoResolution使用player保存的当前尺寸，而非configure失败后已清零的
Android static尺寸。按§77的面积门槛更新**runtime_limit.mode**，不是覆盖用户
quality/display/desired resolution字段。原C++ config ctor/copy、nested mode构造/
修改、SetStreamingClientConfig、protobuf序列化全部执行。相同目标已有时不重复
notify/save/send；改动时先notify、save，client6才发送99，phase5不发送。保留
FEC字段的unset/显式false/true、decoder_limit、字符串与未知tag150。
文件、通知delegate及SendControlMessage是终点；本节比较的是完整config与99
protobuf正文，不将其称为加密/可靠窗口/Socket wire验收。

【可执行范围】247例、741份before/produced/consumed快照；19处选定目标的
全.text直接B/BL及动态重定位、13处常数/Java绑定指令字另存。覆盖SDK失败和成功、
真实helper尝试、PPS嵌套失败、Surface变化、无backend/stopped、hard重复抑制、
未投递事件、phase5与6、7种当前面积/3种旧runtime limit/两种hard/三种FEC presence。
所有案例无Source断言；固定输入完整只读复播。静态扫描不覆盖任意间接调用、
内联/别名写入或其他库/版本，未见直接caller不作为全局不可达证明。

【与Native的边界】本节是官方客户端执行证据扩展，不宣称已经实现上述所有分支。
Native使用FFmpeg/NVTEGRA，仍需分别证明其错误来源、可映射条件、后端重建和
lease/GPU资源顺序；不能把AVERROR统一映射成Android NULL buffer或configure失败。
当前ReportLost与本地身份/资源保护的SubmitError分立；后者直接断开是本地保护，
不是本节证明的“任意backend false都断开”。Android fatal路径仍先有上层DataLost、
后有事件消费，不能把立即disconnect称为同一调度策略。原完整Video factory、
HandlePendingResets/IStreamDecoder Reset、物理输出、平台资源界限和完整UI/owner
继续按独立证据核对，不以这些SDK受控案例替代。没有新加按丢包自动FEC或自动降
分辨率，也没有认定用户停顿、闪烁的根因。

```sh
python3 scripts/audit-steam-decoder-events.py \
  /data/dl/nsteamlink/build/video-recovery-re/libmain-arm64.so \
  --check scripts/fixtures/steam-decoder-events-reference.json
```


## 79. Standalone reset、非空队列与主循环中的处理时机

【官方客户端证据】同§24.1固定SHA core。`audit-steam-decoder-reset.py`从Idle
执行真实IStreamPlayer及CStreamDecoderH264Standalone构造，使用真实重定位虚表。
Base CStreamDecoderVideo的+64/+80/+120分别为0x7b1fb8/0x7b1fbc/0x7b2a68；
standalone对应0x7b0e70/0x7b103c/0x7b124c，不能用base Start的RET替代standalone。
原ResetVideoDecoder、HandlePendingResets、IStreamDecoder Reset/OnStreamStopped、
standalone Stop/Start/Flush及AndroidAccel构造、Flush、Quit、析构实际执行。
CPU/system property、JNI/SDK、线程/OS锁、libc allocator/string/atomic为声明的
平台适配；free记录退休而不unmap。新BCreateDecoder或者执行真实missing-JNI失败
路径，或者使用明确的初始化结果终点；后者返回true不构成真实codec已经工作的证明。

【真实所有权输入】解码输入FIFO经原CStreamFrame ctor/OnReceiveFrame复制、入队，
原始frame随后析构。RTP partial经原DecodeFrame进入linked list；另一组再执行
原OnThink/AppendBuffer，分别形成保留packet引用的数据buffers，或NeedEscape的
28-byte编码缓存。播放器队列经原PutVideoFrame入队。其三个暂存slot为受控输入，
对象使用与BDecodeFrame相同的CDummyFrame构造/SetFrame/SetFormat与CAndroidFrame
vptr/额外字段；不是硬件出队的像素或GPU引用。各队列ID、packet refcount及编码
缓存完整字节、buffers计数、私有状态标量和实际释放终点保留在fixture；释放后的
packet计数取原primitive最后写入记录，不从已退休对象推导Native可解引用。

【实际Reset顺序】请求参数false只置decoder+96，不立即停准入；多次请求可合并。
参数true在置请求后调用OnStreamStopped，立即停准入、按线程flag唤醒/join/purge、
virtual Stop；**不是在该函数内立即执行完整Reset**。以后处理请求仍会Reset。
IStreamDecoder Reset实际先active=0，线程模式下signal→Join(-1)→输入FIFO Purge，
再virtual Stop。Standalone Stop先调用base Stop：FlushVideoStream释放播放器queue
及三个slot，再清linked pending/保留packet/编码buffers，并Flush现有backend；
随后设strict=1、soft=0及请求时间，再Quit/delete backend并清+624。

有旧backend的组合案例确认：解码FIFO、播放器frame、RTP packet引用释放都先于
旧codec delete；旧codec/window/SDL texture各自按原字段清零保护。Texture路径
原Quit/析构的多次DestroyDecoder会多次进入Java texture shutdown终点，但NDK
window/SDL texture只释放一次；最后DeleteGlobalRef。Surface路径依active flag
只发一次Java surface shutdown，JNI全局ref随后释放，Java拥有的window不套用
Texture分支的ANativeWindow_release。JNI调用是终点，不将这些观察外推成Java
方法体或Switch资源生命周期已经验证。

随后Reset清请求、active=1，按standalone真实Start尝试新backend，成功才发
VideoDecoderInfo（原GetInfo/Format产生完整字符串、threads=1）；线程模式下再
尝试Start。HandlePendingResets在其返回后发DataLost(video)。BInit失败仍会清
请求、恢复active/strict等待，backend=NULL，不在此自动Disconnect；线程Start
终点失败亦未使此caller跳过DataLost。原SDK flush/delete错误的受控返回不改变
这些已观察的上层顺序。反复处理已清请求不会重复重建；最终OnStreamStopped仍
清理本次新backend和所有队列。仅覆盖本节受控SDK/线程结果，不提供真实失败时延保证。

【产品调用入口与跨周期顺序】选定目标的全.text直接B/BL/动态重定位审计发现
ResetVideoDecoder的调用来自FinalDecode、OnThink/CheckContentMode、BHandleEvent、
CloseVideo、SetStreamingClientConfig、Android输入和Texture输出包装层。
CloseVideo @0x7c1420/24实际传1；本节未执行其余完整UI关闭路径。
HandlePendingResets没有该范围内的直接B/BL caller，不能因此判为产品不可达：
**真实CStreamClient::OnThink @0x7a5ff8内联了相同处理**，0x7a6058/6070先
处理audio Reset/DataLost，0x7a6084/609c再处理video。之后才在0x7a60c0推进
network、0x7a60c8 transport Update、0x7a60d0消费控制队列；再做decoder think和
phase处理。该OnThink又由§77已核实的SDL_main串流循环调用。

正式案例执行完整OnThink，network/transport/控制消费/phase/log是声明终点，
实际Reset和decoder think保持原指令。控制消费终点注入一次受控请求并尾调用
原ResetVideoDecoder；第一轮只留下request=1，下一轮起点才重建并发DataLost，
然后再进该轮network。它证明顺序/延后机制，不冒充某份消息的完整parser触发链、
socket排程或所有控制生产者都已验证。新请求不能在同一轮控制消费后立即重建。

【对照边界】91例455状态覆盖线程0/1、新backend真实失败及初始化终点false/true、
无旧backend/有旧backend、空/linked/保留packet/编码缓存、非空解码FIFO与播放器
queue/三个held slot、0/1/2次请求与true同步停止、重复drain、线程Start失败、SDK
flush/delete错误、完整Main OnThink两轮时机、Texture/Surface及JNI释放分支。
所有Source案例无断言，完整只读复播。原接收connection/window/FEC没有在本节
引入非空传输状态，不能把本节的decoder FIFO清理扩大为这些状态的等价证明。
原初始化/Java/硬件输出、全部factory和资源边界、实际线程交错及UI返回仍独立。

【Native投射约束】异步reset应由拥有decoder生命周期的actor消费，排除并join
原worker后再释放其依赖，保留连接的接收/反馈所有权，分别清decoder FIFO/partial/
player引用、替换backend、恢复严格等待并请求DataLost。Native epoch/ticket/GPU
lease和renderer mapgroup需要按本地生命周期证明，不能直接复制Android指针释放。
【更正，见§80】撤回“Native尚无整条actor reset”的旧结论。Native actor reset
的契约及本地所有权验证由§80定义；FFmpeg运行时错误与全部SDK producer的映射、
物理解码/显示仍是独立边界，不据SDK错误码猜测AVERROR或添加自动重连/FEC阈值。

```sh
python3 scripts/audit-steam-decoder-reset.py \
  /data/dl/nsteamlink/build/video-recovery-re/libmain-arm64.so \
  --check scripts/fixtures/steam-decoder-reset-reference.json
```

## 80. Video Start的播放器准备、backend状态与恢复入口

【官方客户端证据】同§24.1固定SHA。`audit-steam-video-start.py`经真实控制FIFO、
Frame/Get/protobuf与OnStartVideoData(52)进入真实StartVideoDecoding factory及
H264 standalone ctor/SetUseThreads/尺寸/OnStreamStarted。播放器BStartVideoStream与
新backend BCreateDecoder结果、OS线程、packet refs/libc及最终IO为声明终点。
正式输入证明prepare失败时保留channel映射、重放并消费匹配pending、无decoder；
prepare成功/backend失败时decoder仍active并启动消费线程，不发DecoderInfo；
backend成功才发Info。省略codec使用client协商值+340，显式值不被回退覆盖。
重复Start先stop/join/析构旧decoder再prepare新值，Stop(53)清映射/decoder；重复
Stop无额外效果。完整codec_data保存在原decoder参数buffer，匹配pending按已声明
边界进入实际FIFO。SDK/线程结果不构成真实硬件或物理显示证明。

【对齐契约】Native将播放器prepare与decoder start分开；可恢复的backend不可用
保留decoder actor，完整帧请求异步reset，按§79先于下一轮网络处理消费，join/purge
旧worker、关闭旧epoch/player引用、替换backend、恢复strict等待后请求DataLost。
不把backend不可用等同于播放器准备失败，也不从MediaCodec返回值猜测AVERROR。
FFmpeg/NVTEGRA的配置失败归入本地backend不可用接口；无效身份/尺寸、内存分配
失败仍为明确本地保护。尺寸在player prepare阶段受限，失败保留映射并丢帧；
两个旧domain被picture/map引用占用是backend不可用，释放后可再次初始化，不能
直接断连。平台真实GPU/物理解码与Steam/Switch验收独立。


【正式输入与投射边界】26组52状态执行prepare/backend结果、SetUseThreads两值、
显式H264/省略codec、协商HEVC而Start显式H264的优先级、二进制codec_data、
早到/后续帧、跨channel重复Start、重复Stop、OS Thread Start失败及三种不合法
Start protobuf。每状态确认无Source断言。Native对照执行实际control FIFO/drain、
parser、factory、prepare/start/stop、pending replay，逐状态比较channel/phase/pause/
完整pending和编码FIFO字节、配置/codec_data、prepare参数、Start/Info/Stop顺序。
Native对照的OS视频线程Start固定失败，以观察未消费FIFO；它不是实际调度证明。
Source packet引用仍是借用边界，不取代§79的拥有引用审计。DecoderInfo仅对照
发出条件/顺序，Android字符串与Native平台信息不要求相同。实际覆盖的factory是
H264 standalone；HEVC/AV1/Raw及所有BAvailable分支不得从这些案例外推。

【Native生命周期契约】视频worker只产生原子reset请求，不自行stop/join/recreate。
RX生命周期actor在receiveCycle入口、socket readiness/RX/network/control消费前处理。
旧worker退出并join后，purge complete FIFO，再关闭旧ticket epoch；按§81依次
flush播放器引用、清partial/编码buffers、flush backend、记录恢复mark、退休backend，
随后清请求、打开新epoch、重建backend、启动worker并发DataLost。
旧worker产生的多个请求合并；本轮control drain中实际worker新增的请求留到下一轮。
reset不再次调用player prepare。Backend不可用时仍可接收完整帧，请求后续reset；
等待关键帧的strict/soft语义沿§79。Info发送失败不使已创建backend回滚；OS线程
启动失败保留actor和有界FIFO，直至Stop。取消发生在旧Stop回调中时不再创建新worker。

`test_video_reset_worker.c`经实际control FIFO、tracked组帧、worker及receiveCycle
校验上述顺序、严格等待、请求跨轮、阻塞callback时join、旧FIFO purge、重复drain、
OS启动失败及Stop取消。非空connection RX window和半收FEC组跨reset后可继续完成，
属于Native所有权不变量；§79没有非空connection输入，不能将此标为新的官方等价证明。
`video_reset_runtime.c`使用生产runtime回调表、media和真实FFmpeg图像：受控首次
avcodec_open2失败后恢复；后续submit reset结果是声明的平台输入，不声称这是任何
实际AVERROR的协议映射。真实旧AVFrame/ticket和map lease跨epoch/最终session销毁
保留，两旧domain占用时保持backend不可用，单独释放picture不足以越过map引用，
map释放后初始化可恢复。真实GPU fence、NVTEGRA及物理显示/loader均不在此证明内。

【本地接口保护】可选`prepare`分离player与backend；非零准备结果保留映射/丢帧，
成功后start返回0为ready、1为backend不可用、负值为本地致命保护；reset复用配置
而不重新prepare。无prepare的旧回调保留合并start失败语义，submit-only回调仍可收帧。
无效callback组合、epoch/identity、OOM是本地保护；不冒充官方SDK处理分支。
`sl_video_open_ex`区分保护、不可用、ready；FFmpeg查找/硬件初始化/open的非OOM失败
归于初始化未就绪，OOM保持保护退出。旧bool及本地媒体fixture入口保留原成功约定。
Start空消息拒绝时不得取空buffer指针，和官方Get失败不创建decoder的行为一致。

```sh
python3 scripts/audit-steam-video-start.py \
  /data/dl/nsteamlink/build/video-recovery-re/libmain-arm64.so \
  --check scripts/fixtures/steam-video-start-reference.json
ctest --test-dir build/desktop -R 'video_start_official_vectors|video_reset_worker|video_reset_runtime|nsl-video-pipeline' --output-on-failure
```

## 81. Stop分阶段、backend退休与恢复计时原点

【官方客户端证据】同§24.1固定SHA。`audit-steam-video-stop-phases.py`从§79的
真实构造、非空解码FIFO/player queue/三个held slot、partial与编码buffers进入
原Reset/Stop。原base Stop @0x7b1fbc依次调用player FlushVideoStream、虚表+120
FlushPendingData（standalone继续flush backend），0x7b1fe8写strict=1/soft=0，
0x7b1fec取GetStreamTimestamp、0x7b1ff0保存；返回standalone Stop之后才在
0x7b1060 Quit、0x7b1074析构旧backend。原指令内存写hook确认计时原点在backend
flush之后、旧backend delete之前。旧帧/FIFO/packet引用与编码buffers在delete前
已经清理；SDK/线程/初始化结果、平台存储/引用 primitive边界沿§79。

52例使用SDK flush/delete及新初始化终点的受控tick推进，覆盖两线程flag、
有/无旧backend、新初始化成功/失败、6553/6554边界、组合耗时、linked/编码缓存
以及uint32回绕。它们是受控输入，不是实测SDK耗时。旧backend delete耗6554 tick
时，reset后的首个非关键DecodeFrame按原6553严格比较再次发DataLost；恰6553
不发。flush耗6554单独存在时不产生该重试，因为mark是在flush完成后记录。
新初始化耗时计入mark之后。无旧backend不凭空计入flush/delete耗时。

【Native差异证据及更正】§80生产实现将backend stop和reap合并在stopTracked里，
返回后才DiscardPending并记录mark。相同delete=6554输入，官方mark=1000000、
DataLost计数[1,2]；修改前Native（应用2dc5126、子库42b6a5d）mark=1006554、计数[1,1]（本地baseline日志
`/tmp/nsl-reset81-baseline.json`，正式Source fixture记录输入和原结果）。撤回
§80可将这个合并stop投射视为内部顺序已经对齐的解释。单一固定时钟的§80测试
证明其外层actor/跨轮顺序，不能证明耗时终点之间的计时边界。

【对齐契约】stop由actor在worker join/purge之后执行：先flush播放器所有权，
清协议partial/编码buffers，再flush backend内部引用，然后置strict/soft并记录
恢复mark，最后退休backend。Native可选tracked flush阶段区分Player与Decoder；
既有stopTracked负责最终退休，所有原有回调表需零初始化并同步源码重编译。
本地epoch关闭与GPU map/fence安全引用独立；FFmpeg flush保留调用者AVFrame引用
的API约束来自随工具链安装的libavcodec/avcodec.h，不能作为官方Android策略来源。
真实SDK wall-clock、NVTEGRA/GPU fence/物理显示及全部reset producer仍独立。


【对照与本地资源边界】正式52例逐项比较actual Player/Decoder/mark/retire四阶段
及各自tick、active/backend、strict/soft、恢复mark、后续非关键帧前后的DataLost
计数。Native observer直接包含生产video TU，访问私有字段仅用于观察/断言；真实
组帧、tracked ticket、partial清理、worker join及actor Reset/Stop仍执行生产代码。
Native输入在decoder边界给出，SDK/player/初始化回调为受控终点；不是完整socket
排程或所有producer的证明。原Source非空FIFO、player queue/三个slot及packet引用
的释放在各阶段保留完整观察；这些存储布局不投射为Native像素/GPU引用。

生产runtime回调表连接分阶段media/pipeline：Player关闭准入/释放mailbox持有帧，
Decoder在锁内丢弃scratch和codec内部引用，stopTracked才标记退休并按安全引用数
reap。资源测试记录实际avcodec_flush_buffers、恢复取时、sl_video_stop及可发生的
avcodec_free_context顺序，ready/未就绪分别判断是否进入SDK flush；跨重建与最终
session销毁后持有的AVFrame可见像素MD5保持一致，map lease仍阻止域复用。
调用者/GPU仍拥有的帧按引用及renderer fence退休，不能因复制Android顺序而提前
释放。这是Native平台接口约束；真NVTEGRA/GPU fence仍不在这些离线案例内。

```sh
python3 scripts/audit-steam-video-stop-phases.py \
  /data/dl/nsteamlink/build/video-recovery-re/libmain-arm64.so \
  --check scripts/fixtures/steam-video-stop-phases-reference.json
ctest --test-dir build/desktop -R 'video_stop_phases_official_vectors|video_reset_runtime|video_start_lifetime' --output-on-failure
```

## 82. 首关键片段的backend flush与完整帧提交

【官方客户端证据】同§24.1固定SHA。原DecodeFrame @0x7b20b4–0x7b20c0在
video header bit4到达时调用实际standalone虚表+120；清partial/编码buffers并
flush backend后，0x7b20d0清strict/soft，再加入当前片段。此时不要求FrameFinish。
原OnThink组帧后经FinalDecode→AndroidAccel→BSubmitFrame、真实data-buffer Read
才进入AMediaCodec_queueInputBuffer；后者观察的编码字节与首个AU一致。

`audit-steam-keyframe-flush.py`执行上述原链，129例258状态覆盖有/无backend、
strict/soft四组合、空/linked/packet引用/编码缓存的旧pending、单片/两片/未完成
关键帧被新关键帧替代/重复关键标记，以及受控SDK flush错误。backend缺失的输入
没有预置解码图片；有backend时先将frame 0经同一原DecodeFrame→OnThink→
Android BDecodeFrame链处理，以原CAndroidFrame进入真实player queue；其后关键
标记flush仍保留该旧帧。SDK输出及图像元数据是声明的平台边界，并非真实像素。
SDK、JNI/平台、内存/原子 primitive、NAL元数据与profiling格式终点均明确，不将
SDK入队成功当作物理解码或参考帧解析已经证明。载荷取既有sequential.h264首个
2204-byte AU，ffprobe与实际parser测试交叉确认其边界；完整输入与输出字节均保留。

【Native差异与更正】应用19e6a77/子库58905a7在收到首关键片段时只清协议pending，
backend flush位于完整帧submit。原指令首片段flow为flush，完整帧为flush→decode；
修改前Native首片段无flush/submit，之后才decode（应用pipeline届时才flush）。
撤回可将完整帧submit处的flush视为该触发时机已经与官方一致的解释；§81仅证明
Stop阶段。此次契约将Decoder flush阶段在首关键标记后、协议pending清理完成后
立即分派；该阶段在正常消费时运行于decoder worker，Stop时仍在join后的actor。
它保持player已解码帧、backend对象与epoch，完整帧继续组装并沿原路径提交。

本地FrameFlag FlushHandled只说明Decoder阶段已由回调处理，用于抑制完整帧提交
处的重复flush；它不是wire标志或已重新创建backend的通知。未注册阶段回调的
既有接口保留完整帧keyframe处理约定。真实SDK/GPU输出、其他factory与所有
flush/reset生产者、完整统计及其余原协议范围均需独立证据。


【调用点覆盖边界】对固定binary全.text直接B/BL扫描，base FlushPendingData只有
standalone的0x7b125c一处直接调用；动态符号中选定Video/H264/Standalone共33个
非const方法的虚表slot+120候选为Stop的load/call 0x7b1fdc/0x7b1fe0和首关键标记的
0x7b20bc/0x7b20c0两处。fixture保留扫描范围、指令字节/上下文、重定位和直接引用。
这是该方法集合的调用点证据，不能据此宣布其他类/平台、间接别名及所有reset
producer均已查全；bit6内容模式转换等独立触发也不能从本节bit6=0输入外推。

【Native对照与资源边界】正式129例逐状态比较strict/soft、reset请求、flush时仍未
清除的等待标志、flush/完整submit的先后及完整编码字节，运行实际生产video TU、
组帧与tracked ticket；OS worker在该确定性observer内空闲，不冒充真实调度。初始
strict/soft与旧pending是显式decoder边界输入，linked/packet/encoded存储布局不要求
跨平台一致；非空player的原创建/拥有引用另由Source和真实runtime分别验证。

`video_keyframe_runtime`经实际control parser、生产callback表和decoder线程进入
FFmpeg：首完整关键帧flush/send=1/1，下一关键首半片后2/1，完成后2/2；未完成帧
被新关键帧替代后4/2，完成后4/3；同frame重复关键标记后的完整输入6/4；Stop后
flush=7。整个过程codec只open一次、epoch=1，旧AVFrame跨上述操作和最终session
销毁的可见像素MD5保持一致，map lease仍阻止提前回收。SDL dummy/软件解码测试
不证明NVTEGRA、真实GPU fence、Steam主机互通或Switch物理显示。

Source审计内建五个负向检查：省略关键虚调用、协议purge、SDK flush、等待标志清零
或原AppendBuffer，均必须引起观察差异或原断言。priming已执行过这些地址，内存
补丁后显式失效Unicorn翻译缓存，防止继续执行旧指令。Native额外故意省略首片段
flush、提前清等待、延后purge及遗漏FlushHandled标记，前三项由正式observer检出，
最后一项由真实runtime的重复SDK flush计数检出；负向变体仅在隔离临时编译中运行。

```sh
python3 scripts/audit-steam-keyframe-flush.py \
  /data/dl/nsteamlink/build/video-recovery-re/libmain-arm64.so \
  --check scripts/fixtures/steam-keyframe-flush-reference.json
ctest --test-dir build/desktop -R 'keyframe_flush_official_vectors|video_keyframe_runtime' --output-on-failure
```

## 83. Video bit6模式转换与pending-reset提交门

【官方客户端证据】固定SHA同§24.1。原OnThink先AppendBuffer；只有遇到
FrameFinish才在0x7b2618–0x7b2624提取该**末片段**的bit6。0x7b2648–0x7b26c0
比较video+393/+394的两种已见模式，首次模式仅设置对应字段，同模式不请求重建；
相反模式出现时更新为新模式并实际调用ResetVideoDecoder(false)。随后0x7b26c8/
0x7b26dc/0x7b26f8检查request+96；已有请求即跳过FinalDecode，不提交SDK，也不
进入正常的buffer/packet引用清理。新的顺序连续数据仍经DecodeFrame/OnThink追加，
可保留多帧编码数据；关键标记仍执行§82 purge/flush。下一真实Client::OnThink
开头的原Reset流程才清输入FIFO、player、pending/backend、重启并发DataLost。
+393/+394跨同对象Reset保留，因此新backend同模式的关键帧可正常提交；新decoder
构造从两字段均0开始。bit6的主机侧含义/producer不由这些客户端消费者指令证明，
不得把它命名为缺参考帧、丢包、HDR或桌面模式开关。

【Native差异证据】应用7c3b220/子库af91801无bit6消费，也未在完整提交前检查
pending reset。首帧已建立bit6=0后，下一帧首半片flags=16、末半片flags=72：
官方request=1，flow只有首片flush，末片后2204编码字节保留、无decode；修改前
Native request=0，flow为flush→decode。完整原指令日志`/tmp/nsl-mode83-probe.json`
与实际生产Native observer`/tmp/nsl-mode83-native-baseline.json`支持此差异。
§24旧表“未据此新增重建逻辑”仅描述旧实现，不再据此推导可以忽略这一触发条件；
§80的异步actor生命周期不证明其所有请求producer与提交门已经对齐。

【对齐约束】在完整组帧后按末片bit6更新模式/请求，再检查pending reset；请求
存在时保留编码数据及本地ticket所有权，继续接收连续片段，等待actor或下一关键
标记清理。任何来源的pending reset均适用该提交门，不能只在bit6新请求当帧停止
提交。不得为重建等待添加自行推断的超时或自动FEC阈值。Native固定ticket容量、
内存/OOM与身份保护为本地资源边界，不能冒称官方平台存储上限。


【正式执行与覆盖边界】`audit-steam-video-content-mode.py`运行148例1332状态，
覆盖初始未见/两种已见模式、有/无backend、预先请求、两线程flag、首/末bit6
四组合、有/无关键标记、连续后帧、实际Main OnThink重建、非关键严格等待、
往返模式切换、重建初始化失败，以及actor处理前关键标记purge/重复同frame ID。
有模式历史的旧frame 0由同一原DecodeFrame→OnThink→Android SDK入队链创建；
其player frame与输入packet引用保留/释放都有原观察。成功初始化终点明确安装
codec/window/format存储，让后续真实BSubmitFrame可以执行；不将true返回值冒充
实物decoder。GetBufferCount/GetBuffer执行原函数观察保留的完整字节，不推进Read。
SDK、JNI、NAL元数据、平台primitive、网络/control终点与OS排程均声明边界。

另24例84状态执行导出的CheckContentMode(bool)与实际Main OnThink，记录原两字段
和请求序列；全.text直接B/BL、PLT、动态重定位在该固定库未发现此helper引用，
不能据此认定所有间接/跨库调用均不可达。它们为Source-only helper案例，不据此
给Native新增产品API；实际对齐的入口是原OnThink中已证明的wire末片路径。
Source内建四项反事实：省略模式重建调用、忽略末片bit6、忽略全部pending gate、
请求时提前清编码数据；均改变原结果或触发断言，补丁后失效已翻译指令缓存。

【Native所有权投射】实际video TU逐状态比较strict/soft、request、backend、两模式
字段的等价投射、完整保留编码字节、flush/decode/player/retire/start/info/DataLost
顺序及player帧ID。Native将已拼接帧的ticket引用移交有界deferred表；正常提交或
pending gate后的下帧可各自组装，编码bytes在后者累积。key purge/reset清表与bytes，
同frame ID关键标记保留当前incoming ticket，不能提前将它完成后再复用。observer
另通过真实tracker确认deferred仍未完成，容量案例让256次同ticket追加成功，下一次
触发本地保护并完整销毁。此容量不作为官方限制。省略mode请求、仅门控新请求、
丢弃保留bytes、提前完成ticket、Stop遗忘模式或OR所有片段bit6的隔离变体均检出。

【更正】撤回可将“reset请求未立即停准入”扩展成仍允许后续完整帧提交SDK的解释。
旧§80线程测试在pending时用第二次submit阻塞以验证join，未证明这个提交门。
现实际连续delta被消费而不submit，随后关键片段的Decoder flush仍可运行；测试
阻塞该真实worker阶段，核验actor先join再purge/retire，连接window/FEC仍按原所有权
保留。以上不改变§79/80异步请求与下轮actor时序的证据。

【实际runtime资源验证】既有首关键片段测试追加bit6往返转换，经生产control
parser/decoder线程/callback表和FFmpeg：第一次转换首片flush=7/send=4，末片及后续
delta仍7/4；actor后8/4、epoch2，再来非关键帧不送SDK；同模式关键帧9/5，反向
转换10/5，actor后11/5、epoch3，同模式关键帧12/6，Stop后flush=13。每次epoch只
open一次codec，DataLost只在actor处理后增加，send_packet总接收2204-byte单AU。
旧AVFrame可见像素MD5跨两次重建/最终session销毁保持一致，map lease阻止提前回收。
SDL dummy/软件FFmpeg不证明NVTEGRA、GPU fence、真实Steam/Switch/loader或所有
SDK错误映射；其他reset生产者和bit6主机侧语义仍需各自证据。

```sh
python3 scripts/audit-steam-video-content-mode.py \
  /data/dl/nsteamlink/build/video-recovery-re/libmain-arm64.so \
  --check scripts/fixtures/steam-video-content-mode-reference.json
ctest --test-dir build/desktop -R 'video_content_mode|video_keyframe_runtime|video_reset_worker' --output-on-failure
```


【旧矩阵引用更正】§25.14的关键帧flush、backend重建、客户端outgoing与FEC行改为
指向各自后续执行证据；撤回这些行仍代表初次接收恢复移植边界就是当前实现边界的
解释。具体case/adapter/未证明范围以各节原证据为准，不能将表内引用合并成完整
协议或全平台已经等价的声明。

## 84. Video bit5解密返回值、padding与空明文

【官方客户端证据】固定SHA同§24.1。DecodeFrame在准入后@0x7b2174–0x7b21ac
只在key标记上按bit5变化调用protected-content虚表并记录video+395；每个bit5片段
仍各自解密。H264 standalone两slot转发至CAndroidAccel继承的IVideoAccel方法，
@0x9090c4/0x9090c8均为原ret；这个Android factory没有实际保护内容切换操作，
不能据此扩展到其他factory/平台。实际crypto调用@0x7b223c，零IV、key长度取client
字段，caller栈传verifyPadding=true；返回后直接读取out length并调用原frame Resize，
**未检查bool返回值，不因此请求DataLost/严格等待/reset**，随后继续原partial/OnThink。

CCrypto::SymmetricDecryptWithIV @0x747640实际执行软件AES key schedule @0xaae31c、
AES decrypt @0xaae894和CBC/padding @0x746f28；没有用替身生成解密结果。
初始检查要求至少16字节且为整块，输出容量先与cipher length−16比较。前缀块直接
写输出，末块暂存；verify=true检查pad在1..16且每个padding byte一致。错误时长度
不更新、末块不写输出，所以in-place会留下已解密前缀和原末块密文；短/非整块
输入不改bytes。成功时按容量复制末块全部或仅非pad部分，容量有余则在明文后写NUL。

【Native差异与更正】应用c841a14/子库58e006d在解密错误时立即DataLost并strict=1，
与原caller无此分支不同。其通用CBC helper先覆盖末块再检查padding，允许pad=0，
且要求输出容量至少cipher length而非能容纳实际明文即可。32-byte cipher解出末字节
0时，官方返回false且长度32/末块密文保留；旧Native返回成功。坏pad非一致时，
原视频caller仍提交变换后的bytes并保持strict=0。探索原日志`/tmp/nsl-crypto84-probe.json`
记录这些原结果；不能把原先额外的strict请求描述为官方的解密错误策略。

【空明文与平台边界】16-byte合法全padding密文得到0-byte明文，原DecodeFrame/
OnThink/FinalDecode至SDK入队均无断言、无自动DataLost/reset，之后可继续收帧；
NeedEscape而无NeedStart也允许0-byte数据。NeedStart+NeedEscape的空内容触发原assert
line60；空密文本身触发原assert585/590，这些为独立source-only前置条件失败证据，
不能复制越界/断言后继续执行的字节作为正常协议要求。Native保留相应有界保护。
FFmpeg对NULL-data/zero-size packet定义为drain/EOF，平台不得把合法空明文当作flush/EOS或致命错误；
本地空输入按已验证身份/有效backend消费，无像素输出/ticket不被backend接管，
保留decode begin/end与pending metadata，交既有endpoint过期/epoch关闭退休，
不伪造即时corrupt结局。这个平台映射不声称已证明Android物理输出/最终统计结果。

【对齐约束】video使用原地等价的拥有buffer拷贝，执行实际CBC helper，按原caller
使用out length及输出bytes，解密返回错误不另造请求/严格等待。通用CBC的分块写入、
pad1..16验证、输出容量与末块复制/NUL行为按原指令对照。Zero-size raw组帧合法；
空NeedStart仍受保护。配对授权码与connect/security PIN含义和认证流程均不受影响。


【正式对照与前置条件】`audit-steam-video-crypto.py`固定272个helper输入，覆盖
AES128/256、零/非零IV、in-place/独立输出、pad1..16、pad0/17/255、不一致padding、
短/非整块输入、合法全padding及小于cipher length但可容纳实际明文的容量边界。
比较bool、out length、整个输出/输入变换窗口与guard bytes；原软件AES key schedule/
block decrypt执行次数也保留，不用本地实现生成期望值。另52组240状态经过原帧ctor/
DecodeFrame/原CCrypto及AES/原Frame Resize/OnThink/FinalDecode/BSubmitFrame直至SDK
入队，保留真实输入字节、player引用、strict/soft、mode、请求、SDK/生命周期顺序；
覆盖key16/32、backend有无、已pending请求、正常/坏pad/短数据/空明文、独立加密
分片与明密混合分片、reset后恢复。SDK/JNI/NAL metadata/平台primitive/OS排程沿
§83，不能据SDK终点成功外推物理解码。另4个输入保留原assert，作为Source-only
前置条件失败证据；不投射其断言后不确定数据。会话认证输入保持既有语义。

正式Native observer运行实际mbedTLS、生产video TU/组帧/tracker/actor，逐字节比较
272组helper及52组240状态；后端/player仅记录接口终点，protected字段/空Android
方法调用保留Source证据而不凭空新增Native产品API。原地解密发生在拥有buffer拷贝
上，原接收header/密文输入不被破坏。`/tmp/nsl-crypto84-native-baseline.json`记录
修改前pad0成功与坏pad strict1两项实际反例，Source对应false/strict0。

【负向与本地资源验证】Source四种原指令补丁：跳过padding校验、略过成功NUL、
略过视频crypto调用或frame Resize均被拒绝，补丁后失效已翻译缓存。Native隔离
变体恢复pad0、过早写末块、拒绝可容纳明文的较小输出、恢复解密strict等待、拒绝
合法空组帧，均不能通过同一官方向量；伪造空帧corrupt或将其映射为FFmpeg EOF由
真实runtime检出。变体只在临时编译/库副本中运行。

真实runtime控制parser/worker/callback/mbedTLS/FFmpeg测试在§83往返重建后继续
接收AES-CBC 2208-byte密文，SDK实际接收2204-byte首AU并产生图像；再接合法全
padding的raw及NeedEscape片段，保持decoder、无额外DataLost/退出/EOF；下一真实
关键帧仍出图。新增4个关键标记后flush=16/send=8，Stop后flush=17；epoch保持3，
旧AVFrame像素MD5及map lease跨所有操作和最终session销毁不变。空输入记录decode
begin/end，tracker保留pending元数据，实际callback拦截确认未生成即时corrupt结局；
过期仅退休本地资源，不自行制造协议Complete。空输入的Android真实输出/最终统计、
FFmpeg实际错误码/硬件映射、其他factory/所有producer仍需独立证据。

```sh
python3 scripts/audit-steam-video-crypto.py \
  /data/dl/nsteamlink/build/video-recovery-re/libmain-arm64.so \
  --check scripts/fixtures/steam-video-crypto-reference.json
ctest --test-dir build/desktop -R 'video_crypto_official_vectors|video_keyframe_runtime|^crypto$' --output-on-failure
```

## 85. NAL起始前缀、跨片转义与历史字节边界

【官方客户端证据】固定SHA同§24.1。CStreamDecoderH264::AppendBuffer
@0x7b09d0处理H264 standalone的NAL拼接；NeedEscape=0直接保留packet引用，bit0
不另造前缀。NeedEscape=1时，若NeedStart=1，@0x7b0b00–0x7b0b64先写四字节
`00000001`，再原样复制本片最多**前三字节**；余下部分才送实际CopyAndEscapeNAL。
没有NeedStart时整片都进入转义器，不能每片跳过前两字节。

原scalar @0x8029f0与SIMD名义版本@0x802a3c在该ARM64库均为相同循环：当当前
byte<=3时实际读取已写输出[-2]/[-1]，两者均0则先插入03，再写当前byte。因此
输出历史跨片保留，已经插入的03也参加后续历史。构造@0x7b0984–0x7b09a4按
GetCPUInformation.flags+4的bit0x10选择虚表实例字段+608：0为scalar，1为SIMD；
这是系统CPU输入，不是网络/FEC或硬件decoder选择。两例路径均执行原函数体。

【实际差异】应用d095563/子库6d5d25a每片先原样复制前两字节，再从该片第三字节
开始查找零序列，丢失跨片历史。真实原DecodeFrame/OnThink输入：key首片flags19、
bytes `650000`；末片flags10、bytes `0102`。官方SDK输入
`00000001650000030102`，旧Native为`000000016500000102`，原路径无assert且所有
历史读取均位于已写encoded buffer内。相同模式对多个零序列和不同片长均可触发。
起始标记下复制最多前三字节的差异也有完整原输出，不用NAL规范推测代替原指令。

【前述探针边界澄清】先前fresh buffer直接NeedEscape续片`000001`的单片探针
没有assert，却会读取encoded allocation之前的两个字节；模拟器中的初始零值不
构成协议规定。撤回可把该初始值解释为固定“两个零历史”的推论。正式对照对每个
实际历史读取检查地址，区分拥有的上下文与Source-only缺失历史；跨片反例不依赖
这些外部字节。新NeedStart保证有效前缀；无起始且历史不足/输出依赖未知前缀时
Native采用有界保护，不复制Source越界读取。空NeedStart沿§84保留保护。

【编码存储前置条件】NeedEscape片段到达时已有raw packet buffers，原@0x7b0a14
触发assert82；非空encoded bytes再混入raw并结束帧时，原OnThink触发assert191。
这些不是可任意混拼的两种存储。Native按raw-buffer存在/encoded byte数维护同一
有效域，完整提交或key/actor purge清除，pending-reset保留；非法混合保留本地保护。
空encoded不凭空算非空encoded，空raw packet仍是一个raw拥有引用。断言后继续
执行的Source数据不作正常码流契约。

【HEVC与工厂边界】相同原standalone构造参数codec=5也执行该AppendBuffer。
原StartVideoData控制handler在显式codec5、声明的AMediaCodec_createDecoderByType
("video/hevc") capability非空终点下实际创建同一H264Standalone虚表类；此为SDK
能力输入，不证明物理HEVC支持。Native H264/HEVC byte formatter共用这套已核实
拼接规则；Switch仍只声明已接线H264。SDK不支持时的完整外层UI/其他factory与
物理codec输出仍各自独立。

【可复验的执行范围】`audit-steam-video-nal.py`固定192例444状态，覆盖codec4/5、
CPU bit0x10两值、首片1/2/3-byte直拷、续片空/短/多零序列、raw忽略bit0、完成提交
与pending-reset保留、key与actor purge、每片独立CBC解密后再拼接。每次真实helper
历史读取记录地址，正常组要求无原assert、无encoded allocation之前读取；16组原
断言/缺历史输入另列source_only。constructor、AppendBuffer和两个escape函数完整
原指令随fixture保留，三项原指令反事实（scalar/SIMD分别去插03、起始只直拷两字节）
必须仍在有效拥有上下文执行、实际SDK bytes改变才算检出；修改已翻译指令后清缓存，
不把harness异常当成功。HEVC正能力factory执行证据单列，SDK不可用外层UI没有闭合。

同一真实2204-byte H264 AU拆成四个NAL共八片，含一个实际跨片零序列，去除已有
emulation prevention后按原NeedStart/NeedEscape重组。原SDK收到2206 bytes（原两个
三字节start code改写为四字节），明文/逐片CBC与两种CPU选择共四例均完整字节相同。
Native实际生产video TU、tracker、reset actor、mbedTLS与callback终点逐状态/完整
bytes一致。独立本地guard核对空NeedStart、缺历史、零字节raw引用、非空encoded
后raw与容量边界；这些保护不构成新的peer恢复算法。

真实应用parser/worker/生产callbacks/FFmpeg也接收同一八片明文和逐片CBC数据，
每次送2206-byte AU，均输出128x72图片，可见像素MD5与原2204-byte AU解码一致；
旧图片/map lease跨flush/重建保留。此证明软件管线可消费该有界fixture，不是物理
Android/Switch输出、所有slice grammar或实际Steam host分片producer证明。Native
隔离反事实分别遗忘跨片suffix、只直拷两字节、丢失空raw引用、允许encoded后raw，
均被完整字节/guard对照检出，未改生产文件或原golden。既有mode/crypto/reset/start
原golden仍按默认H264输入独立核对，不由新NAL规则重写旧期望。

复验命令（官方库路径由本地合法取得的固定SHA二进制替换）：

```sh
python3 scripts/audit-steam-video-nal.py /path/libmain-arm64.so \
  --check scripts/fixtures/steam-video-nal-reference.json
python3 scripts/check-steam-video-nal.py \
  --receiver build/desktop/third_party/ihslib/tests/session/ihs-video-nal-oracle
ctest --test-dir build/desktop --output-on-failure \
  -R '^(video_nal_official_vectors|video_keyframe_runtime)$'
```

【结论边界】正常NAL字节转换按以上原客户端执行策略实现；缺历史/原assert域以
本地有界检查处理，不复制越界读取。没有由此增加等待关键帧、FEC阈值或重发计时。
发现的字节差异尚不证明用户一两秒停顿/菜单闪烁根因；bit0/1主机producer、bit6
主机含义、其余decoder factory、完整平台错误映射各需独立官方证据。

## 86. 分片范围连续性、bit2与结束片段身份

【官方客户端证据】固定core SHA同§24.1。原DecodeFrame @0x7b2274/227c从视频
header偏移3/5读两个LE16值，并在partial节点+12/+16以32位保存；入队扫描
@0x7b22c4–22dc只在frame ID相同且incoming.end < existing.start时插前，否则
继续向后。因此这是严格小于，不是按sequence重新排序或去重，也不跨frame ID排序。

原OnThink @0x7b2540–256c：end=0直接绕过范围检查及推进；end!=0要求
start等于decoder+420的32位next值，不等则保留头节点、退出本轮，不在这个分支
设置strict/请求DataLost。匹配且bit2=1时，FrameFinish=1写next=0，否则写
end+1；bit2=0保持next，含FrameFinish=1也不凭空清零。因此65535+1保存为65536，
不是LE16回绕。原FlushPendingData清零next，普通提交不统一清零此字段。

原OnThink @0x7b258c/2594、261c/2620从**结束片段**取得frame ID/timestamp，
@0x7b2744/2748将它们传FinalDecode；在这些原组帧指令里没有“中途frame ID变化
就strict丢弃”的条件。完整实际输入：key首片frame1/seq1/flags16/range0,0/`41`，
末片frame2/seq2/flags8/range0,0/`42`，原SDK收到`4142`，提交ID为2，strict=0、
无DataLost、无原assert。该例证明decoder边界行为，不证明任意Host正常产生它。

【差异与更正】子库9824e01的next为uint16，65535边界会错误回到0；同一组帧
还强制所有partial的frame ID/ticket必须等于第一片，否则DiscardPending并严格
等待/请求DataLost。撤回将这条wire frame ID一致性要求视作官方组帧准入策略的
含义；旧test_video_tracked中“ID变化不得完成组帧”的断言同样撤回，
该用例现检查完整`xy`提交至结束ID及相应ticket。epoch/resource身份保护仍有独立意义，不能据此改变原片段拼接条件。正确
投射须保留当前epoch，并在完整提交采用结束片段的tracked ticket；不能把由不同
片段ID贡献的字节丢弃或将完成错误地记在第一片ID。

【执行循环边界】原IStreamDecoder::RunDecodeLoop @0x766d50–766e60实际先排空
input FIFO，再调用虚OnThink，将原返回值送CThreadSyncObject::Wait：-1是idle
等待输入，0是pending-reset返回，1是在尚有partial时短等后再循环。本审计将OS
Wait作为有界排程终点，可继续wait1循环；wait0/-1结束本轮观察并保留对象供后续
动作。记录原Wait参数，不把受控终点解释为真实线程延迟/唤醒或物理显示证明。

【执行向量与反事实】`audit-steam-video-subframe.py`固定160例544状态，涵盖
codec4/5、有/无backend、end0/1/65535、bit2/FrameFinish组合、非匹配范围保留、
同ID反序修复/等边界不插前、跨ID不排序、结束不带bit2的next继承、wire sequence
回绕/缺口、key/actor purge、pending-reset、逐片CBC与真实AU。每状态记录完整
partial顺序/header/bytes、32位next、sequence、严格/软等待、backend/mode/request、
完整SDK输入/提交ID/player引用和反馈有序列表；20份148正文由原generated protobuf
序列化后与Native完整wire比较。未用观察者公式生成范围/排序/反馈期望。

queued_finishes案例先在同ID范围2..3排入结束片，再排入另一ID的结束片；最后
0..1的bit2片插前补齐范围，原RunDecodeLoop先提交第一个ID的完整`4142`，实际
Wait(1)后再提交第二个ID的`43`。idle时Wait(UINT_MAX)、请求挂起时Wait(0)也实际
执行并保留参数。Native对照在动作边界排空有界工作，只证明列表/状态/顺序相同；
没有声称其OS条件变量和官方Wait毫秒排程、线程竞争或真实帧间时序等价。

六项原指令反事实分别截断32位next、跳过范围比较、等边界也插前、改用第一片ID、
忽略bit2、强制检查end0。均清除翻译缓存后实际执行，无原assert/harness异常，
必须观察到真实状态/partial/SDK数据变化才算检出。Native六项隔离变体分别恢复
16位next/首ID veto/第一片ticket、所有结束清next、等边界插前与检查end0，均被
实际生产TU对照或提交ticket身份断言检出，不改生产文件/golden。

【Native拥有引用】wire ID变化本身不再丢字节/请求strict。完整提交时先retain结束
片ticket，再release先前assembly ticket，使用结束片ID和同一epoch；此前贡献者
没有SDK提交，不伪造decode/corrupt完成，metadata按既有有界settlement/epoch规则
收尾。pending-reset仍保留待清理的完整frame tickets；key/actor及Stop负责清理。
原统计的全部最终结果/评分/跨记录生命周期仍有独立范围，不由这些本地ticket
断言外推。矩阵timestamp固定，原结束片timestamp参数的选择有原指令证据，但非
一致timestamp及完整音视频同步尚不由本对照证明。

真实应用parser/worker/callback/mbedTLS/FFmpeg用四片范围0..1/2..3/4..5/6..7
接收同一2204-byte H264 AU，前两片ID与后两片ID不同；明文和逐片CBC均出128x72
图片，pixel MD5与原AU一致。输出ticket实际属于结束片ID，前ID仍pending且无
decode begin/end，结束ID有真实decode阶段；无额外DataLost/epoch重建。旧AVFrame
像素和map lease继续跨flush/重建/session销毁有效。这是软件fixture与拥有引用验证，
不是任意Host分片可达、Android/Switch硬件输出、同步或用户原故障归因证明。

复验：

```sh
python3 scripts/audit-steam-video-subframe.py /path/libmain-arm64.so \
  --check scripts/fixtures/steam-video-subframe-reference.json
python3 scripts/check-steam-video-subframe.py \
  --receiver build/desktop/third_party/ihslib/tests/session/ihs-video-subframe-oracle
ctest --test-dir build/desktop --output-on-failure \
  -R '^(video_subframe_official_vectors|video_keyframe_runtime)$'
```

## 87. 视频媒体时间戳、jitter准入与已到期帧选择

【官方客户端证据】固定core SHA同§24.1。§86末片的ID与timestamp分别经
OnThink @0x7b261c/2620、FinalDecode @0x7b1088传到Android SDK输入与真实
CAndroidFrame。时间戳探索例中，末片time1002000原样保存在player队列frame+32，
SDK presentationTimeUs为15289307。frame1/time1000000贡献字节、frame2首片
/time1001000、frame2末片/time1002000均无原assert。此为decoder边界的实际输入，
不证明Host正常生成同ID不同timestamp的分片。

【字段语义澄清】Native `receive.senderFrameTimestamp`是tracker首次接收记录；
不能因它保留1001000就直接把它改为1002000并称统计已对齐。RX统计与decoder
媒体时间戳是两个消费位置。正确的播放接线须另携带末片媒体时间戳，且在解码输出
envelope上快照；不可用可复用ticket的后续字段覆盖先前已发布图片的metadata。
§70已证明正常RX先按缓存offset归一化再进入video消费者；直接decoder输入的
raw时间戳也只归一化一次。两种路径均保持原packet/body不变。

【实际准入生产者】IStreamPlayer构造 @0x767734–773c在player+296构造
CFrameJitterTracker("Video",60)。PutVideoFrame @0x767dc8–7dec从真实frame虚表
取媒体timestamp，并取当前GetStreamTimestamp，调用原Update。原Update
@0x76678c先查BShouldUseVideoSurface；true直接返回。否则按32位回绕有符号差
将now-frame转为float32毫秒：负值忽略，>150ms清当前样本批次与计数，保留旧budget。
每60个有效样本实际Calculate得到mean/stddev，budget=trunc(mean+2*stddev)；已有
非零budget时再按带符号整数除二截断平滑。清样本后继续下一批，不要求先丢包。

BReady @0x7668d8在budget=0时直接true；否则比较float32帧龄>=整数budget。
GetCurrentWait @0x766974在budget=0时返回0，否则max(budget-trunc(age_ms),0)。
两者都使用媒体时间戳、当前stream clock与32位回绕。原GetVideoWait
@0x767e64、GetAvailableVideoFrame @0x767f1c将FIFO头保留在player+272，再按该
帧时间戳检查jitter；头尚未ready不会跨过它选后面的帧。GetNextVideoFrame
@0x767fe0与BGetNextVideoFrame @0x76817c反复取得已ready帧，较旧ready帧以
result6释放，保留最新ready帧。未ready的后继仍保留，不能一律在发布时替换旧帧。

FlushVideoStream @0x7681ec–82d0清FIFO和三个held slot，未重置player+296的
jitter样本/budget；同一player的decoder重建应保留。新player构造从0开始。IHSlib
tracked ticket/epoch、FFmpeg/GPU所有权仍是平台资源约束，不能复制Android引用布局。

【Surface开关的产品条件】原BShouldUseVideoSurface @0x909ea4–9ff4首次读取
SDL_IsTV与ro.product.manufacturer/model，拼接"manufacturer model"后：精确
"Amlogic X96-W"、"Google Chromecast"禁用；以"Oculus Quest"或"Pico "开头
启用；其他保留SDL_IsTV。结果缓存。此为Android平台/设备分支，不是FEC、丢包或
解码器错误的动态开关。Native FFmpeg/texture/import路径没有Android VideoSurface
能力，按非Surface播放路径核对；不能把“硬件解码/zero-copy”本身等同于该开关。

【已有差异与本地界限】旧Native发布时只保留最新图片，并以本地解码输出时间和
自有adaptive pacer决策；没有上述媒体时间戳jitter准入。Source自然运行60个约10ms
帧龄的图片得到budget9，随后帧龄0的图片GetVideoWait=9、GetAvailable返回null；
不是每一张解码输出都立即可绘。Native采用20个lease与两个domain/map/fence保护作为明确资源界限。原固定6个lease
在新jitter准入下不够覆盖合法高budget：60个[0,150]ms样本的mean+2*sample_stddev
严格小于244ms，按已声明最大60fps需15个排队帧，加candidate/current、两GPU批次
与一次发布交接得到20。更小壳数会在帧到期前反复淘汰它们，不能冒称已对齐。
此调整扩大预分配AVFrame/envelope壳预算至20+2 scratch，不改变renderer自分配
96MiB、导入backing128MiB与map组等既有独立约束；真实codec pool/显存仍独立验证。
资源预算触发的淘汰/失败不冒称原无界队列策略。OS/GPU
实际等待、完整CStreamPlayer渲染/UI、音频同步和Host完整producer仍各有独立范围。

【SDK输入与输出的时序纠正】PutVideoFrame中的CAndroidFrame是已接受输入的frame job，
并不是已取得物理像素的证明。原Android BDecodeFrame @0x906570与BSubmitFrame
@0x906660执行SDK queueInputBuffer后建job并入player；解码输出映射由另一消费位置负责。
原OnThink @0x7b2720–2734记录event14，FinalDecode返回后@0x7b2754–2768记录event15。
因此撤回“在Native publish得到像素后采样jitter/记decodeEnd即可等价”的判断：
两者会把后端输出延迟混入输入抖动/提交耗时；无输出的已接受输入也会漏采样。
Native在成功send_packet后、receive_frame前采样并结束提交计时；protocol提交范围负责
开始计时与失败/无backend的结束兜底。同一次调用只记录一次结束，后续输出不覆盖它。
物理输出耗时仍保留在本地frame诊断字段，不混入此协议提交计时。

固定时钟对照将SDK输入接受推进65 ticks，Native输出另推进650 ticks：原event14/15
实际分别在1000000/1000065；Native实际runtime→worker→FFmpeg在相同阶段结束。
对照逐步检查原RecordFrameEvent调用的ID/14/15/受控stream clock；这证明调用位置与
本例先后顺序，不证明完整Stats报文或物理NDK输出/空job映射等价。原frame job序列
与Native有像素的完成序列仅在所列非空AU用例投影比较；空AU仅比输入采样/提交事件，
Native不生成伪图片。完整AVsync/UI、物理codec错误/延迟与全部统计消费者均有独立边界。

【可复现对照】`scripts/audit-steam-video-timing.py CORE --check
scripts/fixtures/steam-video-timing-reference.json.gz`执行固定SHA原构造、DecodeFrame、
OnThink/FinalDecode、Android SDK提交、jitter/stat与player选择/flush原函数：15组1659状态，
另18组真实Surface条件/缓存、1个空输入采样/提交事件投影。静态保留15个完整原函数。
SDK接受/平台属性/时钟/渲染机会作为明确终点；不是把Native算法当作官方期望值。
`video_timing_official_vectors`将同一动作交给实际controlStart/Stop、parser、worker、
生产callback与FFmpeg，核对完整媒体ID/time、样本float bits/budget、队列、等待、选帧、
实际提交事件，像素逐张比独立framemd5。原VideoFrameComplete产生的缺ID result3等
完整调用另保存在fixture，当前Native完成比较只投影已知非空图片的result1/6。

八项Source反事实须执行原分支且实际改变状态/SDK或选择，不能以原assert/harness异常充数。
十三项Native隔离变体覆盖错误RX/末片timestamp、stddev/负样本/outlier/平滑、直接ready/
wait0、每epoch清样本、发布即替换、输出后采样、输出后结束计时与六lease资源界限。
高budget连续20帧场景实际观察到六lease变体选帧结果不同；正式20lease保留到期画面。
资源用例还持有旧图片与map跨actor重建/Stop/session销毁/IHS_Quit释放，核对同player
budget保留及所有域最终回收。重排输出另将submit后ticket时间戳污染为0xdeadbeef，
证明每个packet/output快照独立；这不证明Android帧job映射与FFmpeg B帧重排消费等价。

## 88. Android输入任务到SDK输出：texture与VideoSurface消费边界

【官方客户端证据】固定Android 1.3.32 core及SHA同§24.1。实际
CAndroidAccel::RenderFrame @0x906d40先检查全局禁用位/codec句柄，再按
BShouldUseVideoSurface转到texture @0x908e04或VideoSurface @0x908494；
CAndroidVideoDecoder::BRenderFrame @0x906e34另有同类dispatcher。同用MediaCodec
不等于同一套输出消费规则。固定输入经原DecodeFrame/OnThink/FinalDecode、
BSubmitFrame与player选择创建真实CAndroidFrame；NDK输出index/PTS/status/format
作为显式平台输入。SDK/JNI/SDL输出终点不冒称已取得Android物理像素。

### 88.1 texture的PTS匹配、等待、复用与失败

原frame+32是媒体16.16时间戳，frame+40是BSubmitFrame实际传给SDK的presentationTimeUs；
后者在@0x906aec–6b6c按float32增量生成并缓存，不可假定与Native的receiveSerial PTS
数值相同。texture比较frame+40与decoder+192（上次**请求**的PTS）：

| 触发条件 | 实际原分支/结果 |
| --- | --- |
| 请求PTS不大于缓存值 | @0x908e38–e40跳过SDK取输出，继续画既有texture；首次PTS=0、重复/回退PTS亦受此guard约束 |
| 请求PTS更大 | 先@0x908e70写缓存，再取SDK输出；失败也已更新缓存 |
| SDK取得目标PTS | @0x908e80–ecc停止取更多buffer，以render=true释放该index、JNI更新texture后绘制 |
| SDK取得其他PTS，后面还有buffer | @0x908e90–ec0以零等待再取；先前index以render=false释放；重复比较目标PTS |
| SDK取得其他PTS，再取返回-1 | @0x908ea0–ecc使用最后取得的index，render=true；没有再对这个实际输出做媒体jitter准入 |
| 初次/重试取buffer的status为负 | 前五个负status交给原BHandleOutputBuffer；成功处理后重试，每次传250000us，合计最多六个这样的等待请求；末次仍无数据的域见§88.3 |
| release/status处理失败 | @0x90906c–9084请求ResetVideoDecoder(false)，本例video请求位变1；之后由既有主循环消费 |

BHandleOutputBuffer @0x9080c4–8490的原分支：index>=0调用NDK release（按render与时间参数
选普通/AtTime）；status=-1调用AMediaCodec_flush并返回true，未按flush返回值改结果；
-2读取/应用output format并释放format；-3记录buffer变化后返回true；其他负status或release
失败返回false。这些是该NDK API边界上的实际调用，不能机械地把FFmpeg的AVERROR(EAGAIN)
当作相同的250000us超时。所用Switch/desktop avcodec.h的receive_frame注释明确其EAGAIN
表示当前无输出、需再送输入；Native receive_frames也在该条件退出本次drain。
六个250000us是传入SDK的等待额度，不能据此认定实际必停1.5s，更不能认定原用户Switch
停顿就是这条Android分支造成。

### 88.2 VideoSurface的映射、统计与148触发

原VideoSurface每次传timeout=0，按SDK PTS查BSubmitFrame建立的PTS→输入ID map；
BGetFrameFromTimestamp @0x908934、DropFramesBefore @0x9089d0与
BMarkFrameCompleteForTimestamp @0x908d48实际执行。对取到的输出，先移除更早的map
条目并以result4回报；已选输出按真正render与release结果回报result1/4/5。该map和反馈
不是texture分支的共有规则，不能因Switch也用硬件解码便直接套用。

已知映射、非目标PTS且比上次输出新时，@0x9085d8–8658比较16位ID差与PTS差：
ID差<=4且时间差<35000us允许落后的输出，并在恢复时清decoder+201 latch。
超过任一边界时，实际GetFrameStats查询进一步分流：对应帧result为0/1仍可使用；
统计不存在或result>=2则进入落后恢复分支。原RecordFrameReceived/RecordFrameComplete
创建及完成的真实统计记录分别覆盖0..8，查询非空、ID和result逐次断言，未以假返回值代替。
首次进入该恢复分支执行@0x90873c–8750或@0x90883c–8850：调用官方反馈函数，实际生成
148 CStreamVideoOverflowMsg，完整原protobuf正文为`08001000`（first/last均0），并置
latch=1、移除/丢弃对应输出。持续落后时latch抑制重复反馈；重新进入较近输出后清latch，
后续再落后可再次反馈。这是VideoOverflow生产者证据，不是FEC开关或其启用参数的证据。
完整Host对该反馈的反应仍不能仅凭客户端发送端推定。

### 88.3 SDK未提供BufferInfo的Source-only域

SDK负status输入不写BufferInfo，保留显式种下的旧栈内容。texture六次均无输出后
@0x908e80仍读取该槽PTS；两种栈种子可改变后续零等待调用数。Surface对首次-2/未知负值
也可能在@0x908568等处读取本次未由成功SDK返回提供的PTS。fixture逐次记录
unsupplied_info_reads，把这些观察单列为栈内容相关的Source-only域；不能以模拟器初始零、
旧栈值或这些域中的绘制调用作为确定的跨平台策略。成功取到目标/其他输出的主要对照
没有这种未提供数据读取。也未把SDL/JNI调用等同于物理新画面显示。

### 88.4 Native投影差异与可复现基线

【纠正】§87按输出envelope做jitter FIFO比较，仅证明所列一输入一输出用例中的投影；
不能当成完整官方texture输出消费等价证明。原选择对象是输入任务，实际SDK输出还可
另选。正式输出适配需要分别表达输入任务、实际像素/PTS、等待与复用，以及上层完成结果
的归属；仅移动采样点或扩大像素FIFO不足以证明这些语义一致。原采样和提交结束时机的
独立证据仍见§87；完整CStreamPlayer::BUpdateVideo/呈现完成调用者有独立验证范围。

固定budget10ms、now1000000：输入1媒体time998689已到期，输入2媒体time1001311未到期。
原player选择任务1、保留任务2；SDK只提供输入2对应PTS15278794，再返回-1，原texture
仍以render=true交付该index并绘制。Native产品基线87d99be在相同输入/输出可用性边界中，
真实parser/worker/FFmpeg的第一个实际输出被平台适配器抑制，第二个实际输出仍保留：
now1000000时不选图，到now1003000才选输入2，且该图像通过独立framemd5校验。
这证明当前像素队列准入与原输入任务/SDK输出选择有差异；不证明设备自然发生了该缺输出，
也不推定官方上层最终把显示结果归到哪一个任务。像素引用、GPU/map与统计ticket的归属
不能在尚未验证调用者语义时任意互换。

`audit-steam-video-output.py CORE --check scripts/fixtures/steam-video-output-reference.json.gz`
复播固定官方函数与触发输入；保留九个完整原函数指令。SDK/属性/时钟/JNI/SDL/锁/存储和
libc++ uint64排序原语为明确终点；map筛选、移除、统计、latch与原protobuf序列化均执行
官方代码。Source反事实要求实际SDK调用、选择、反馈正文或完成结果改变，无assert/适配器
异常充数。`observe-native-video-output-gap.py --build build/desktop --output DIR`从已配置
真实runtime/pipeline oracle构建隔离观察器，保留实际codec/像素校验并输出comparison.json；
它报告差异，不把现有差异固化为必须通过的产品测试，也不修改产品/golden文件。

固定对照含60组289状态、12项原指令反事实；含codec guard、PTS匹配/重复guard、等待额度、
丢弃index的render位、-1 flush、release失败、Surface ID/时间边界、真实pending统计与已丢弃
统计分流、反馈latch抑制/恢复。全部反事实必须在上述实际输出/反馈观察中产生差异。

## 89. 呈现调用者的输入任务归属与像素所有权

【官方客户端证据】固定SHA同§24.1。配置好的streaming/window边界中，完整
CStreamPlayer::BUpdateVideo @0x7b782c–8110经原BGetNextVideoFrame选输入任务；
format2实际调用CAndroidAccel::RenderFrame。SDK格式先经原BHandleOutputBuffer(-2)
建立1280×720参数，避免把NAL metadata适配器未提供的零尺寸当正常UI状态。
SDK/JNI/SDL与overlay绘制原语、图表/显示历史sample sink是明确平台/IO终点；
选择、渲染调用、事件16/17、present调用点、派生/base/client完成函数和真实帧统计均执行原代码。
此不是完整CStreamPlayer构造/startup或物理SDL/GPU验收。

固定budget10、任务1媒体time998689已到期、任务2媒体time1001311未到期、now1000000：
原调用者持有任务1，texture使用仅有的任务2对应SDK输出；之后原
@0x7b7fac–7fe8按current输入任务调用VideoFrameComplete(Displayed=1)。原
CStreamPlayer::VideoFrameComplete @0x7c2b28再进入base/client完成链。
由原RecordFrameReceived建立的真实记录验证：任务1结果变1，任务2仍0。
因此完成权属于选中的输入任务，不属于这次实际借用的像素输出。不能为了适配该规则
改写已发布像素envelope的输入身份；任务ticket和像素/decoder引用需要独立所有权。

同一调用者@0x7b7bcc–7be0、@0x7b7d94–7db4记录16/17，均关联current输入任务；
硬件format2路径也执行。这是呈现准备范围，不能把协议这两个事件仅理解成CPU拷贝像素。
原调用忽略SDL_RenderPresent返回值，SDK release失败请求重置后仍可沿调用者完成输入任务；
这些原调用观察不等于物理新画面成功，也不抹除Native显式图形设备/资源故障的独立边界。
原完成后current清空、previous仍持有输入任务用于重画；重复previous重画不重复完成该任务。
新任务可借用先前的texture，而其完成仍归自己的输入ticket。空输入亦能产生输入任务，
不能因为它没有像素token就从任务生命周期中消失。

【Android/MediaCodec投影契约】视频消费者须分别持有：已接受输入的有序任务、真实解码输出队列、已选像素缓存、
本次呈现任务ticket。先按原媒体jitter选最新已到期任务，再按其后端PTS选择输出或复用缓存；
输出的不可变物理身份/PTS留在像素对象中，16/17及最终结果写任务ticket。缺输出时的NDK等待/
flush与FFmpeg EAGAIN不是同一个API事件，物理等待/超时适配仍需单独验证；不能在每次普通
EAGAIN时立即flush。暂停/关闭清任务、待选输出和缓存，持有中的GPU/map/像素引用按既有ABI
规则独立退出。单独decoder Flush @0x906f40–6fa8保留SDK输入/请求PTS缓存及player任务，
只处理backend/map；新decoder构造才建立新的后端PTS状态。

【Native接线与可复现边界】`sl_video_selection`独立移交任务ticket与可空像素引用；
`media.c`真实present路径按任务记录16/17与完成，软件纹理缓存和GPU/map继续按物理像素身份
管理。像素FIFO的淘汰、token在已接受后无输出的释放不再擅自回报该任务corrupt/reset；
任务被新就绪任务跳过以6完成，关闭则以7完成。已使用的目标图像可在无新输出时复用；
如队列还有更新输出，仍按原规则继续取，不能仅因缓存PTS匹配而跳过它们。
后端PTS累加器逐字段复播原SDK输入时间，包括0、重复、回退与回绕；新decoder重置，
单独flush保留。decoder-only flush清未取走输出、保留已选图像和任务，player关闭清全部内部
拥有者；清理检查也包含CPU任务/等待ticket/图像缓存，不能只查codec domain。

`audit-steam-video-present.py CORE --check scripts/fixtures/steam-video-present-reference.json.gz`
执行24组99状态与四项原指令反事实，保留调用者四个完整原函数。Native
`video_present_official_vectors`执行实际control/parser/worker/FFmpeg/media/SDL/endpoint，
对照13组18个呈现状态的任务完成、16/17归属及有成功SDK输出的像素身份，另核60组SDK PTS
输入；每个实际像素均比独立framemd5。No BufferInfo供给域仅比较已执行的调用者完成语义，
不比较假想物理像素。§87已有15组1659状态对照保留，观察对象明确改为输入任务队列。
`observe-native-video-output-gap.py`现直接运行该真实receiver的显式后端缺首输出输入，
同时回读任务1/像素2/完成1与任务2后续复用，selection_matches从§88基线false变为true。
不以较早构造的隔离观察器或固定差异测试代替实际播放接线。

七项Native隔离变体检出像素时间戳替代任务准入、像素ticket冒领完成/16–17、漏接输入任务、
关闭漏清任务、decoder flush误清已选图像，以及缓存匹配时忽略更新输出；前四类中有实际
任务/像素/回报变化，生命周期项以资源/所有者断言检出。资源用例通过实际首标记分片flush、
actor重建、已接受但无输出的等待任务取消，持有旧AVFrame/map跨SessionDestroy/IHS_Quit直至
最终回收。无输出等待任务的统计保持decode begin/end而未伪造corrupt。

【尚未被本节证明的行为范围】Native非空输入等待首个输出时仍保留已选任务，未移植或验证
Android六次250000us的timeout/flush到NVTEGRA/FFmpeg的对应事件；不能称该分支已经等价。
NDK/Native图形错误返回、完整startup/UI cadence、全部音画同步与物理decoder/资源/设备验收
各有独立范围。完整FEC启用/非空上行producer和Host响应亦未由本节推定。

## 90. 官方客户端连接、配置与非空麦克风上行的FEC观察

【官方客户端证据】仅使用§24.1固定SHA的Android 1.3.32 core。复播脚本
`audit-steam-client-fec-lifecycle.py`记录18个原函数的地址、长度与指令SHA，
从原Connection构造、Connect/SendConnectPacket到原HandleConnected及其真实
CStreamClient::OnStreamConnected回调；随后在明确的认证完成边界进入实际
HandleIncomingPackets dispatcher、协商/Starting、QoS、主动配置API和peer99。
原channel工厂和构造均执行，不以受控channel存储代替。

Socket注册、锁、最终connect发送/Channel发送、加密、refcount、stats/player启动、
配置保存/delegate是明示adapter。HandleConnected输入为Socket已准入且去掉CRC后的
17字节包；认证完成前的密码学握手没有执行。它不代表完整认证会话、实际麦克风采集/
编码、Channel outgoing window/RS/UDP发出、真实Steam或设备测试。

【连接字段】Connection构造@0x7fb250的4B清零覆盖+11，本节预先污染+8…+15以验证
确实执行初始化。原HandleConnected @0x7fbef4–7fc000从包首字节取bit7，
@0x7fbf44写入的是connection+10，即CRC开关；不是+11的outgoing FEC开关。
原回调实际产生ClientHandshake(6)正文`060a00`并走可靠发送；随后连接保持state1，
没有由观察者强行设置connected或FEC gate。

【配置与控制】初始字段25分别缺失/false/true，经过真实OnNegotiationInit，产生的
消息4保留该字段的presence和值。peer消息4中附带相反值的streaming_client_config
不会替换客户端自己的配置；实际peer SetConfig仍推进4→5，原Starting推进5→6。
运行期主动SetStreamingClientConfig在local_only=0时实际产生99，在=1时不发；
peer99的缺字段/false/true配置实际整体替换，坏protobuf保留旧配置。上述轨迹均直接
观察原连接+11和原channel percentage，二者保持0，不从字段25推导本机发送开关。

【调用链更正】撤回本节初稿将消息87的dispatcher路径表述为调用原OnSetQoS入口。
实际HandleIncomingPackets在@0x7a6c3c–7a6c80内联QoS处理，@0x7a6c74调用
SetQOS；同名导出OnSetQoS @0x7adcd0–7add8c没有被此dispatcher调用。两条路径分别
执行false/true/坏protobuf对照，均将use_qos=false/true转为UDP SetQOS参数0/2，
对端地址来自connection+20；坏protobuf不调用该终点。该原路径不设置FEC开关或比例，
不能把QoS消息当作尚未发现的“对端要求本机启用FEC”协议。此结论限该消息/函数，
不等于已经穷尽所有消息、别名写入或其他库。

【非空上行producer】原StartMicrophoneStream @0x7a87f0分配通道3、发送107完整
正文`6b100318032880f7023002`（Opus/48000/stereo），并经原setter设priority1，
未调用SetChannelFECPercentage。随后原SendMicrophoneData @0x7a8a38–7a8b18
写真实非空payload `11223344`，经原Frame::Send和Connection发送入口：

- 协商reliable_data=true：走Channel可靠发送。
- 协商reliable_data=false：实际读取connection+11=0，走普通不可靠发送。
- 初始FEC=true、主动API改false/true（local_only两值）、peer99替换配置前后，
  以上选择仍由协商reliable_data决定，没有因为字段25改用上行FEC。

本节实际执行原麦克风数据producer，不再仅用空FEC周期调用或强制gate=1能力对照。
最终Channel发送为终点，因此观察到的是官方生产者与发送选择，不声称已经得到
真实麦克风UDP wire或全部上行producer的启用策略。

【内存与检测边界】12组CRC×reliable_data×字段25初值组合共360个状态，记录
每阶段实际配置、完整明文frame正文、gate分支及全部执行期间覆盖gate/percentage的
内存写。动态内存hook包含宽写/指针别名；不是只扫描STRB +11。不过它仅覆盖这些
实际执行的轨迹，不能据“未观察到写入”断言全局永不启用。
七项原指令反事实分别删构造清零、把CRC写到FEC gate、漏消息4配置copy、反转发送
门禁、将麦克风可靠性错取自字段25、改错内联/导出两个QoS分支的参数类型；每项确认
修改指令实际执行，再由字段/正文/发送选择断言或固定观察对照检出。没有用本地FEC实现产生期望结果。

【实现约束】继续按§32官方客户端的手动设置、预设、网络测试推荐后用户确认来决定
请求对端FEC的字段25；接收type11与本机outgoing gate独立。不增加“看到丢包立即自行
开FEC”、从CRC/QoS推导FEC或从字段25推导本机上行冗余比例。此处的正常麦克风
轨迹没有新的FEC开启触发，不将其包装为全部产品入口已经穷尽或全协议已经等价。

```sh
python3 scripts/audit-steam-client-fec-lifecycle.py \
  --binary /data/dl/nsteamlink/build/video-recovery-re/libmain-arm64.so \
  --output /tmp/steam-client-fec-lifecycle.json --verify-mutations
```

正常运行只读核验压缩fixture；`--refresh-reference`仍拒绝覆盖已有不同观察结果。

## 91. 官方Linux AVCodec客户端：收帧错误与Android投影的边界

### 91.1 来源、身份与复播边界

【官方客户端材料】从Valve的[1.3.32.316目录](https://repo.steampowered.com/steamlink/1.3.32.316/)
取得`steamlink-1.3.32.316.tgz`；archive SHA256为
`cb12c08e14ce4dfd4c4544bc783e94c51c0a474e30cccbd98a6937e14aa5d8e8`，
与[分发manifest](https://github.com/flathub/com.valvesoftware.SteamLink/blob/master/com.valvesoftware.SteamLink.yml)
固定的该版本值一致。[Valve README](https://repo.steampowered.com/steamlink/README.txt)
将桌面Linux客户端指向该Flatpak；该文件也限制二进制再分发。审计只在本地读取原包，
不将Valve ELF/库提交到项目或发布包。`package/bin/steamlink`的SHA256固定为
`95482ca6120f90bb90798b27206b7946ab732e079f008d7fc90ea58a8b0074e1`。
版本与平台独立记录，不把它冒称Android ELF或所有当前官方版本。

ELF去掉了普通函数符号。命名依据是实际RTTI `25CStreamDecoderH264AVCodec`、
相对重定位及vtable、原构造写入的vptr、GetName返回字符串、与导出的Android基类
虚接口顺序交叉核对。完整函数范围由`.eh_frame`的FDE确定，不取最近的残余导出名；
objdump将这里标为附近ctype导出的偏移不能据此命名。原构造@0x324610实际写入
vptr=0x10ffaa8，其slot14指向@0x324190；后者参数为decoder/id/timestamp/buffers，
是本节的FinalDecode。函数元数据包含19个完整FDE范围的地址/长度/指令SHA，
案例合计逐个观察到其入口执行。

`audit-steam-client-avcodec.py`执行原函数指针表设置@0x173b10、完整decoder/base构造、
受控仅支持软件H264的SDK能力下的原codec选择与StartDecoding @0x3246d0、
完整FinalDecode @0x324190–32460d、CAVCodecVideoFrame构造/身份、原RecordFrameComplete、
DataLost protobuf与原Frame::Put/Send。AVCodec/parser/frame/packet API、输入buffer接口、
锁/CPU/file/time、日志、最终player Put与Connection发送是明确终点。

SDK返回值/格式/尺寸/输出PTS是输入；没有物理解码、绘图、GPU或真实网络。
统计槽显式种为合法pending状态，执行原完成门禁；不声称完整RecordFrameReceived、
网络/统计Start/Stop生命周期。没有完整Qt/认证/client启动。COPY/TLS全进程初始化
边界受控，未使用的导入对象保持零。后述hardware_format值是直接控制的能力分支，
不冒称已经走通硬件选择、驱动失败或NVTEGRA等价。

### 91.2 FinalDecode的触发条件与可观察结果

原StartDecoding为H264建parser并置complete-frame标志。FinalDecode从buffer取得整个AU，
分配AVPacket与CAVCodecVideoFrame；解析/提交/取输出按以下分支推进：

| 明确输入/条件 | 原函数观察 |
| --- | --- |
| parser消费字节数不等于本次输入长度 | @0x324253–273记result5、释放packet，不send/receive/Put；不是无限等待parser补齐 |
| send_packet返回0 | 继续一次receive_frame |
| send_packet返回非0，包括-11 | @0x324520–548记录错误并请求ResetVideoDecoder(false)，随后仍执行一次receive；没有在此drain并重发同一packet |
| send返回-5/EIO | @0x3245c8–5eb打印禁用硬件加速说明，client+0x1d8置0x10000000并清+0x264，再进入上述reset/receive；完整配置保存/重协商未由这些裸成员写证明 |
| receive返回0且宽/高均大于0 | @0x324389以后设frame身份为本次FinalDecode的id/timestamp，选择格式后调用player Put |
| receive返回0但宽或高不大于0 | 释放packet，不交付该对象；不能把SDK成功状态单独视为有效画面 |
| receive返回-11/EAGAIN | @0x324560–57a先调用RecordFrameComplete(video,id,7)，再进入共有错误分支调用result5 |
| receive其他非0错误，包括EOF/INVALIDDATA/EIO | 进入共有错误分支，调用result5 |
| 共有receive错误分支 | @0x324480–4a4调用SendDataLost(video,空vector)，unref AVFrame，然后按context尺寸继续后处理；hardware_format=51/157另请求Reset(false) |

这里的7是DroppedReset结果；不能把结果名直接等同于实际ResetVideoDecoder调用。
仅receive EAGAIN且普通软件能力的案例，真实reset请求成员仍为0。`RecordFrameComplete`
@0x318b50实际先检查槽ID和pending结果；7之后的5不能覆盖它。合法pending槽的实测最终值
为7，其他receive错误为5。不是用观察者挑选第一个结果来模拟该门禁。

原SendDataLost @0x31f7f0检查client phase6；本节在该前置状态下执行原空message构造、
protobuf与Frame::Put/Send，最终Connection终点收到video channel3、完整frame正文`02`，
表示k_EStreamDataLost且protobuf正文为空。没有凭空加入丢失的sequence ID，亦不是148。
原Codec API的EAGAIN路径没有Android六次250000us取输出或SDK flush。

正常输出的AVFrame PTS由SDK输入分别取不同值，原frame的协议id/time仍按本次FinalDecode
参数设置；AVPacket PTS保留SDK分配时的AV_NOPTS_VALUE。它不同于Android按SDK输入PTS
再取texture的规则；这不证明Host会自然产生任意B帧/重排，也不取消Native物理像素token的
引用安全要求。媒体任务身份与物理解码来源是两个需分别映射的对象。

### 91.3 错误后的占位对象不是有效像素证据

共有receive错误路径先unref AVFrame；SDK替身按FFmpeg默认语义将其宽高清零、format=-1、PTS=AV_NOPTS_VALUE。
这些默认值另由随包libavutil.so.59（SHA256
`6df6556b6026144eb545dd95c0e2cc8c4568f462c9bd7e036531207d4172db34`）
实际av_frame_alloc/unref核对，未把模拟器零内存当作默认PTS。
随后原代码以codec context宽高设置IVideoFrame尺寸，使用format0并仍调用player Put。
因此可观察到“声明128×72、AVFrame实际0×0/format=-1”的对象。此处只记录对象元数据及
调用者交接，不生成/校验物理像素；不能把模拟内存或占位对象当作官方成功显示，亦不能
要求Native向GPU提交无像素的AVFrame。完整Linux呈现调用者、jitter/提交阶段与这类对象的
消费语义，不能由Android对应函数或本节的player Put终点替代；§92沿同一Linux客户端
继续执行这些调用者，单独记录该边界的证据。

### 91.4 撤回共有后端推断与Native反例

【撤回】§87–89的官方正向证据来自Android/MediaCodec。撤回将“接受输入即入任务队列、
无输出继续pending、输入后端PTS选择texture”当成FFmpeg/所有官方后端共有策略的判断。
那些Android原指令观察仍成立；其Native投影仅证明所列Android边界案例，不能用来证明
Linux AVCodec错误处理、任务身份、采样顺序或NVTEGRA平台策略等价。§89契约标题据此限定
为Android/MediaCodec投影；`VIDEO_RENDERING_DESIGN.md`同样明确当前Native资源模型与
官方后端策略证据的区别。已有COPY_OPAQUE/跨销毁像素引用检查的资源价值不等于协议完成
行为已经对齐。

`observe-native-avcodec-gap.py --build build/desktop --output DIR`从实际已配置oracle的
compile/link命令生成隔离观察器；保留真实control/parser/worker/FFmpeg/media与FrameTracker，
第一张实际解码像素先比独立framemd5，再显式在codec返回边界抑制为EAGAIN。这是声明的
后端可用性输入，不是自然Switch故障。观察器不改产品/golden、不添加必须保留差异的测试。

产品基线1a6d145、frame1、相同2204B AU与媒体time1000000：原Linux函数最终统计7并生成
`02`反馈；Native实际tracker有decode begin/end，但complete=false、result0，选择后仍持有
waiting_id1，DataLost调用0。`completion_matches=false`是实际记录差异；不从较早隔离模型
或预设期望拼出Native状态。不以这个受控反例认定原用户卡顿/闪烁根因。

【复现与检测力】固定来源29组32状态：正常/连续输出、不同输出PTS、send错误仍收一次、
receive EAGAIN/EOF/INVALIDDATA、parser消费长度、空输入/空parser输出、无效尺寸，以及受控
格式分支。六项原指令反事实分别去掉EAGAIN特判、去掉DataLost、把错误视为成功、漏send失败
reset、漏输出身份赋值、漏EIO配置修改；均须完整返回且实际状态/反馈/交付结果改变，
不以assert或harness错误充数。该审计是官方客户端证据，不是产品等价或设备测试。

```sh
python3 scripts/audit-steam-client-avcodec.py \
  --binary build/video-recovery-re/linux-1.3.32.316/package/bin/steamlink \
  --output /tmp/steam-client-avcodec.json \
  --sdk-library build/video-recovery-re/linux-1.3.32.316/package/lib/libavutil.so.59
python3 scripts/observe-native-avcodec-gap.py \
  --build build/desktop --output /tmp/native-avcodec-gap
```

## 92. 同一官方Linux客户端的OnThink、播放队列与占位对象消费

### 92.1 官方客户端证据链与终点

来源仍是§91的Valve Steam Link 1.3.32.316客户端ELF，SHA256不变。
`audit-steam-client-avcodec-player.py`不使用Windows Host行为，也不把Android/MediaCodec
策略翻译成AVCodec期望；它在同一原客户端内继续执行以下函数：

| 原函数边界 | 地址/身份依据 | 执行范围 |
| --- | --- | --- |
| decoder OnThink | @0x326f30，已固定decoder vtable slot4 | 完整函数，原partial链表删除、AppendBuffer、mode检查、FinalDecode前后事件与清理 |
| AppendBuffer | @0x3236e0，slot13 | 原完整函数；显式合法carrier/list-node输入，结束标记8，2204B AU |
| IStreamPlayer构造/注册 | @0x2ee0f0、0x317ab0 | 原完整函数；在client phase0注册后回到受控streaming phase6 |
| PutVideoFrame | @0x2edf70，CStreamPlayer主vtable 0x11001a0的slot9 | 原采样、锁、ring queue push/commit与唤醒入口 |
| jitter update/ready | @0x2ed080、0x2ed1d0 | 原浮点与年龄门禁；构造批量60，预算可作为显式调用边界输入 |
| 播放队列选择 | @0x2ee9e0、0x2eea50、0x2eeaa0 | 原pop、ready筛选、跳过旧ready对象、设置current |
| video update调用者 | @0x33d350 | 完整函数，含格式分支、16/17、SDL调用、呈现后完成 |
| 完成虚调用 | 主vtable slot49 → @0x33b5b0 → @0x2ee8d0 → @0x2ee7a0 | 原derived/base完整函数；不是把slot49直接当作base函数 |
| 事件/统计门禁 | @0x318a90、0x318b50、0x318df0及原helper | 原函数执行；原槽的最终结果直接读回 |

39个完整FDE的地址/长度/指令SHA收录于fixture，案例逐个覆盖入口。
SDK/parser/frame/packet接口及返回码沿用§91的明确终点；没有执行物理解码。
原base player构造运行，但derived player的vptr、已初始化render handle/模式由调用边界
显式提供，不冒称跑过完整CStreamPlayer工厂、Qt/UI/session启动。输入UI pump、overlay
虚调用、完成后的统计UI消费者、OS锁/事件/clock、可选外部显示服务及SDL是终点。
SDL返回值是输入，不表示真实显示成功；不以零像素或伪造GPU内存通过画面校验。

复用的decoder构造在受控`fopen(/proc/cpuinfo)=NULL`下会触发原CPU信息读取assert，
并走原fallback；其精确line2919/表达式地址0x8c88d0另列`bootstrap_assertions`，
不把它藏进“没有assert”的主张。之后注册与各submit/present状态均检查无新增assert。
统计仍从显式合法pending槽起步，不是完整RecordFrameReceived/统计启停或全并发生命周期。

### 92.2 可直接复跑的策略与触发条件

【证据】OnThink @0x3270bf记录14；@0x3270d8虚调用完整FinalDecode；@0x3270ef记录15。
FinalDecode里的receive成功或错误处理完成后，才调用原PutVideoFrame。
PutVideoFrame @0x2edfac在实际入队前采样。在显式send耗时100ticks、receive耗时200ticks
下，原14为1000000，原15与采样时刻为1000300；不是1000100。

【证据】receive EAGAIN的原路径保持§91的`7 → 尝试5 → DataLost(video,空正文) → unref`。
随后原format0/AVFrame无像素对象真实进入原播放队列，并参与同一个jitter门禁。
budget0时立即可选；预算20ms时，在1000000尚不可选，到1001311可选。
这20ms是显式jitter边界案例，不是重传timeout，也不能解释为官方固定等20ms。

选中该对象后，完整video update原函数的可观察顺序为：

1. 尝试记录该任务的事件16。
2. format0不进入@0x33d900的软件像素上传分支，也不把无像素AVFrame交给SDL_UpdateYUVTexture。
3. 尝试记录17，继续界面相关绘图与SDL_RenderPresent。
4. 由原slot49的derived/base调用链尝试完成result1；原统计槽已有7，最终仍为7。

原普通软件能力下的reset成员保持0。占位对象被消费并成为previous，不是挂在
“等待同一任务将来解出像素”的状态。后面普通结束标记8、没有协议关键帧标记的任务，
在显式SDK成功输入下可以入队/上传并完成1；这里的SDK成功是边界条件，不证明物理P帧
一定能在丢参考后解出，也不证明真实Steam重发或NVTEGRA恢复延迟。

【证据】旧占位对象和新有效对象同时ready时，原选择器尝试给旧对象记6并释放它，
仍保留旧对象已有7；新对象上传后完成1。重复呈现previous占位对象可再次调用SDL呈现，
但不重复16/17或完成。SDL_RenderPresent显式返回false的案例，调用者仍尝试完成1。
不能把这个结果1独立解释为物理屏幕已经正确显示。

【结论边界】这补齐了§91缺少的“占位对象交给谁、怎样消费、统计是否被后续成功覆盖”。
不上传无像素对象已由原分支证明；“一定保留上一张游戏画面”“一定黑屏/闪烁”仍未证明，
需要完整renderer/backbuffer与平台显示证据。源函数的调用顺序也不等于真实多线程调度时序。
这些分支没有建立新的FEC自动启用入口，不改变§32/90对FEC配置来源与能力门禁的区分。

### 92.3 与实际Native的差异及实现约束

`observe-native-avcodec-gap.py`增加第二个独立真实runtime/control/parser/worker/FFmpeg/media
进程；实际输出仍比独立framemd5，SDK耗时由同样的100/200ticks显式控制。
Native实际decode-end记录为1000100，jitter样本也只包含send后的年龄；与原OnThink的
1000300不符。原§91的EAGAIN反例仍为Native result0/pending、loss_calls0，而官方为7和`02`。
这些是实际执行读回的差异，不是只比较两个自写模型。

【撤回/限定】继续撤回把Android的“输入被SDK接受就结束解码计时、无输出任务等待texture”
当作FFmpeg共有策略的推断。Native当前结构描述及Android正向投影测试仍可说明各自覆盖范围，
不能作为这里AVCodec分支已对齐的验收条件。

按本节证据约束AVCodec实现时，须分别核验：receive后任务入队/采样/15的顺序；
7/5首次完成门禁与空DataLost；format0任务可被消费而无无效像素上传；正常下一任务可继续；
跳过/重复呈现不覆盖错误结果。物理像素token/AVFrame引用安全保持独立，不能为了任务策略
对齐而把无效帧或错误身份送入GPU。send错误的reset/仍receive一次、parser长度分支、
具体硬件格式与平台reset映射仍各按§91或平台官方客户端证据处理，不能被这一占位分支替代。

固定18案例45状态包括普通/异常收帧、send异常后收帧、parser长度、无效宽度、未知格式、
SDK耗时、SDL失败、占位后恢复、旧占位被跳过、jitter等待和重复呈现。
五项原指令反事实去掉15、采样、完成调用、跳过旧ready或DataLost，均完整返回且读回状态
改变；不以harness异常充检测力。该fixture是官方客户端证据，既非Native等价证明，亦非
原用户停顿/闪烁根因或全官方平台统一策略的证明。

```sh
python3 scripts/audit-steam-client-avcodec-player.py \
  --binary build/video-recovery-re/linux-1.3.32.316/package/bin/steamlink \
  --output /tmp/steam-client-avcodec-player.json
python3 scripts/observe-native-avcodec-gap.py \
  --build build/desktop --output /tmp/native-avcodec-gap
```

## 93. AVCodec Native任务、反馈与关键标记的映射

### 93.1 官方客户端的补充证据与撤回

来源沿用§91的Valve Linux客户端固定ELF/SHA，不使用Host发送端替代客户端策略。
`audit-steam-client-avcodec-key.py`执行原默认Frame构造/reset、完整DecodeFrame @0x3260d0、
FlushPendingData @0x325ec0、OnThink与FinalDecode。已解析的明文Frame描述符、carrier外部
引用及SDK/OS/UI终点显式受控；不声称经过完整Socket/CRC/crypto/Frame接收解析或整条引用生命周期。
四案例13状态保留六个完整FDE地址/长度/指令SHA；包含完整/分片标记、替换未完成AU、
已排队画面后收到新标记。实际送入原parser/send的完整AU字节逐份读取。

【证据】原DecodeFrame @0x326225调用slot15 → FlushPendingData。原完整函数清理partial与
尚未提交的压缩buffer引用，所有这些轨迹的AVCodec SDK flush调用数为0；已进入原player队列
的对象保留。漏掉该原虚调用的反事实完整返回，实际AU从2204B变成3304B，检出未清旧压缩片。
这不是根据函数名推断“flush”的含义。

【撤回】§79/87–89来自Android的“关键标记立即调用SDK flush、清未取走输出”不能泛化为
Linux AVCodec策略。Native在每个标记上avcodec_flush_buffers及删除已发布像素的行为据此撤回。
协议层仍在标记时清旧partial/组装数据；SDK状态在明确异步reset/stop销毁重建时退休。

§92原18案例的全部逐状态前缀保持；同一原客户端复播扩展为23案例413状态，增加完整60样本
预算、第二批平滑、send错误后pending reset阻止下一次FinalDecode，以及空AU/零parser输出的
受控EOF分支。五项原指令反事实不变。这里的EOF等codec状态是明确输入，不冒称自然设备返回。
原StartDecoding @0x324725–756将decoder尺寸及32/16对齐值写入context原偏移
0x70/0x74/0x78/0x7c，@0x324774–77a置context+0x44的0x1，@0x3247b5置parser+0xb8的0x1。
【更正，§94】这些原指令写入已经复播，但此前直接将四个context偏移命名为SDK的
width/height/coded_width/coded_height并称初始化一致，证据不足；随包SDK实际元数据API的
读取位置存在差异。flags2选项+0x44已由真实SDK独立核验。Native采用目标ABI的命名尺寸字段
及该对齐模式，不声称原客户端完整SDK启动或这四字段的原始布局已经对齐。

### 93.2 Native提交、任务与统计契约

Native使用相同的complete-frame parser/send/receive策略。parser消费长度不等于AU长度时
记5、不Put、不反馈DataLost；长度相等后只send一次、receive一次，不drain并重发同一个packet。
send非0先同步设置异步reset请求，随后仍receive。receive EAGAIN先记7再尝试5，其他非0记5；
首次完成门禁保留已有结果。空DataLost经真实channel serializer/queue排入，随后才采样/Put；
事件15由协议调用者在提交返回后记录。不能把SDK输入接受时刻当作decode-end。

`IHS_SessionVideoDecodeFeedback`只允许在同步submitTracked借用的session/epoch中调用，
验证当前video类/epoch后设置请求或排入DataLost，不保存session。Return结果新增reset与lost
组合值；应用已在正确时刻处理的反馈返回OK，避免在外层重复发送。send reset与receive lost
在两个明确位置发生，不把组合值的方便接口误当作官方调用顺序。

每次Put的CPU任务绑定这次receive得到的对象；任务身份/媒体时间取当前提交参数，实际像素
仍持有原输入的不可变token/receiveSerial。AVPacket PTS保持AV_NOPTS_VALUE，不按Android
SDK PTS累加/比较来重用另一张texture。SDK成功且有效尺寸的格式0对象、或错误后的无像素
占位任务均可按普通jitter到期消费，不等待后续任务的像素。无效尺寸不入任务队列。
成功返回的有效格式不再额外按FFmpeg missing-reference/corrupt标记淘汰；解码器内部如何
处理参考关系仍由SDK决定，不把这点外推为主机所有参考帧/切片语法已经核实。

正常选择使用最新ready任务及其实际输出序号；跳过旧ready记6，已有7/5不被覆盖。
占位任务不上传或绘制无效AVFrame，也不把旧有效帧当作本次新对象。重复界面重绘不重复
任务完成。呈现尝试后的统计不以output_returned这一返回标记定义物理成功；本地布局/import/
固定资源上限错误仍是单列的移植保护，不能冒称官方SDL错误或所有GPU平台错误等价。
不据这些控制调用证明必定黑屏、保留旧图或解释用户闪烁。

固定20个像素lease与256个任务是本地资源界限。任务用发布序号关联输出，避免每个CPU任务
额外锁住一张已淘汰像素；因本地上限丢失对象的任务明确记late。旧AVFrame与mapping引用不
随编码partial清理失效。退出仍先停/join生产者，再清任务、pixel/mapping、parser和codec；
parser在codec之前销毁，不新增后台线程或session异步借用。

### 93.3 可复现的验证范围

`check-steam-video-avcodec.py`直接消费上述原客户端两份fixture，真实Native runtime/control/
parser/worker/FFmpeg/media/SDL执行27案例426状态。对照实际首次统计结果、任务选择、jitter
count/budget、14/15与16/17、精确空DataLost正文02、SDK调用次数/状态/packet长度，以及
send → reset → receive、失败 → DataLost → sample → 15的顺序。reset回调受理标记与实际
pending gate的行为分别检查，未用一个观察者bool模拟其门禁。

SDK状态、耗时、元数据/可用性及呈现返回标记是明确终点输入；每张被返回的物理图像先由
真实FFmpeg生成，并在任何状态/元数据注入前与独立framemd5比较。重复重绘的缓存可避免
无变化的像素复制，不把这当作所有SDL调用次数或物理显示等价。tracker的CopyStats是一次性
消费；观察器仅保存实际消费过的完成历史，不能把后续“不重复报告”误记成重新pending。

实际重排H264 fixture另证明：task3可使用input1的真实像素，完成归task3，input1已有7仍
保留；每个逻辑任务都出队、像素MD5有序、不可变物理身份不被改写。旧帧/mapping跨四个
decoder epoch的真实actor重建、session销毁及IHS_Quit后释放的资源契约由原runtime用例继续检查。
真实AES-CBC的两个合法空明文在Native SDK中产生EOF；第一次反馈lost，第二次send失败
再请求actor重建，重建后正常帧仍出图。没有为了维持旧Android断言而屏蔽SDK结果。

六项隔离Native反事实分别去掉EAGAIN首结果、漏DataLost、提前结束计时、恢复标记SDK flush、
漏真正reset atomic、错误完成物理输入ticket。均先成功编译/链接：前五由真实oracle正常返回
后的官方对照拒绝，最后一项由真实B帧任务完成断言拒绝，不将编译失败或policy oracle崩溃
算作检出。旧Android官方复播与fixture保留；旧Native texture投影不再是AVCodec验收门禁。
无SDK耗时的共享timing检查另保留14个Android来源案例1538状态，不将它标成Linux完整策略证明。

这些是条件分支与Native映射的证据。官方SDK在完整client启动中的实际工厂/许可/硬件可达性、
send EIO的完整配置禁用/重协商、51/157等硬件格式的特殊reset与NVTEGRA对应关系、所有
平台SDK/渲染失败、完整统计启停/并发和真实Steam/Switch/loader仍各需对应证据。直接加载随包
libavcodec.so.61尝试软件H264 open返回-1，不能据此声称已运行官方SDK物理解码；没有更改
该库或绕过这个结果。上述官方原码的codec API仍是受控终点，Native实际解码是另列证据。
不新增根据丢包自动FEC的策略，§32/90的启用来源与上行能力区分保持。

```sh
python3 scripts/audit-steam-client-avcodec-player.py \
  --binary build/video-recovery-re/linux-1.3.32.316/package/bin/steamlink \
  --output /tmp/steam-client-avcodec-player.json
python3 scripts/audit-steam-client-avcodec-key.py \
  --binary build/video-recovery-re/linux-1.3.32.316/package/bin/steamlink \
  --output /tmp/steam-client-avcodec-key.json
python3 scripts/check-steam-video-avcodec.py --receiver build/desktop/app/nsl-video-timing-oracle
python3 scripts/check-avcodec-native-mutations.py --build build/desktop --output /tmp/avcodec-mutants
python3 scripts/observe-native-avcodec-gap.py --build build/desktop --output /tmp/avcodec-observation
```

## 94. 官方随包AVCodec的启动门禁与尺寸字段边界

### 94.1 来源与可复现调用

沿用§91固定Valve Linux客户端归档/ELF。随包`libavcodec.so.61`的SHA256为
`c53a7e3d32a986323ec6bedd28df73a6e5842c4753b67b1d2aa0d6e4f524472f`，
`libavutil.so.59`为`6df6556b6026144eb545dd95c0e2cc8c4568f462c9bd7e036531207d4172db34`。
`audit-steam-client-sdk-boundary.py`分别记录六个SDK和两个client完整FDE的地址/长度/指令SHA，
执行原client的StartDecoding（沿§91明确SDK/OS adapter），独立实调未改的随包SDK。
不改进程名、token、门禁或二进制，不把库测试冒称完整原客户端factory/启动。

### 94.2 H264初始化返回-1的本次证据

【证据】SDK H264 availability入口@0x11d4e0跳到@0x258f20，H264 init @0x22579的
@0x2258c也调用同一原函数；返回0时init沿@0x22593到失败出口，返回-1。
完整gate @0x258f20–0x25900d检查缓存后，通过dlsym解析getauxval，参数31取得执行文件名；
匹配`steamlink`或`streaming_client`会缓存允许。另一路检查`STEAMVIDEOTOKEN`；此处只记录
分支存在，不复制token值、不将它与Steam配对/安全PIN或网络协议关联。

本次普通Python进程的实际执行文件名不含上述client名称，也没有该环境变量。直接执行
未改的原gate返回0，缓存由[0,0,0]成为[0,1,0]。原find_decoder(27)返回NULL；by_name("h264")
能找到codec对象，仍经原open2/init得到-1。by_name查找原函数未经过availability分支，不能
将“查得到对象”等同于解码器已经可用。所有context/parameters由原API释放并核对置NULL。

【结论】本次独立Python调用的H264初始化受上述环境门禁限制。不能将这个-1当作官方
Steam Link进程在真实启动中失败，也不能当作硬件错误/网络恢复策略。原完整应用自然启动
是否使用该对象、其后的SDK调用结果及硬件可达性仍不由本次探针证明。

### 94.3 原client写入与SDK实际参数读取的差异

【证据】128×72受控decoder配置执行原StartDecoding，在open调用前观测到四次原写入：
context+0x70=128、+0x74=72、+0x78=128、+0x7c=80。SDK真实av_opt_find返回
flags2 offset=0x44、video_size offset=0x74、threads=0x290、thread_type=0x294。
SDK原avcodec_parameters_from_context的视频分支@0xb79b9/0xb79bf读取context+0x74/+0x78，
而非+0x70/+0x74。将上述四个原标量写入投影到另一个真实SDK分配的context，调用真实参数
API成功，参数width/height实际为72×128；没有拷贝模拟器里的指针/callback或声称执行完整启动。

【撤回】§93把原四偏移直接命名成随包SDK尺寸字段并称初始化一致的说法撤回。
Native通过目标ABI命名字段设置128×72及32/16对齐值，其真实图片已有独立像素验证；
这与原client raw layout如何进入真实SDK是两个证据范围。不能为了匹配偏移而将Switch尺寸
改成72×128。确切ABI/构建原因、完整启动是否有额外适配仍待验证，不能据此认定官方发布
存在可见尺寸bug。该差异不撤回已直接复播的FinalDecode控制分支及明确SDK终点下的对照，
但禁止将其扩张为原完整SDK/硬件已经自然运行。

```sh
LD_LIBRARY_PATH="$PWD/build/video-recovery-re/linux-1.3.32.316/package/lib" \
  python3 scripts/audit-steam-client-sdk-boundary.py \
  --binary build/video-recovery-re/linux-1.3.32.316/package/bin/steamlink \
  --sdk-directory build/video-recovery-re/linux-1.3.32.316/package/lib \
  --output /tmp/steam-client-sdk-boundary.json
```
