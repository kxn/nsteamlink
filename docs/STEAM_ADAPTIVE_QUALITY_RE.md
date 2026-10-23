# Steam Link 画质自适应的客户端证据边界

## 样本与方法

复核官方 Android Steam Link 1.3.32 的 ARM64 客户端，使用动态符号、完整
`objdump -d -C` 及调用点上下文；不将符号存在当作实际策略执行证明。

- `libmain-arm64.so` SHA256：`50e1d3147d5d47b71ef1970e1867a2fe4f3e1ecf2ea6153f927fac88b88ea38e`。
- `libshell-arm64.so` SHA256：`15b2d79881eef0c47ed2f96c17d1d60a5f42d3285abcf9f512cfffdac5b238a2`。
- 原有执行对照与字段证据见 [协议参考](STEAMLINK_PROTOCOL_RE.md) §23、§29.4、§56–57、§74、§116。

以下结论限定该固定版本及所列入口，不声称覆盖所有间接调用、主机编码器或更新版本。

## 分辨率、画质偏好和带宽是三个不同输入

`remoteplay.proto` 将 quality、video limits、`desired_bitrate_kbps` 分开保存。
`EStreamBitrate` 定义 −1=Autodetect、0=Unlimited；正数是 kbps 请求值。
720p 不确定实际编码码率，也不保证丢包或网络排队消失。正数请求值不能仅凭字段名
断言为每秒恒定输出，主机如何处理它必须另行取证。

官方 shell 的预设工厂和 `OnBitrateChanged @0xc909d8` 属于配置/用户设置链；
网络测试的自动目标值与推荐确认属于测试流程，不等同于游玩期间的自适应控制器。
Valve 的[网络帮助](https://help.steampowered.com/en/wizard/HelpWithGameIssue/?appid=353380&issueid=350&nodeid=35&return_nodeid=31)
也提供 Automatic 带宽选项，但该说明没有公开自动策略的计算公式或阈值。

## 运行中修改配置：机制存在，网络触发器未由此证明

`CStreamClient::SetStreamingClientConfig @0x7b01c4`：

1. 复制配置，通知可选 delegate，并保存。
2. bool 参数最低位为 0 且 client state=6，才构造消息 99 并发送给主机
   （`0x7b021c–0x7b0264`）。
3. 其他情况只有本地更新/通知/保存，不发该消息。

本次 main ELF 的直接调用清单共 13 处，来自：Init、UpdateDesktopMode、
BHandleEvent（3 处）、OnWindowMoved、OnWindowResized、OnDisplayScaleChanged、
ReduceVideoResolution、TogglePerformanceOverlay、ResizeOneToOne、
ToggleStreamingMicrophone、player 的 SetStreamingClientConfig 包装。
逐个检查调用点，不能从这份清单得出“按 RTT/丢包自动调低 bitrate/quality”的规则。
这是一份直接调用清单，不是穷尽间接调用后证明全客户端不存在该行为。

## 已定位的主动降分辨率属于解码配置失败恢复

调用链为：

`Android accel BUpdateDecoder configure 最终失败 @0x907af0`
→ `NotifyReduceResolution @0x7c9d9c`
→ SDL 用户事件 `type=0x8000/code=2`
→ `BHandleEvent @0x7b8f14`
→ `ReduceVideoResolution @0x7b9a4c`
→ `SetStreamingClientConfig(config, false)`。

ReduceVideoResolution 用当前宽高的 32 位乘积比较：超过 1920×1080 时请求
1920×1080；否则超过 1280×720 时请求 1280×720；再低则走终止保护。
它修改的是 runtime limit，不是把网络带宽/RTT 换算成分辨率。
上述 producer/事件证据和既有 SDK 错误执行对照相符；不能将其解释成网络卡顿时
从 720p 自动降到 480p 的功能，也不能由此构造网络阈值。

## 主机下发目标与客户端持续反馈

- `OnSetTargetBitrate @0x7aebb4` 接收消息 94，解析后保存 client +664，并通知
  decoder/player observer。`CStreamPlayer::SetTargetBitrate @0x7c9df4` 在该 ELF
  是 `ret`；这一通知不是客户端请求降低码率。
- `OnSetTargetFramerate @0x7aead8` 以及消息 69 提供目标帧率和原因字段；方向同样
  是主机到客户端。quality/bitrate override 通知也不能反过来作为客户端算法证据。
- `SendFrameEvents @0x7a82e8` 及客户端更新/帧完成路径持续发送统计；
  BitrateStats、PingStats、VideoBitrateStats 记录速率、RTT 与帧链路样本。
  统计采样、统计上报、编码决策是三个边界。客户端提供反馈，不代表它自己选择编码码率；
  收到主机目标也不能反推出主机的增减公式。

因此该客户端具备自动模式、持续反馈和主机动态目标通路；本次复核没有确认
“客户端检测高延迟后主动改低画质设置”的独立策略。主机端具体如何利用反馈、
正数带宽限制是否允许向下变化、调整周期/恢复周期以及动态捕获尺寸策略仍未由上述
客户端样本证明，不能按经验数字补齐。

## NSteamLink v0.7.0 的接线

- `auth_store.c::sl_auth_load` 新安装默认 6000 kbps。既有配置保留用户值，
  不能把默认值当作某次设备会话的实际设置或实测码率。
- `ui_model.c` / `ui_layout.c` 的网络设置已经提供自动（UINT32_MAX 对应 wire −1）、
  不限制（0）与 4/6/10/20 Mbps；自动分辨率的掌机 720p 是另一项设置。
- `stream_settings.c` 保留完整有符号码率，并在会话配置时交给 IHS；没有根据
  RTT/丢包反复写入低 quality/低 bitrate 的本地控制器。已有设置编辑在 UI 禁止串流时进入。
- IHS `ch_control_negotiation.c` 采集网络样本并调用 `IHS_SessionSendFrameEvents`；
  `frame_stats.c` 编码帧事件与累计统计，经 stats channel 发送。这条反馈通路已经存在。
- IHS `ch_control_video.c` 接收目标码率并提供可选回调，但应用没有注册目标码率回调，
  目前普通诊断摘要没有持续记录主机 target bitrate 的时间线。因此仅从本次热点
  `route=sns_relay`、重传和呈现帧率，不能认定主机未自适应或请求一直为 6 Mbps。

要验证现有主机自动模式的实际效果，应同时区分保存的请求值、消息 94 的主机目标、
接收视频实测速率、RTT/丢失/恢复与解码/呈现耗时。高 RTT 的固定传播时延本身
不会因降低视频码率消失；若主要瓶颈是排队或吞吐，降低负载才可能改善，这一因果
仍须由同次会话的测量验证。这里不据单次卡顿修改产品策略。


## 主机侧追加复核：动态机制与模式门槛

前面的“未由客户端样本证明”不能扩展为“官方没有动态机制”。追加的主机侧材料
已经证明动态估计器存在并有实际调用；以下仍区分估计器变化和最终编码器输出。

### 固定来源与新旧样本

- Windows x86 SteamUI.dll：SHA256
  `0cad7c69ace13e802be17beb06df299f7f733f01b4450a74bc68709494b21ddb`，
  官方 win32 manifest `1769731672`，ImageBase `0x3a000000`。
- 更新的 Windows x64 SteamUI.dll：SHA256
  `1b9457943205dc3af0bd53463ba331cbd2a381388699705c02271aac7a2b1252`，
  官方 win64 manifest `1791918634`，ImageBase `0x13a000000`。
- 来自 client-update.steamstatic.com 的已保存官方 package，原始 manifest、archive
  hash 和 binary hash 均在材料的 audit-inputs.json。两个样本不能合成一个版本。

### 实际执行的 x86 丢失处理

`0x3a10add0` 调用 Plat_FloatTime，比较 now−estimator+8 与常数 3.0；
严格小于三秒只记录 ignore early data loss。进入有效分支后计数加一，按
`max(lower_bound, float(current * 0.8999999761581421))` 更新 estimator+0x68，
并记录最后一次丢失时间。0.5 秒条件另影响 +0x6c 的历史值，不能说每次都复制它。

`tools/steam-adaptive-host-audit.py` 离线执行该完整原函数及原浮点 max 实现，
仅替换时钟和日志。显式对象输入验证 2.999 秒不降、3.0/4.0 秒 10→9、
到下限时保持 1。这里的 10/1 是受控状态输入，不冒充设备吞吐测量。

### 配置值与动态线程不是同一个“自动”概念

x86 `CGameStreamSession` RTTI vtable `0x3aa19f14` 的 +0x24 指向
`0x3a121180`：先取 override +0x4000，−1 时用 server getter `0x3a16a240`
读取 +0x18c。配置更新 `0x3a172078/0x3a17226b` 将配置对象 +0x50 搬到该成员；
配置 serializer `0x3a372481–0x3a372487` 对 +0x50 使用 wire tag 0x30，即字段6。
这将分支输入与 desired_bitrate_kbps 相连，不能只按函数名推测。

`0x3a11ff60` 在无 override 的普通编码路径中分流：

| 请求值 | 该样本的目标上限选择 | 动态估计线程 |
|---|---|---|
| 正数，例如 6000 | 该正数，再受能力上限约束 | 停用 |
| −1 | 依据尺寸与 quality 选预设；720p Fast/Balanced/Beautiful 为 5000/10000/15000 kbps | 停用 |
| 0 | 选择较高上限，配置 FPS/上下界 | 启用 |

脚本另执行实际虚表 getter、分流、预设表和能力上限读取；以显式平台/FPS provider
及线程启停记录终点核对上述五例。没有真实创建 host 工作线程，不作为完整运行会话证明。
因此不能把 UI 的“自动”名字直接解释为该动态线程必然启用；也不能把“无限制”理解为
完全没有任何估计器或能力上限。

### x64 样本的交叉核对

新样本的模式选择 `0x13a18b340` 仍对非0/−1请求停用估计器；−1按尺寸/quality
选上限并停用；0分支设置 bounds/FPS，并调用 start `0x13a171ef0`。
普通路径的0分支上限是250000 kbps，**不是旧样本的100000**；特殊编码路径有独立上限，
不能把旧常量直接移植为客户端默认值。
后面的27例已进一步执行该原入口、实际配置getter和reset/start/stop；此段不再仅靠静态分支。

新样本还存在两种独立反馈入口：

- `0x13a170fc0`：data loss 的早期时间门槛、估计速率取样、历史记录及重算。
- `0x13a171a10`：client video decoder overflow，亦有早期门槛并进入重算。

重算 `0x13a172500` 结合丢失后时间、链路估计、系数、decoder约束和上下限；
它与旧x86直接乘0.9的处理不同。目标更新入口 `0x13a1948f0` 在新的选择值与保存值
相差至少1000 kbps时推进目标/突发预算设置。通知目标、动态估计值和编码器实际输出
仍是不同观测量；不能把任一条目标日志当作整套自适应已通过。
此前x64仅做静态复核；下面追加独立的x64原指令执行证据，不把x86用例算成x64回归。


## x64 反馈门槛、重算与编码阶段的原指令组合

### 时间与限额必须按版本核对

独立执行 `tools/steam-adaptive-host64-audit.py` 的93个受控输入（其中8个为Ping窗口、10个为非空统计缓冲、9个为发送producer/FPS阈值、17个为Ping producer/请求过期/应答入口、27个为模式选择和估计器重入）：
原重算、两类反馈处理、source callback门控、重复loss的latch、真实session虚表getter，
以及编码stage的回调循环和写入均执行原指令。仅提供时钟、日志、可选第二码率回调、单线程临界区、直方图清零原语、
全局发送guard、帧删除及下游交付终点；没有改写这些算法入口。输入对象不含速率采样/历史缓冲的那组，原函数
自行走空缓冲分支；后续显式非空组另行核对查询、更新及合并，但都不是真实Steam进程执行。

**版本差异**：x64 loss入口 `0x13a170fc0` 与 overflow入口 `0x13a171a10`
从 estimator+0x10 起算，严格小于 **5秒** 时忽略；旧x86的3秒不能套到这里。
4.999/5.0/6.0边界均执行核对。达到门槛后写last_event(+0x90)，并调用
原采样函数及重算。没有历史缓冲不等于跳过算法；它仍执行时间、门槛和最后的重算。

`0x13a172500` 中，本次候选值按原浮点操作顺序为
`link(+0x98) * coefficient(+0xa0) * ramp`，其中
`ramp=max(0.08f,min(1.0f,float(2*(now-last_event))))`。
先由正数decoder样本(+0xb4)的 **0.96f** 和正数history cap(+0xb8)
约束upper(+0xb0)。候选低于lower(+0xac)则直接返回lower，否则返回
min(受约束upper,候选)。这不是无条件按每次事件乘0.9。

合成link=10、coefficient=1时，事件后0.25秒候选为5，0.5秒为10；
decoder=5时受约束输出约4.8；另核验upper=6、history=4、lower保护。
这些数字只说明原函数的受控算术，不代表实际链路会在半秒内恢复到某个吞吐。
将0.96改成1的反例必须被oracle拒绝。

### 客户端反馈确实到达该门槛

host `CGameStreamSession` offset=0x4528 的RTTI虚表为 `0x13ac8f8b0`：

- +0x48 → `0x13a1907f0`：检查callback+0x408的enabled字节，再将this+0x400
  交给上述overflow入口。host控制接收 `0x13a1ed49b–0x13a1ed4d7` 构造对象
  RTTI为 `CStreamVideoOverflowMsg`（vtable `0x13ad5ce50`），解析成功且delegate
  存在才调用delegate+0x48；没有把first/last当码率值传入。
- +0xe8 → `0x13a190740`：先检查pending loss(+0xca4)，尚无pending且enabled
  才调用loss入口，随后设置pending。连续调用不等于连续削减；清pending的producer
  和完整收发循环另行核对，不能自行发明固定去抖期限。

4个source callback输入分别覆盖enabled 0/1及两种事件；loss再调用一次验证latch。
这些用例从已解码的callback入口进入，**没有**把fixture当作完整控制消息148的
认证/加密/解析实验。解析条件与虚表绑定另由静态指令和RTTI核对。

### 估计器到编码阶段：已跨过“仅供显示”的边界

`CGameStreamSession` offset=0x4538 的RTTI虚表 `0x13ac8fa20` 的+0x28为
`0x13a18c4c0`：

- enabled(+0x3f8)非零，读当前估计(+0x498)，乘1000后向零转为整数kbps。
- disabled，直接返回保存的目标(+0x110)。

这些相对位置分别落在根对象的estimator+8、estimator+0xa8与目标字段+0x4648，
并非读取另一份UI统计对象。

`CGameStreamVideoStageUpdateBitRate` RTTI虚表 `0x13ac92060` 的处理函数
`0x13a1a2fe0` 遍历encoder+0x68的callback数组，对每项调用+0x28，按原循环
选择限制值，以原子xchg写encoder+0x168，再交给下一级stage。

4个组合用例从原recompute→原session getter→实际RTTI回调→原stage循环/写入：
动态5 Mbps写入5000 kbps；另一callback限制3000时写3000；disabled则沿保存值6000；
另一callback8000时仍取6000。第二callback和下一级stage只是明确终点，主回调与
限制循环不是替身。删除原xchg的反例必须被拒绝。

因此已证明这条估计结果能够进入编码器的生产stage状态，并非仅打印日志。
仍未执行GPU/NVENC/AMF/x264编码器设备调用或比较真实编码比特流；“写入编码器状态”
不能扩大为“任意真实会话必然以该码率输出”。

### 会话Ping样本参与系数调整

另8个原指令用例从 `CGameStreamSession` offset0x4528的真实callback
`0x13a18e8f0` 进入：其RTTI虚表 `0x13ac8f8b0` 的+0x50指向该地址，
先检查enabled，再把16.16秒差转换为float毫秒，尾调用 `0x13a171820`。

静态接收链 `0x13a1f04d0` 构造RTTI为 `CDiscoveryPingResponse`
（vtable `0x13ad5cc70`）的对象，解析成功后按sequence找到保存的请求项，
检查packet-size条件，再以本机保存的发送/接收时间差调用delegate+0x50。
这是会话通道0的Ping，不是首页主机广播发现、DNS耗时或客户端自行编造的网络状态。
这8个用例从已验证的callback入口执行；后面的17例另行进入原请求/应答入口，
解析仍是显式终点，不冒充完整加密Socket/认证/主机进程实验。

`0x13a171820` 仅在active-thread成员非0且slot<500时处理：写入500槽数组，
用非负样本计算mean；将新样本与mean的差和阈值(+0x54)比较。在正常有效浮点输入下：

- 差超过阈值时，按超出量/阈值缩小系数(+0xa0)，有0.08下限，且不高于已有系数。
- 未超过时，正常范围内每次处理可将系数加0.04，最高1，然后执行原recompute。
- 0.04是每次处理量，不是每秒恢复量；500槽是原数组长度，不代表本次执行了真实
  工作线程、周期唤醒和完整窗口淘汰；下面单独执行有界worker原指令。

显式阈值10ms、500槽初始10ms，新样本约25ms（16.16量化后）使系数约0.503609、
目标约5.036092 Mbps；约40ms触及0.08系数并受1 Mbps下限约束。
初始窗口200ms、新样本约210ms不触发这一分支的下降；因此这里比较的是相对窗口的
增量，不能改写成“RTT超过某个固定值立即降画质”。系数0.5的低差样本恢复到约0.54，
0.99恢复到1。另覆盖enabled关闭、slot=500及active-thread=0门禁。
这些窗口、阈值、link和thread成员都是显式输入，不是当前设备实测值或默认参数推测。

原浮点min/max helper仍执行；仅Enter/LeaveCriticalSection为明确的单线程终点。
把0.04改为0的反例在实际恢复结果比较中被拒绝。此链补充了延迟反馈能参与生产目标的
证据，但没有覆盖原速率样本/事件直方图的全部分支，也没有让合成窗口替代真实公网验证。
IHS当前已有会话Ping应答，见 `ch_discovery.c::OnPingRequest` 与协议§43；它按官方
观察复制request正文并按请求尺寸填充，不因response字段标签而擅改应答内容。

### 非空速率环与事件历史：区分立即反馈和后续更新

另10个用例不再仅依赖缺省空缓冲分支：

- 6个loss/overflow输入给原对象提供190个分箱的显式历史。原事件入口按
  `max(采样值,当前目标)` 计算分箱，基准50、步长5，向零转换后限制到0..189，
  给raw event计数加1，再执行 `0x13a171fd0` 的完整相邻分箱合并。
  目标10、100分别进入bin0、bin10；合成高值2000只检验上界钳制到189，
  不作为当前主机允许该目标值的证据。
- 每箱初始weight=1、event=0时，bin0增加一个事件后，原合并把190箱的
  pooled weight/event均写成190/1；bin10的后180箱为180/1，前10箱保持1/0。
  bin189只影响末箱。这是对原指令写入的逐箱核验，非将本地拟合器当期望结果。
  原始weight/event、pooled结果分别读取，不能把它们混为同一概率数组。
- 4个输入执行完整速率更新 `0x13a1710f0` 及真实 `0x13a170e80` 查询：
  显式30槽、cursor29、相邻时间0.1秒，入口数量125000按原计算写成1，时间写为10，
  cursor回到0。数量转换为×8/1000000；该组从consumer进入，下面另核对一个实际发送producer。
  真实会话节奏仍未执行，不把此环当真实捕获的帧流或公网吞吐。
- 该受控环中，无recent-event/pressure时link约10→10.012001；recent-event时
  重算受事件后ramp限制；pressure=1、coefficient=0.5时link约10→9.925，
  目标约4.9625。另执行非零hint分支。数值依赖这份显式历史和状态，不能变成
  产品自创的固定降幅、固定恢复周期或网络阈值。

原history pooling、采样查询和rate update均执行；仅临界区与memset等平台/存储
原语为终点。删除loss入口的原pool调用后，raw event仍更新，但pooled结果不匹配，
反例在正常返回后被拒绝。这与只看最后target是否变化的检查不同。

上述事件发生后并未直接对link一律乘某个固定百分比：即时路径写last-event及历史，
随后recompute；非空速率更新与pressure状态再参与后续link选择。因此旧x86的乘0.9
不能代替新样本的整条策略。这里仍未执行历史的时间衰减/置信估计全部条件、真实工作线程
周期及物理编码输出，不能把10个合成输入扩展为整套稳态/恢复已对齐。

### 速率样本来自发送负载，不是客户端报告的吞吐

追加6组原指令输入，从实际单帧发送入口 `0x13a192b90` 执行到上述rate update，
随后继续进入原forwarder `0x13a1f1eb0`。帧buffer、两个header flag、offset、模式和
连接状态是显式对象输入；不把这类fixture写成从真实编码器取到的帧。

这个producer在估计器enabled且允许当前帧时，以
`buffer_length - 13 - (flag16?1:0) - (flag17?12:0) - offset`
作为更新数量。剩余正文包含视频帧头，不能当成只含编码图像的数据量。
原body flags的0x10是key-frame标记：普通模式跳过该帧的速率样本，模式字段
`session+0x51b0=9` 则不跳过。这里只记录该数值分支，不为9臆测产品模式名称。
测试保持encrypted位0；原函数内的加密、padding调整并未由这6例执行。

受控正文125000 bytes分别在普通header、额外header/offset输入下，均向真实
30槽环写入1 Mbit；50000 bytes写入0.4 Mbit。普通key frame和disabled时不更新cursor，
模式9的key frame则更新。原函数仍分配并写入视频sequence，7→8；随后原forwarder
在显式 `connection=null` 时自行返回false，已写入的速率样本没有撤销。
全局发送guard与帧删除是明确终点；尤其 `0x13a1ec710` 是帧虚析构/删除边界，
不是网络发送结果。没有把替身的零返回值当作真实丢包或超时。

**Conclusion：** 至少这个真实producer提供本地待发送正文的负载样本，而不是远端ACK
吞吐或客户端测得的可用带宽。不得把该环的值直接显示成“公网已可用带宽”。
loss、Ping、历史/pressure随后参与容量估计；一个发送producer不穷尽批量/FEC路径，
也不证明实际公网时序或重传是否会从其他入口重复计入。删除原producer→rate update
调用的反例在原发送函数返回后，因缺少采样/cursor变化被拒绝。

### Ping增长阈值来自帧周期

原setter `0x13a171e70` 把 `1000.0f / fps` 写到estimator+0x54，
不是全局固定10ms。构造器 `0x13a17089d` 直接写入float bits `0x41855555`
（约16.666666ms）；普通0码率分支在 `0x13a18b3a0–0x13a18b4e5`
查询帧率分子/分母，成功则做除法，失败则读取原60.0f常数，再调用这个setter。
构造/查询的绑定在此为静态证据，没有虚构实际主机当前帧率。

新增3例执行原setter→原session Ping callback→500槽均值→原recompute。
显式fps=30/60/120分别产生约33.3333/16.6667/8.33333ms阈值。同一初始10ms窗口，
新样本1638 ticks（约24.9939ms），在30/60fps输入时系数保持1；120fps输入时约0.204331，
目标约2.04331 Mbps。不同结果来自原帧周期阈值，不代表我们要在Switch写三个阈值或
把当前会话设成120fps。移除原除法的反例会得到错误的1000ms并被比较拒绝。
之前显式10ms阈值的8例仍是受控边界测试，不能当作官方缺省值；本次进一步补齐了
其上游设置依据。没有把此处帧周期等同于主机真实Ping发送周期。

### Ping producer、请求账本和实际应答入口

以下17例与此前49例独立列出；49例输出逐项保持不变。固定x64样本、SHA与上文相同。
构造器 `0x13a189cc0` 把session+0x4548虚表设为 `0x13ac8fb38`，作为observer交给
session+0x4928的estimator。其worker成员虚表 `0x13ac8b458` 的+0x10指向
`0x13a171d60`；observer+8指向 `0x13a18b320`，后者尾调用实际请求入口
`0x13a1eb010`。这些绑定由原构造指令核对；fixture没有运行完整对象构造或真实线程。

4例从原worker开始：active非0时请求Sleep 20ms，在锁内把旧cursor对应的500槽值
写为−1，cursor模500推进，再以旧cursor通知observer。Sleep是明确的有界调度终点，
不实际睡眠/开线程；临界区终点不模拟并发。请求protobuf原构造器 `0x13a4797a0`
执行，观察到vtable `0x13ad5c9f0`、presence=3、sequence和requested-size=0。
Frame::Put仅记录原对象字段与length-prefix参数，**没有执行请求序列化或实际发送**。

- 非零slot1/2保留为sequence1/2，自动计数器不变；active=0不发请求也不改窗口。
- slot0在请求入口具有特殊语义：改用session+0x26c自增计数器。初始0产生sequence1；
  从slot499回绕到0、计数器700时，先产生499，再产生701。不能把worker传入的0
  无条件当作线上的0，也不能把序列号与500槽索引永远等同。
- 原请求表使用预分配的16项CUtlLinkedList存储，原插入/链接/删除/复用逻辑执行；
  这不包含真实分配扩容、完整窗口寿命或实际网络时序。

3例核对请求过期：原全局时限 `0x13b0bbee0=1966080` 个16.16秒tick，即30秒。
旧sequence17在30秒−1tick仍保留；正好30秒及其后已删除，槽可复用。随后给原应答
入口同一旧sequence，只有未过期例进入实际RTTI callback、窗口更新和重算。
这是账本淘汰边界，不是客户端连接/断开超时，不得拿来修改产品等待时间。

另10例从真实应答入口 `0x13a1f04d0` 执行，原response构造器 `0x13a4797c0`
与vtable `0x13ad5cc70` 保留；Frame复制/解析显式提供已解码字段和接收时间。
原链表反向查找、尺寸检查、时间处理、delegate+0x50、500槽窗口及recompute均执行：

- 从最新请求向旧请求查找sequence；多个相同sequence时命中新项。
- 请求size非0时要求应答size相同；请求size=0则不因应答该字段为1472而拒绝。
  未知sequence、非零size不匹配及解析失败不进入callback。
- 接收时刻早于发送时刻时，原入口将其钳为发送时刻，RTT为0。
- 正常应答后原记录仍保留；同一应答再次到来可再次进入callback并调整系数。
  显式系数0.5的低差样本两次约为0.54、0.58，不能自行加去重改变官方行为。
- estimator disabled时接收记录仍更新，但callback门禁不改估计目标。

**Evidence / Conclusion：** 这里已跨过“仅从反馈callback调用算法”的边界，核对了
worker producer和真实请求/应答入口对该callback的使用；socket、加密、protobuf parser、
真实调度和主机设备仍不在这些执行用例内。slot0替换与回绕带来的真实长期反馈分布
不能由两次有界迭代推定。四个新增反例分别删除slot失效写入、删除自动sequence自增、
跳过size拒绝、改变精确过期比较，均在原函数正常执行后的输出比较中失败，
不是依靠模拟器崩溃、缺少指令支持或patch签名错误制造失败。

### 配置模式和初始化：执行新版原入口，不沿用旧版表格

追加27例进入原 `0x13a18b340`，session根虚表 `0x13ac8f830` 来自构造器
`0x13a189cff–0x13a189d13`。实际的+0x50 getter `0x13a18c8e0` 选择override
（root+0x461c）或server有效值（+0x25c）；server codec字段+0x248为9时忽略override。
质量+0x48 getter `0x13a18c920` 选择override +0x4618或server +0x22c。
fixture显式提供这些成员，不把它们冒充本轮收到的message99或用户主机实值。

FPS接口仍用原session+0x4538虚表，+0x20为 `0x13a18b1c0`：当前模式字段为0时
读取实际局部FPS分子/分母，否则调用原server FPS getter `0x13a1ec780`。
60/1及60000/1001输入均走原分支和除法；能力上限 getter `0x13a1ec7c0`
读取root+0x260，0表示该次不钳制，正数限制返回上限。没有替换模式入口、虚表getter、
预设选择、FPS/bounds setter或reset/start/stop来制造结果；只有线程OS start/join为观察终点。

| 普通编码路径的有效请求 | 原入口返回的上限（kbps） | 估计器enabled |
|---|---:|---|
| 6000，能力无额外限制 | 6000 | false |
| 6000，能力上限3000 | 3000 | false |
| −1，720p，quality 1/2/3 | 5000 / 10000 / 15000 | false |
| −1，1920×1200边界，quality 1/2/3 | 10000 / 15000 / 30000 | false |
| −1，2560×1600边界，quality 1/2/3 | 15000 / 20000 / 30000 | false |
| −1，3840×2160，quality 1/2/3 | 25000 / 30000 / 50000 | false |
| 0，能力无额外限制 | 250000 | true |
| 0，能力上限6000 | 6000 | true |

另核对缺尺寸、未知quality的15000回落，两个override来源及server codec=9忽略码率
override。session编码字段+0x51b0为9时，0与−1均选1000000上限，但只有0启用估计器；
不能把该特殊分支的数值当普通Switch客户端默认值。

原bounds setter `0x13a171df0` 将普通0分支的2500/上限转为Mbps，例中为2.5/250、
带cap时2.5/6；编码字段9则为100/1000。原start `0x13a171ef0` 首次启用前调用
`0x13a171b40`，其原reset清空30槽速率/时间数组，失效500个Ping样本、归零Ping cursor、
恢复coefficient=1，并把link/+0x9c写成15 Mbps。**15是这份原函数的初始化值，
不是fixture预置的吞吐，也不是实际编码输出已经15 Mbps。** reset发生在bounds setter之后；
不要擅自交换顺序或宣称中间link值已受最终能力上限约束。

enabled和worker不是同一状态：显式worker-permission(+9)=false时，0分支仍置enabled，
不调用线程OS start，active-word保持0；true时原指令先把active-word置1再进start终点。
切到正数或−1时，原stop `0x13a171f40` 关闭enabled，若worker活动则先清active再join，
随后原 `0x13a171c40` 重置Ping窗口。join参数0xffffffff是原调用参数；没有真实等待、
并发或worker退出证据，不能把这条离线轨迹当作主机线程生命周期验收。

独立重入例执行0→0→6000→0：第二次0保留速率/Ping样本和原start时间，不重开worker；
6000停止并重置Ping；再回0则重新reset并记录新start时间。由此，持续反复应用同一0值
不等于每次重置估计器。此前66例输出逐项不变，3个新反例分别改变正数分流、移除cap
钳制、跳过首次reset，均在原函数正常返回后的上限/窗口比较中被拒绝。

**Conclusion：** 在该固定新版主机样本中，UI常称“自动”的−1属于预设选择；
0才启用这里核对的动态估计器，正数关闭它。不能用“自动”名称反推运行中动态降码率，
也不能把“无限制”误解为没有估计器或能力上限。这是官方主机算法的输入/初始化证据，
不排除其他编码器/帧率策略，也不证明当前真实主机版本、完整wire配置接收或物理码流。
研究没有修改产品默认带宽或在Switch加入自创控制器。

### 从配置明文到原模式选择：同一仿真器内的接线核对

`tools/steam-adaptive-config64-audit.py` 另有13例，不把前述显式成员输入当完整配置链证明。
复用 `scripts/audit-steam-host64-fec.py` 的平台/分配/交付终点并记录该文件SHA；
显式提供明文frame、server状态、session虚表/override、尺寸/FPS与预分配估计器存储。
同一仿真器内执行原dispatcher、C++ protobuf parser `0x13a4627a0`、CopyFrom
`0x13a47cd90`、ApplyConfig `0x13a1f5c10`，再进实际getter、selector和reset/start/stop。
没有把Python对象解析结果直接写入server成员来替代原接收链。

固定DLL内嵌的 `steammessages_remoteplay.proto` descriptor确认
`CStreamingClientConfig.desired_bitrate_kbps` 是字段6、缺省−1。原CopyFrom后
server+0x230保存该请求；ApplyConfig的 `0x13a1f5f76` 读入r12d，普通codec路径
在 `0x13a1f6192` 写入+0x25c，随后真实getter使用它。codec9的ApplyConfig另有
取+0x240的静态分支，这13例仅使用codec4，不以普通编码案例代替它。

四种请求分别经初始消息4（host state6）和更新消息99（state7）进入：
省略字段、显式−1、0、6000均保留预期值；普通720p/quality2的−1返回10000上限并
停用估计器，0返回250000并启用，6000返回6000并停用。host state8也接受99；
state6/9忽略这条更新，不执行copy/apply，也不改变先前6000。
状态数字属于host枚举，不是客户端phase编号。

0之后再给省略字段的有效配置，原clear/copy/apply恢复−1并停用估计器，观察到
start→join；它不是保留旧0值的局部patch。截断正文 `0a0230` 则解析失败，不copy/apply，
保留之前0和已启用状态，再进selector也不重开worker。两种缺字段/坏消息不可混为一谈。
更新报文明文例：quality2/0为 `0a0408023000`，quality2/6000为 `0a05080230f02e`；
其中外层字段1包config、内层 `30` 是字段6的varint tag，并非一种新的传输指令。

**Evidence / Conclusion：** 这组补齐了“wire字段6→主机有效请求→模式初始化”的原指令
组合，且移除原+0x25c写入的反例在正常返回后因applied值不匹配被拒绝。继承的
platform-ID查询明确返回0，250000是该受控路径的结果，不是当前主机实测能力。
仍没有执行真实认证/解密网络、host进程或线程调度/编码设备；frame存储、分配/释放、
锁、日志/时钟和出站交付沿用明确终点。不能把该明文输入检查宣布为完整串流验收。

### Switch接线比较需要保留平台边界

IHS `ch_data_video.c::CheckPartialOverflow` 已发送message148，是压缩帧pending
跨度反馈。官方Android另在解码输出落后时发送first/last均0的message148，见协议§88.2，
有latch抑制重复且追近后解除。当前Switch应用未见对应的解码输出端148producer；
它的队列替换/帧ticket完成已有DroppedLate等统计。

**撤回此前的缺口暗示**：仅凭Android有这个producer，不能把Switch没有它列为应补齐的
AVCodec缺口。追加的同类Linux客户端证据如下：固定1.3.32.316的AVCodec路径有压缩帧
积压发送者，但没有在这份直接调用清单中出现Android输出落后的额外发送者。
这不证明所有间接/内联发送者不存在，也不证明NVTEGRA的实际处理能力；它已经足以否定
“任意DroppedLate/解码错误/高RTT都应补发Android式148”的移植依据。

### 同类Linux客户端的反馈producer

Linux固定ELF来源及SHA沿用协议§91：
`95482ca6120f90bb90798b27206b7946ab732e079f008d7fc90ea58a8b0074e1`。
`tools/steam-adaptive-client-feedback-audit.py`扫描其全部可执行section的原指令：
SendVideoOverflow `0x31f740` 只有一个直接call/jmp引用，来自压缩decoder检查
`0x326c60` 的 `0x326d2d`。ELF RELA中无该目标addend引用；不将这份有界清单
扩展为不存在间接/内联生成消息的全程序证明。该检查在OnThink中由 `0x327241` 调用，
不是由player输出落后直接调用。

11组15状态执行完整原CheckOverflow、SendVideoOverflow、protobuf构造/序列化、
Frame Put/Send与Connection交付终点。SDK、时钟、锁、日志和存储继承既有AVCodec
审计终点；**Frame加密另有显式成功终点，保持明文不变**，因此下列字节是观测的明文，
不是完成认证/加密的线上ciphertext或主机已接收证明。两个partial端点及调度是显式输入，
没有运行完整接收端生产这些对象，也没有模拟真实解码吞吐。

- waiting-key、syncing或partial计数<=1时，检查不发反馈。
- head=100/tail=102时，control channel1正文为 `9408641066`：首字节148，随后
  first=100、last=102。相同跨度再检查仍可发送；跨度缩小只更新比较值，再增长可再发。
  这里没有Android输出端那种一次发送后latch抑制到恢复的语义。
- timestamp差=9830时只发148；=9831时先发video channel3正文 `02`（空DataLost），
  再发148，并记录syncing与最后恢复时刻。这是原检查的两个独立判断，不是同一触发条件。
- frame ID回绕采用原有有符号差：65535→0的inclusive span为−65534。初始比较值0时
  抑制148但保存负值，下一次相同范围则允许发送。不能私自改为模65536的正数跨度。
- client phase非6时，原SendVideoOverflow不发，但调用者仍更新跨度比较值。

当前IHS的压缩pending检查在范围比较、恢复阈值和发送顺序上相符；这里的源码比较
不替代完整Socket/crypto/并发和设备证明。IHS通用control send本身没有同样的phase6
判断，非streaming时能否到达该producer取决于外层会话/worker生命周期，尚不能凭
活动会话分支宣布这一门禁等价。官方AVCodec的receive错误另使用DataLost及首次完成结果，
已有独立原指令与Native比较，见协议§91–93；不能把它换成Android输出端的148。
移除原 `0x326d2d` 发送调用的反例正常执行到结果比较后，必须因缺少明文反馈被oracle拒绝。
脚本只用于研究，不改变产品配置或协议行为。

复查命令（无需连接设备）：

```sh
python3 tools/steam-adaptive-host64-audit.py --binary /path/to/pinned/win64/SteamUI.dll
# 下列反例应非零退出，并明确因输出不匹配失败：
python3 tools/steam-adaptive-host64-audit.py --binary /path/to/pinned/win64/SteamUI.dll --mutation decoder-margin
python3 tools/steam-adaptive-host64-audit.py --binary /path/to/pinned/win64/SteamUI.dll --mutation encoder-store
python3 tools/steam-adaptive-host64-audit.py --binary /path/to/pinned/win64/SteamUI.dll --mutation ping-recovery
python3 tools/steam-adaptive-host64-audit.py --binary /path/to/pinned/win64/SteamUI.dll --mutation history-pool
python3 tools/steam-adaptive-host64-audit.py --binary /path/to/pinned/win64/SteamUI.dll --mutation sender-rate
python3 tools/steam-adaptive-host64-audit.py --binary /path/to/pinned/win64/SteamUI.dll --mutation fps-threshold
python3 tools/steam-adaptive-host64-audit.py --binary /path/to/pinned/win64/SteamUI.dll --mutation ping-slot-expiry
python3 tools/steam-adaptive-host64-audit.py --binary /path/to/pinned/win64/SteamUI.dll --mutation ping-auto-sequence
python3 tools/steam-adaptive-host64-audit.py --binary /path/to/pinned/win64/SteamUI.dll --mutation ping-response-size
python3 tools/steam-adaptive-host64-audit.py --binary /path/to/pinned/win64/SteamUI.dll --mutation ping-ledger-expiry
python3 tools/steam-adaptive-host64-audit.py --binary /path/to/pinned/win64/SteamUI.dll --mutation mode-request-branch
python3 tools/steam-adaptive-host64-audit.py --binary /path/to/pinned/win64/SteamUI.dll --mutation mode-cap
python3 tools/steam-adaptive-host64-audit.py --binary /path/to/pinned/win64/SteamUI.dll --mutation mode-reset
python3 tools/steam-adaptive-config64-audit.py --binary /path/to/pinned/win64/SteamUI.dll
# 此反例移除apply的请求值写入，应因applied值不匹配而非零退出：
python3 tools/steam-adaptive-config64-audit.py --binary /path/to/pinned/win64/SteamUI.dll --mutation
python3 tools/steam-adaptive-client-feedback-audit.py \
  --binary /path/to/pinned/linux/package/bin/steamlink --output /tmp/linux-feedback.json
# 此反例同样应因反馈缺失而非零退出：
python3 tools/steam-adaptive-client-feedback-audit.py \
  --binary /path/to/pinned/linux/package/bin/steamlink --output /tmp/linux-mutant.json --mutation
```

## 复刻能力的实际边界

客户端可以忠实实现配置、实时帧/网络反馈、丢失及decoder压力通知、下行配置/目标处理，
让仍运行官方Steam的主机使用其原有控制器。主机估计器不需要再在Switch复制一份后
同时调节同一请求。代码已具有部分反馈通路，但尚无全链等价验收。

完整复刻的验收必须覆盖配置到host模式门槛、实际feedback到各host入口、decoder溢出
通知、host内部估计到实际编码器设置/输出，以及恢复/稳态分支；只恢复消息99或者
移植旧x86的乘0.9都不构成完整复刻。本轮已执行到x64编码stage状态，未完成真实wire到设备编码输出的全部producer/consumer闭环，
也未证明当前用户Steam版本与该快照完全一致。因此不把“机制已经找到”写成“实现已完整”。
