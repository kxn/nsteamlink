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

新样本还存在两种独立反馈入口：

- `0x13a170fc0`：data loss 的早期时间门槛、估计速率取样、历史记录及重算。
- `0x13a171a10`：client video decoder overflow，亦有早期门槛并进入重算。

重算 `0x13a172500` 结合丢失后时间、链路估计、系数、decoder约束和上下限；
它与旧x86直接乘0.9的处理不同。目标更新入口 `0x13a1948f0` 在新的选择值与保存值
相差至少1000 kbps时推进目标/突发预算设置。通知目标、动态估计值和编码器实际输出
仍是不同观测量；不能把任一条目标日志当作整套自适应已通过。
本轮x64为静态复核，不能把x86执行用例算成x64回归。

## 复刻能力的实际边界

客户端可以忠实实现配置、实时帧/网络反馈、丢失及decoder压力通知、下行配置/目标处理，
让仍运行官方Steam的主机使用其原有控制器。主机估计器不需要再在Switch复制一份后
同时调节同一请求。代码已具有部分反馈通路，但尚无全链等价验收。

完整复刻的验收必须覆盖配置到host模式门槛、实际feedback到各host入口、decoder溢出
通知、host内部估计到实际编码器设置/输出，以及恢复/稳态分支；只恢复消息99或者
移植旧x86的乘0.9都不构成完整复刻。本轮未完成x64全部producer/consumer闭环，
也未证明当前用户Steam版本与该快照完全一致。因此不把“机制已经找到”写成“实现已完整”。
