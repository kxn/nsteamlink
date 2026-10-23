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
