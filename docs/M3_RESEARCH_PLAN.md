# M3 调研与实施计划：串流请求到第一帧

> 日期：2026-08-24
> 状态：调研/规划完成，尚未开始实现。

## 目标边界

M3 的目标是：复用 M2 已保存的 `auth.bin` 身份，在 Switch 真机上向 Steam host 发起
`IHS_ClientStreamingRequest()`，建立 `IHS_Session`，收到视频 data channel 的 H264 帧，并通过
Switch 版 FFmpeg/NVTEGRA + SDL2 显示第一帧。

M3 不包括音频、输入回传、完整菜单、长期串流稳定性、HEVC、1080p、零拷贝渲染和自动重连。这些进入
M4/M5。M3 的验收画面可以是 720p30/720p60 的第一帧，默认只走 H264。

## 证据等级

- P0：本项目真机日志、用户截图/反馈、实际命令输出。
- P1：本仓 vendored 源码、本机 devkitPro/portlibs 头文件和库。
- P2：上游 primary source，例如 SteamDatabase protobuf、beudbeud/plume、beudbeud/ihslib、
  devkitPro 包脚本、FFmpeg 官方示例/邮件列表。
- P3：需要真机验证的假设。文档中统一标为 `待验证`。

## 已确认事实

### M2 基线

- P0：2026-08-24 真机日志显示 `switch-discover` 已发现 `kxn-pc (10.10.10.166)`，且
  `gamesRunning=1`。
- P0：同次日志显示 pairing code `3383`，authorization response 从 `result=5` 进展到
  `result=0 steamid=76561198217069647`，并保存 `sdmc:/switch/nsteamlink/auth.bin`。
- P0：用户确认 `debug exit` 后退出成功，无 Atmosphere fatal。
- 结论：M3 可以直接复用 M2 的 `auth.bin` 身份和 host discovery 结果，不应重新改 pairing 主流程。

### Steam streaming request 语义

- P1：`third_party/ihslib/include/ihslib/client.h:52` 定义 streaming result；`PINRequired=11`。
- P1：`third_party/ihslib/include/ihslib/client.h:78` 定义 `IHS_StreamingRequest`，字段包括
  `pin`、video/audio/input enable、resolution、`streamingInterface`、`streamDesktop`、`gamepadCount`。
- P1：`third_party/ihslib/src/client/streaming.c:72` 处理 proof request，用 `secretKey` 加密 host
  challenge。
- P1：`third_party/ihslib/src/client/streaming.c:101` 处理 streaming response；成功时解密
  `encrypted_session_key`，回调给应用 session 地址、端口和 session key。
- P1：`third_party/ihslib/src/client/streaming.c:176` 把 request 的 `pin` 填入
  `CMsgRemoteDeviceStreamingRequest.pin`。这是 streaming/security PIN，不是 M2 pairing code。
- P1：`third_party/ihslib/src/client/streaming.c:209` 说明 `device_version="1.1.0"` 用于让 host 尊重
  max resolution；streaming request 没有 codec 字段。
- P2：SteamDatabase 当前 `steammessages_remoteclient_discovery.proto` 定义
  `CMsgRemoteDeviceStreamingRequest` 字段 `pin`、enable flags、transport、`stream_interface` 和
  `CMsgRemoteDeviceStreamingResponse` 的 `port/encrypted_session_key`。
- 结论：M3 的第一步必须是独立验证 streaming request 成功拿到 session 地址/密钥；遇到
  `IHS_StreamingPINRequired` 时才显示/输入 streaming PIN，不能回退到 pairing 解释。

### Session 与视频通道

- P1：`third_party/ihslib/include/ihslib/session.h:36` 的 `IHS_SessionInfo` 包含 streaming address、
  `sessionKey[32]`、`sessionKeyLen`、`steamId`。
- P1：`third_party/ihslib/include/ihslib/session.h:43` 的 session config 可控制
  audio、HEVC、最大分辨率、FPS 和码率。
- P1：`third_party/ihslib/src/session/session.c:76` 创建 session 时建立 discovery/control/stats channel、
  retransmission、HID manager 和 frame stats。
- P1：`third_party/ihslib/src/session/session.c:110` 的 `IHS_SessionConnect()` 启动 session worker。
- P1：`third_party/ihslib/src/session/session.c:139` 的 `IHS_SessionDisconnect()` 会先发
  `StopRequest`，最多等待 ACK 后断开；M3 退出必须沿用这个标准路径。
- P1：`third_party/ihslib/src/session/channels/ch_control_negotiation.c:77` 根据应用回调填充 session
  config；默认 H264、audio on，但应用可改成 audio off、HEVC off。
- P1：`third_party/ihslib/src/session/channels/ch_control_negotiation.c:198` 总是启用 video streaming，
  `:220` 之后按 `enableHevc` 宣告 H264/HEVC 能力。
- P1：`third_party/ihslib/src/session/session.c:270` 支持 host 未发送 StartVideoData 时按已协商 codec
  懒创建 video channel。
- P1：`third_party/ihslib/include/ihslib/video.h:79` 定义 video callbacks；`submit()` 收到
  `frameId`、完整帧 buffer 和 keyframe flag。
- P1：`third_party/ihslib/src/session/channels/video/ch_data_video.c:188` 解析 video frame header、
  解密、处理丢包和 keyframe 重请求；`:262` 组帧完成后调用应用 `submit()`。
- P1：`third_party/ihslib/src/session/channels/video/frame_h264.c:29` 在需要时插入 Annex-B start sequence；
  `frame_hevc.c` 同理。
- 结论：M3 解码层收到的是 IHSlib 已组好的 H264/HEVC 帧；应用仍必须按 `frameId` 回报 decode/upload
  stage 和 frame complete，否则 host 的 adaptive bitrate/stats 会缺信息。

### plume 参考实现

- P2/P1：本地 plume `7ebd62b` 的 `src/ihs.c:273` 在 stream success 中先检查 `keyLen <= 32`，
  再复制进 `IHS_SessionInfo`。本项目 M3 必须保留这个边界检查。
- P2/P1：plume `src/ihs.c:314` 使用 static streaming callbacks；注释说明 IHSlib 保存的是 callback
  指针，不是结构体拷贝。M3 所有 callback struct 必须具备静态或长期生命周期。
- P2/P1：plume `src/ihs.c:317` 发起 request 时默认 video/audio/input 全开；`streamDesktop=true`
  对应 Desktop，false 对应 Big Picture/game session；`:326` 说明先 `IHS_ClientStartDiscovery(client, 0)`
  保持 worker/socket 服务。
- P2/P1：plume `src/main.c:196` 的 session 流程是 `MediaAttach -> IHS_SessionCreate -> set callbacks ->
  IHS_SessionConnect -> MediaPresent loop -> Disconnect/Join/Destroy`。
- P2/P1：plume `src/media.c:153` 在 video start 中选 FFmpeg decoder，`:332` 在 `submit()` 中把 IHS buffer
  复制到 `av_new_packet()`，`:347` 的注释说明 FFmpeg bitstream reader 需要 padding。
- P2/P1：plume `src/media.c:417` 在主线程上传/呈现帧，并回报 upload/display stats。
- 结论：M3 可以复用 plume 的流程思想，但不能照抄 SDL3、Linux DRM/V4L2 代码；Switch 路线应是
  FFmpeg NVTEGRA 解码 + SDL2 texture 上传。

### Switch FFmpeg / SDL2 依赖

- P1：本机 `/opt/devkitpro/portlibs/switch` 已安装 `libavcodec 61.19.100`、`libavutil 59.39.100`、
  `libswscale 8.3.100`、`libswresample 5.3.100`、`SDL2 2.28.5`、`opus 1.3`。
- P1：`libavutil/hwcontext.h` 暴露 `AV_HWDEVICE_TYPE_NVTEGRA`；`libavutil/pixfmt.h` 暴露
  `AV_PIX_FMT_NVTEGRA`；`strings libavcodec.a` 能看到 `h264_nvtegra`、`hevc_nvtegra`。
- P2：devkitPro `switch-ffmpeg` PKGBUILD 使用 `--enable-libnx --enable-nvtegra` 构建 FFmpeg。
- P2：averne 在 FFmpeg-devel patch series 中说明该 backend 面向 Tegra/Nintendo Switch，并支持 H264/HEVC
  等硬件解码。
- P2：FFmpeg `doc/examples/hw_decode.c` 展示了标准硬解初始化流程：枚举 `avcodec_get_hw_config()`，
  `av_hwdevice_ctx_create()`，设置 `get_format`，必要时 `av_hwframe_transfer_data()`。
- 结论：M3 应直接使用 devkitPro portlibs 的 switch-ffmpeg，不再从 Moonlight-Switch 拷预编译库；
  首帧验收必须打印 `AV_HWDEVICE_TYPE_NVTEGRA` / `AV_PIX_FMT_NVTEGRA` 是否实际命中。

### Socket buffer 风险

- P1：M2 工具当前用 `socketInitializeDefault()`。
- P1：IHSlib UDP backend 在 `third_party/ihslib/src/platforms/ihs_udp_posix.c:60` 请求 4MB
  `SO_RCVBUF`，并在 `:70` 打印实际 buffer 不足的警告。
- P2/P1：libnx `SocketInitConfig` 暴露 `udp_rx_buf_size`；官方源码默认值是 `0xA500`，约 42KB。
- 结论：M3 session/video 前必须改为自定义 `socketInitialize()` 配置，并在 Switch 真机日志里记录
  UDP receive buffer 实测值；否则第一帧可能因为 keyframe datagram burst 丢包而失败。

## M3 实施顺序

### M3.0：保护 M2 基线

- 新增 `tools/switch-stream-probe`，不要在第一轮直接改 `switch-discover` 主路径。
- 复用 M2 的 `auth.bin` 文件格式和英文 console 输出；不引入中文 UI 字符串。
- 保留固定 Switch 地址规则：netloader `10.10.10.77:28280`，debug UDP `28772`；不做 TCP 空探测。
- 新 probe 先只支持 debug 命令驱动，避免再依赖用户反复手动按键。

验收：

- `scripts/build-switch.sh` 能同时构建 M2 和 M3 probe。
- M2 的 `switch-discover` 不回归：能启动、读 `auth.bin`、发现 host、退出。

### M3.1：streaming request probe

实现一个最小 `stream-request` 命令：

- 加载 `auth.bin`，发现或复用最近 host。
- 构造 `IHS_StreamingRequest`：
  - `video=true`
  - `audio=false`
  - `input=false`
  - `maxResolution=1280x720`
  - `streamDesktop=true` 默认；另提供 `game` 选项设置 `streamDesktop=false` /
    `IHS_StreamInterfaceBigPicture`
  - `pin=""`，只有 host 返回 `IHS_StreamingPINRequired` 后才允许 debug/UI 输入 streaming PIN 重试
- 调用 `IHS_ClientStartDiscovery(client, 0)` 后再调用 `IHS_ClientStreamingRequest()`。
- streaming success 时做 `keyLen <= sizeof(sessionKey)` 检查，打印 session IP、port、keyLen。

验收：

- debug `state` 可看到 `stream_result=0`、`session_port=<host返回端口>`、`key_len<=32`。
- 若返回 `PINRequired=11`，屏幕/debug 明确显示需要 streaming PIN；不得称为 pairing code。
- 若返回 `Unauthorized=1`，进入 M2 pairing 路径或提示重配对；不得要求用户输入 Steam security PIN。

### M3.2：session/video channel probe，不解码

在 M3.1 成功后创建 `IHS_Session`：

- session callbacks 使用 static storage。
- `configuring()` 设置 `enableAudio=false`、`enableHevc=false`、`maxWidth=1280`、`maxHeight=720`、
  `maxFps=30` 或 `60`、`maxBitrateKbps=6000`。
- video callbacks：
  - `start()` 打印 codec、width、height、codecDataLen。
  - `submit()` 只计数和记录前几帧大小/keyframe/frameId；为了不让 stats 缺口无限扩大，对每个处理过的
    frame 调用 `IHS_SessionReportVideoFrameStage(...DecodeBegin/DecodeEnd...)` 和
    `IHS_SessionReportVideoFrameComplete(...DroppedDecodeSlow...)`，并在日志中明确这是 probe 模式。
  - 收到首个完整 frame 后可自动断开 session，走 `IHS_SessionDisconnect -> ThreadedJoin -> Destroy`。

验收：

- 日志出现 session connected/negotiation。
- 日志出现 `video_start codec=4`（H264）和至少一个完整 frame 的 `frameId/size/keyframe`。
- 退出后 host 不残留串流会话；Switch 无 fatal。

### M3.3：FFmpeg/NVTEGRA 解码 + SDL2 显示第一帧

在 M3.2 证明协议/session/video data 正常后接解码和渲染：

- 初始化 SDL2 window/renderer。
- H264 only：`avcodec_find_decoder(AV_CODEC_ID_H264)`，枚举 `avcodec_get_hw_config()`，优先选择
  `device_type == AV_HWDEVICE_TYPE_NVTEGRA` 和 `pix_fmt == AV_PIX_FMT_NVTEGRA`。
- `av_hwdevice_ctx_create(&hwDeviceCtx, AV_HWDEVICE_TYPE_NVTEGRA, NULL, NULL, 0)` 成功后设置
  `vctx->hw_device_ctx` 和 `get_format`。
- `submit()` 使用 `av_new_packet()` 分配带 padding 的 packet，再复制 IHS buffer。
- `avcodec_send_packet()` / `avcodec_receive_frame()` 解码；若输出 `AV_PIX_FMT_NVTEGRA`，M3 先用
  `av_hwframe_transfer_data()` 读回 CPU frame，再上传 SDL2 texture。零拷贝以后再做。
- SDL2 上传优先尝试 `SDL_PIXELFORMAT_NV12` / `SDL_PIXELFORMAT_IYUV`；不支持时用 swscale 转成稳定格式。
- 每帧按 IHSlib API 回报 DecodeBegin/DecodeEnd、UploadBegin/UploadEnd 和 `Displayed`。

验收：

- Switch 屏幕出现 Steam host 画面第一帧。
- nxlink/debug 日志至少包含：
  - streaming request success：host、port、keyLen
  - session connected
  - negotiation request：1280x720、H264、audio off
  - decoder：`AV_HWDEVICE_TYPE_NVTEGRA` 命中，或明确失败原因
  - first frame displayed：frameId、resolution、decoded pixel format、upload format
- 用户确认退出无 fatal；日志显示标准 session cleanup。

### M3.4：从 probe 合入 app

只有 M3.1 到 M3.3 在真机上有证据后，再把已验证代码迁入 `app/`：

- 不把实验性 debug-only 状态机直接变成主 app 架构。
- 把 auth/host discovery/stream request/session/media 分成小模块。
- UI 仍保持英文；完整菜单、数字输入和手柄输入放到 M4 或 M3 后续补丁。

## 待验证问题

- `socketInitialize()` 自定义配置具体给多少：计划从 4MB UDP RX、4 个 BSD session 起步，但必须以
  `getsockopt(SO_RCVBUF)` 真机实测为准。
- Switch SDL2 是否能稳定创建 `NV12` texture。不能则先走 `IYUV` 或 RGB fallback。
- `AV_HWDEVICE_TYPE_NVTEGRA` 在真机上是否能初始化成功。当前证据只证明头文件/库已包含该 backend。
- H264 first frame 是否总带足 SPS/PPS。IHSlib 已插入 Annex-B start sequence，但若某些 host 将 codec
  data 单独放在 `codecData`，M3 需要在 decoder open 或首包前处理。
- FFmpeg 静态链接后 NRO 大小会明显增加；若 nxlink 再次卡在 `0 out of ... written`，测试阶段允许改用
  SD 卡复制，不把 netloader 传输问题误判为协议失败。

## M3 期间禁止事项

- 禁止把 streaming/security PIN 和 pairing code 混成同一概念。
- 禁止没有真机日志就断言 host 没响应、广播不可靠、Steam 没开、游戏没跑。
- 禁止只凭 `nxlink` 进程状态判断 Switch 程序是否仍在运行。
- 禁止在 M3 第一轮同时做音频、输入、菜单和解码优化。
- 禁止在没有 source/log 支持时改 IHSlib 状态机。

## Primary sources

- SteamDatabase current protobuf:
  https://github.com/SteamDatabase/Protobufs/blob/master/steam/steammessages_remoteclient_discovery.proto
- SteamDatabase Remote Play session protobuf:
  https://github.com/SteamDatabase/Protobufs/blob/master/steam/steammessages_remoteplay.proto
- beudbeud/plume `7ebd62b`:
  https://github.com/beudbeud/plume/tree/7ebd62bbf09c43412dfad86b91885a07ef46c098
- beudbeud/ihslib plume commit `8c5a17c`:
  https://github.com/beudbeud/ihslib/tree/8c5a17cc3da37222eb118550e2d9a62aac9f301b
- devkitPro switch-ffmpeg package:
  https://github.com/devkitPro/pacman-packages/blob/master/switch/ffmpeg/PKGBUILD
- averne FFmpeg NVTEGRA patch series:
  https://ffmpeg.org/pipermail/ffmpeg-devel/2024-May/328549.html
- FFmpeg hardware decode example:
  https://github.com/FFmpeg/FFmpeg/blob/master/doc/examples/hw_decode.c
- libnx socket init API/source:
  https://github.com/switchbrew/libnx/blob/master/nx/include/switch/runtime/devices/socket.h
  https://github.com/switchbrew/libnx/blob/master/nx/source/runtime/devices/socket.c
