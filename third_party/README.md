# third_party — 第三方依赖目录

所有外部库以 git submodule 或 vendored 源码形式放在这里，**禁止就地修改**；
需要的改动以 patch 文件放 `patches/<库名>/`，并在 `docs/decisions.md` 登记。

## 已引入

| 库 | 版本 | 说明 |
|---|---|---|
| IHSlib | `beudbeud/ihslib` plume 分支，pin `8c5a17c` | 协议层依赖；libnx/构建兼容改动走 `patches/ihslib/` |

## IHSlib 本地补丁

**应用方式（2026-08-26 起）**：在干净的 ihslib 检出上只应用
`0020-switch-port-cumulative.patch` 一个文件即可，它由 submodule 工作区对 pin `8c5a17c`
的完整 diff 生成，应用后与当前构建所用代码逐字节一致。
`0001–0011` 是按主题分层的历史记录，因后续改动共享上下文，单独/顺序重放已不可靠，
仅作查阅用途（文件头部有相同说明）。

- `0020-switch-port-cumulative.patch`：上述全部改动的当前权威快照，含新增的 SDL3 兼容垫片头文件。
- `0001-libnx-portability.patch`：Switch/libnx 构建与 socket/线程移植。
- `0002-optional-sdl-hid.patch`：SDL HID provider 改为可选，避免 Switch SDL2/SDL3 冲突。
- `0003-authorization-copy-termination.patch`：授权请求固定缓冲区复制后显式补 NUL。
- `0004-authorization-pairing-logs.patch`：补授权响应和 pairing 相关消息日志。
- `0005-streaming-request-lock-order.patch`：streaming request 不在持有 client base 锁时启动 timer，
  避免 `base -> timer` / `timer -> base` 锁顺序风险。
- `0006-sdl2-hid-provider-compat.patch`：让 `ihslib-hid-sdl` 可在 Switch SDL2 portlibs 下编译，
  复用上游 SDL HID provider 的 report/event 逻辑。
- `0007-enable-input-streaming-negotiation.patch`：session negotiation 显式请求
  `enable_input_streaming=true`，避免 HID report 被 `streamingInput` 门控丢弃。
- `0008-hid-diagnostic-logs.patch`：补 HID `StartInputReports` / `RequestFullReport`
  成功路径 debug 日志，让 app 能用 UDP `hid` 命令判断 Steam host 是否真的启动输入报告。
- `0009-sdl-hid-wire-report-length.patch`：SDL HID provider 按 Steam
  `StartInputReports(length=...)` 请求的 wire 长度发送 full/delta report；当前真机证据为 host 请求
  `length=73`，旧 provider 硬编码发送 48 字节。
- `0010-hid-active-input-player-index.patch`：SDL provider 优先上报 app 写入的 active player index，
  修复 Switch SDL 后端 player-index setter 空实现导致 feature report 回报 `-1`。
- `0011-video-channel-restart-cleanup.patch`：host 侧重发 `StartVideoData` 时先 remove 再重建 video
  channel（不再静默忽略），并修复 `IHS_SessionChannelRemove()` 删除非末尾 channel 时漏减
  `numChannels` 的确定性 bug。
- `0012-sdl-hid-full-state-refresh.patch`：实现 `IHS_HIDRefreshSDLGameControllers()`——对主机已启动
  input reports 的 SDL 设备强制追加一份当前状态 full report 并发送，供 app 以低频心跳重发，
  在可靠控制通道丢包后有界恢复手柄状态（delta 链本身无法自愈）。动机与证据见 decisions D-030；
  该 API 的声明与"低频刷新"契约此前已写在公开头文件 `ihslib/hid/sdl.h` 中，本补丁补上实现。

## 待引入（按里程碑）

| 库 | 引入时机 | 说明 |
|---|---|---|
| plume | M1 | 参考实现，仅作对照学习，不链接进本项目；克隆必须 `--recursive` |
| protobuf-c | M2 | devkitPro 无现成 Switch 包，用 `$DEVKITPRO/cmake/Switch.cmake` 交叉编译装入 portlibs |
| FFmpeg / SDL2 | M3 | 使用 devkitPro `switch-ffmpeg` / `switch-sdl2` portlibs；FFmpeg 已启用 `--enable-nvtegra` |

## 注意

- 克隆/拉取后务必 `git submodule update --init --recursive`，
  否则会静默回退上游版本且行为不对（kickoff §7.2 的坑）。
- 复用的任何第三方代码保留原版权与许可声明，并更新 `DEVELOPMENT.md` §7 的依赖表。
