# third_party — 第三方依赖目录

所有外部库以 git submodule 或 vendored 源码形式放在这里，**禁止就地修改**。
对一般第三方库的改动以 patch 文件放 `patches/<库名>/` 并在 `docs/decisions.md` 登记；
**例外：IHSlib 使用本项目的 GitHub fork（D-037），改动直接提交到 fork 分支并推送**。

## 已引入

| 库 | 版本 | 说明 |
|---|---|---|
| IHSlib | `kxn/ihslib` `nsteamlink` 分支，基线 `8c5a17c`（fork 自 `beudbeud/ihslib` plume） | 协议层依赖；改动直接进 fork 分支（D-037） |

## IHSlib fork（kxn/ihslib，分支 nsteamlink）

基线为上游 `beudbeud/ihslib` plume 分支 pin `8c5a17c`。基线之上的全部项目改动
（历史补丁 0001–0013 的内容 + 后续工作）已固化为 fork 上的单提交 `263fd5d`，
其内容与当时通过双目标构建和 ihslib 27/27（host / ASan+UBSan / TSan）测试的
submodule 工作区逐字节一致。旧 patch 文件已删除，需要查阅时从本仓库 git 历史取回
`third_party/patches/ihslib/`（0001–0013 为按主题分层的历史记录，0020 为当时的
权威累计快照；分层补丁单独/顺序重放已不可靠）。

改动内容按主题：

- Switch/libnx 可移植性：socket/线程/构建适配，SDL HID provider 改为可选；
  授权请求固定缓冲区复制后显式补 NUL；streaming request 不在持有 client base 锁时
  启动 timer；授权响应与 pairing 消息日志。
- SDL HID provider：SDL2 兼容垫片（Switch 无 SDL3 portlib）；wire report 长度跟随
  `StartInputReports(length=...)`；active_input 与 player-index feature report 修正；
  `IHS_HIDRefreshSDLGameControllers()` 全量状态心跳（D-030）。
- 控制通道可靠状态机（D-034）：初发前登记、精确 ACK 删除、NACK 立即重发不设次数上限；
  被新完整快照取代的旧 HID 包三次补洞后以 superseded 退休；HID 双可靠在途 lane +
  最新待发快照，单 ACK 永久缺失不再锁死输入；SDL 线上只发完整状态。
- 会话稳定性：session negotiation 显式请求 `enable_input_streaming=true`；
  host 侧重发 `StartVideoData` 时先 remove 再重建 video channel；
  `IHS_SessionChannelRemove()` 的 `numChannels` 簿记修复（D-029）；
  session socket 10ms receive timeout，StopRequest 后 join 有界返回（D-035）。
- 测试：重传状态机、HID admission、HID report replace、disconnect-destroy 回归，
  共 27 例。

## 后续改 ihslib 的流程（取代 patch 流程，D-037）

1. 在 `third_party/ihslib` 内（`nsteamlink` 分支）正常提交；
2. `git push fork nsteamlink`（remote `fork` = `https://github.com/kxn/ihslib.git`）；
3. 父仓库随之更新 submodule pin 并提交；
4. 若日后上游恢复活动，评估把 `nsteamlink` 分支的独立主题以 PR 反哺上游
   （控制可靠状态机是现成素材）；反哺被吸收前，fork 为权威源。

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
