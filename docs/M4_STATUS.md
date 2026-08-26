# M4 状态整理

> 目标：把 M3.5 的自动串流 probe 变成可操作的正式 app UI；先做 host/mode/PIN/stop/exit，
> 再接入 Steam Remote Play 手柄输入回传。

## 当前状态

- 2026-08-25 已完成 M4 UI 与第一版手柄输入回传本地实现；真机反馈为菜单按键有效。
- 2026-08-26 真机验证通过 D-029 两项：用户确认 `A/B/X/Y` 按 Switch 面壳字母方向响应（映射
  override 生效），且在 Steam UI 内启动游戏不再卡帧（video channel 重启路径工作）。同轮
  长跑证据：单会话 16409 帧 / 293 秒，全程 `gaps=0`，所有 `hid summary` 行 `send_fail=0`，
  `+` 退出后完整 cleanup（join watchdog/stream worker、IHS_Quit、SDL teardown、关日志 socket）。
- 2026-08-26 用户新报告真机症状：串流中时不时输入完全断流——断流期间 Steam 端完全收不到
  按键事件，此前按住的动作（如奔跑）会一直保持，直到恢复后才由下一次按键跳变纠正。
- 机制定位（代码证据链，详见 decisions D-030）：输入以 delta 增量链语义发送
  （`sdl_hid_event.c` 每个 SDL 变化 `AddDelta` 且立即推进 baseline）；报告走可靠控制通道，
  HID 重试上限仅 3 次×10ms 后放弃不补（`ch_control.c:110`、`retransmission.c:184`）；app 只在
  有新 SDL 事件的帧才 flush（`media.c` hid_changed 门控），SDL provider 无 poll()，事件间通道
  完全静默。三者叠加：视频高码率突发期小包持续被丢 → 窗口内全部按下/释放 delta 丢失 → 主机
  状态停在丢失前（松键丢失=持续奔跑，后续 delta 继续丢=看起来无任何键事件）。
- 同轮日志证据支持该链：控制通道在激烈画面时段大量 `Giving up on Packet(channelId=1)`
  （HID 上限 3 次，routine give-up），而全程 `hidSendFail=0`、视频满速——本地提交侧从未失败，
  丢失发生在网络/主机侧；整场会话主机未发过一次 `DeviceRequestFullReport`（协议内建的
  全量重同步请求，ihslib 双端已实现），即主机没有自动兜底。
- 修复（D-030 定案）：实现公开头文件早已预留的 `IHS_HIDRefreshSDLGameControllers()`（强制全量
  快照入队并发送，等价官方 RequestFullReport 触发的处理逻辑），app 在 streaming present 循环中
  每 100ms 心跳调用；Moonlight 以 `inputSendPeriodUs` 周期全量重发防 UDP 丢包，为同族协议的
  战场验证先例。UDP debug `hid` 输出与每秒 summary 新增 `stateFull` 计数用于真机核验。
- 本地构建产物：
  - `build/switch/app/nsteamlink.nro`
    sha256 `bc7ef74b79938c2b4978133730869369660c6b01d3ec041f1b2920b90f38d31e`；
  - `build/switch/tools/switch-stream-probe/switch-stream-probe.nro`
    sha256 `845b622d94319358752ea3f14bed1304e9e05591095b250fc63fc3eb0d86b93d`。
- 正式 app 不再默认开机自动开始串流；`switch-stream-probe` 仍保留自动 3600 帧长跑行为。
- 2026-08-25 真机复测：按键不再卡死画面和本地 `+` 退出，说明日志背压修正有效；但 stream
  内普通按键仍对 Steam/game 无效果。当前结论只能收敛到“本地事件循环可退出，Steam 端输入消费链路仍未证实”，
  不能断言是 report 格式、设备声明或 host open/start 的哪一环。
- 2026-08-25 诊断版真机计数：`hidEvents=266 hidSendOk=149 openOk=8 start=7 startLen=73`
  且 `ctrlRetrans=5 ctrlWarn=3`。证据证明 Steam host 已经 open 设备并启动 input reports，
  Switch 也在发送 HID report；新的待验证假设是 host 要求 73 字节 wire report，而 ihslib SDL provider
  仍硬编码发送 48 字节 full/delta report。
- 2026-08-25 后续真机计数：`hidEvents=928 hidSendOk=478 openOk=8 start=8 startLen=73
  ctrlWarn=0 activeInput=1`，用户观察仍为“没有效果”。该证据排除“本地没有 SDL 事件”、
  “host 没 open/start input reports”、“wire 长度仍是 48”、“control warning 卡住”作为当前直接结论。
- 2026-08-25 重新研读上游后修正：`third_party/ihslib/samples/stream` 没有添加 HID provider，
  不能作为 Steam 手柄输入端到端可用的证据；ihslib SDL HID 的 managed test 只覆盖本地虚拟 controller，
  也没有真实 Steam host。Switch SDL2 后端固定暴露 8 个 `Switch Controller`，而本项目 stream request
  只 reserve `gamepadCount=1`，因此将正式 app 改为按 ihslib unmanaged provider 示例由 app 打开并只
  上报默认 controller，避免 8 个 SDL 槽位泄漏到 Steam host。
- 2026-08-25 用户真机确认输入已经能被 Steam/game 消费；新问题是 Steam 端看到的 `A/B` 映射反了
  （`X/Y` 待用户确认），以及在 Steam UI 内选定游戏启动时，host 停止当前串流、游戏在 PC 上独立运行，
  Switch 端停在最后一帧但进程未死。
- 正式 app 不再默认开机自动开始串流；`switch-stream-probe` 仍保留自动 3600 帧长跑行为。

## 已完成

- `nsteamlink.nro` 启动后自动初始化 SDL2 媒体层、IHS client，并发起一次 host discovery，但等待用户操作后才开始 stream。
- 新增 SDL2 英文 overlay UI：
  - 内置 5x7 bitmap 字体，不依赖 Switch console 字库；
  - 菜单/PIN 页面使用暗底大面板；
  - 串流中只显示左上角小 HUD，避免遮挡画面。
- 菜单控制：
  - `A`：启动当前 host 的 stream；
  - `X`：切换 `GAME` / `DESKTOP`；
  - `Y`：重新 discovery；
  - `UP/DOWN`：切换 host；
  - `B`：停止当前 stream；
  - `+`：退出 app。
- Streaming PIN UI：
  - Steam 返回 `IHS_StreamingPINRequired` 后进入 PIN 输入模式；
  - `LEFT/RIGHT` 移动 4 位光标；
  - `UP/DOWN` 修改当前数字；
  - `A` 提交 PIN 并按原 stream 模式重试；
  - `B` 取消 PIN 输入。
- debug `press` 命令复用同一套输入逻辑，支持
  `A/B/X/Y/MINUS/PLUS/MINUS+B/MINUS+PLUS/UP/DOWN/LEFT/RIGHT`。
- 第一版输入回传：
  - `nsteamlink.nro` 的 streaming request 启用 `input=true` 与 `gamepadCount=1`；
  - app target 链接 `ihslib-hid-sdl`，使用 ihslib SDL HID provider；当前使用 unmanaged provider
    只暴露 app 打开的默认 Switch controller，和 `gamepadCount=1` 对齐；
  - Switch 目标没有 SDL3 portlib，故 `ihslib-hid-sdl` 在 Switch 上通过 SDL2 compatibility shim 构建，
    不在 app 中重新拼 HID report；
  - SDL controller events 在 media present loop 中交给 `IHS_HIDHandleSDLEvent()`，并按 ihslib 注释建议
    一帧 flush 一次 `IHS_SessionHIDSendReport()`；
  - session negotiation 显式发送 `CStreamingClientConfig.enable_input_streaming=true`；源码证据是
    `IHS_SessionHIDSendReport()` 会被 `IHS_SessionInputEnabled()` 门控；
  - stream 中按约每秒输出 `hid summary: events=... send_ok=... send_fail=...`，用于区分 SDL 事件、
    report 发送门控、Steam host 接收三类问题；
  - 用户真机观察到按键后 overlay 帧数卡住且 `+` 无法退出；同期日志显示 HID event/report 已进入，
    随后控制通道重传日志爆发。修正为 nxlink 日志 fd 非阻塞、每帧最多 drain 8 条日志，并对控制通道
    retransmission 日志做限流，避免诊断输出卡住渲染和本地退出路径；
  - 2026-08-25 用户复测确认“不会卡死”，且 `+` 可退出；同次观察确认输入仍无效果；
  - 新增 UDP debug `hid` 命令，不依赖 `nxlink -s`：
    `hidEvents/hidSendOk/hidSendFail` 来自 Switch SDL/media 侧累计计数；
    `openOk/openFail/start/startLen/full/getFeature/getStrings/noDevice/ctrlRetrans/ctrlWarn`
    来自 ihslib HID/control 日志解析，用于判断 Steam host 是否 open 设备、是否 start input reports、
    是否出现 control 重传/告警；
  - ihslib 成功路径补 `StartInputReports(id, length)` 与 `RequestFullReport(id)` debug 日志；
  - 根据上面的真机计数，把 SDL provider 的 full/delta report 改为按
    `StartInputReports(length=...)` 请求的 wire 长度发送；内部 SDL 状态仍为 48 字节，wire report 前
    48 字节为实际状态，剩余字节补 0；
  - `hid` UDP 输出新增 `providerDevices/sdlJoy/sdlIndex/sdlInstance/sdlType/lastEvent/sdlName/sdlGuid`，
    用于验证 SDL 事件是否落在 Steam open/start 的同一 controller；
  - ihslib `DeviceFeatureReport` 优先使用 `SetPlayerIndex` 写入的 `sdl->playerIndex`，避免 Switch SDL
    后端 player-index setter 空实现导致 feature report 一直回报 `-1`；
  - third_party 侧新增 `third_party/patches/ihslib/0010-hid-active-input-player-index.patch` 记录
    `active_input=true` 与 player-index feature report 修正；
  - session stop 前调用 `IHS_HIDResetSDLGameControllers()`，再 disconnect/join/destroy session；
  - streaming 中 `+` 保留为本地退出/停流逃生键，`MINUS+B` 停止 stream；普通游戏按键和摇杆不再被本地
    UI 截获。
- 输入映射修正：
  - devkitPro SDL Switch 后端证据：
    `/tmp/devkitpro-sdl-switch-2.28-573101/src/joystick/switch/SDL_sysjoystick.c` 的默认 raw button
    顺序是 `A,B,X,Y`；
  - SDL gamecontrollerdb 证据：
    `/tmp/devkitpro-sdl-switch-2.28-573101/src/joystick/SDL_gamecontrollerdb.h` 对
    `Switch Controller` 使用 `a:b1,b:b0,x:b3,y:b2`；
  - app 启动时用 `SDL_GameControllerAddMapping()` 覆盖为 `a:b0,b:b1,x:b2,y:b3`，让 Steam 端按
    Switch 面壳字母接收，日志打印 `hid sdl mapping override` 与选中 controller 的最终 mapping。
- 游戏启动/串流切换修正：
  - 代码证据：`third_party/ihslib/src/session/channels/ch_control_video.c` 旧实现收到
    `k_EStreamControlStartVideoData` 时若已有 video channel 就直接 `break`，会静默忽略新的 video start；
  - 代码证据：`third_party/ihslib/src/session/channels/channel.c` 的 `IHS_SessionChannelRemove()` 在删除
    非最后一个动态 channel 时只 `memmove`，没有递减 `numChannels`，会留下已销毁 channel 指针；
  - 修正为 `StartVideoData` 到达时记录 channel/codec/size/codecData，如已有 video channel 则先
    remove 再按新消息创建；`StopVideoData` 也记录当前 channel；
  - `state` debug 输出新增 `lastFrameAgeMs`，streaming overlay 显示 `STATUS`；首帧后超过 2500ms 没有新帧时，
    UI 显示 `Video stalled; waiting for Steam`，避免停在最后一帧时没有本地证据。

## 本地验证

- `cmake --build build/switch --target nsteamlink_nro switch-stream-probe_nro -j$(nproc)` 通过。
- `git diff --check` 与 `git -C third_party/ihslib diff --check` 通过。
- 当前产物：
  - `build/switch/app/nsteamlink.nro`
    sha256 `b3ba34d9debf3ee0d52816681ae2b10ed13621251a1ada1ab4ee8e29f787059a`
  - `build/switch/tools/switch-stream-probe/switch-stream-probe.nro`
    sha256 `e602cac58c6e730aa01fe8dded8b59b9d925de3e9b0a109b0b0a240622849b91`

## 待验证

- 真机上菜单文字可读、没有遮挡主要串流画面。
- `A` 启动 game stream；菜单中 `B` 停止、`+` 退出；streaming 中 `MINUS+B` 停止、`+` 退出。
- 如果 Steam host 返回 `PINRequired`，四位 PIN UI 能提交并成功重试。
- Steam host 能收到 Switch 手柄输入，且 stop/exit 后不会残留按键按下状态。
- 真机确认 Steam/game 里的 `A/B/X/Y` 是否按 Switch 面壳字母正确映射。
- 真机确认在 Steam UI 内选游戏启动时，host 是否发送 `StopVideoData` / 新 `StartVideoData`，以及本版是否能
  重新接上 video channel；若仍停帧，用 `state` 的 `lastFrameAgeMs` 与屏幕 `Video stalled` 判断是 host
  不再送帧，还是 client 仍在接收但渲染/解码停住。
- `CMsgRemoteDeviceStreamingRequest` protobuf 有 `gameid` 字段，但当前 `IHS_StreamingRequest` 与 UI 没有
  游戏 ID 来源。直接按 appid/gameid 启动游戏属于后续功能，不能把它当作本次 Steam UI 内选游戏停流的已证根因。
- 下一次真机 stream 中若按键仍无效果，先用 UDP `hid` 命令采集证据：
  - `openOk=0`：Steam host 没有 open 我们枚举出的 HID 设备；
  - `openOk>0 && start=0`：host open 了设备但没启动 input reports；
  - `start>0 && hidSendOk>0 && ctrlRetrans/ctrlWarn>0`：优先看 control reliable packet / ACK 路径；
  - `start>0 && hidSendOk>0 && ctrlRetrans=0`：再检查 48 字节 report 内容、caps、controller 类型/映射。

## 下一步

- 真机确认手柄输入后，进入音频输出；并开始把 UI/stream 状态模块从 probe 源中逐步拆出，避免正式 app
  和证据 probe 长期共用越来越多临时代码。
