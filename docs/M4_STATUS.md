# M4 状态整理

> **本文件已于 2026-08-28 冻结为历史档案，不再更新。**
> 后续状态与任务跟踪迁移至 GitHub Issues：当前遗留工作见
> [#1 BUG-M4-HID-001](https://github.com/kxn/nsteamlink/issues/1)、
> [#2 VIC transfer 验收](https://github.com/kxn/nsteamlink/issues/2)、
> [#3 音频验收](https://github.com/kxn/nsteamlink/issues/3)、
> [#4 本地控制键验收](https://github.com/kxn/nsteamlink/issues/4)、
> [#5 PIN/映射复核](https://github.com/kxn/nsteamlink/issues/5)、
> [#6 Frames window overflow 旁支](https://github.com/kxn/nsteamlink/issues/6)，
> 以及 [M4 milestone](https://github.com/kxn/nsteamlink/milestone/1)；
> backlog 见 #7 gameid 启动、#8 deko3d 迁移、#9 UI/stream 模块拆分。
> UDP 调试命令与字段释义已抽至 `docs/UDP_DEBUG.md`。
> 以下正文保留 2026-08-25 → 2026-08-28 的完整证据时间线，仅供追溯。

> 目标：把 M3.5 的自动串流 probe 变成可操作的正式 app UI；先做 host/mode/PIN/stop/exit，
> 再接入 Steam Remote Play 手柄输入回传。

## 当前状态

- 2026-08-28 用户在双 lane 版再次复现约 10 秒 host/game 输入无响应，并在故障后按数次 `-`。
  完整 SD 日志确认 SDL 与 libnx raw 均看到 marker；marker 前后约 4.4 秒内 HID 新快照发送/精确 ACK
  同步增加 93，最大 ACK 延迟保持 63ms，视频与音频持续推进。因此这轮不是 SDL 拒绝输入、客户端
  admission 堵塞或 Wi-Fi 整体断流，transport ACK 之后的 host virtual controller/game apply 仍待查。
  同时日志发现旧 HID packet 519 已重传 1400 余次；另一轮 packet 71 更持续 205 秒/2044 次，而新
  快照照常确认。现只对被更新完整快照取代的旧 HID 包保留至少三次补洞重传后退休，并将 exact ACK
  与 superseded 分开统计；这是独立状态机清理，不宣称修复上述约 10 秒症状。
- 2026-08-27 后续真机测试推翻了 D-034 的“单个 HID 在途包可以无限等待 ACK”设计。用户观察为
  Steam/game 端所有按钮均无效果；同轮 SD 持久日志仍有大量 SDL 事件与本地提交，但
  `rel=68/67 retry=420 out=1 oldest=41647ms@1/15/0#416`、
  `hidSM=1498/1497/2/1/1/1@15`。证据直接证明 control packet 15 的 ACK 缺失后，单在途 admission
  把 1497 次后续完整快照全部合并在 pending，实际只发出 2 次。修正为：可靠重传只在初发真正完成后
  才启动（25ms 首次等待），HID 使用两个可靠在途 lane 加 latest pending；即使一个 ACK 永久缺失，
  另一个 lane 仍可持续发送并确认最新完整状态。host、ASan+UBSan、TSan 均 27/27 通过，待真机复验。
- 2026-08-27 用户真机发现本地退出回归：串流中按 `L3+R3+VOL+` 后 Steam host 已停止串流，
  但 Switch 保持最后一帧且本地输入不再响应，只能 HOME 后强杀。D-035 已用 host 回归测试确定性复现：
  session StopRequest/transport timer 已执行，但 session UDP receive worker 仍永久阻塞在 `recvfrom()`，
  主线程因此卡在 `IHS_SessionThreadedJoin()`。根因是 10ms receive timeout 只配置给 discovery client，
  streaming session socket 被遗漏。现已给 session socket补相同 timeout；修复前测试超过 6 秒不返回，
  修复后无 host ACK 路径约 1.5 秒完成 `Disconnect -> Join -> Destroy`。同版真机退出日志完整出现
  `session disconnected`、session join/destroy、`IHS_Quit`、`SDL_Quit done` 与 `exiting`，用户确认
  Switch 端不再停在最后一帧，D-035 实机验收通过。
- 2026-08-27 已按 D-034 重写 control reliable/HID 发送状态机。旧的
  `Reliable + fire-and-forget` 方案会消耗可靠 packet ID 却不补丢包，与 control 有序接收窗口的
  head-gap 行为矛盾，现已撤回并删除。可靠包改为初发前登记、精确 ACK 删除、NACK 立即重发且不再
  按次数放弃；SDL 不再发送 delta 链。最初采用的“一个在途 full snapshot + latest pending”已被上述
  packet 15 真机证据否掉并改为双在途；该记录不再代表当前实现。
- 2026-08-27 新版已通过 nxlink 部署；用户在真机启动串流并实际测试后反馈没有任何问题。当前可记为
  首轮 smoke 通过，但后续 packet 15 复现已证明它不足以验收单在途状态机。

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
- 正式 app 不再默认开机自动开始串流；`switch-stream-selftest` 仍保留自动 3600 帧长跑行为。
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
- 正式 app 不再默认开机自动开始串流；`switch-stream-selftest` 仍保留自动 3600 帧长跑行为。
- 2026-08-26 第二轮真机：心跳按设计满节奏运行（`stateFull` 稳定 9~10/s），用户反馈卡键
  "不如之前明显"，但仍有一次 RT 按压后长时间无响应的残留症状。日志分析（见 git log D-030
  后续消息）：该冻结发生在线路最平静的时段，心跳与 ACK 全程健康——原"丢包黑洞"假设对该
  症状不成立；结合用户补充（按压集中在静默窗内、事件计数为零、恢复后短暂操作即退出），
  将 **Switch 本地 SDL 事件捕获间歇性停摆**列为主要嫌疑，但仍不是已证结论。事件级探针包括
  每秒 ax/btn/sen/pump 分类计数 + 按钮轴值即时打点限速 12 行/秒。
- 2026-08-27 后续复盘：`Unreliable` 帧类型方案已被真机证据否掉（host 不接受并导致会话秒断），
  当前实现为 Reliable 类型帧但 HID input report 不进入本地重传队列，继续依赖 100ms full
  heartbeat 收敛。SDL 捕获停摆仍是待验证嫌疑，不是已证结论；当前版本新增 raw libnx HID 采样
  `rawAx/rawBtn` 与 style/attribute 抖动计 `styFl`，用于判断静默窗里是 SDL 队列停摆，还是 libnx
  HID sharedmem 本身没有变化。本轮修正了这些探针的 per-second 计数窗口，避免累计值误导复盘；
  UDP `hid` 另输出累计 `rawAxTotal/rawBtnTotal/styFlTotal/sty`，可在复现时连续查询。
- 2026-08-27 追记：用户澄清本轮复现的卡住窗口发生在发消息之前；当时运行的 NRO 没有机内历史
  ring buffer，PC 端也已停止 nxlink，因此事后 UDP `hid/state/stats` 轮询只能描述恢复后的窗口，
  不能作为“卡住期间 SDL 已停摆”的证据。已补 `hidlog [n]`：app 内保存最近 60 个一秒 HID 摘要，
  默认返回最近 16 秒，允许复现结束后再拉取刚才的证据。
- 同次新版启动日志读到 SD 卡上一条持久 watchdog 记录：
  `reason=main_stall ... main_stall_ms=8006 ... displayed_frames=9589`。源码只读取、不清除
  `stream_watchdog.txt`，因此它证明曾发生过一次主循环停跳超过 8s 的 watchdog 退出，但不单独证明
  必然就是用户刚报告的那次卡住；根因范围也从“SDL 队列停摆”扩大到“主循环停摆期间输入/本地退出都无法被处理”。
- 新版真机 smoke：`hidlog` 可通过 UDP 返回最近秒级历史；用户旋左摇杆时可见 `e/ax` 每秒约
  100-260、`raw` 每秒约 3-4、`sendFail=0`、`sty=0:2/3`，证明新版 SDL 与 raw 两条探针在正常输入
  阶段都工作。期间另出现一次 `Frames window overflow` 后 session 断开并可重连，暂记为 control
  channel/window 稳定性旁支，不能直接等同于“输入静默后恢复”的原症状。
- 2026-08-27 复现重读：用户澄清正确时间线为先观察到 host/game 侧卡住，然后持续旋转左摇杆约
  10+ 秒，再回电脑发消息，之后才关闭游戏。本次 `hidlog` 中那段 10 秒应对应 `e/ax/raw/sendOk`
  持续增长的窗口，而不是用户停手后的零事件窗口。结论：本轮证据不支持“卡住期间 SDL 必然拒收
  输入”。用户补充 host/game 侧表现像是右摇杆某方向持续按下导致画面旋转，同时左摇杆和 A/B 可能
  无响应；该问题先作为已知 bug 挂起，不继续阻塞 M4 其它功能。
- 2026-08-27 音频输出第一版落地（D-032）：正式 app 的 streaming request 与 session
  negotiation 开启 audio，audio channel count 为 2；应用侧通过 ihslib audio callbacks 接收 Opus
  payload，用 libopus 解码为 S16LE PCM 后送入 SDL queued audio device。`state`/`stats`/overlay
  与新增 UDP `audio` 命令输出 active、codec/frequency/channels、frames、queued bytes、drops、
  decode/queue errors。`switch-stream-selftest` 仍保持 audio off，作为 video/session 证据工具。
- 2026-08-27 用户再次复现 BUG-M4-HID-001 后退出串流程序；本轮旧版只有进程内 60 秒 `hidlog`
  ring，退出后 UDP debug 已不可达，因此没有可恢复的卡住窗口证据。该诊断设计被证明不适合真机
  复现节奏。已改为后台 joinable 诊断线程，每秒将 `state/hid/audio` 摘要和新增左右摇杆四轴、按钮
  mask 的 HID 秒级历史 append+flush 到 `sdmc:/switch/nsteamlink/stream_diag.log`；启动时把上一轮
  轮转为 `stream_diag_prev.log`，并通过 UDP `diag [current|prev|status]` 读取尾部或线程状态。
- 2026-08-27 BUG-M4-HID-001 后续诊断约定：streaming 中 `-` / `MINUS` 只作为被动故障 marker。
  用户发现 host/game 输入失灵时按住 `-`，诊断记录 `minus=sdlHeld/sdlSamples/rawHeld/rawSamples`，
  并单独写 `stream_diag_markers.log`；UDP `diag marker current|prev` 只读 marker 记录。`-` 不再触发
  本地停流，`+` 也不再触发本地退出，两者都恢复给 Steam/game 使用。
- 2026-08-27 marker 复现证据：用户在失灵时按了几次 `-` 并摇左摇杆，恢复后又摇左摇杆。
  重启轮转后 `diag marker prev` 返回 `markMinus` seq 365-369/373；这些秒内 `minus` 样本非零，
  `btn` 非零，`ax` 在 366/367/368/369/373 非零，`sticks` 多次为左摇杆非零值，且 `ok` 非零、
  `f=0`、`h=9-10/s`。结论：该复现窗口内 Switch 侧 SDL/input pump/HID send 路径仍在工作；
  不能再把这次症状结论为“本地完全没收到输入”。用户观察的 host/game 无响应应转向下游：
  report 传输/ACK、host virtual controller apply、Steam/game 输入状态等路径继续排查。
- 2026-08-27 Wi-Fi 断流假设：上一条 marker 证据中的 `ok` 只证明 HID report 已进入 Switch
  本地发送路径，不证明 host 收到或应用。用户怀疑 Wi-Fi 短断流；该假设与“本地仍采到 `-`/左摇杆，
  但 host/game 无响应”兼容，但上一版 marker 同窗没有记录媒体帧/音频帧/control 计数，因此还不能
  直接证实。已补下一版 `markNet` marker 同窗行，记录每秒 `frames/displayed/audio` 增量、
  `lastFrameAgeMs`、`mainAgeMs`、`gaps/maxGap`、`ctrlRetrans/ctrlWarn` 及其增量，用于下一次
  marker 复现时判断是否是整条 Wi-Fi/stream 同步断流。
- 2026-08-27 更名落位后产物：
  - `build/switch/app/nsteamlink.nro`
    sha256 `a18280eb6462e0bead54cea5d48bf3766a867622ee76b903f313f1cf4280ff92`；
  - `build/switch/client/switch-stream-selftest.nro`
    sha256 `fa2c2ad0358cfd0dd652b073e60d45bff2948343986087cada0b1e9923b73d3d`。
  - 更名映射见 decisions D-031。
- 2026-08-27 本轮诊断修正版产物：
  - `build/switch/app/nsteamlink.nro`
    sha256 `2852e20f5a829d0d8bc21f98177523eadae702aaa36597607e5987c26fd2c8b9`；
  - `build/switch/client/switch-stream-selftest.nro`
    sha256 `2524e98f28d6ab2ca6310a601684873f69f75b8bbb8eabae41d9725898d0fa18`。
- 2026-08-27 音频版产物：
  - `build/switch/app/nsteamlink.nro`
    sha256 `64cece35a5a00fa4ac48aac4b7ee0d60ab1d8e9650ad14177498b71e4eecc5f6`；
  - `build/switch/client/switch-stream-selftest.nro`
    sha256 `fea042eab5298fd39d269e22a144e569d5a1725a09bd16aff722aaeb0a546819`；
  - `build/switch/client/switch-stream-selftest-core.nro`
    sha256 `9cd53a1b15c198404d15d0cfe67e27b5b3743a67c7542da275a7998f793d6dfc`。
- 2026-08-27 持久诊断版产物：
  - `build/switch/app/nsteamlink.nro`
    sha256 `fb5738602230db2c7211ccb49c7a680a3a02370d89feb630dd126f3af8c9868e`；
  - `build/switch/client/switch-stream-selftest.nro`
    sha256 `f944a72970147b1ccbbbf58fb191386605fac19ae8b14e69dd882c2477fa9e9c`；
  - `build/switch/client/switch-stream-selftest-core.nro`
    sha256 `fa401723f40003ba7728bcee0e4465f5f61a543455e5d93f5d4e27bcb56159dc`。
- 2026-08-27 持久诊断 live tail 修正版产物：
  - `build/switch/app/nsteamlink.nro`
    sha256 `275d74e0ee5a298736c6fc6c4ae5e861b237a03b28b178f955987d5cf0a4dd69`；
  - `build/switch/client/switch-stream-selftest.nro`
    sha256 `a2f30c8753956146c6bf143da2f8bb53c23ed0ccb0ea4dda30b6ab30c291524f`；
  - `build/switch/client/switch-stream-selftest-core.nro`
    sha256 `5e8abc1ec637d74e64279562782a4347876e0f484ad0500f54a1ebe78d336998`。
- 2026-08-27 输入 marker 诊断版产物：
  - `build/switch/app/nsteamlink.nro`
    sha256 `f445fb5a5cedc306951f21e0961179ff904c3d5a669fbf7f79fc046f0bd779b6`；
  - `build/switch/client/switch-stream-selftest.nro`
    sha256 `1714fbad77e949c1a0099b629632e332689e5da342eb8f7c964ec2e1459f3193`；
  - `build/switch/client/switch-stream-selftest-core.nro`
    sha256 `7e91033029e28d4ca6d59cbbe64fae188f4ec367c4321f917929acd7e00385a3`。
- 2026-08-27 marker 网络同窗诊断版产物：
  - `build/switch/app/nsteamlink.nro`
    sha256 `37aeeb34a1439e446932a86b32ac933676e15ce5c805dce95f9e9bed1fbf780f`；
  - `build/switch/client/switch-stream-selftest.nro`
    sha256 `d931681928e070ff102dab0e6af7f83358fc35765586f110ac54bd5d9e151f0f`；
  - `build/switch/client/switch-stream-selftest-core.nro`
    sha256 `e0806c78dd353a9c84f55f1394797f5991be2291446af95c6bea7e1db5b149a3`。
- 2026-08-27 `+` / `-` 恢复映射与本地音量组合键版产物：
  - `build/switch/app/nsteamlink.nro`
    sha256 `634bbef96245ef4b9fb28e20ebf6306006178dfbd8c69c1e77d70a4b14de3393`；
  - `build/switch/client/switch-stream-selftest.nro`
    sha256 `7faa33e9421c7f6ca4d2259b53bcd4ee557cf62746fb1e35f5307aaf30c20c40`；
  - `build/switch/client/switch-stream-selftest-core.nro`
    sha256 `699cb052949360610fd46021eea6e5be7b44bdb81a6d26282958d75105891e4d`。

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
  - `B`：停止当前 stream。
- 本地控制：
  - `+` / `-` 不再作为本地控制键，streaming 中恢复给 Steam/game；
  - `L3+R3+VOL+`：退出 app；
  - `L3+R3+VOL-`：停止当前 stream；
  - 音量键通过 audctl 音量值变化识别，音量到顶/到底时对应方向可能不会触发。
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
  - SDL controller events 在 media present loop 中交给 `IHS_HIDHandleSDLEvent()` 更新 canonical state，
    每个有变化的 pump 生成一个 forced full snapshot；等待前一快照 ACK 时只保留最新待发状态；
  - session negotiation 显式发送 `CStreamingClientConfig.enable_input_streaming=true`；源码证据是
    `IHS_SessionHIDSendReport()` 会被 `IHS_SessionInputEnabled()` 门控；
  - stream 中按约每秒输出 `hid summary: events=... send_ok=... send_fail=...`，用于区分 SDL 事件、
    report 发送门控、Steam host 接收三类问题；
  - 用户真机观察到按键后 overlay 帧数卡住且 `+` 无法退出；同期日志显示 HID event/report 已进入，
    随后控制通道重传日志爆发。修正为 nxlink 日志 fd 非阻塞、每帧最多 drain 8 条日志，并对控制通道
    retransmission 日志做限流，避免诊断输出卡住渲染和本地退出路径；
  - 2026-08-25 用户复测当时版本确认“不会卡死”，且旧版 `+` 可退出；同次观察确认输入仍无效果；
  - 新增 UDP debug `hid` 命令，不依赖 `nxlink -s`：
    `hidEvents/hidSendOk/hidSendFail` 来自 Switch SDL/media 侧累计计数；
    `openOk/openFail/start/startLen/full/getFeature/getStrings/noDevice/ctrlWarn`
    来自 ihslib HID/control 日志解析，用于判断 Steam host 是否 open 设备、是否 start input reports、
    是否出现 control 告警；可靠性直接计数见 `rel=tracked/acked retry/fail/out/oldest/maxAck` 与
    `hidSM=submitted/coalesced/sent/acked/pending/inFlight`；
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
  - 该条的本地热键部分已由 2026-08-27 后续修正取代：`+` / `-` 不再作为本地控制键，恢复给
    Steam/game；本地退出/停流迁移到 `L3+R3+VOL+` / `L3+R3+VOL-`。
- 持久诊断：
  - 正式 app 启动后开启后台磁盘诊断线程，不在 SDL input/present 热路径直接写盘；
  - 每秒写入 `sdmc:/switch/nsteamlink/stream_diag.log` 并 flush/fsync；
  - 下一次启动会把上一轮日志轮转为 `stream_diag_prev.log`，UDP `diag prev` 可读上一轮尾部；
  - HID 秒级记录包含 `sticks=lx/ly/rx/ry` 与 `b=0x...`，用于判断卡住时 Switch 本地右摇杆是否已回中；
  - `-` / `MINUS` marker 另写 `stream_diag_markers.log`，但只被动记录、不吞键；若故障时 marker 出现，
    说明 Switch 侧输入路径至少看到了该键；同一 seq 的 `markNet` 记录媒体/控制通道同窗状态；若完全不出现，
    才把嫌疑收敛到本地输入捕获/pump/raw sample 路径。
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
- 音频输出第一版：
  - 正式 app 开启 Steam audio request/config，`audioChannelCount=2`；
  - ihslib audio channel 回调接入 `stream_media_audio_start/submit/stop`；
  - Opus payload 用 libopus 解码为 S16LE PCM，送入 SDL queued audio device；
  - SDL audio queue 限制在约 300ms，超限清队列并累计 `audio_queue_drops`，避免延迟无限增长；
  - `state`/`stats`/streaming overlay 与 UDP `audio` 命令输出音频状态和错误计数。
- NVTEGRA transfer 优化第一步：
  - 当前 SDL/Mesa 路线仍需把硬件帧转成 CPU 可见 NV12；本版不宣称 zero-copy；
  - 下载目标 frame 改为 4KB 对齐 backing、256B pitch，使 switch-ffmpeg 满足条件时使用 VIC 做
    block-linear 到 pitch-linear transfer，避免旧路径的 CPU 解块拷贝；
  - 首次命中会打印 `NVTEGRA transfer path: VIC 256B-aligned`；`stats`/`perf summary` 新增
    `vicTransfers` 与 `transferFallback`，仅 transfer 成功后计数；
  - 对齐准备或 VIC transfer 失败会自动重试原 FFmpeg transfer，继续保留 SDL NV12 upload 与
    IYUV fallback。

## 本地验证

- `cmake --build build/switch --target nsteamlink_nro switch-stream-selftest_nro -j$(nproc)` 通过。
- `cmake --build build/switch --target switch-stream-selftest-core_nro -j$(nproc)` 通过。
- `git diff --check` 与 `git -C third_party/ihslib diff --check` 通过。
- ihslib SDL2 host tests 27/27、ASan+UBSan 27/27、TSan 27/27 通过。
- 当前产物：
  - `build/switch/app/nsteamlink.nro`
    sha256 `3efdbe4a93fa8333deed418fd0ac3a6bc31b6fdc79b050291f7475c1b0050bab`
  - `build/switch/client/switch-stream-selftest.nro`
    sha256 `c1e42074b9abe51f448720b6f82c7e3b74b6e8331c4a9daea49e739137f2ba68`
  - `build/switch/client/switch-stream-selftest-core.nro`
    sha256 `a3cdd6e3b7e7537df2303f7fc52c718b75642150847d1b380568843fc11887a8`

## 待验证

- BUG-M4-HID-001（已定位到 host 收包之后，仍待根因化）：stream 中曾偶发 host/game 侧输入状态卡住，表现为画面像
  右摇杆某方向持续按下而持续旋转，期间左摇杆与 A/B 可能无响应；随后可自行恢复。本轮已知证据
  2026-08-28 marker 复现进一步证明故障窗口的新 HID 快照持续获得 Steam transport ACK，且没有
  音视频断流；ACK 不能证明 host 已应用 report。后续优先取 host Remote Play/virtual controller 日志，
  并记录“再动/松右摇杆是否恢复”，不再从 Switch 状态机堵塞假设出发。
- 真机上菜单文字可读、没有遮挡主要串流画面。
- `A` 启动 game stream；菜单中 `B` 停止；streaming 中 `+` / `-` 能作为普通 Steam/game 输入。
- D-035 已真机确认 `L3+R3+VOL+` 能在 host 停流后继续完成 session join/destroy 和 app cleanup，
  Switch 正常离开最后一帧；`L3+R3+VOL-` 单独停流仍保留为独立交互验收项。
- 如果 Steam host 返回 `PINRequired`，四位 PIN UI 能提交并成功重试。
- Steam host 能收到 Switch 手柄输入，且 stop/exit 后不会残留按键按下状态。
- 真机确认 Steam/game 里的 `A/B/X/Y` 是否按 Switch 面壳字母正确映射。
- 真机确认正式 app 音频有声、无明显爆音/持续延迟，`audio` 输出 `audio=1 frames>0 errors=0`；
  stop/exit 后音频停止且没有残留播放。
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

- 真机验证 VIC transfer：要求首次命中日志、`vicTransfers == transferFrames`、
  `transferFallback=0`，并与旧版约 `transferAvgUs=1.6ms` 比较；若失败，保留 fallback 错误原文。
- 真正 NVTEGRA zero-copy 已确认需要 deko3d 图形后端迁移；应作为独立阶段迁移窗口/swapchain、
  YUV shader、overlay 与 cleanup，而不是在 SDL renderer 内叠加第二个图形后端。
- 不让 BUG-M4-HID-001 继续阻塞主线；继续真机验证音频输出，并逐步拆分 UI/stream 状态模块。
