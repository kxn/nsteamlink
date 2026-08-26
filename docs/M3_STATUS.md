# M3 状态整理

> 目标：先证明 Steam streaming request、session 认证/协商和视频数据通道，再在同一个 probe 中接入
> FFmpeg/NVTEGRA + SDL2 texture 显示，完成第一帧显示。

**当前状态：M3.1/M3.2 probe 已在真机跑通；M3.3 FFmpeg/NVTEGRA + SDL2 texture 第一帧已在真机跑通。
2026-08-25 官方 OpenGL 基准在 Album applet 下 fatal、在卡带 title override/full application 下正常，
因此 Mesa 阻塞解除，M3 主线恢复 SDL2/Mesa 正常流程。**

## 当前结论

- 2026-08-24 用户已用 M2 手动验证 `auth.bin` 可以复用；这是 P0 真机证据。因此 M3 不再重复验证
  身份文件本身，直接加载 `sdmc:/switch/nsteamlink/auth.bin`。
- `sessionInfo.steamId` 会进入 ihslib 的 `CAuthenticationRequestMsg`，所以 M3 probe 使用 M2 保存的
  `steamId`，不是置零或重新猜。
- M3.1/M3.2 probe 先不解码视频，只统计 assembled encoded frames。M3.3 已接入 FFmpeg + SDL2
  texture 显示，2026-08-25 真机日志已出现 `first frame displayed`。
- 2026-08-24 首次 M3 真机启动证据：4MB UDP RX / 512KB UDP TX 的自定义 socket pool 会导致
  debug UDP `socket()` 失败，`errno=105`（`ENOBUFS`），且 IHS discovery send 返回 false。
  结论：M3.1/M3.2 先使用 M2 已验证的 `socketInitializeDefault()`；视频大 buffer 留到 M3.3 单独验证。

## 已完成

- 新增独立工具：`tools/switch-stream-probe`，保护 M2 `switch-discover` 基线。
- 构建系统已加入 `switch-stream-probe.nro`，`./scripts/build-switch.sh` 会打印三个 NRO 产物路径。
- probe 会加载已配对的 `auth.bin`；若没有 `steamId`，直接报错要求先跑 M2。
- probe 会做 IHS host discovery，并保留固定 fallback host `10.10.10.166:27036`。
- probe 复用 UDP debug port `28772`，固定 Switch IP 仍是 `10.10.10.77`。
- debug 命令支持：`state` / `stats` / `perf`、`hosts`、`select <n>`、
  `stream [desktop|game] [short|long|frames=N|seconds=N|hold] [pin]`、`stream-pin <pin>`、
  `stop`、`exit`。
- 2026-08-24 真机测试确认：PC 端没有发 debug `stream` 命令前出现的 stream 是用户手按物理按键触发，
  不是 hbmenu/netloader 残留输入。为让后续自动化证据更干净，probe 仍改为只允许 debug 命令发起
  stream；手柄只保留 `UP/DOWN`、`B`、`PLUS`。
- 当前默认 `stream`/`stream game` 在收到 3600 帧后自动 stop；`short` 为 120 帧短测，
  `hold` 会取消自动 stop。
- streaming success 后自动创建 `IHS_Session`，配置为 H264-only、audio off、HEVC off、1280x720@60、
  6000 kbps。
- session/video callback 会记录 `streaming success` / result、`session connected`、`video start`、
  frame count、keyframe count、last frame id、last encoded bytes。
- M3.1/M3.2 退出仍走标准路径：`IHS_SessionDisconnect()` -> `IHS_SessionThreadedJoin()` ->
  `IHS_SessionDestroy()`，再清理 IHS client、IHS_Quit、nxlink socket、socketExit。M3.3 安全修正版
  对 `+`/debug `exit` 改为优先正常返回 `main()`，见 D-019。
- M3.3 已接入 `tools/switch-stream-probe/media.c`：
  - 使用 devkitPro `switch-ffmpeg`，显示层使用 SDL2 renderer/texture；
  - SDL 初始化保持 devkitPro 官方示例关键流程：
    `SDL_Init(SDL_INIT_VIDEO | SDL_INIT_JOYSTICK)`、`1920x1080 flags=0` window、
    `SDL_RENDERER_ACCELERATED | SDL_RENDERER_PRESENTVSYNC` renderer、打开 joystick 0/1；
  - H264-only，audio/input/HEVC 继续关闭；
  - 优先尝试 FFmpeg `AV_HWDEVICE_TYPE_NVTEGRA`，失败时回退 H264 software decoder；
  - `video.submit` 线程执行 `av_new_packet`、`avcodec_send_packet`、drain frames，并 latch 最新帧；
  - 主线程 `probe_media_present()` 通过 `SDL_PollEvent()` 驱动 SDL applet lifecycle，并使用
    `SDL_UpdateYUVTexture` + `SDL_RenderCopy`/`SDL_RenderPresent` 显示 IYUV frame；
  - debug `state` 增加 `decoded`、`displayed`、`firstFrame`、`decoder`、`mediaError` 字段。
- M3.3 安全修正版：
  - 移除 `appletLockExit()` 与 `appletRequestToAcquireSleepLock()`；
  - debug `stream` 只排队，实际 `IHS_ClientStreamingRequest()` 在独立 worker 线程执行；
  - 2026-08-25 追加：图形/媒体初始化从启动阶段拆出，改为 debug `media-init` 显式触发；
    `stream` 在媒体未初始化时拒绝并提示先运行 `media-init`；
  - 2026-08-25 继续追加：media 版启动阶段完全被动化，不再自动 `IHS_Init()`、
    `IHS_ClientCreate()` 或发 discovery；改由 debug `ihs-init` / `discover-once` 显式触发；
  - `+` / debug `exit` 优先退出主循环并从 `main()` 正常返回；只有无 stream/session 活动时才走
    blocking cleanup/join；
  - watchdog 检测主循环停跳 8 秒、或 stream 开始 45 秒仍无首帧，写 `stream_watchdog.txt` 后
    `appletRequestExitToSelf()`；
  - SDL 无首帧时画无文字活动指示，不再纯黑；renderer 去掉 vsync；
  - IHS streaming request timer 首次延迟调为 25ms，降低 handle 尚未写回时 timer 先执行的竞态。
- FFmpeg/SDL2 静态链接后，`switch-stream-probe.nro` 从约 487KB 增至约 19MB。若 nxlink/netloader
  传输很慢，不能据此推断程序卡死；必要时改用 SD 卡复制做真机回归。
- 2026-08-24 首次 M3.3 真机启动证据：SDL2 初始化成功进入 window 创建，但
  `SDL_CreateWindow(1280x720, SDL_WINDOW_FULLSCREEN)` 失败：
  `Could not set NWindow dimensions: 0xf59`。devkitPro SDL2 Switch 示例使用
  `SDL_CreateWindow(..., 0, 0, 1920, 1080, 0)`，当前代码已按示例改为 1920x1080、flags=0，
  并且 M3.3 probe 不再初始化 libnx console，避免与 SDL video backend 争用默认图形窗口。
- 同次测试还暴露失败态控制问题：media init 失败后 probe 进入 error mode 且未创建 IHS client，
  旧主循环没有轮询 debug UDP，导致 PC 端无法 `state/exit`。当前代码已改为 error mode 仍轮询
  debug，只有 `stream` 在 client 不可用时拒绝。
- 2026-08-25 M3.3 第二次真机启动证据：SDL 初始化成功，屏幕变黑，日志出现
  `media init: SDL2 renderer ready`。PC 端发送 `stream game` 后 debug 命令超时，nxlink 只出现
  `stream: StartDiscovery(one-shot) -> 1`，没有后续 `stream request:`。结论：尚未进入 Steam
  streaming response 或 FFmpeg 解码，黑屏不是“解码失败”，而是主线程卡在 streaming request 入口。
- 源码证据：`IHS_ClientStreamingRequest()` 原实现持有 `client->base` 锁后调用 `IHS_TimerTaskStart()`；
  discovery timer 回调在 timer 锁内调用 `IHS_ClientSend()`/`IHS_BaseSend()`，需要 `client->base` 锁。
  这形成 `base -> timer` 与 `timer -> base` 的 AB-BA 死锁风险。当前修正：
  - `IHS_ClientStreamingRequest()` 不再持有 base 锁调用 `IHS_TimerTaskStart()`；
  - probe 发起 stream 前改为 `IHS_ClientStopDiscovery()`，不再紧贴着 `StartDiscovery(one-shot)`。
- 用户随后反馈整机一度近似 hang：`+`、HOME、长按 POWER 起初都无响应；之后补充证据显示：
  拔掉充电器时设备亮起锁屏界面，并正常进入锁屏/hbmenu，当时电量不足。结论修正：该轮不能记录为
  Atmosphere fatal、硬 hang 或 stream/decode crash；“低电量/充电/休眠或 applet lifecycle 导致
  主循环结束”只是待验证假设。上述 IHS 锁补丁仍有源码证据支持，但不能被当作该现象的完整根因。
- 2026-08-25 M3.3 安全修正版首次回归（未发 `stream game`）PC 侧证据：
  - nxlink 成功发送 `switch-stream-probe.nro`，大小 `19142853` bytes；
  - 日志出现 `watchdog active=1 mainStall=8000ms noFirstFrame=45000ms`、
    `applet exit/sleep locks disabled for M3.3 safety`、`stream worker active=1`；
  - 日志出现 `media init: SDL2 renderer ready`；
  - debug `state` 返回 `mode=ready hosts=1 ... games=1 ... displayed=0 firstFrame=0`；
  - debug `exit` 后日志出现 `fast exit requested`、`fast exit: fast_exit:requested`、`exiting ...`，
    nxlink 进程退出；用户随后反馈 Switch crash。因此 `svcExitProcess()` 退出方案已撤销。
    PC 侧 `exiting ...` 不是安全退出证据。
- 2026-08-25 M3.3 安全修正版第二次回归（未发 `stream game`）真机证据：
  - 用户观察到 SDL idle 画面正常刷新：底部绿色动画、左上橙色方块；
  - debug `state` 返回 `mode=ready hosts=1 ... games=1 ... displayed=0 firstFrame=0`；
  - debug `exit` 后日志走到 `return path: safe_cleanup=1`、`cleanup: stop IHS client`、
    `cleanup: join IHS client`、`cleanup: destroy IHS client`、`cleanup: IHS_Quit`、
    `exiting ...`；
  - 用户确认 Switch 正常回到 hbmenu。结论：撤掉 `svcExitProcess()` 并正常返回 `main()` 后，
    M3.3 idle/exit 安全回归通过。
- 2026-08-25 随后一次重新推送在未发 `state` / `stream game` 前用户侧 crash，PC 侧没有拿到可用
  应用日志。结论：这不能归因于 stream 后 hang；为拆分启动加载与 SDL 初始化风险，下一版改为
  启动只初始化网络/debug/IHS，SDL/媒体层延迟到 debug `media-init`。
- 2026-08-25 延迟 `media-init` 版安全回归真机证据：
  - 启动日志出现 `media init deferred; use debug command media-init`，debug `state` 正常返回
    `mode=ready hosts=1 ... games=1`；
  - debug `media-init` 返回 OK，nxlink 日志出现 `media init requested` 与
    `media init: SDL2 renderer ready`；
  - debug `exit` 后日志走到完整 cleanup 与 `exiting ...`；
  - 用户确认 Switch 一切正常并返回 hbmenu。结论：启动加载、手动 SDL 初始化和退出路径已分别通过；
    下一轮可以把风险收敛到 `stream game` 后的 streaming/session/decode 路径。
- 2026-08-25 继续复查媒体版启动 crash：
  - 用户指出不能无证据怀疑 netloader/大 NRO，因为其它项目也能加载更大的 NRO；
  - 本地 ELF 证据显示媒体版 `.init_array` 有 9 个 pre-main constructor，core 版只有 1 个；
  - `addr2line` 显示媒体版额外 constructor 来自 `builtin_functions.cpp`、`glsl_types.cpp`、
    `ir_to_mesa.cpp`、`st_glsl_to_tgsi.cpp`、`builtin_types.cpp`、`nv50_ir_ra.cpp`、
    `eh_alloc.cc`、`eh_globals.cc`；
  - `pkg-config --libs sdl2` 显示 Switch SDL2 链接项包含 `-lEGL -lstdc++ -lglapi -ldrm_nouveau`；
  - 结论：当前证据不支持“netloader 大文件必然有问题”；更强的待验证假设是媒体版存在
    `main()` 前的 Mesa/Nouveau/C++ runtime 初始化路径。下一版在 `main()` 极早期写
    `sdmc:/switch/nsteamlink/stream_boot_stage.txt`，用来判定 crash 是否发生在进入 `main()` 前后。
- 2026-08-25 boot-stage 媒体版回归补充证据：
  - nxlink 日志显示程序已进入 `main()`，完成 auth、socket、nxlink、debug UDP，并自动创建 IHS client
    与发起 discovery；
  - 日志出现 host found / fallback discovery，且没有收到 PC 端 `media-init` 或 `stream` 命令；
  - PC 侧随后看到 `exiting ...`，但用户补充真机并未 fatal/硬死，而是拔充电器后亮锁屏并回到 hbmenu；
  - 结论：该轮不能证明 pre-main constructor 崩溃，也不能证明 stream/decode 崩溃。为缩小证据面，
    当前 media 版已改为完全被动启动：默认只加载 auth、初始化 socket/nxlink/debug，IHS/client/
    discovery、SDL/FFmpeg、stream 都需 debug 命令逐步触发。
- 2026-08-25 完全被动启动版最小回归（PC 侧证据，Switch 侧显示待用户确认）：
  - 推送产物 `switch-stream-probe.nro` 大小 `19151045` bytes，sha256
    `653dc376a6721ea17151f3c6e50d0ae7e667d8b6041915c81ad82aef1a324ec7`；
  - nxlink 日志出现 `IHS/client/discovery deferred; use debug command discover-once` 与
    `stream worker deferred`；
  - debug `state` 返回 `mode=ready hosts=0 ihs=0 client=0 worker=0 ... status="Passive boot ready; run discover-once when needed"`；
  - debug `exit` 后日志出现 `exit requested`、`main loop ended`、`return path: safe_cleanup=1`、
    `cleanup: close nxlink log socket`、`exiting ...`；
  - 结论：PC 侧证明完全被动启动和最小退出路径已走通；是否真机安全返回 hbmenu仍以用户观察为准。
- 2026-08-25 同一完全被动媒体版再次推送出现 Atmosphere fatal（用户截图为主证据）：
  - 截图：`Error Code: 2144-0001 (0x290)`，`Program: 0100000000001000`，PC
    `0x000000103064A27C`，Backtrace Start Address `0x0000001030400000`；
  - PC 侧证据：nxlink 只到 `server active ...`，没有应用侧 `nxlink log socket active`；debug
    `state` 超时；我们尚未发送 `ihs-init`、`discover-once`、`media-init` 或 `stream`；
  - 本地地址解析：`0x103064A27C - 0x1030400000 = 0x24a27c`，对应
    `vbo_exec_VertexAttrib1fARB`（Mesa `vbo_exec_api.c`）；其它可读 backtrace 地址也落在 Mesa/SDL
    或 libnx 区域；
  - 结论：该轮 fatal 发生在 IHS/client/discovery/media-init/stream 之前；不能归因于 Steam 协议、
    解码或 stream 请求。它给出强证据要求 M3.3 Switch probe 移除 SDL2/EGL/Mesa 链接面。
- 2026-08-25 SDL2/EGL/Mesa 移除后的本地构建证据：
  - `switch-stream-probe` 不再 `pkg_check_modules(SDL2 ...)`，链接项为 `ihslib + libavcodec/libavutil/libswscale + nx`；
  - 新 `media.c` 使用 libnx `framebufferCreate/framebufferMakeLinear/framebufferBegin/framebufferEnd`
    做 1280x720 RGBA 软件显示，保留 FFmpeg H264 NVTEGRA 优先、软件解码 fallback；
  - 新 NRO 大小约 `13M`，sha256
    `a829eeb1c36dea582a089e3faca4b872cac0e5e7efaeec3e27f86ca697b5c466`；
  - `nm` 搜索不到 `vbo_exec`、`_mesa_`、`SDL_`、`drm_`、`nouveau`、`glapi`、`EGL`；
  - `.init_array` 大小降为 `0x8`，唯一 constructor 为 `frame_dummy`。
- 2026-08-25 framebuffer 版被动启动最小回归：
  - 推送产物大小 `12720325` bytes，应用侧日志出现 `nxlink log socket active=1`；
  - 日志出现 `media init deferred; use debug command media-init`、
    `debug udp ready: port=28772 allowed=10.10.10.9`、
    `IHS/client/discovery deferred; use debug command discover-once`、
    `stream worker deferred`；
  - debug `state` 返回 `mode=ready hosts=0 ihs=0 client=0 worker=0 ... status="Passive boot ready; run discover-once when needed"`；
  - debug `exit` 后日志出现 `exit requested`、`main loop ended`、`return path: safe_cleanup=1`、
    `cleanup: close nxlink log socket`、`exiting ...`；
  - 用户确认 Switch 侧正常返回 hbmenu；
  - 结论：移除 SDL2/EGL/Mesa 后，被动启动/debug 通道/最小退出路径真机回归通过。
- 2026-08-25 Mesa/full application 对照结果：
  - Album/PhotoViewer applet 下，同一官方 OpenGL 基准 `switch-gfx-gl-official.nro`
    fatal 于 Mesa/Nouveau buffer allocation/cache flush 路径；
  - 用户通过实体卡带 title override 进入 hbmenu/netloader 后，推送同一 NRO，用户反馈 `都正常了`；
  - 结论：当前证据支持 Mesa fatal 的主因是 applet/full application 资源差异。M3 不再继续 Mesa
    对照测试，回到 SDL2/Mesa 正常流程的 stream/session/decode 第一帧验收。
- 2026-08-25 full application 资源条件确认后的 M3.3 实现修正：
  - 撤回 framebuffer 作为 M3 主线，只保留它作为此前隔离 Mesa/applet 问题的临时证据；
  - `switch-stream-probe` 重新链接 SDL2/EGL/Mesa/Nouveau；
  - `media.c` 改为 SDL2 renderer + IYUV texture；
  - `main.c` 在 media 未启动时才直接调用 `appletMainLoop()`；media 启动后由
    `SDL_PollEvent()` 调用 SDL Switch backend 的 `SWITCH_PumpEvents()`，避免外层
    `appletMainLoop()` 与 SDL 双消费 lifecycle；
  - 本地构建通过，`switch-stream-probe.nro` sha256
    `ef417b826ca1a4c8b2252b8370c643ca90e7227b5187b2a049a09d7edab7d146`。
- 2026-08-25 SDL2/Mesa 主线 M3.3 第一帧真机结果：
  - 运行环境：用户通过实体卡带 title override/full application hbmenu 启动 netloader；
  - 推送产物：`switch-stream-probe.nro`，sha256
    `ef417b826ca1a4c8b2252b8370c643ca90e7227b5187b2a049a09d7edab7d146`；
  - 被动启动后黑屏，debug `state` 仍正常返回 `mode=ready ihs=0 client=0 worker=0`；
    结论：该黑屏只是 media/console 未初始化时没有画面，不是 hang；
  - debug `media-init` 成功，用户反馈 `看到了`，PC 侧日志出现 `media init: SDL2 renderer ready`；
  - debug `discover-once` 后发现 host：`kxn-pc 10.10.10.166 games=1`；
  - debug `stream game` 后 PC 侧日志出现：
    `streaming success`、`session connected`、`video start: 1280x720 codec=H264(4)`、
    `video decoder opened: h264 (nvtegra)`；
  - 首帧证据：`first frame displayed: id=0 size=1280x720 fmt=0`；
  - auto-stop 证据：debug `state` 返回
    `frames=120 keyframes=2 decoded=120 displayed=98 firstFrame=1 mediaDrop=21 decoder="h264 nvtegra"`
    与 `status="Session stopped; frames=120 keyframes=2"`；
  - PC 侧退出日志走到 `cleanup: stop IHS client`、`cleanup: join IHS client`、
    `cleanup: destroy IHS client`、`cleanup: IHS_Quit`、`cleanup: close nxlink log socket`、
    `exiting ...`；
  - 用户随后补充：屏幕能看到串流画面，但闪得比较厉害；退出正常，看起来不像电脑端顺滑。
    结论：M3.3 首帧、120 帧 auto-stop 和退出均通过；流畅度/闪屏进入下一轮修正。
- 2026-08-25 首帧后闪屏修正：
  - 代码证据：`probe_media_present()` 在没有新 decoded frame 时会调用 `draw_idle_indicator()`；
    串流期间这会把视频帧与 idle 黑底/绿色动画交替 present，解释了用户观察到的明显闪烁；
  - 修正：已显示首帧或 video active 时，没有新帧则保持上一帧，不再绘制 idle；
  - 修正版首次重推时，用户观察到 Switch 侧 OS 报错关闭软件。该轮 PC 侧 `nxlink` 无应用日志，
    因此不能证明崩溃发生在应用 `main()` 前、SDL 初始化前、退出清理残留，或 hbmenu/netloader
    连续重载状态；
  - 待验证假设：上一轮 SDL/Mesa app 正常返回 hbmenu 后，hbmenu/netloader 连续重载大 NRO/SDL
    app 时状态不稳定；或应用释放/退出路径仍有未记录的问题；
  - 追加证据改动：`probe_media_shutdown()` 分步记录 joystick/renderer/window/`SDL_Quit` teardown；
    退出清理顺序改为先停 IHS client/`IHS_Quit`，再释放 SDL renderer/window，减少 SDL teardown
    时的后台活动；
  - 本地构建通过，证据版 `switch-stream-probe.nro` sha256
    `04c12d9adc0ac9c5b763c1162e71fa9dd25a4306096d7e9576a55dd7f6501056`。
- 2026-08-25 闪屏修正版复测结果：
  - 真机证据：用户反馈“不闪了”，但屏幕停留在结束 streaming 的状态；
  - PC 侧 debug `state` 返回
    `frames=120 keyframes=2 decoded=120 displayed=117 firstFrame=1 mediaDrop=2 decoder="h264 nvtegra"`
    与 `status="Session stopped; frames=120 keyframes=2"`；
  - debug `exit` 后用户确认“正确回去了”；
  - 结论：闪屏修正通过；auto-stop 后仍留在 probe UI 是状态机/测试流程问题，不是视频解码失败。
- 2026-08-25 简化主路径：
  - `stream` debug 命令已改为自动准备 media/IHS/discovery，不再要求手工先执行
    `media-init` / `discover-once`；
  - 默认 probe 流在 120 帧 auto-stop 后自动退出返回 hbmenu；`stream game hold` 保留长时间观察模式；
  - 简化版 `0b6020bbe785e079d9ed58fde8414db83bdce309c822547efd10a0ee21435c44` 推送后，
    用户观察到 Switch OS 报错关闭软件；PC 侧无应用日志，debug `state` 超时，且尚未发送
    `stream game`。结论：该轮不能归因于 streaming/decode；只能记录为启动/加载到 debug ready
    前的 fatal，待 fatal PC 或 `stream_boot_stage.txt` 证据定位；
  - 当前新版改为启动后自动排队 `game` stream probe，120 帧后自动退出；启动时会通过 nxlink
    打印上一轮 `stream_boot_stage.txt` / `stream_exit_stage.txt` / watchdog / exception 摘要；
    本地构建通过，
    `switch-stream-probe.nro` sha256
    `3418640b03711ea7163dadda018113b22912b9fe57a4acfd60f0c0272bafb621`。
  - 自动 stream 版 PC 侧回归证据：
    `media init: SDL2 renderer ready`、`auto stream queued: game autoStop=120`、
    `streaming success`、`session connected`、`video start: 1280x720 codec=H264(4)`、
    `video decoder opened: h264 (nvtegra)`、`first frame displayed`；
    120 帧后日志出现 `auto stop requested after 120 frames`、`session stopped: frames=120 keyframes=2`、
    `auto exit requested after probe stream`、`return path: safe_cleanup=1`、`cleanup: IHS_Quit`、
    `exiting ...`，`nxlink` 进程正常退出；
  - 该轮启动时还打印出上一轮遗留证据：`previous boot_stage: socket:init:start`、
    `previous watchdog: reason=main_stall ... stream_start_ms=0` 与一段旧 exception 摘要。由于本轮
    已成功进入 `main()` 并完成 stream，上一轮失败仍只能记为启动/加载阶段待定位问题；
  - 真机屏幕是否已回 hbmenu 仍以用户观察为准，不能只用 `nxlink` 退出代替。
- 2026-08-25 二次启动被 OS 关闭问题调研与修正：
  - 用户证据：同一自动 stream 版本第一次运行能返回 hbmenu，但返回后再次启动会被 Switch OS
    关闭；多个 netloader 残留入口均表现一致；
  - 上游证据：Homebrew ABI 要求应用返回 loader 前必须不泄漏 handle、重置 MemoryState，并且不能
    留后台线程；hbmenu 通过 Homebrew ABI / nx-hbloader launch NRO，nx-hbloader 会 unmap previous
    NRO 后再加载下一个；
  - 本地证据：`switch-stream-probe` 自己创建的 `stream_worker` 和 watchdog 原先都是
    `pthread_detach()`，退出时只 signal 不 join；
  - 修正：`stream_worker` 与 watchdog 改为 joinable，cleanup 中打印并执行
    `cleanup: join watchdog`、`cleanup: join stream worker`；`probe_media_shutdown()` 后 drain log queue，
    让 `media shutdown: SDL_Quit done` 可见；
  - 当前证据版 `switch-stream-probe.nro` sha256
    `2c3c900504fb4ed434d12db97b96ab4a5103af27a82c0d0d73c502dcedf3e03b`。
  - 该版首次推送 PC 侧日志已验证单次 cleanup：`first frame displayed`、`auto stop requested after 120 frames`、
    `cleanup: join watchdog`、`cleanup: join stream worker`、`media shutdown: SDL_Quit done`、
    `cleanup: close nxlink log socket`、`exiting ...`；
  - 用户随后连续多次启动验证通过，并确认“没问题了，这就是原因”。结论：二次启动被 OS 关闭的
    根因是本项目返回 hbmenu 前留下 detached 线程，违反 Homebrew ABI cleanup 要求。
- 2026-08-25 M3.4 长跑稳定性探针实现：
  - 目标：不再重复验证启动/退出，而是把 probe 改成可量化长时间播放，用证据区分网络丢帧、
    解码/硬解回读、SDL texture upload 和 present 节奏；
  - 默认 auto stream 从 120 帧短测改为 3600 帧长跑；`short` 仍保留 120 帧；
  - debug `stream` 支持 `short`、`long`、`frames=N`、`seconds=N`、`hold`，裸数字仍只作为
    streaming/security PIN 使用，避免与帧数语义混淆；
  - `state` 增加 `gaps/maxGap/encodedKB/avgKbps/firstRxMs/elapsedMs`；
  - `stats` / `perf` 增加长跑性能统计：`decodeAvgUs/max`、`transferAvgUs/max`、
    `convertAvgUs/max`、`uploadAvgUs/max`、`presentAvgUs/max`、`transferFrames`、`converted`；
  - session stop 时自动打印 `perf summary`，便于 auto-stop 后从 nxlink 日志保留证据；
  - 首轮真机 PC 侧长跑证据：3600 帧 auto-stop，日志出现 `session stopped: frames=3600 keyframes=3`、
    `perf summary`、`cleanup: join watchdog`、`cleanup: join stream worker`、
    `media shutdown: SDL_Quit done` 和 `exiting ...`；
  - 首轮性能摘要：
    `decoded=3600 displayed=3589 mediaDrop=10 gaps=1 maxGap=15 encodedKB=18070 avgKbps=2132`
    `elapsedMs=69422 firstRxMs=1437 transferFrames=3600 converted=3600`
    `decodeAvgUs=5572 transferAvgUs=1716 convertAvgUs=515 uploadAvgUs=2837 presentAvgUs=781`；
  - 同轮证据显示 FFmpeg 每帧提示 `Frame address/pitch not aligned to 256, falling back to cpu transfer`，
    且每帧都从 decoded format `23` 转到 YUV420P。结论：当前瓶颈调查应优先看 NVTEGRA CPU transfer /
    frame 对齐、格式转换和 IYUV upload，而不是先猜 netloader 或启动流程；
  - 已抑制重复的 alignment/format-conversion per-frame 日志，只保留首次证据，避免日志 I/O 污染长跑；
  - 降噪版真机 PC 侧长跑证据：3601 帧后 auto-stop，日志出现 `session stopped: frames=3601 keyframes=5`、
    `perf summary`、完整 join/cleanup、`media shutdown: SDL_Quit done` 和 `exiting ...`；
  - 降噪版性能摘要：
    `decoded=3601 displayed=3592 mediaDrop=8 gaps=3 maxGap=15 encodedKB=34140 avgKbps=4228`
    `elapsedMs=66148 firstRxMs=1881 transferFrames=3601 converted=3601`
    `decodeAvgUs=5629 decodeMaxUs=8289 transferAvgUs=1659 transferMaxUs=2705`
    `convertAvgUs=505 uploadAvgUs=2578 uploadMaxUs=14523 presentAvgUs=780 presentMaxUs=11646`；
  - 同轮出现 3 次 IHSlib `Unexpected video frame sequence ... request keyframe`，与 `gaps=3/maxGap=15`
    一致。结论：已有证据支持继续调查 UDP/socket buffer 或 host/network burst，但不能忽略本地
    CPU transfer/format conversion/upload 的持续成本；
  - 降噪版暴露一个小状态机瑕疵：stop 已经开始后仍可能多收一帧，导致 `auto stop requested`
    打印两次；已修正为 auto-stop 只请求一次。
- 2026-08-25 M3.4 第一轮优化：
  - 根据上轮证据，先做两项小步优化：socket pool 的 UDP RX 从 default 改为 1MB，失败时自动 fallback
    default；显示层优先使用 FFmpeg transfer 后得到的 NV12 frame，直接创建 `SDL_PIXELFORMAT_NV12`
    texture 并用 `SDL_UpdateNVTexture()` 上传，若 runtime 不支持则 fallback 到旧 IYUV conversion；
  - 真机 PC 侧长跑证据：日志出现 `SDL video texture ready: NV12 1280x720`，首帧
    `first frame displayed: id=0 size=1280x720 fmt=23`，3600 帧 auto-stop 后完整 cleanup；
  - 性能摘要：`decoded=3600 displayed=3596 mediaDrop=3 gaps=0 maxGap=0 encodedKB=6900 avgKbps=453`
    `elapsedMs=124696 firstRxMs=1683 transferFrames=3600 converted=0`
    `decodeAvgUs=4993 decodeMaxUs=11333 transferAvgUs=1599 transferMaxUs=2769`
    `convertAvgUs=0 uploadAvgUs=2088 uploadMaxUs=9025 presentAvgUs=599 presentMaxUs=7655`；
  - 与降噪基线相比：`gaps 3 -> 0`，`mediaDrop 8 -> 3`，`converted 3601 -> 0`，
    `uploadAvgUs 2578 -> 2088`，`presentAvgUs 780 -> 599`；
  - 结论：NV12 直接上传已证实有效；1MB UDP RX 与当前网络/host 场景下的 `gaps=0` 同时成立，
    但 socket buffer 改动还需要下一版日志直接打印 `udpRx/sampleRcvbuf` 才能作为完整 runtime 证据。
    当前代码已补充 nxlink 连接后重复打印 socket 初始化摘要。
- 2026-08-25 M3.4 收口回归：
  - 真机 PC 侧日志已直接打印 socket runtime 摘要：
    `socketInitialize custom ... udpRx=1048576 ... sampleRcvbuf=1048576`；
  - 同轮日志出现 `SDL video texture ready: NV12 1280x720` 与
    `first frame displayed: id=0 size=1280x720 fmt=23`，证明本轮走 NV12 direct upload；
  - 3600 帧自动 stop 后摘要：
    `frames=3601 keyframes=2 decoded=3601 displayed=3580 mediaDrop=20 gaps=2 maxGap=1`
    `encodedKB=19820 avgKbps=2462 elapsedMs=65923 firstRxMs=1618 transferFrames=3601 converted=0`
    `decodeAvgUs=4867 transferAvgUs=1648 convertAvgUs=0 uploadAvgUs=2137 presentAvgUs=717`；
  - 退出日志出现 `session stop: IHS_SessionDisconnect`、`session stop: join`、
    `session stop: destroy`、`return path: safe_cleanup=1`、`cleanup: join watchdog`、
    `cleanup: join stream worker`、`cleanup: IHS_Quit`、`media shutdown: SDL_Quit done`；
  - 用户随后手动二次启动并反馈“没问题”。结论：M3.4 的长跑、NV12 direct upload、1MB UDP RX
    runtime 证据和 Homebrew ABI 二次启动回归均已通过。`gaps=2/maxGap=1` 是后续流畅度优化输入，
    不是 M3 阻塞项。
- 2026-08-25 M3.5 正式 app 合入：
  - 背景证据：`app/src/main.c` 此前只是 skeleton，正式 `nsteamlink.nro` 尚未包含
    auth/discovery/stream/session/media 链路；
  - 实现：Switch 版 `app` target 直接复用已验证的
    `tools/switch-stream-probe/main.c` 和 `tools/switch-stream-probe/media.c`；probe `main()` 在
    app target 内通过源文件级 compile definition 重命名为 `nsteamlink_stream_main()`，
    正式 `app/src/main.c` 的 `main()` 只负责调用该入口；
  - 构建系统：根 CMake 在 Switch 目标下先创建 `ihslib` target；`switch-discover` 的旧
    `add_subdirectory(third_party/ihslib)` 加 `if(NOT TARGET ihslib)` guard；`app` target 链接
    `ihslib`、FFmpeg、SDL2 和 `nx`；
  - 本地验证：`./scripts/build-switch.sh` 通过；`build/switch/app/nsteamlink.nro` 大小约 `19M`，
    sha256 `bf9977cf0e5b8055e38e21b12378285401d0524757498fa4efe2ece8c947e497`；
    `nm build/switch/app/nsteamlink.elf` 可见正式 `main`、`nsteamlink_stream_main` 和
    `probe_media_*` 符号；
  - 正式 app 首轮真机 PC 侧证据：nxlink 推送的是 `nsteamlink.nro`，日志出现
    `socketInitialize custom ... udpRx=1048576 ... sampleRcvbuf=1048576`、`streaming success`、
    `session connected`、`video decoder opened: h264 (nvtegra)`、`SDL video texture ready: NV12 1280x720`
    和 `first frame displayed: id=0 size=1280x720 fmt=23`；
  - 同轮 3600 帧摘要：
    `frames=3600 keyframes=2 decoded=3600 displayed=3598 mediaDrop=1 gaps=0 maxGap=0`
    `encodedKB=9434 avgKbps=655 elapsedMs=117924 firstRxMs=1166 transferFrames=3600 converted=0`
    `decodeAvgUs=4961 transferAvgUs=1559 convertAvgUs=0 uploadAvgUs=2135 presentAvgUs=587`；
  - 同轮退出日志出现 `auto exit requested after probe stream`、`return path: safe_cleanup=1`、
    `cleanup: join watchdog`、`cleanup: join stream worker`、`cleanup: IHS_Quit`、
    `media shutdown: SDL_Quit done` 和 `exiting ...`；
  - 二次启动 PC 侧证据：再次推送 `nsteamlink.nro` 后成功进入应用并显示首帧，debug `exit`
    在 `frames=2105 decoded=2105 displayed=2099 converted=0` 时被接收；退出日志再次出现
    `session stop: IHS_SessionDisconnect`、`session stop: join`、`session stop: destroy`、
    `return path: safe_cleanup=1`、`cleanup: join watchdog`、`cleanup: join stream worker`、
    `cleanup: IHS_Quit`、`media shutdown: SDL_Quit done` 和 `exiting ...`；
  - 用户随后要求后续不要默认重复测试回 hbmenu。结论：正式 app 的 PC 侧首轮长跑和二次启动清理
    均已通过；屏幕是否返回 hbmenu仍以用户观察为准，后续只在生命周期高风险变更时先说明再测。

## 真机证据 2026-08-24

- 启动证据：
  - `debug udp ready: port=28772 allowed=10.10.10.9`
  - `loaded auth.bin: deviceId=0x5314b232d44fa52d steamId=76561198217069647 lastHost=kxn-pc`
- host 发现证据：
  - `host found: kxn-pc (10.10.10.166) gamesRunning=1`
- M3.1 streaming request 通过：
  - `stream request: host=kxn-pc ip=10.10.10.166 desktop=0 pin=empty steamId=76561198217069647`
  - `streaming success: host=kxn-pc stream=10.10.10.166:27031 keyLen=16 steamId=76561198217069647`
- M3.2 session/video probe 通过：
  - `Session Authenticated`
  - `Negotiation Requesting at most 1280x720 @ 60 fps, 6000 kbps`
  - `session connected`
  - `Host offers video codec 4 (H264)`
  - `video start: 1280x720 codec=H264(4) codecData=0`
  - `video frame: count=120 id=119 ...`
- 自动 stop 与清理证据：
  - `auto stop requested after 120 frames`
  - `session disconnected`
  - `video stopped`
  - `session stopped: frames=121 keyframes=2`（另一次 game stream 为 `frames=123 keyframes=3`）
  - debug `exit` 后日志走到 `cleanup: destroy IHS client`、`cleanup: IHS_Quit`、
    `cleanup: close nxlink log socket`、`exiting ...`
- 观察项：stop 后 host status 可变为 `gamesRunning=0`，这仍只是 Steam status 字段，不代表发现失败。

## 操作方式

构建：

```bash
./scripts/build-switch.sh
```

推送 M3 probe：

```bash
$DEVKITPRO/tools/bin/nxlink -a 10.10.10.77 -s \
  build/switch/tools/switch-stream-probe/switch-stream-probe.nro
```

当前默认行为：启动后自动执行 `game` stream probe，收到 3600 帧后自动 stop 并退出回 hbmenu。

PC 端控制（备用排障入口）：

```bash
tools/switch-debugctl.py 10.10.10.77 state
tools/switch-debugctl.py 10.10.10.77 hosts
tools/switch-debugctl.py 10.10.10.77 select 1
tools/switch-debugctl.py 10.10.10.77 stream game
tools/switch-debugctl.py 10.10.10.77 stats
tools/switch-debugctl.py 10.10.10.77 exit
```

长跑参数：

```bash
tools/switch-debugctl.py 10.10.10.77 stream game short
tools/switch-debugctl.py 10.10.10.77 stream game long
tools/switch-debugctl.py 10.10.10.77 stream game frames=1800
tools/switch-debugctl.py 10.10.10.77 stream game seconds=60
tools/switch-debugctl.py 10.10.10.77 stream game hold
tools/switch-debugctl.py 10.10.10.77 stats
```

如果 Steam 返回 `streamResult=11/PINRequired`，这是串流阶段 host PIN，不是 M2 pairing code：

```bash
tools/switch-debugctl.py 10.10.10.77 stream-pin <host-pin>
```

## 真机验收标准

- M3.1 通过：debug `state` 或 nxlink 日志出现 `streaming success`，并给出 stream port、`keyLen`、
  `steamId`。
- M3.2 通过：出现 `session connected`、`video start`，且 `frames` 增长到大于 0。
- M3.3 通过：nxlink 日志出现 `media init: SDL2 renderer ready`、`video decoder opened`、
  `first frame displayed`；debug `state` 中 `firstFrame=1` 且 `displayed>0`。
- M3.3/M3.4 安全回归：启动自动 stream 后，必须看到首帧、3600 帧 auto-stop 和自动返回 hbmenu；
  之后必须连续第二次启动成功。若第二次启动前 OS 报错，不能归因于 streaming/decode，
  需保留 fatal 截图与 boot stage 文件。
- 自动 stop 通过：默认 3600 帧后日志出现 `auto stop requested`、`session stopped`、
  `auto exit requested after probe stream`、`cleanup: join watchdog`、`cleanup: join stream worker`、
  `media shutdown: SDL_Quit done`，Switch 返回 hbmenu，Steam host 不应长时间停留在 streaming 状态。
- 长跑统计通过：`stats` / `perf summary` 中 `firstFrame=1`、`displayed` 持续增长；
  `gaps/maxGap/mediaDrop`、`decode/transfer/upload/present` 耗时必须作为后续优化依据，不得在没有这些
  证据时猜测 socket、NVTEGRA 或 SDL 是瓶颈。
- 退出通过：`exit` 后返回 hbmenu，无 Atmosphere fatal；若 fatal，保留 Switch 截图、
  `sdmc:/switch/nsteamlink/stream_exit_stage.txt`、`stream_watchdog.txt` 与
  `stream_exception_dump.txt`。

## 下一步

M3.5 正式 app 的 PC 侧首轮长跑和二次启动清理已通过。下一步进入 M4：把自动 probe 流程改成可用
UI，补 streaming PIN 输入、host 选择、停流/退出交互，再开始音频和输入回传。后续不默认重复做
hbmenu/二次启动测试；只有线程、SDL/Mesa、socket 或退出生命周期改动时先说明风险再决定是否测。
