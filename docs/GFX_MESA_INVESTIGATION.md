# Mesa / SDL2 Switch 崩溃调研

日期：2026-08-25

## 触发背景

M3.3 旧 media 版静态链接 `switch-sdl2` 后，在完全被动启动测试中出现 Atmosphere fatal。
当时尚未发送 `ihs-init`、`discover-once`、`media-init` 或 `stream`。

## 已有证据

- 用户 fatal 截图：
  - `Error Code: 2144-0001 (0x290)`
  - `Program: 0100000000001000`
  - `PC: 0x000000103064A27C`
  - `Backtrace Start Address: 0x0000001030400000`
- 本地地址解析：
  - `0x103064A27C - 0x1030400000 = 0x24a27c`
  - `addr2line -e switch-stream-probe.elf 0x24a27c` -> `vbo_exec_VertexAttrib1fARB`
  - 该符号来自 Mesa 的 VBO/GL dispatch 路径。
- PC 侧：
  - nxlink 只到 `server active ...`
  - 没有应用侧 `nxlink log socket active`
  - debug `state` 超时
- 旧媒体版本地 ELF：
  - 静态链接 SDL2/EGL/glapi/drm_nouveau/Mesa；
  - `.init_array` 有 9 个 constructor，其中多个来自 Mesa/Nouveau/C++ runtime。
- 移除 SDL2/EGL/Mesa、改用 libnx framebuffer 后：
  - 被动启动/debug `state`/debug `exit` 真机通过；
  - `nm` 搜不到 `vbo_exec`、`_mesa_`、`SDL_`、`drm_`、`nouveau`、`EGL`；
  - `.init_array` 只剩 `frame_dummy`。

## 上游/本机源码证据

- `switch-sdl2` 包：
  - 版本：`2.28.5-4`
  - 依赖：`switch-mesa`、`libnx`
  - `sdl2-config --libs` 输出包含：
    `libSDL2.a -lEGL -lstdc++ -lglapi -ldrm_nouveau -lnx -lpthread`
- devkitPro SDL `switch-sdl-2.28` 分支：
  - `SWITCH_VideoInit()` 初始化 `psm`、touch、keyboard、mouse、software keyboard；
  - `SWITCH_CreateWindow()` 要求 EGL 已初始化，使用 `nwindowGetDefault()`，并对默认
    `NWindow` 调 `nwindowSetDimensions()`、`SDL_EGL_CreateSurface()`；
  - `SWITCH_PumpEvents()` 内部调用 `appletMainLoop()`；
  - 若窗口带 `SDL_WINDOW_RESIZABLE` 且 operation mode 变化，`SWITCH_PumpEvents()` 会调用
    `SDL_SetWindowSize()`，后者会销毁并重建 EGL surface。
- devkitPro SDL2 simple 示例：
  - 注释写明 Switch 上 `SDL_Init(SDL_INIT_VIDEO | SDL_INIT_JOYSTICK)` 是必要的，否则 gfx 不能正确关闭；
  - 创建 `1920x1080` window，flags `0`；
  - 创建 accelerated renderer 时带 `SDL_RENDERER_PRESENTVSYNC`；
  - 主循环是 `while (!done)`，由 `SDL_PollEvent()` 触发 SDL 的事件/app lifecycle 处理，
    没有外层 `appletMainLoop()`。
- devkitPro OpenGL 示例：
  - README 写明不能同时使用 libnx console 和 GPU；
  - 直接 EGL 示例自己调用 `appletMainLoop()`，但不使用 SDL；
  - EGL 初始化顺序为：
    `eglGetDisplay` -> `eglInitialize` -> `eglBindAPI`/`eglChooseConfig` ->
    `eglCreateWindowSurface(nwindowGetDefault())` -> `eglCreateContext` ->
    `eglMakeCurrent`；
  - 退出顺序为：
    `eglMakeCurrent(... EGL_NO_*)` -> destroy context -> destroy surface -> `eglTerminate`。

## 当前结论

- 旧 fatal 不能归因于 Steam 协议、IHS discovery、FFmpeg 解码、stream request 或 framebuffer 代码。
- 旧 fatal 与 SDL2/EGL/Mesa 链接面强相关：移除该链接面后，被动启动和退出通过。
- 这还不能证明“唯一根因是 Mesa bug”。更准确的结论是：旧 probe 对 Switch SDL2/Mesa 的初始化/
  lifecycle 使用方式不安全，且 fatal PC 落在 Mesa GL dispatch 路径。

## 高优先级待验证假设

1. **双 applet lifecycle 假设**：
   旧 probe 外层 `while (appletMainLoop())`，`probe_media_present()` 又调用 `SDL_PollEvent()`；
   SDL Switch backend 的 `SWITCH_PumpEvents()` 内部也调用 `appletMainLoop()`。
   这可能导致 applet lifecycle 被双消费，尤其在退出、HOME、锁屏、充电/休眠边界时破坏 EGL/renderer
   状态。
2. **SDL renderer/GL context 初始化顺序假设**：
   官方 SDL2 示例使用 `SDL_INIT_VIDEO | SDL_INIT_JOYSTICK`、`1920x1080 flags=0`、accelerated+vsync
   renderer 和 SDL 自己的事件循环。旧 probe 只 `SDL_INIT_VIDEO | SDL_INIT_EVENTS`，并把 SDL 延迟放进
   一个已运行网络/debug/线程程序里。
3. **默认 NWindow 独占假设**：
   SDL/EGL、libnx framebuffer、libnx console 都操作默认 `NWindow`。OpenGL 示例明确禁止 console+GPU；
   后续也应避免同进程混用 framebuffer/SDL/EGL，除非分阶段严格关闭前一图形后端。
4. **pre-main constructor 假设**：
   旧 ELF 的 Mesa/Nouveau/C++ constructor 明显多于 framebuffer 版。fatal 没有应用侧日志，仍需
   link-only 对照来判断是否存在进入 `main()` 前崩溃。

## 基准测试策略

先不要从散碎变量开始试验。第一轮只跑上游官方用法基准，每个基准只增加诊断能力：
stage 文件、nxlink 日志和固定帧数后自动退出。

1. `switch-gfx-sdl-official`
   - 基于 devkitPro `graphics/sdl2/sdl2-simple`；
   - 保持关键流程：`SDL_Init(SDL_INIT_VIDEO | SDL_INIT_JOYSTICK)`、`1920x1080 flags=0`
     window、`SDL_RENDERER_ACCELERATED | SDL_RENDERER_PRESENTVSYNC` renderer、SDL 自己的
     `while (!done)` + `SDL_PollEvent()` 主循环；
   - 不在 SDL 循环外层调用 `appletMainLoop()`。
2. `switch-gfx-gl-official`
   - 基于 devkitPro `graphics/opengl/simple_triangle`；
   - 保持关键流程：直接 `EGL` + `glad`、`nwindowGetDefault()`、OpenGL 4.3 context、
     VAO/VBO triangle、外层 `appletMainLoop()`、官方 EGL cleanup 顺序。

只有在这两个官方基准有结果后，才继续做差分 probe：

- 若官方 SDL 基准稳定，而旧 app 结构不稳定，优先验证双 applet lifecycle 与 app 内部集成顺序。
- 若官方 OpenGL 基准稳定，而官方 SDL 基准不稳定，问题更偏向 SDL Switch backend 使用/初始化。
- 若官方 OpenGL 基准也 fatal，问题才上升到 Mesa/EGL/Atmosphere/固件/hbmenu 环境或库版本层。
- 若官方基准均稳定，再把主程序图形路径改造成同一种生命周期模型，而不是把 SDL/EGL 混进现有
  `appletMainLoop()` 主循环。

## 当前本地产物

- `build/switch/tools/switch-gfx-probe/switch-gfx-sdl-official.nro`
  - size: 6.5M
  - sha256: `04dcadc7ec99e4bff3a4db22a418b2f911d678b04e904d4aadf9b2dae2206db2`
- `build/switch/tools/switch-gfx-probe/switch-gfx-gl-official.nro`
  - size: 5.7M
  - sha256: `59159054a014f1a672ca1d755f9e57012115248f5f1cde1aafa392cfa356a65d`

## 2026-08-25 官方 OpenGL 基准真机结果

用户通过 hbmenu/netloader 推送 `switch-gfx-gl-official.nro` 后直接 fatal。

证据：

- 用户截图：
  - `Error Code: 2168-0002 (0x4a8)`
  - `Program: 010000000000100D`
  - `PC: 0x00000010498A6DFC`
  - `Backtrace Start Address: 0x00000010494CA000`
- 本地地址解析：
  - `0x10498A6DFC - 0x10494CA000 = 0x3dcdfc`
  - `addr2line -e switch-gfx-gl-official.elf 0x3dcdfc`
    -> `armDCacheFlush_L0`
  - 可见 backtrace 地址解析：
    - `0x3d431c` -> `nouveau_bo_new`
    - `0x1ae10`, `0x1b61c` -> `nvc0_screen_create`
    - `0x13f34` -> `_eglMatchDriver`
    - `0x158c8` -> `switch_initialize`
- 反汇编证据：
  - `nouveau_bo_new` 调 `nvMapCreate`；
  - `nvMapCreate` 在 `nvioctlNvmap_Alloc` 成功路径上调用 `armDCacheFlush`；
  - fatal PC 落在 `dc civac` cache maintenance 循环。
- Switchbrew 资料：
  - `010000000000100D` 是 `photoViewer (LibraryAppletPhotoViewer)`；
  - Album/PhotoViewer applet 使用 `0xF200000` heap（约 242 MiB，至少 10.0.0 如此）。

结论：

- 这次 fatal 不能归因于 SDL。直接 EGL + glad + Mesa/Nouveau 的官方 OpenGL 基准也会崩。
- 崩溃发生在 Mesa/Nouveau 初始化 GPU buffer 对象阶段，不是 shader 编译后期、Steam、FFmpeg 或主程序业务逻辑。
- 当前 Switch 运行环境从 Program ID 看是 Album/PhotoViewer library applet，而不是普通 application title。

待验证假设：

- **最强假设：Applet Mode 资源/内存限制导致 Mesa/Nouveau BO 创建路径不稳定。**
  证据是 Program ID 为 Album applet，且 fatal 位于 Nouveau buffer allocation/cache flush 路径。
- 还不能排除 22.5.0/Atmosphere 1.11.2 与当前 devkitPro `switch-mesa`/`libdrm_nouveau` 的兼容问题；
  但该假设必须先在 full application/title override 环境下复测同一 NRO 后才能成立。

下一步：

- 不继续改 OpenGL 代码。
- 先用 title override / full application 环境重新启动 hbmenu/netloader，再推同一个
  `switch-gfx-gl-official.nro`。
- 如果 full application 环境通过，主程序必须在 applet mode 下禁用 GPU/Mesa 路径并显示英文提示；
  真正运行流媒体时要求 full application 环境。
- 如果 full application 环境仍 fatal，再转向库版本/固件/Atmosphere/Mesa 兼容性调查，并保留 crash report。

## 2026-08-25 官方 OpenGL 基准 full application 复测

证据：

- 用户插入可用实体卡带后，通过卡带 title override 进入 hbmenu/netloader。
- PC 侧推送的是同一份 `switch-gfx-gl-official.nro`：
  - sha256: `59159054a014f1a672ca1d755f9e57012115248f5f1cde1aafa392cfa356a65d`
- 用户反馈：`都正常了`。这表示同一官方 OpenGL 基准在 full application 环境下正常运行/退出。

结论：

- 这与此前 Album/PhotoViewer applet 环境下同一 NRO fatal 构成直接对照。
- “Applet Mode 资源/内存限制导致 Mesa/Nouveau BO 创建路径失败”从待验证假设升级为当前最强结论。
- 继续 M3 时不再阻塞于 Mesa 对照测试；full application 条件确认后，M3 主线恢复 SDL2/Mesa 正常流程。
  后续 GPU/Mesa 路径必须要求 full application 环境，且 applet mode 下应禁用或明确提示。

## Ban / 无已安装 Application Title 时的 full mode 路径

证据：

- Atmosphère `override_config.ini` 模板说明 `override_any_app` 只作用于 application program IDs；
  因此 Album/PhotoViewer applet 本身不能变成 full application mode。
- 社区资料对无已安装游戏的常见建议收敛到两类：
  - 使用任意实体卡带作为 title override 目标；
  - 安装一个 Homebrew Menu Loader / hbmenu forwarder NSP 作为 HOME 菜单 application title。
- GameBrew 记录的 Homebrew Menu Loader 是基于 `nx-hbloader` 的 NSP app/forwarder，用于加载
  `sdmc:/hbmenu.nro`；这是 homebrew loader，不是游戏 NSP。
- Atmosphère `system_settings.ini` 模板提供 `[hbloader]` applet heap 设置：
  `applet_heap_size` 和 `applet_heap_reservation_size`。这只能调整 applet 模式下的可用 heap，
  不能把 applet 变成 full application mode。

结论：

- 被 ban 只影响 eShop/在线下载，不改变 title override 的技术要求：仍需要一个 application title。
- 若没有已安装 application title，最稳妥路径是实体卡带；其次是本地安装合法 homebrew loader/forwarder。
- 在暂时没有实体卡带/forwarder 时，可以尝试把 applet heap reserve 调低作为 Mesa 调查 workaround，
  但这不是 full mode 验证，结果不能替代 title override 复测。

## TooTallNate/switch-nsp-forwarder 评估

证据：

- 上游 README 说明该项目用于在 Switch 上生成并安装 NRO forwarder NSP：
  <https://github.com/TooTallNate/switch-nsp-forwarder>
- GitHub latest release 当前为 `0.0.8`，资产包括 `nsp-forwarder.nro` 和 `nsp-forwarder.nsp`：
  <https://github.com/TooTallNate/switch-nsp-forwarder/releases/tag/0.0.8>
- `0.0.8` release note 明确修复 forwarded NRO 按 `+` 退出时应返回 HOME，而不是重新加载 NRO。
- GameBrew 页面说明该 app 自身需要 full memory/title redirection，不能直接从 Album menu 启动：
  <https://www.gamebrew.org/wiki/Switch-NSP-Forwarder>
- 本地已暂存官方 release 资产：
  - `/data/dl/switch-setup/sd-root/switch/nsp-forwarder/nsp-forwarder.nro`
    - sha256: `c668d6cf665ec8f38faf6288d7767df2ca3796bb0502ac25a5ae20eeecd4bdb5`
  - `/data/dl/switch-setup/downloads/nsp-forwarder.nsp`
    - sha256: `bf34c8d686402b1d6aba1d00682ab279e81e9923572679207b190512055819e7`

结论：

- 该工具适合作为长期方案：生成一个从 HOME 菜单启动 `hbmenu.nro` 或项目 NRO 的 application
  title/forwarder，从而进入非 Album applet 的 full application 环境。
- 它不是纯 applet 状态的完整自举方案。`nsp-forwarder.nro` 本身需要 full memory 才能可靠运行；
  若当前只有 Album applet，没有实体卡带、已安装 application title 或可用 title installer，则仍缺少
  第一次安装 forwarder 的入口。
- 若能先安装 `nsp-forwarder.nsp` 或其它 hbmenu forwarder NSP，后续即可从 HOME 启动该 forwarder，
  再运行 hbmenu/netloader 做 Mesa full mode 复测。

## 当前工程策略

- framebuffer 版只作为隔离 applet/Mesa 资源问题的临时证据，不作为 M3 最终图形路线。
- full application 下官方 OpenGL 基准已通过后，M3 主程序恢复 SDL2 renderer/texture 路线。
- 主程序图形路径必须收敛到 SDL-owned lifecycle：media 启动后由 `SDL_PollEvent()` 驱动 SDL Switch
  backend 的 `SWITCH_PumpEvents()`，不在外层再调用 `appletMainLoop()`。
- applet mode 下禁止启用 SDL/Mesa 路径；真正运行流媒体要求 title override/full application 环境。
