# Switch 系统按键与 Steam Guide 输入参考

本参考核对 HOME/Capture 的平台边界、NSteamLink 现有控制器身份与特殊按键报告格式。
核对日期：2026-10-23。平台依据为本机 devkitPro headers、联网取得的 libnx、
devkitPro SDL、nx-hbloader、Atmosphère 上游源码，以及 Valve 的 Steam Input 文档。
本研究没有运行 Switch 程序、修改运行时、连接设备或启动 Steam 游戏。
源码核对点为研究分支 `10ebff5f61799f949ead37d1a0dda855c179ce68`。

## 1. 用户可理解的结论

- **Capture 短按存在正规的 applet 通知路径。** libnx 提供
  `appletSetRequiresCaptureButtonShortPressedMessage(true)`（系统 3.0.0 起），
  收到的是消息 90，可通过 `AppletHookType_OnCaptureButtonShortPressed` 获取。
  这不是普通 SDL 手柄按钮，但可以作为生成 Steam Guide 按键的触发来源。
  上游还明确说明：非 Overlay applet 启用该通知后，系统 Overlay 不再收到用于截图的短按。
  因而“两个键都完全不能被自制软件接收，必须打系统补丁”不成立。
- **HOME 的读取和阻止系统动作是两件事。** 全应用模式有阻止 HOME 短按、或短按及长按
  的 applet API；libnx 也公开了需要 `hid:sys` 激活的 HOME 专用共享内存读取 API。
  但源代码中的 API 存在并不证明我们的进程/固件上读取成功、所有状态都可用，
  更不证明读取会取消 HOME 菜单动作。当前证据不足以承诺直接把物理 HOME 当 Steam 键。
- **无需冒充 Xbox、DualShock 或 Steam Deck 才能发送 Guide。** 现有 Generic RAW
  报告已经能表达 Guide、Misc1，并声明了相应能力。普通可读按键组合可以由本地逻辑
  转成 Guide 的按下/释放；目前尚未实现这项组合键映射。
- **当前设备证据是 Generic 身份，配 Nintendo ABXY 标签，线上使用 Generic RAW 格式。**
  最近留存日志是 VID/PID `0000:0000`、SDL type `0`；历史日志里的 `057e:2009`
  不能代表该构建。手柄名字叫 `Switch Controller` 并不等于 Steam Switch Pro 类型。

## 2. 平台证据：不要混淆四类能力

| 能力 | 直接证据 | 可以得出的结论 | 不能据此声称 |
|---|---|---|---|
| 普通按键读取 | 本机 `hid.h:255–299` 的 `HidNpadButton` 无 HOME/Capture；SDL Switch `pad_mapping_default` 也无这两个键 | 当前 pad/SDL 常规输入链不会自然生成它们 | 任何系统接口都读不到它们 |
| 禁止截图 | `applet.h:723–727`，`appletSetScreenShotPermission` | 可以设定截图权限 | 获得 Capture 的按下、释放或短按通知 |
| Capture 短按通知 | `applet.h:750–755`、消息/Hook `:46/:61`；上游 `applet.c:1140,3107–3108` | 系统 3.0.0 起有专用短按消息；非 Overlay 接收时原截图通知不再转给 Overlay | 长按/释放事件、连续原始状态、每个控制器的独立来源，或已在本机验证 |
| HOME 系统动作屏蔽 | `applet.h:1481–1505`；上游 `applet.c:2094–2097` | `AppletType_*Application` 可调用成对 Begin/End；短按屏蔽和短/长按屏蔽分开 | 自动得到按键事件、适用于 LibraryApplet，或已验证实际屏蔽效果 |
| HOME/Capture 原始读取入口 | `hid.h:1546–1580`、`hidsys.h:214–256`；上游 `hid.c:278–303`、`hidsys.c:234–255` | 专用共享内存、更新事件、激活命令存在 | 普通 HID 已自动激活；取得 `hid:sys` 就必然获得有效状态；读取会阻止系统菜单 |

这里的本机头文件路径均以 `/opt/devkitpro/libnx/include/switch/services/` 为根。
上游 libnx 固定版本：
[`b156b4774fb2df7b93402169509266da7547fc4c`](https://github.com/switchbrew/libnx/tree/b156b4774fb2df7b93402169509266da7547fc4c)。
相关文件为 [applet.h](https://github.com/switchbrew/libnx/blob/b156b4774fb2df7b93402169509266da7547fc4c/nx/include/switch/services/applet.h)、
[applet.c](https://github.com/switchbrew/libnx/blob/b156b4774fb2df7b93402169509266da7547fc4c/nx/source/services/applet.c)、
[hid.c](https://github.com/switchbrew/libnx/blob/b156b4774fb2df7b93402169509266da7547fc4c/nx/source/services/hid.c)、
[hidsys.c](https://github.com/switchbrew/libnx/blob/b156b4774fb2df7b93402169509266da7547fc4c/nx/source/services/hidsys.c)。

**Evidence：** `hidsysInitialize()` 连接 `hid:sys`，记录当前 applet resource user ID；
HOME 激活命令 111、Capture 激活命令 151 均发送该 ARUID 及 PID
（上游 `hidsys.c:14–34,234–255`）。`hidGetHomeButtonStates` 等只从已经映射的
HID 共享内存 LIFO 读取，不会自行发激活请求。`HidHomeButtonState` 与
`HidCaptureButtonState` 各只有 sampling number 与 buttons；不能从这些声明推导
当前设备的有效按钮位值或访问权限。`hidsys.h` 也明确提醒这些激活/事件接口通常由 AM
系统模块内部使用。

**权限边界：** Atmosphère 的 [SM 实现](https://github.com/Atmosphere-NX/Atmosphere/blob/6b0c077b4c608a3a2ee712b8dc35fee87ceb62e8/stratosphere/sm/source/impl/sm_service_manager.cpp#L613)
在 `GetServiceHandle:613–624` 检查进程 service access control；`:222–242`
支持 wildcard 匹配，找不到匹配返回 NotAllowed。
nx-hbloader 的 [hbl.json:20–25](https://github.com/switchbrew/nx-hbloader/blob/82b95122c5ae8dc059bf23893ba7623c72c86773/hbl.json#L20)
声明 `service_access: ["*"]`，仓库自带 `third_party/nx-hbloader/hbl.json:20–25`
亦如此。因此不能笼统说 hbloader 自制程序永远没有 `hid:sys` 权限。
不过 wildcard 仅是服务连接层证据，不能证明 HID 服务内部允许当前 ARUID 激活并产出
系统按键状态，也不能证明用户设备实际采用了这份 NPDM。

**其他名称易误导的接口：**

- `appletBeginToWatchShortHomeButtonMessage`/`End` 是 OverlayApplet 专用输入转发控制
  （本机 `applet.h:2360–2374`），不是普通应用的 HOME 短按 Hook。
- `appletSetHandlingHomeButtonShortPressedEnabled` 在 Overlay 的 8.0.0+、非 Overlay
  的 9.1.0+ 可用（`:2703–2708`）。源码只是发送布尔设置，非 Overlay 走
  ICommonStateGetter 命令 100（上游 `applet.c:3007–3020`）；不能仅凭函数名推断
  它会把 HOME 按键交给应用。
- `hidSetNpadCaptureButtonAssignment`（8.0.0+，`hid.h:2050–2061`）指定哪些普通按键
  触发系统 Capture；它不是把物理 Capture 变成普通 Npad 键的接口。
- `appletPerformSystemButtonPressing*` 是请求系统执行一次系统按钮动作，不是读取键值。

**Conclusion：** Capture 的短按通知路径不需要新增系统级 patch 才能在源码层成立。
HOME 则有“应用模式屏蔽 + 系统 HID 读取”的候选路径，是否可以无 patch 组合使用，
在本机进程权限/固件上仍待验证。若这些服务拒绝或不产出 HOME 状态，独占截获 HOME
就会涉及系统 HID/AM 或 MITM/patch 层，超出普通客户端输入适配；本研究没有实施。
不能把尚未验证的候选路线写成必须 patch，也不能承诺完全无需 patch。

## 3. NSteamLink 实际控制器身份、布局与报告格式

**Evidence：研究 worktree 留存的设备日志。** 以下两份未入库日志实际位于归档根
`/data/dl/nsteamlink-anywhere/`，不是 `/data/dl/nsteamlink/` 的 build 目录；
这里的 `build/...` 均相对于该归档根。来源是该 worktree 已留存的设备采集材料，
本次研究仅读取，没有重新连接设备。

`build/device-d6dcce4-10.10.10.66/accepted-hotspot/session-00000000001792751101-097833528-00000.log`：

- `:13` 记录选中 controller 0，SDL `type=0`，名称 `Switch Controller`，
  GUID `000038f853776974636820436f6e7400`。
- `:255` 记录 `HID: Device found: sdl://0, id=0000:0000, name=Switch Controller`。
- 较旧的 `build/device-d6dcce4-10.10.10.66/home-startup/stream_diag_older.log:40`
  确实是 `057e:2009`；它只证明历史构建曾报告 Nintendo VID/PID。

**Evidence：源码与已安装依赖。**

1. 本机安装包元数据
   `/opt/devkitpro/pacman/var/lib/pacman/local/switch-sdl2-2.28.5-4/desc:1–8`
   记录 `switch-sdl2 2.28.5-4`。
   devkitPro [PKGBUILD](https://github.com/devkitPro/pacman-packages/blob/master/switch/SDL2/PKGBUILD)
   对应的 [SDL 补丁](https://github.com/devkitPro/pacman-packages/blob/master/switch/SDL2/SDL2-2.28.5.patch)
   SHA-256 为 `eb2da665a014dc540ad3dfeb62b3f7c5e15ae090ebdd631fe8b78c1f272c7aa0`，
   与下载实际计算一致。补丁所加 `SDL_sysjoystick.c:187–206` 固定使用名称和名字 GUID；
   同逻辑的固定上游源见
   [devkitPro SDL:187–206](https://github.com/devkitPro/SDL/blob/0738d3c9f6993875e2f3dd0e8cc0bb4ae4440b4e/src/joystick/switch/SDL_sysjoystick.c#L187)。
2. `app/platforms/common/media.c:199–215` 安装 ABXY 标签映射：`a:b0,b:b1,x:b2,y:b3`；
   它没有 `type:Switch Pro`、`guide:` 或 `misc1:` 项。故 NSteamLink 的 A 是 Switch
   标 A 的右侧键；不能把“SDL A”在这里简单解释成物理南侧键。
3. `third_party/ihslib/src/hid/sdl/src/sdl_hid_enumerator_unmanaged.c:143–148`
   在 GUID 非标准 VID/PID 形式时填零。`sdl_hid_utils.c:33–56` 给出解析条件。
   `control_hid.c:588–592` 仅在 VID/PID 均非零时发送这两个可选字段。
4. `third_party/ihslib/src/hid/sdl/src/sdl_hid_feature_report.c:136–168`
   根据 SDL type 选择 Steam controller type；未知类型走 `30`
   （UnknownNonSteamController），Nintendo Pro 分支才走 `38`。
   结合设备 `type=0` 的日志，当前代码会报告 generic 类型。
   这是源码结合日志得出的结论，不是本次重新抓取的 host feature-report 字节。
5. `third_party/ihslib/src/session/channels/control/control_hid.c:602`
   固定声明 `is_generic_gamepad=true`；
   `third_party/ihslib/src/hid/sdl/src/sdl_hid_common.h:99–124`
   使用 Generic RAW 结构，版本选择器 `wire[27]=3`。它与 VID/PID、外观布局是独立维度。

**Conclusion：** 当前构建是 Generic 身份与 Generic RAW 传输，ABXY 采用 Switch 标签映射。
即便以后仅把 VID/PID 改成 `057e:2009`，也不能据此声称实现了真实 Pro Controller HID
协议；反过来 `is_generic_gamepad=true` 也不意味着必须丢弃真实设备 VID/PID。
相关历史混淆和按钮映射更正见 `OFFICIAL_INPUT_RE.md:469–629`，尤其 §17.9。

## 4. Steam 特殊按键的精确编码

当前 Generic RAW 的按钮字段在报告偏移 `16`。官方客户端的 SDL 按钮位顺序证据记录于
`OFFICIAL_INPUT_RE.md:607–629`：`CHIDDeviceSDLGamepad::OnButtonEvent @0x754034`
直接写 `1 << ev->button`。当前 packer 对应 `sdl_hid_common.h:88–124`；
`sdl_hid_report.c:42–52` 接受编号 `0..15` 并设置相应位。
这些 wire 位来自官方二进制研究及现有源码；Valve 的公开 Steam Input 用户文档没有
公布这份 Remote HID RAW 字节布局，不能把该文档当 wire 格式的直接出处。

| 意图/按钮 | SDL2/应用编号 | RAW 按钮掩码 | 仅此键按下时关键字节 | 当前声明的能力位 |
|---|---:|---:|---|---:|
| Steam/Guide/PS/Xbox 系统键语义 | Guide = `5`，`SL_KEY_GUIDE=5` | `1 << 5 = 0x0020` | `wire[16]=0x20`, `wire[17]=0x00` | `IHS_HID_CAP_GUIDE=0x00000200` |
| Capture/Share 类额外按钮 | Misc1 = `15` | `1 << 15 = 0x8000` | `wire[16]=0x00`, `wire[17]=0x80` | `IHS_HID_CAP_MISC_1=0x00800000` |

释放时清除相应 bit，保留其他正在按下的按键。其余字节遵循现有报告结构，不能只发送
这两个字节代替完整/delta HID 信封。能力位是设备声明，不是输入按钮掩码。
`EGamepadButton_Steam=16` 属于配置消息枚举，**不是** RAW 按钮 bit 16；混用历史上造成
真实按键错乱，见 `OFFICIAL_INPUT_RE.md` §17.9。

能力定义在 `third_party/ihslib/include/ihslib/hid.h:55,65`；设备声明已同时 OR 入两者
（`control_hid.c:605–616`）。SDL2 的
[官方枚举](https://github.com/libsdl-org/SDL/blob/release-2.28.5/include/SDL_gamecontroller.h#L710)
明确把 Misc1 包含 Nintendo Switch Pro Capture、Xbox Share 等用途；它不表示无论何种
host 配置，Misc1 都会打开 Steam 浮层或 Quick Access Menu。

**协议可表达与应用已接通不同。**

- Guide 已有 `app/src/input/input_router.h:9` 的逻辑键编号，最终经
  `app/platforms/common/media.c:2005–2027` 合成 SDL controller event，送入 HID provider。
  因而本地普通按键组合转 Guide 不需要更换报告协议或特定设备身份。
- Misc1 的 `15` 在 HID packer 可表达，但 app router 的 `SL_KEY_COUNT=15`
  （`input_router.h:3–19`），`input_router.c:240` 会拒绝 `code >= 15`。
  当前没有物理 Capture→Misc1 的完整应用链。
- 当前 `-/+` 同按在 100ms 窗口内开始，保持 800ms 打开的是 **NSteamLink 本地菜单**
  （`input_router.c:6,276–300`），不是 Steam Guide。若另设 host 浮层组合，应与这个已用
  手势区分，并抑制组成该组合的普通键泄漏给游戏。
- 短按通知没有释放边沿。合成 Guide pulse 必须确保按下状态至少提交一次，再提交释放；
  同一 flush 前写 down/up 会合并回中性状态。依据是
  `sdl_hid_event.c:280–292` 只更新 `states.current`，报告在独立 flush 时读取。
  hook 回调应仅排队意图，由已有输入 owner 发送和释放；不在 hook 中阻塞网络或打印日志。

## 5. Steam 浮层语义与设计边界

Valve [Steam Input 玩家文档](https://partner.steamgames.com/doc/features/steam_controller/getting_started_for_players)
将 Guide 定义为 Steam/Xbox/PlayStation 那类系统键，并说明 Guide Button Chord
Configuration 是跨设备的组合输入配置。Valve 的
[Big Picture 公告](https://store.steampowered.com/news/app/593110/view/3394051164709183116)
（2022-10-27；正文亦可在 [官方新闻归档](https://store.steampowered.com/news/posts/?enddate=1671645631&feed=steam_blog) 阅读）
说明游戏内 Guide 打开浮层，Guide+A 可打开 Quick Access Menu。
这证明“普通控制器也有 Guide/浮层路径”，不证明用户当前 Steam 版本、个性化配置、
游戏 overlay 状态下每个动作都保持该默认绑定。

**Conclusion：** 适合现有协议的目标是 host Guide 输入，而不是虚构一个“Steam Overlay”
专用 HID 键。Capture 短按通知或本地普通键组合都可成为该输入的来源；Guide+A 也是可表达
的按钮组合（当前标签映射中 A=bit0，因此掩码 `0x0021`），但 Quick Access 的实际动作仍取决于
host 的 Guide chord 配置。不要将该 A 擅自换成物理南侧 B，也不要把 Misc1 等同于 Steam Deck
专用 Quick Access 键。

**HOME 保留系统用途的理由：** 当前未验证 HOME 原始读取，提前屏蔽 HOME 可能移除用户
在串流故障、输入线程失效时返回系统菜单的常用路径。仅屏蔽短按和屏蔽短/长按风险也不同。
若实现 HOME 接管，必须以独立平台决策说明权限、系统动作恢复及异常退出路径，并遵循
Homebrew ABI 的线程/句柄清理要求。Capture 通知注册也应在退出/回 loader 前显式恢复并
撤销 hook；普通输入组合则可完全避开对 HOME 系统行为的依赖。

**待验证边界：** 当前证据尚未覆盖本机 Capture 通知实际送达及截图抑制、Capture 长按、
HOME 激活/状态有效性与屏蔽交互、各固件/进程 NPDM 差异、合成 Guide 后 host 浮层实际打开，
以及多控制器来源区分。这些均不能由 nxlink 退出或 PC 侧 ACK 推定。

## 6. 应用级接线：复用 applet 分派，不另建消息接收循环

**Evidence：现有消息消费位置。** `app/platforms/switch/system.c:53–57` 的
`sl_system_running()` 调用 `appletMainLoop()`，主应用循环在
`app/platforms/common/application.c:328` 调用它。当前 deko 路径的
`media.c:849–850` 不初始化 `SDL_INIT_VIDEO`，`switch/events.c:33–53` 在现有事件链
查询 libnx focus，并调用 `SDL_PollEvent`。

**Evidence：SDL 和 libnx 上游。** 已安装 SDL 对应补丁新增的
`src/video/switch/SDL_switchvideo.c:109,345–355` 安装视频后端 PumpEvents，
其中同样调用 `appletMainLoop()`；若返回 false，就生成 `SDL_QUIT`。
固定上游文件见
[SDL_switchvideo.c](https://github.com/devkitPro/SDL/blob/0738d3c9f6993875e2f3dd0e8cc0bb4ae4440b4e/src/video/switch/SDL_switchvideo.c)。
补丁内没有 `appletHook`/`appletGetMessage` 的独立 SDL 接收器；此处是借用 libnx 分派，
不是 SDL 将 Capture 映射成手柄按钮。当前无 SDL video 的 deko 构建不能指望该视频
PumpEvents 帮它收 Capture，但已有 `sl_system_running` 提供消息泵。

libnx `applet.c:3119–3124` 的 `appletMainLoop()` 取一个消息，调用
`appletProcessMessage()`；后者在 `:3070–3080` 处理退出/focus，在 `:3107–3108`
分派 Capture hook。hook 链 `:521–551` 没有自行取消息，只在分派时调用注册回调。
如果应用另设 `appletGetMessage()` 循环只挑 Capture，其余消息会被取走，导致既有
`appletMainLoop()` 看不到退出请求或不能刷新 focus 缓存。这与 Capture 功能无关的
生命周期风险不应引入。

**建议方案（设计候选，未实现/未真机验证）：**

1. 在 Switch 平台初始化/事件适配层注册一个持久 `AppletHookCookie`，再调用
   `appletSetRequiresCaptureButtonShortPressedMessage(true)` 并检查 Result。
   该方案使用当前 applet 的 ISelfController，不需要新增 `hid:sys` 连接、
   HOME 屏蔽或系统级 patch。失败时保留普通组合键入口。
2. hook 只识别 `AppletHookType_OnCaptureButtonShortPressed`，写入一个有界 intent
   队列/计数；不直接消费 `appletGetMessage`，不操作 IHS session、SDL 状态或网络。
   让现有 `sl_system_running`（以及视频后端存在时的 SDL）继续完整分派生命周期消息。
3. 由 `switch/events.c` 或现有应用输入 owner 消费 intent，按当前 foreground、streaming、
   local-menu/input gate 决定是否转为 Guide pulse。该事件是一次短按通知，不能冒充
   物理 down/up 或可持续长按；Guide pulse 必须有有界持续时间和显式 release，
   并保证按下至少形成一次提交后才释放。队列溢出要合并/丢弃，不能累积为长时间连发。
4. gate 关闭、focus 丢失、会话结束时走现有 neutral/release 语义，清空待发 intent；
   生命周期恢复后不能补发陈旧 Capture。退出和初始化失败均撤销自己启用的通知，
   配对 `appletUnhook`，且 cookie 生存期覆盖整个注册期。hook 链本身没有锁，注册、
   撤销与消息泵应保持同一 owner/严格时序。

**Conclusion：** 应用级首选是 Capture 短按 Hook→现有平台输入→合成有界 Guide pulse，
普通键组合是同协议的另一入口。两条路线都不依赖读取物理 HOME。
HOME 仍需另行证明其系统 HID 读取、权限和动作屏蔽，不能用 Capture 消息的可用性代替。
hook 通知、Guide 报告形成和 host 浮层打开是三个独立验证事实。
