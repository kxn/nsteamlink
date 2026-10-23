# Switch 系统按键与 Steam Guide 输入参考

本参考核对 HOME/Capture 的平台边界、NSteamLink 现有控制器身份与特殊按键报告格式。
核对日期：2026-10-23。平台依据为本机 devkitPro headers、联网取得的 libnx、
devkitPro SDL、nx-hbloader、Atmosphère 上游源码，以及 Valve 的 Steam Input 文档。
初始研究没有运行 Switch 程序、连接设备或启动 Steam 游戏。
初始源码核对点为研究分支 `10ebff5f61799f949ead37d1a0dda855c179ce68`；
应用级实现的契约与自动验证范围另见 §7，不把 PC 侧测试当作 Switch 实机结论。

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

**初始研究的待验证边界更正：** 本机系统模拟 Capture 的通知接收与关闭后无通知，现已有
§8 的实机日志证据，撤回“没有任何本机通知送达证据”的旧范围描述。Capture 物理首按、长按、
HOME 激活/状态有效性与屏蔽交互、各固件/进程 NPDM 差异，以及多控制器来源区分仍须
分别判断；它们不能由 API 模拟请求、nxlink 退出或 PC 侧 ACK 推定。

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

**接线约束（§7 实现采用此结构；实机与 host 行为另行区分）：**

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

## 7. Capture→Guide 的应用契约

更正初始研究中“只有平台候选、尚无 Capture 接线”的实现范围：应用现有
`switch/events.c` 使用 `appletHook`，由原有 `appletMainLoop` 分派短按消息；
没有增加原始消息消费者、线程或 HOME 屏蔽。

`设置→应用→Steam Guide 键` 是应用设置中的值行，右侧显示当前的“关闭”或“截图键”；
进入后沿用既有单选页。原“特殊功能”分类已移除。当前设置模型使用
`sl_guide_key` 枚举 `SL_GUIDE_KEY_OFF=0` / `SL_GUIDE_KEY_CAPTURE=1`，不提供未验证的 HOME
选项；应用在枚举等于 CAPTURE 时才向现有媒体 bool 接口请求 Capture→Guide。
`services/special_settings.c` 使用独立应用级 `special.conf` v2：

```text
version=2
guide_key=capture
```

关闭写为 `guide_key=off`。缺文件表示从未具有该设置的旧安装，默认 CAPTURE；读取 v1 的
`capture_guide=0/1` 分别迁移为 OFF/CAPTURE，每次保存均写 v2，保留原来明确关闭的偏好。
未知版本、来源值（含未支持的 `home`）、损坏或读取失败均回落 OFF；非法枚举拒绝保存。
存盘沿用 temp/backup/rename 的恢复方式，保存失败进入现有设置保存错误反馈，
不修改身份/配对 `profile.bin` 格式。

**通知所有权。** 通知仅在设置开启、本地输入 gate 开放、前台、实际 session 连接并允许
input、且选中 joystick 已被 host 打开并开始 RAW 输入报告后启用。目标 readiness
通过 `IHS_HIDSDLInputReady(session, joystickId)` 在既有 lookup/设备锁下检查，不读首设备
诊断缓存来推测。菜单、失焦、连接/断开及关闭开关恢复通知为 false；本功能不设置
`appletSetScreenShotPermission`，也没有增加全局禁止截图。系统 3.0.0 以下不尝试注册，
可选 enable 失败保留系统行为；只有成功 enable 才产生恢复义务。

**Guide 报告。** hook 只写容量一的 intent；输入 owner 经 `input/guide_pulse.c` 合成为
一次 Guide pulse。每次按下/释放分别调用现有 SDL event→显式 full refresh→IHS 可靠队列
路径，按下只有在 `IHS_HIDRefreshSDLGameControllers` 返回 true 后才标记为 admitted。
50ms 是已 admission 后的脉冲时长，不是提交证据；250ms 未 admission 则取消。
释放即使 canonical/baseline 已经为 0 仍可强制 full refresh，失败保留 release 重试，
不重放旧 intent、不累计连续短按。Guide 只改 bit5，普通 A/轴由现有 canonical state 保留。
会话或目标设备替换前中性化旧设备，再清掉该目标的 pulse，不能跨会话补发。
这里的 admission 仅证明本地加密队列接纳，不能表示传输 ACK 或主机已打开浮层。

**退出顺序。** 主循环先关 input gate 并中性释放，再撤 Capture 通知；正常 teardown
撤通知/Hook 后，按既有顺序停止并 join HID flush worker、移除 session、释放音视频/SDL。
初始化失败也通过相同的 event shutdown 配对撤 Hook。成功开启后的 off IPC 若失败，
保留恢复义务，退出阶段有界重试三次；仍失败就终止而不是把已知未恢复的 applet 状态
当正常 hbmenu 返回。从未成功开启的“不支持/enable 失败”不会触发这条异常路径。

**自动测试证据范围。** `test_capture_guide.c` 覆盖默认迁移、OFF 保留、版本/损坏、
发布失败、独立页面和有界 pulse；`test_switch_capture_events.c` 执行真实平台适配器，
以 libnx service terminal 替身检查消息 coalescing、unsupported、enable/off 失败与成对清理。
`test_capture_guide_hid.c` 执行真实输入 owner、SDL provider、RemoteHID/full72 序列化、
加密和队列，检查目标不是首设备时的 bit5 down/up、普通 A/轴保留、report 尚未开始、
InputEnabled/连接状态、admission 拒绝、释放重试、gate/设置/失焦/会话清理。
这些测试不调用设备服务、不启动 Steam 游戏，也不证明 Switch 截图或 Steam 浮层可用。

**诊断主应用的 API 自测。** 仅 `NSL_DIAGNOSTICS=1` 的 Switch 构建接受
`--capture-guide-selftest`，自动强制 offline，沿用正常主循环，结束后清理退出；Release
不包含该入口。它在前台使用系统 6.0.0 起的
`appletPerformSystemButtonPressingIfInFocus(CaptureButtonShortPressing=6)`：先 enable 并请求
一次系统 Capture-short，等待真实 hook；off 成功后再请求一次，检查 1500ms 窗口内本应用
不再收到 Capture hook。来源为 libnx `applet.h:583–587`、
[applet.c:1043](https://github.com/switchbrew/libnx/blob/b156b4774fb2df7b93402169509266da7547fc4c/nx/source/services/applet.c#L1043)
的 ICommonStateGetter cmd80、固件门槛 6.0.0。
各阶段、Result 和错误以 `{"test":"capture_guide",...}` 写现有持久诊断日志；hook
本身不打印、不发网络。触发 API 不可达、通知未送达或失焦会记录错误并恢复通知，
不能当作“通过”。完成记录显式保留 `physical_key_verified=false`、`album_verified=false`、
`host_overlay_verified=false`，因为系统模拟请求不是物理按键，且未读取 Album 或连接 Steam。


## 8. 系统模拟请求与物理首按的实机证据边界（2026-10-23）

**Evidence：** 已部署构建 `b336a3ee177b60635fbc7f930824508ad7cd4bd2` 的留存日志
`/data/dl/nsteamlink-anywhere/build/capture-guide-b336a3e/latest-first-capture/session-00000000001792764162-091678080-00000.log:15–17`
依次记录 `trigger_on rc=0`、`hook_on_restore_trigger_off rc=0`，以及
`complete api_hook=true, off_hook_absent=true`。这些是 Switch 实际执行 API 自测的日志，
不是 PC 上的替身用例。完成行同时明确标记 physical_key、Album、host_overlay 均未验证。

**Evidence：** 用户对同一已部署构建直接报告：实体 Capture 第一次按下仍触发系统截图，
之后才作为 Guide。用户的屏幕观察是该物理首按问题的主证据；不能用上一段的模拟 API
自测通过否定它。用户询问 HOME 是否实际拦截试过时，已有证据范围仍是未进行 HOME 实机
读取/屏蔽试验，不能提供一个声称已验证可用的 HOME 设置项。

**Conclusion：** 模拟 Capture 的通知开关/API 路径已具备本机正证据；物理 Capture 首按仍
存在与预期不符的直接反证。两者不是同一测试终点。后续任何首次按键修正必须保留这条
反证并单独证明物理行为；不能把新增设置来源枚举或 UI 改名当作首按问题已经解决。

定位时序的诊断输出中，`capture_route=ipc` 记录通知开启/关闭及对应 Result；
`capture_route=notification` 记录实际通知计数、`allowed` 与 `pending`。
媒体侧 `gate_bits` 分别为：bit0/值1 配置选择 Capture，bit1/值2 本轮允许路由，
bit2/值4 输入 gate 开启，bit3/值8 session 允许输入，bit4/值16 session 存在；
`pulse_bits` 的 bit0/值1 为 held，bit1/值2 为 admitted，bit2/值4 为 releasing。
`down_queued` / `up_queued` 仅表示本地 IHS 队列接纳，不等于对端 ACK、最终发送成功或浮层
已经出现。这些日志仅在状态变化/按键时有界输出，hook 内不打印。
“第一次实体按键发生在 readiness 建立前”仍为待验证假说；已有旧日志未捕获该实体首按
相对于通知接管的准确时序，因此本轮只增加取证，不改变生产门控，也不声称修复首按。

## 9. 离线 HOME / HDLS 能力诊断契约

诊断构建的主应用支持 `--system-buttons-selftest`。解析该参数后强制 offline，禁止
建立发现、鉴权、串流会话；该诊断与原 `--capture-guide-selftest` 互斥，由前者优先。
Release 不编译 `switch/system_buttons_probe.c`，不包含该 CLI 或 HDLS 虚拟输入代码。
所有阶段由既有主循环逐 tick 推进，继续使用原 applet 消息分派；没有独立消息接收循环、
额外线程、物理按键操作要求或 Album 图片读取。

**Evidence：上游权限分界。** libnx
[applet.c:197–202](https://github.com/switchbrew/libnx/blob/b156b4774fb2df7b93402169509266da7547fc4c/nx/source/services/applet.c#L197)
只为 SystemApplet / LibraryApplet / OverlayApplet 获取 IAppletCommonFunctions；
`:613–619` 的命令包装在服务未初始化时返回 `LibnxError_NotInitialized`。
[`:2842`](https://github.com/switchbrew/libnx/blob/b156b4774fb2df7b93402169509266da7547fc4c/nx/source/services/applet.c#L2842)
的 `appletIsHomeButtonShortPressedBlocked` 经该接口 cmd52 查询，固件要求 10.0.0。
相反，短按屏蔽 Begin/End 是 Application 的 IFunctions cmd32/33
（[`:2096–2097`](https://github.com/switchbrew/libnx/blob/b156b4774fb2df7b93402169509266da7547fc4c/nx/source/services/applet.c#L2096)）。
因此完整 Application 模式中“可调用 Begin，但无法通过 getter 复查”是可能出现的能力组合；
getter 拒绝不能单独推导 HOME 一定无法读取，也不能当作屏蔽已确认。
按当前 libnx 的上述初始化规则，普通 Application 的 getter 接口不会初始化，调用预期返回
NotInitialized；本诊断在该模式只记录能力阶段并跳过虚拟 HOME 注入，不能提供“实际截获
HOME 已通过”的结论。真实 HOME 读取/屏蔽效果仍须独立证据。

诊断依次记录 `hid:sys` 初始化、HOME 共享内存激活、事件获取、短按屏蔽基线查询、
`BeginBlockingHomeButton(0)` 与屏蔽后查询的真实 Result。只有基线可读且未屏蔽、自己 Begin
成功、复查为 true、共享内存有有效采样且当前按钮中性，才可注入一次虚拟 HOME down/up。
只用短按屏蔽；长按 HOME 保留。HOME 的通过标准是新采样中非零→零，且全程未失焦；
API 成功但无新状态仍是未通过。getter/服务权限不足时跳过 HOME 注入，保留 Result 证据。
注入门禁判断前另记 `home_raw_samples_available` 及一条 `home_raw_baseline` 的采样号/原始
按钮值，让激活后的有效共享内存状态与单纯 IPC 成功可以分别判断；基线不冒充物理按键。
HOME event 以 `autoclear=false` 获取，只做零超时观察，避免清除 AM 也在使用的事件信号。

HDLS 使用专用 FullKey/Bluetooth 虚拟设备，独占页对齐的 `0x1000` 工作缓冲，取自
[switchbrew 官方 HDLS 示例](https://github.com/switchbrew/switch-examples/blob/master/hid/hdls/source/main.c)。
按钮值以 libnx
[hiddbg.h:13–15](https://github.com/switchbrew/libnx/blob/b156b4774fb2df7b93402169509266da7547fc4c/nx/include/switch/services/hiddbg.h#L13)
为据：HOME 为 bit18、Capture 为 bit19；它们属于调试注入值，不能当作正常 Npad 读键位。
若 HDLS 可达，随后独占原 Capture 通知路由，分别发两次 Capture down/up；每次以实际 hook
计数增量记录首按/第二按是否收到。计时窗口仅用于有界等待，不能把等待时间结束当成通知
已经到达。第二次收到通知不会补写第一次通过。该虚拟设备路径仍不证明实体按键、相册
新增截图、系统画面状态或 host Guide 浮层行为。

清理顺序为：虚拟按钮归零 → detach 临时设备 → release 工作缓冲 → 恢复 Capture 路由
→ 关闭 HOME event → 关闭 `hid:sys` / `hid:dbg` → End 自己成功启用的短按屏蔽 → getter
复查恢复。只清理自己成功取得的资源；原本已经屏蔽时不会接管/解除别人的屏蔽。
正常完成、失焦、外部退出和阶段失败共用该清理路径；probe 在媒体初始化完成后才开始，
因此此前的初始化失败没有 probe 资源。libnx
[hiddbg.c:494–512](https://github.com/switchbrew/libnx/blob/b156b4774fb2df7b93402169509266da7547fc4c/nx/source/services/hiddbg.c#L494)
要求 release 在 hiddbgExit 前调用，并在 release IPC 失败时仍关闭本地 transfer-memory 句柄。
对自己成功建立的设备/工作缓冲/短按屏蔽若有清理失败，诊断记录错误并完成其他资源清理；
detach/End 各最多尝试三次，持续失败不会带着未恢复的系统状态返回 loader。可选 API
从未成功取得资源时的拒绝不会触发该保护。Capture 已成功启用后的持续恢复失败仍由现有
events shutdown 保留其恢复义务。`hidsysActivateHomeButton` 没有在这里调用全局
`hiddbgDeactivateHomeButton` 作为反操作，避免干扰 AM 使用的 HOME 共享内存。

本机 fake libnx 测试仅证明状态机门禁、独立计数及资源清理；它不等于 Switch 权限、
HDLS 注入或物理 HOME 的实测通过。所有完成记录独立标明
`physical_key_verified=false`、`album_verified=false`、`host_overlay_verified=false`。
