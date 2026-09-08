# 决策记录（ADR-lite）

每条记录包含：日期、背景、决定、理由、影响。**新条目追加在文件末尾，禁止改写历史结论**；
推翻旧决策时新增一条并在开头注明"取代 D-xxx"。

---

## D-001 统一使用 SDL2 作为两个目标的 UI / 渲染 / 音频输出层

- 日期：2026-08-23
- 背景：plume 桌面端用 SDL3；devkitPro 侧只有 `switch-sdl2`（SDL2）。
- 决定：本项目两目标统一 SDL2，不引入 SDL3。
- 理由：跨目标 API 一致是薄 HAL 策略的前提；SDL3 在 Switch 上无维护的 portlib。
- 影响：桌面端放弃 SDL3 新特性；plume 的 SDL3 用法仅作参考，不能照抄。

## D-002 IHSlib 选定 beudbeud fork（取代"待定"，M1 对比后落定）

- 日期：2026-08-23
- 背景：plume 使用其自有 fork `beudbeud/ihslib`（`plume` 分支），kickoff §3.1 要求先 diff 补丁差异再定。
- 考察结果（fork @ `8c5a17c` vs 上游 `mariotaku/IHSlib@master`）：
  - fork 是上游的**严格超集**：上游没有 fork 缺失的提交；
  - fork 额外带 25+ 个实战修复，覆盖串流稳定性关键路径：重传队列死锁/
    孤儿分片、控制通道发送序列化（否则 host 静默丢消息）、HID 悬挂指针与
    delta 缓冲区溢出、session 停止前等待 host ACK、protobuf 与 Valve 现行
    定义重新同步、按调用方分辨率/帧率/码率上限协商等；
  - fork 去除了 SDL2 依赖（纯 POSIX 线程后端）→ 降低 Switch（libnx）移植成本；
  - 有 plume 在树莓派5 上 1080p60 的端到端实测背书。
- 决定：以 `https://github.com/beudbeud/ihslib.git` 分支 `plume`（pin `8c5a17c`）
  作为本项目协议层依赖，M2 起 submodule 引入。
- 影响：若上游日后吸收这些补丁，可评估切回；切换需重跑配对与串流回归。

## D-003 环境变量策略：bashrc 只放路径，交叉编译变量按需加载

- 日期：2026-08-23
- 背景：devkitPro 官方建议 source `switchvars.sh`，但那会全局导出交叉 `CC/CFLAGS/LDFLAGS`。
- 决定：`~/.bashrc` 只导出 `DEVKITPRO / DEVKITA64 / PATH`；构建脚本按需 source
  `$DEVKITPRO/switchvars.sh`。
- 理由：避免污染本机其他桌面项目的编译环境（全局 CC 指向 aarch64 交叉编译器是隐蔽事故源）。
- 影响：任何直接调用 `make`/`cmake` 构建 Switch 目标的人，必须先 source switchvars.sh 或走 scripts/。

## D-004 许可证定位：项目整体 GPLv3

- 日期：2026-08-23
- 背景：计划复用 Moonlight-Switch 的预编译库与解码代码（GPL-3.0），IHSlib 为 LGPL-3.0。
- 决定：接受 GPLv3 开源，不做闭源尝试（kickoff §7.1）。
- 影响：复用第三方代码必须保留版权声明并在依赖表登记。

## D-005 性能目标：默认 720p60，1080p 属于 M5 打磨项

- 日期：2026-08-23
- 背景：Tegra X1 NVDEC 硬解能力对齐 Moonlight-Switch 实测；1080p 高码率需超频。
- 决定：M3/M4 验收一律以 720p 为准；1080p/超频相关优化推迟到 M5（kickoff §6）。
- 影响：代码必须在默认频率下达成 720p60，不得把超频当前提条件。

---

## D-006 骨架中 platforms/switch/hal.c 是"M1 前不写 Switch 代码"的例外

## D-007 protobuf-c 交叉编译安装方式与 ihslib vendoring 策略

- 日期：2026-08-23
- 背景：devkitPro 无 protobuf-c 包；其自带 CMake 强依赖宿主 C++ Protobuf，交叉编译走不通；
  IHSlib 需以 submodule 形式引入并带补丁。
- 决定：
  1. protobuf-c（v1.5.0）不走其 CMake，直接 `switchvars.sh` 环境下编译 `protobuf-c.c`
     成静态库，手工安装到 `$DEVKITPRO/portlibs/switch`（含 `protobuf-c/` 子目录布局的
     头文件与手写 `libprotobuf-c.pc`）；
  2. IHSlib 以 submodule 固定 `beudbeud/ihslib@8c5a17c`（plume 分支），平台层靠
     顶层 CMake 在 NintendoSwitch 下强制 `set(UNIX ON)` 选中 POSIX 后端；
  3. 对 ihslib 的修改一律走 `third_party/patches/ihslib/*.patch`，克隆/submodule 更新后
     `git -C third_party/ihslib apply ../patches/ihslib/*.patch`（暂为手工步骤，
     待自动化）。
- 补丁清单：
  - `0001-libnx-portability.patch`：守卫 Linux 专有的 `SO_RCVBUFFORCE`；
    `ihs_ip_posix.c` 补 `<sys/socket.h>`（libnx 的 `arpa/inet.h` 不带出 `AF_*`）。
- 影响：SDK 侧构建失败时优先怀疑 portlibs 里的手工安装件；升级 protobuf-c 或 ihslib
  时需重放补丁并重跑 M2 探针回归。

---

## D-008 已撤销：曾误判广播不可靠

- 日期：2026-08-24
- 状态：撤销。见 D-009。
- 背景：该条曾把“发现到运行 Steam 的主机但 `gamesRunning=0`”误判成“广播不可靠”。
  复盘真机日志后确认，这个推论错误；`gamesRunning=0` 只表示 Steam 当时没有运行游戏。
- 决定：不采用本条原结论。发现策略以 D-009 为准：广播发现是默认路径，单播/手动 IP 仅作 fallback。
- 附带发现（M3 待办）：libnx 侧 `SO_RCVBUF` 被压到 ~42KB（IHSlib 想要 4MB）——视频流
  必须在 `socketInitialize` 时调大缓冲配置，否则视频包会丢。
- 影响：保留本条是为了留下错误决策的修正轨迹；M2 发现验收不再以单播路径为准。

- 日期：2026-08-23
- 背景：kickoff §6 要求 M1 完成前不碰 Switch 特有代码；M0 需要打通交叉编译管线。
- 决定：允许一个约 10 行的 HAL stub（仅返回平台名）随骨架提交，用于验证
  devkitA64 + CMake 工具链 + nro 产出全链路；不含任何协议/媒体/UI 逻辑。
- 影响：真正的 Switch 功能代码仍从 M2 开始。

---

## D-009 取代 D-008：UDP 广播发现可用，单播/手动 IP 作为 fallback

- 日期：2026-08-24
- 背景：复盘 M2 探针日志后确认，Switch 侧已经通过 UDP 广播发现到运行 Steam 的主机；
  日志里的 `gamesRunning=0` 只表示 Steam 当前没有正在运行的游戏，不表示发现失败，也不能推出
  广播包被 AP 丢弃。D-008 将“发现到主机但无游戏运行”误判为“广播不可靠”，该结论撤销。
- 决定：正式客户端发现流程以 IHSlib 的 UDP 广播发现作为默认路径；保留单播发现/手动
  `IHS_HostInfo` 直连作为调试与网络异常 fallback，不作为默认主路径。
- 附带发现（M3 待办）：libnx 侧 `SO_RCVBUF` 被压到约 42KB（IHSlib 想要 4MB）的风险仍需验证；
  视频流前需要确认 `socketInitialize` 缓冲配置是否足够，否则可能丢视频包。
- 影响：M2 发现验收以“广播能发现 Steam 主机”为准；后续 UI 仍应提供固定主机 IP 配置项，
  但它是兜底能力，不是主发现策略。

---

## D-010 M2 配对必须提供 PIN 输入 UI，并持久化客户端身份

- 日期：2026-08-24
- 背景：IHSlib 的 `IHS_ClientAuthorizationRequest(client, host, pin)` 需要传入本次 Steam
  配对流程使用的 PIN；该 PIN 不能在客户端固定写死。另一方面，Steam 记住的是客户端身份材料
  （`deviceId` + `secretKey` 派生出的 `deviceToken`），不是 PIN 本身。若每次启动都使用临时
  身份，真机测试会反复要求配对，开发体验不可接受。
- 决定：
  1. M2 配对探针/客户端必须提供最小可用的 Switch 端 PIN 输入界面；
  2. 第一次启动时生成并保存稳定的 `deviceId` 与 32 字节 `secretKey`；
  3. 身份文件默认放在 `sdmc:/switch/nsteamlink/auth.bin`；
  4. 后续启动优先读取 `auth.bin`，复用同一客户端身份；
  5. UI 或调试按键需要提供“清除配对/重置身份”能力。
- 文件格式：二进制小文件，至少包含 magic/version、`deviceId`、`secretKey[32]`、`deviceName`；
  可选记录最近成功的 `steamId`、主机名与主机 IP，方便下次默认选择与调试。
- 写入策略：先写临时文件，再 `rename` 覆盖正式文件，避免断电或崩溃留下半截身份文件。
- 影响：M2 验收不只看“能输入 PIN 并收到授权成功”，还要确认重启后无需再次输入 PIN 即可复用授权；
  当前阶段使用 SD 卡文件即可，NSP/forwarder 阶段再评估 system save data。

---

## D-011 IHSlib 的 SDL HID provider 在 Switch 目标下可关闭

- 日期：2026-08-24
- 背景：IHSlib 的核心 HID 源文件属于协议/输入栈的一部分，但 `src/hid/sdl` 是面向 SDL3 的
  HID provider。Switch portlibs 只有 SDL2，本项目也已在 D-001 决定统一 SDL2；因此全量 Switch
  构建会在 `SDL3/SDL.h` 等头文件处失败，即使 M2 发现/配对工具并不需要 SDL HID provider。
- 决定：给 IHSlib 增加 `IHSLIB_HID_SDL` CMake 开关；默认仅在找到 SDL3 时启用，Switch 目标
  保留核心 HID 源文件但不构建 `ihslib-hid-sdl`。
- 补丁：`third_party/patches/ihslib/0002-optional-sdl-hid.patch`。
- 影响：`./scripts/build-switch.sh` 可完成全量构建；后续 M4 输入回传若需要 SDL HID provider，
  需重新评估 Switch 侧用 SDL2 还是直接走 libnx HID。

---

## D-012 IHSlib 授权请求字符串复制后显式补 NUL

- 日期：2026-08-24
- 背景：`IHS_ClientAuthorizationRequest()` 把 `deviceName` 和 `pin` 复制进固定长度缓冲区后，
  原实现没有显式写入结尾 NUL。常见 4 位 PIN 不会触发问题，但长 PIN 或 63 字节设备名会让后续
  `strlen()` 越过缓冲区边界。
- 决定：在复制 `deviceName` 与 `pin` 后显式设置最后一个字节为 `'\0'`。
- 补丁：`third_party/patches/ihslib/0003-authorization-copy-termination.patch`。
- 影响：不改变正常协议行为，只收紧 M2 PIN 输入路径的内存安全边界。

---

## D-013 PLUS 退出必须做标准资源清理并保留崩溃证据

- 日期：2026-08-24
- 背景：真机反馈显示旧版 `switch-discover` 按 PLUS 后提示 3 秒返回，倒计时结束后崩溃。
  本地代码证据显示旧退出路径只调用 `IHS_ClientStop()`，它只设置 worker interrupt 标志，没有
  等 worker 线程退出；随后立即调用 `socketExit()`。这会让仍在 `recv`/socket 路径里的 IHS worker
  与主线程 socket 子系统析构发生竞态。该竞态是已证实代码 bug；它是否是唯一崩溃原因需真机新版日志验证。
- 证据：
  - libnx `nxlinkConnectToHost()` / `nxlinkStdio()` 文档要求 cleanup 时 `close()` 返回的 socket fd；
  - libnx `appletLockExit()` 文档说明 `appletMainLoop()` 在 exit request 后返回 false，
    且使用 lock 后 `main()` 返回前必须 `appletUnlockExit()`；
  - devkitPro `applet/lockexit` 示例将 cleanup 放在 `appletLockExit()` 与 `appletUnlockExit()` 之间；
  - IHSlib samples 使用 `IHS_ClientStop()` 后 `IHS_ClientThreadedJoin()`、`IHS_ClientDestroy()` 的顺序；
  - 本仓 IHSlib worker 初始化设置了 10ms `SO_RCVTIMEO`，libnx BSD header 定义了 `SO_RCVTIMEO`，
    因此有证据支持先恢复 `ThreadedJoin()`，并用真机日志验证是否会卡住。
- 决定：
  1. `switch-discover` 退出路径改为 `StopDiscovery/Stop -> ThreadedJoin -> Destroy -> IHS_Quit`
     后再 `socketExit()`；
  2. 第一版保存并关闭 `nxlinkStdio()` 返回的 fd；后续真机 fatal 证明该路径仍需修正，见 D-015；
  3. `appletLockExit()` / `appletUnlockExit()` 成对使用；
  4. `appletRequestToAcquireSleepLock()` 只在成功时对应 `appletReleaseSleepLock()`；
  5. 移除 3 秒倒计时，退出阶段打印 `cleanup:` 分步日志；
  6. 加入 libnx userland exception handler，崩溃时写 `sdmc:/switch/nsteamlink/exception_dump.txt`。
- 影响：M2 真机回归新增一项：PLUS/B/取消路径必须能返回 hbmenu；若仍崩溃，使用 exception dump
  中的 `pc/lr` 配合 `build/switch/tools/switch-discover/switch-discover.elf` 做 `addr2line` 定位。
- 回归纠正：2026-08-24 使用 PC 端 debug command `press PLUS` 触发同一退出路径，nxlink 日志
  完整输出 `cleanup: stop discovery`、`cleanup: stop IHS worker`、`cleanup: join IHS worker`、
  `cleanup: destroy IHS client`、`cleanup: IHS_Quit`、`cleanup: close nxlink fd`、`exiting ...`，
  且 nxlink 进程正常结束；但用户随后提供的 Switch fatal 截图显示实际已经崩溃：
  `2144-0001 (0x290)`，`Program: 0100000000001000`，`Firmware: 22.5.0
  (Atmosphere 1.11.2-master-5388824be)`。因此“未复现/回归通过”是错误结论，必须以截图为准。

---

## D-014 M2 工具提供 PC 端 debug command 通道

- 日期：2026-08-24
- 背景：M2 真机测试需要反复发现主机、输入 PIN、提交授权、触发退出。完全依赖手柄手动输入
  会放大沟通误差，也无法让开发机自动判断程序是否仍活着。`nxlink -s` 只提供部署和 stdout/stderr
  回传，不提供可依赖的运行时输入通道。Atmosphère standalone gdbstub 可用于远程调试，但官方
  changelog 明确提醒调试使用 socket 的进程可能因 gdbstub 自身使用 socket 而 hang。sys-botbase
  可以远程模拟手柄，但需要额外安装/启用 sysmodule，不适合作为本项目默认验证路径。
- 决定：`switch-discover` 内置一个仅用于开发测试的 UDP debug command 入口，默认端口 `28772`。
  通过 nxlink 启动时，命令来源优先限制为 `__nxlink_host`。PC 端脚本 `tools/switch-debugctl.py`
  封装命令发送与响应读取。
- 命令集（D-014 当时）：`ping`、`state`、`hosts`、`select <n>`、`pin <digits>`、`submit`、
  `pair <digits>`、`press <button>`、`delete-auth`、`exit`。D-017 已修正 pairing 方向：
  当前 `pair` 不接收 PIN，并新增 `code`；`pin/submit` 只返回 deprecated 错误。
- 影响：后续 M2 真机验收优先由开发机脚本驱动：NRO 启动后先 `state/hosts` 确认活性与发现结果，
  再用当前 `pair` 生成 code 做授权，最后 `exit` 验证标准清理。产品化客户端不得把该 debug command 通道
  带入默认发布构建；M2 之后应改为编译期开关或移除。

---

## D-015 PLUS 退出回归以 Switch fatal 截图为准，并规避 nxlink stdio 重定向

- 日期：2026-08-24
- 背景：M2 新版通过 `nxlink -s` 部署后，开发机看到 `nxlink` 日志正常结束，但 Switch 屏幕实际进入
  Atmosphere fatal。该事实推翻“nxlink 进程退出 == NRO 安全退出”的判断。
- 已证据：
  - 用户截图显示 `2144-0001 (0x290)`、`Program: 0100000000001000`、`Firmware: 22.5.0
    (Atmosphere 1.11.2-master-5388824be)`；
  - libnx applet ID 表标注 `0100000000001000` 为 qlaunch/SystemAppletMenu；
  - libnx `nxlinkConnectToHost()` 文档说明返回 socket fd，cleanup 时应 close；`nxlinkStdio()` 等价于
    `nxlinkConnectToHost(true, true)`，即接管 stdout/stderr；
  - 本仓当时实现会在退出阶段 close 该 fd，但 C runtime / stdio 是否仍会访问被重定向的 stdout/stderr，
    当前没有直接 dump 证据。
- 决定：
  1. 不再把 `nxlink` 进程结束当作“不崩溃”的证据；退出验收必须以 Switch 是否返回 hbmenu、
     是否出现 fatal screen 为准；
  2. `switch-discover` 不再使用 `nxlinkStdio()` 重定向 stdout/stderr，改为
     `nxlinkConnectToHost(false, false)` 只建立 socket，`logline()` 手动 `dprintf()` 到该 socket；
  3. close nxlink socket 前先把全局 fd 置为不可用，保证后续 `logline()` 不再写已关闭 fd；
  4. 退出阶段写入 `sdmc:/switch/nsteamlink/exit_stage.txt`，用于证明 fatal 发生在 cleanup 的哪个阶段；
  5. 根因结论必须等下一版真机回归、`exit_stage.txt` 或 crash report 证据支持后再写。
- 影响：M2 状态从“退出回归通过”退回“退出 crash 待修复验证”。下一版先验证该最小退出风险修复；
  如果仍崩溃，再基于 `exit_stage.txt` 精确拆分 `socketExit()`、`consoleExit()`、`appletUnlockExit()`、
  `main()` return 等阶段。

---

## D-016 取代 D-010 的 PIN 方向：区分 pairing code 与 connect/security PIN

- 日期：2026-08-24
- 背景：D-010 把 `IHS_ClientAuthorizationRequest(client, host, pin)` 需要的 `pin` 解释成
  “Switch 端输入 Steam 端 PIN”，导致 M2 UI 只做了输入框。真机反馈显示：用户输入 Steam 端设置的
  PIN 后，Steam host 继续要求“设备上的四位数授权代码”，而 Switch 没有显示该码。复查上游 plume
  和 IHSlib/proto 后确认，至少存在两个不能混淆的码。
- 证据：
  - 上游 plume README 与源码明确生成四位 pairing PIN，在客户端显示，并让用户输入到 Steam host；
  - 本仓 IHSlib authorization ticket 把 `IHS_ClientAuthorizationRequest()` 的参数写入 encrypted
    ticket 的 `password`，同时带上 `deviceId` 与 `secretKey`；
  - 本仓 IHSlib streaming request 另有独立 `pin` 字段，且 streaming result 有 `PINRequired=11`；
  - SteamTracking proto 定义了 authorization response 的 `auth_key/device_token`，以及
    `AuthorizationConfirmed`/`PairingState`/`PairingExclusivity`；D-016 当时 IHSlib 尚未处理 14/15/16。
- 决定：
  1. 首次 pairing UI 必须由 Switch 生成并显示四位 authorization code，让用户在 Steam host 输入；
  2. Switch 数字输入 UI 保留，但语义改为 streaming/connect/security PIN，只能在串流阶段需要时使用；
  3. `auth.bin` 持久化客户端身份材料（`deviceId`、`secretKey`、可选最近 host/steamId），不保存
     pairing code；
  4. 对 `auth_key/device_token` 和 message type 14/15/16 先加日志和抓证据，不得在未验证前写成根因；
  5. 认证流程的详细证据以 `docs/STEAM_REMOTE_PLAY_AUTH.md` 为准。
- 影响：D-010 中“M2 必须提供 Switch 端 PIN 输入界面”这一句被修正为：M2 必须提供 Switch 端
  pairing code 显示界面；输入界面是后续 streaming/security PIN 的能力，不是 authorization
  request 的主流程。D-017 已按此决定改造 M2 UI；首次配对是否完成仍以真机回归结果为准。

---

## D-017 M2 pairing code UI 与授权日志实现

- 日期：2026-08-24
- 背景：D-016 已确认首次 pairing code 方向反了；用户在 Steam host 设置/输入的
  security/connect PIN 不能作为 `IHS_ClientAuthorizationRequest()` 的主流程输入。M2 必须改成
  Switch 生成 code，并让用户把该 code 输入 Steam host。
- 证据：
  - 上游 plume 在客户端生成四位 PIN，显示给用户，并传给 `IHS_ClientAuthorizationRequest()`；
  - 本仓 IHSlib authorization ticket 把该参数写入 encrypted ticket 的 `password` 字段；
  - 真机反馈显示，输入 Steam host 侧 PIN 后，Steam 继续要求“设备上的四位数授权代码”，说明旧 UI
    没显示客户端 pairing code；
  - proto/source 定义了 `AuthorizationConfirmed`/`PairingState`/`PairingExclusivity`，但目前没有真机
    抓包证明它们应改变授权状态机。
- 决定：
  1. `switch-discover` 发现页按 `A` 直接生成四位 pairing code，并显示英文 ASCII 文案
     `Enter this code in Steam on the host`；
  2. PC 端 debug `pair` 命令不再接收 PIN，返回的 `state` 中包含 `code=xxxx`；新增 `code` 命令用于
     重新读取当前 code/state；
  3. 旧 `pin`/`submit` debug 命令只返回 deprecated 错误，不再进入 authorization request；
  4. pairing 发起前保持 discovery worker/socket 服务，并调用 `IHS_ClientStartDiscovery(client, 0)`
     对齐 plume；
  5. IHSlib 增加授权日志：response 记录 `result`、`steamid`、`auth_key` 长度、
     `device_token` 长度；message type 14/15/16 只解码/记录，不改变 success/failure 语义；
  6. `auth.bin` 继续只保存客户端身份材料和最近 host/steamId，不保存 pairing code。
- 回归结果：2026-08-24 真机验证通过 M2 主路径。`switch-discover` 加载 `auth.bin`，发现
  `kxn-pc (10.10.10.166) gamesRunning=1`，生成 pairing code `3383`，authorization response
  从 `result=5` 进展到 `result=0 steamid=76561198217069647`，保存 `auth.bin`；debug `state`
  返回 `mode=done paired=1`。debug `exit` 后用户确认退出成功，无 Atmosphere fatal。
- 影响：M2 的正确配对入口已经从“Switch 输入 PIN”改为“Switch 显示 code”。M2 主路径完成；B 取消授权
  路径保留为补充回归项，后续进入 M3 串流请求。

---

## D-018 M3 采用分层 streaming probe，FFmpeg 来源改为 devkitPro portlibs

- 日期：2026-08-24
- 背景：M2 的主要返工来自没有先读透上游流程，尤其是 pairing code / streaming PIN 语义被混淆。
  M3 进入 streaming request、session、视频解码和 SDL2 渲染，风险面更大，不能再以猜测推进。
- 证据：
  - M2 真机已证明 `auth.bin` 身份持久化、host discovery、pairing code 授权、debug exit 主路径成立；
  - vendored `beudbeud/ihslib` plume 分支已包含 streaming request、proof response、session negotiation、
    video frame assembly、frame stats 和 StopRequest cleanup；
  - plume 参考实现把 streaming request、session、media decode/present 分层，并要求 IHSlib callbacks
    使用 static/长生命周期 storage；
  - 本机 devkitPro portlibs 已安装 Switch 版 FFmpeg/SDL2，且 FFmpeg 头文件和静态库包含
    `AV_HWDEVICE_TYPE_NVTEGRA`、`AV_PIX_FMT_NVTEGRA`、`h264_nvtegra`；
  - devkitPro `switch-ffmpeg` 包脚本使用 `--enable-libnx --enable-nvtegra`；averne 的 FFmpeg patch
    series 明确目标包含 HorizonOS/Nintendo Switch；
  - libnx 默认 UDP receive buffer 约 `0xA500`，而 IHSlib 对视频 burst 请求 4MB `SO_RCVBUF`，
    因此 M3 必须真机实测/调整 socket 初始化配置。
- 决定：
  1. M3 先新增独立 `tools/switch-stream-probe`，保护 M2 `switch-discover` 基线；
  2. M3 分为 streaming request probe、session/video channel probe、FFmpeg/NVTEGRA+SDL2 第一帧、
     再合入主 app 四步；每步都有真机日志验收；
  3. M3 默认 H264、audio off、input off、720p；audio/input/HEVC/1080p/零拷贝推迟；
  4. streaming/security PIN 只在 `IHS_StreamingPINRequired` 时处理，不得和 pairing code 混用；
  5. FFmpeg 来源改为当前 devkitPro `switch-ffmpeg` portlibs，不再从 Moonlight-Switch 拷预编译库；
  6. session 退出必须走 `IHS_SessionDisconnect -> IHS_SessionThreadedJoin -> IHS_SessionDestroy`，
     不能只关闭 socket 或直接 return；
  7. 具体执行计划以 `docs/M3_RESEARCH_PLAN.md` 为准。
- 影响：M3 不直接做完整 Steam Link UI，而是先用 debug 命令收集可证伪证据。只有第一帧链路在真机
  证明后，才把代码迁移到 `app/`。

---

## D-019 M3.3 视频实验探针优先可恢复性，退出不再持有 applet/sleep lock

- 日期：2026-08-25
- 背景：M3.3 第二次真机测试中，SDL2 初始化成功后屏幕变黑；PC 端 `stream game` 到达程序后没有
  后续 `stream request:` / video start / decoder 日志，debug UDP 随后无响应。用户随后反馈整机近似
  hang：`+`、HOME、长按 POWER 起初都无响应，最终通过硬件强制重启恢复。
- 证据：
  - 真机日志显示 `media init: SDL2 renderer ready`，证明黑屏只是 SDL 接管画面，不证明已解码；
  - 同次日志显示 `stream: StartDiscovery(one-shot) -> 1` 后没有 `stream request:`，证明尚未进入
    Steam streaming response 或 FFmpeg 解码；
  - `switch-stream-probe` 代码当时在主线程 debug handler 中直接调用 `start_stream_request()`，
    因此 IHS 任一步阻塞都会停止 `appletMainLoop()`、按键扫描、debug UDP 和 SDL present；
  - 代码当时先处理 `stop_requested`，再处理 `exit_requested`；`+` 同时设置 stop/exit 时会先进入
    `IHS_SessionThreadedJoin()`，存在退出前再次阻塞的路径；
  - libnx `appletLockExit()` 文档说明它会延迟 HOME/关闭触发的退出，且必须在返回前 unlock；
    `appletRequestToAcquireSleepLock()` 也会主动阻止睡眠。两者适合短清理窗口，不适合可能卡住的
    M3.3 视频实验路径；
  - IHS timer worker 持有 `timer->mutex` 执行 task，streaming request 原实现持有
    `client->base` 锁启动 timer，形成 `base -> timer` 与 `timer -> base` 的 AB-BA 死锁风险。
- 决定：
  1. `switch-stream-probe` M3.3 不再调用 `appletLockExit()` 或 `appletRequestToAcquireSleepLock()`；
  2. debug `stream` 只排队，实际 `IHS_ClientStreamingRequest()` 在独立 worker 线程执行，主线程保持
     `appletMainLoop()`、debug `state/exit` 和 SDL present；
  3. `+` / debug `exit` 优先退出主循环，随后从 `main()` 正常返回；只有在没有 stream/session 活动时
     才走可能阻塞的 cleanup/join；
  4. watchdog 线程不依赖 `state.lock`，主循环停跳超过 8 秒或 stream 开始 45 秒仍无首帧时，写
     `sdmc:/switch/nsteamlink/stream_watchdog.txt` 并调用 `appletRequestExitToSelf()`，不再
     `svcExitProcess()`；
  5. 无首帧时 SDL 画无文字活动指示，不再纯黑；
  6. IHSlib `IHS_ClientStreamingRequest()` 启动 timer 时不持有 `client->base` 锁，并给首个 task
     25ms 延迟，降低 handle 尚未写回时 timer 先执行的竞态。
- 影响：M3.3 probe 的退出策略和 M3.2 已验证的优雅 cleanup 不同；这是为了避免视频/FFmpeg/GPU
  实验把整机卡死。第一帧链路稳定后，产品化客户端再分阶段恢复 StopRequest、join 和资源析构，
  每一步都必须用真机返回 hbmenu/fatal 截图作为证据。
- 回归纠正：2026-08-25 安全修正版 v1 在只测启动/debug `exit`、未发 stream 的情况下仍出现
  Switch crash；PC 侧日志到 `fast exit: fast_exit:requested` 和 `exiting ...` 不能证明安全退出。
  因此 `svcExitProcess()` 作为 NRO/hbmenu 退出手段被撤销，改为主线程 break 后正常 return。
- 回归结果：2026-08-25 安全修正版 v2 在只测启动/debug `exit`、未发 stream 的情况下通过。
  用户观察到 SDL idle 画面有底部绿色动画和左上橙色方块；debug `state` 正常回包；debug `exit`
  后 PC 日志走到 `return path: safe_cleanup=1`、IHS client cleanup、`IHS_Quit`、`exiting ...`，
  且用户确认 Switch 正常回到 hbmenu。
- 后续修正：同日随后一次重新推送在未发 `state` / `stream game` 前用户侧 crash，PC 侧没有拿到
  可用应用日志。该证据不能支持“stream 后 hang”的结论。为拆分启动加载与 SDL 初始化风险，
  M3.3 probe 改为启动时只初始化网络/debug/IHS，SDL/媒体层延迟到 debug `media-init`；
  `stream` 在媒体未初始化时拒绝并提示先运行 `media-init`。
- 继续修正：用户指出不能无证据怀疑 netloader/大 NRO，因为其它项目也能加载更大的 NRO。本地
  ELF 证据显示媒体版 `.init_array` 有 9 个 pre-main constructor，core 版只有 1 个；额外入口
  来自 Mesa/Nouveau/C++ runtime（`builtin_functions.cpp`、`glsl_types.cpp`、`ir_to_mesa.cpp`、
  `nv50_ir_ra.cpp`、`eh_alloc.cc`、`eh_globals.cc` 等），且 Switch SDL2 pkg-config 链接项包含
  `-lEGL -lstdc++ -lglapi -ldrm_nouveau`。因此下一版增加
  `sdmc:/switch/nsteamlink/stream_boot_stage.txt`，在 `main()` 极早期和各初始化阶段写入 stage；
  只有该证据返回后，才能判断 crash 是否发生在进入 `main()` 前、SDL 初始化前或后续阶段。

---

## D-020 修正 M3.3 最新启动现象判断，并把 media 探针改为完全被动启动

- 日期：2026-08-25
- 背景：boot-stage 版 `switch-stream-probe` 一次真机回归中，PC 侧日志显示进入 discovery 后
  `exiting ...`，随后 debug `state` 超时；一度被记录为完全 hang。用户随后补充：拔掉充电器时
  Switch 亮起锁屏界面，并正常进入锁屏/hbmenu，当时机器电量不足。
- 证据：
  - 同轮 nxlink 日志显示程序已进入 `main()`，完成 auth、socket、nxlink、debug UDP，并自动创建
    IHS client 与发起 discovery；
  - 同轮没有收到 PC 端 `media-init` 或 `stream` 命令，因此不能归因到 SDL/FFmpeg 解码或 Steam
    streaming/session 路径；
  - 用户补充的真机观察证明该轮没有 Atmosphere fatal，也不能记为硬 hang；
  - 代码证据显示当时 media 版默认启动仍会执行 `IHS_Init()`、`IHS_ClientCreate()`，并在主循环里
    周期性 `StartDiscovery(one-shot)` 与 fallback discovery，导致“启动稳定性”证据被 IHS/discovery
    行为混入。
- 结论：
  - 撤回“该轮硬 hang/crash”的结论；准确表述为：设备曾短时黑屏/无响应，随后从锁屏/hbmenu
    正常恢复；
  - “低电量、充电器状态、休眠或 applet lifecycle 导致 `appletMainLoop()` 结束”是待验证假设，
    不是已证明根因；
  - 该轮证明不了 pre-main constructor crash，也证明不了 stream/decode crash。
- 决定：
  1. M3.3 media 版默认启动只做 auth、socket、nxlink 和 debug UDP；
  2. SDL/FFmpeg 继续延迟到 debug `media-init`；
  3. IHS 初始化、client 创建、stream worker 启动延迟到 debug `ihs-init` 或 `discover-once`；
  4. discovery 不再自动周期触发，改为 debug `discover-once` 单步执行一次 broadcast + 固定 fallback；
  5. debug `state` 增加 `ihs`、`client`、`worker` 字段，boot stage 增加 `ihs:deferred`、
     `loop:ready:passive`、`loop:ended`；
  6. 下一次真机验证必须分步执行：被动启动/退出 -> `ihs-init`/退出 -> `discover-once`/退出 ->
     `media-init`/退出 -> `stream game`。
- 影响：M3.3 的第一帧验收继续暂停在安全回归之后。任何新的黑屏、锁屏、fatal、退出或 timeout
  都必须先归到具体分步阶段，再下结论。

---

## D-021 M3.3 Switch probe 移除 SDL2/EGL/Mesa 链接，改用 libnx framebuffer

- 日期：2026-08-25
- 背景：D-020 后，同一个完全被动 media 版再次推送。该版本默认不执行 `IHS_Init()`、
  不创建 IHS client、不发 discovery、不执行 `media-init`，但真机出现 Atmosphere fatal。
- 证据：
  - 用户截图显示 `Error Code: 2144-0001 (0x290)`、`Program: 0100000000001000`，PC 为
    `0x000000103064A27C`，Backtrace Start Address 为 `0x0000001030400000`；
  - PC 侧 nxlink 日志只到 `server active ...`，没有应用侧 `nxlink log socket active`；
  - debug `state` 超时；在 fatal 前我们没有发送 `ihs-init`、`discover-once`、`media-init` 或 `stream`；
  - 本地地址解析：`0x103064A27C - 0x1030400000 = 0x24a27c`，对应
    Mesa `vbo_exec_VertexAttrib1fARB`；
  - 当时媒体版 ELF 仍静态链接 SDL2/EGL/Mesa/Nouveau，且此前本地证据显示其 `.init_array`
    含 Mesa/Nouveau/C++ runtime constructor；
  - `pkg-config --libs libavcodec libavutil libswscale` 只返回 `-lavcodec -lavutil -lswscale`，
    因此 FFmpeg 链接本身不要求 SDL2/EGL/Mesa。
- 结论：
  - 该 fatal 发生在 Steam 协议、IHS discovery、FFmpeg 解码、SDL `media-init` 和 streaming request
    之前，不能归因于这些路径；
  - PC 落点在 Mesa 代码，这是足够强的工程证据，要求 M3.3 probe 先移除 SDL2/EGL/Mesa 链接面；
  - 这仍不是“SDL2/Mesa 是唯一根因”的最终断言，因为还缺少 crash dump 与可重复对照；但继续带着
    Mesa 链接推进 M3.3 已不符合证据纪律。
- 决定：
  1. `tools/switch-stream-probe` 不再链接 `PkgConfig::SDL2`；
  2. Switch M3.3 显示层从 SDL2 renderer/texture 改为 libnx
     `framebufferCreate/framebufferMakeLinear/framebufferBegin/framebufferEnd`；
  3. 保留 FFmpeg H264 NVTEGRA 优先、software fallback，以及 CPU YUV420P/NV12 -> RGBA framebuffer
     blit，用于第一帧证据；
  4. debug `media-init` 语义改为初始化 libnx framebuffer + FFmpeg 日志回调；
  5. D-001 的“项目统一 SDL2”暂不用于 M3.3 Switch probe；正式 UI/产品化是否回到 SDL2，必须等
     framebuffer 第一帧链路稳定后重新评估。
- 本地验证：
  - 新 media NRO 约 `13M`，sha256
    `a829eeb1c36dea582a089e3faca4b872cac0e5e7efaeec3e27f86ca697b5c466`；
  - `nm` 搜索不到 `vbo_exec`、`_mesa_`、`SDL_`、`drm_`、`nouveau`、`glapi`、`EGL`；
  - `.init_array` 大小为 `0x8`，唯一 constructor 解析为 `frame_dummy`。
- 影响：下一次真机测试回到最低风险顺序：被动启动/`state`/`exit`，确认无 fatal 后，才依次测试
  `ihs-init`、`discover-once`、`media-init`、`stream game`。

---

## D-022 full application 对照通过后，M3.3 主线恢复 SDL2/Mesa 正常流程

- 日期：2026-08-25
- 背景：D-021 的 framebuffer 路线是为了隔离 applet mode 下的 Mesa fatal，而不是最终图形方案。
  用户随后通过实体卡带 title override 进入 full application hbmenu/netloader，并要求在资源条件满足后
  不再用 framebuffer 绕过图形栈，而是按官方 SDL 示例逻辑继续 M3。
- 证据：
  - Album/PhotoViewer applet 下，同一官方 OpenGL 基准 `switch-gfx-gl-official.nro` fatal 于
    Mesa/Nouveau buffer allocation/cache flush 路径；
  - 用户通过实体卡带 title override 进入 hbmenu/netloader 后，推送同一 NRO，用户反馈 `都正常了`；
  - devkitPro SDL2 示例使用 `SDL_Init(SDL_INIT_VIDEO | SDL_INIT_JOYSTICK)`、1920x1080 flags=0
    window、`SDL_RENDERER_ACCELERATED | SDL_RENDERER_PRESENTVSYNC` renderer、SDL 自己的事件循环；
  - `switch-sdl2` backend 的 `SWITCH_PumpEvents()` 内部调用 `appletMainLoop()` 并在结束时推送
    `SDL_QUIT`。
- 结论：
  - 当前最强结论是 applet/full application 资源差异导致此前 Mesa fatal；
  - framebuffer 版只作为隔离证据，不再作为 M3 主线；
  - SDL/Mesa 路径必须要求 full application 环境，applet mode 下后续应禁用或明确提示。
- 决定：
  1. `tools/switch-stream-probe` 重新链接 SDL2/EGL/Mesa/Nouveau；
  2. `media.c` 使用 SDL2 renderer + IYUV texture，`SDL_UpdateYUVTexture` 后
     `SDL_RenderCopy`/`SDL_RenderPresent`；
  3. SDL 初始化保持官方示例关键流程：`SDL_INIT_VIDEO | SDL_INIT_JOYSTICK`、1920x1080 flags=0、
     accelerated+vsync renderer、打开 joystick 0/1；
  4. media 未启动时主循环仍可直接调用 `appletMainLoop()`；media 启动后由 `SDL_PollEvent()` 驱动
     SDL Switch backend 的 lifecycle，不在外层再调用 `appletMainLoop()`；
  5. 保留 debug `media-init`/`discover-once`/`stream game` 分步入口，便于定位协议、解码和显示阶段。
- 本地验证：
  - `./scripts/build-switch.sh` 通过；
  - 新 `switch-stream-probe.nro` 大小约 `19M`，sha256
    `ef417b826ca1a4c8b2252b8370c643ca90e7227b5187b2a049a09d7edab7d146`；
  - `nm` 可见 `SDL_Init`、`SDL_CreateWindow`、`SDL_CreateRenderer`、`SDL_PollEvent` 和 Mesa/EGL 符号；
    不再出现 `framebufferCreate`/`framebufferBegin`。
- 后续修正：
  - 首帧真机通过后，用户观察到串流画面明显闪烁；
  - 代码证据显示没有新 decoded frame 时会绘制 idle indicator，导致视频帧与 idle 画面交替 present；
  - 已修正为 video active/已显示首帧后无新帧时保持上一帧；
  - 修正版首次重推时用户观察到 Switch OS 报错关闭软件，该轮无应用日志，不能证明根因；
  - 已追加 SDL teardown 分步日志，并将退出清理顺序改为先停 IHS client/`IHS_Quit`，
    再释放 SDL renderer/window；
  - 证据版 `switch-stream-probe.nro` sha256
    `04c12d9adc0ac9c5b763c1162e71fa9dd25a4306096d7e9576a55dd7f6501056`。
- 继续修正：
  - 闪屏修正版复测中，用户确认“不闪了”；debug `state` 显示
    `frames=120 keyframes=2 decoded=120 displayed=117 firstFrame=1 mediaDrop=2`，随后 debug `exit`
    用户确认正确返回 hbmenu。结论：闪屏修正与清理路径在该轮通过；
  - 同轮暴露出 auto-stop 后仍停留在 probe SDL 画面，已改为默认 120 帧 probe 结束后自动退出；
  - debug `stream` 命令也改为自动执行 media/IHS/discovery 准备，旧 `media-init`/`discover-once`
    只保留为排障入口；
  - 简化版 `0b6020bbe785e079d9ed58fde8414db83bdce309c822547efd10a0ee21435c44` 推送后，
    用户观察到 OS 报错关闭软件；PC 侧无应用日志，debug `state` 超时，且尚未发送 stream 命令。
    因此该轮只能记为启动/加载到 debug ready 前 fatal，不能归因于 stream/decode；
  - 当前版启动后自动排队 `game` stream probe，120 帧后自动退出；启动时会通过 nxlink
    打印上一轮 boot/exit/watchdog/exception 摘要；sha256
    `3418640b03711ea7163dadda018113b22912b9fe57a4acfd60f0c0272bafb621`。
  - 自动 stream 版 PC 侧回归通过：日志出现 `auto stream queued`、`streaming success`、
    `session connected`、`first frame displayed`、`auto stop requested after 120 frames`、
    `auto exit requested after probe stream` 与完整 cleanup；是否返回 hbmenu 仍以用户真机观察为准。

---

## D-023 NRO 返回 hbmenu 前必须 join 本程序创建的所有线程

- 日期：2026-08-25
- 背景：自动 stream 版多次测试中，用户观察到：第一次运行能正常返回 hbmenu，但返回后再次启动同一
  netloader 残留入口会被 Switch OS 关闭。该模式说明问题发生在“返回 loader 后的进程/loader 状态”，
  不能只看单次 `nxlink` 正常退出。
- 证据：
  - Switchbrew Homebrew ABI 明确要求 application 返回 loader 前必须清理自身，包括“不泄漏 handles”、
    “重置 MemoryState”以及“不能留下后台线程”；
  - Switchbrew Homebrew Menu 文档说明 hbmenu 通过 Homebrew ABI 启动应用，通常由 nx-hbloader 实际
    launch；
  - nx-hbloader 源码在加载新 NRO 前会先 unmap previous NRO，再 map/load 下一个 NRO；因此若旧 NRO
    返回前留下线程或未释放 loader 可见资源，会影响下一次 NRO load；
  - 本地代码证据：`switch-stream-probe` 自己创建的 `stream_worker` 和 watchdog 原先使用
    `pthread_detach()`，退出时只 signal，不 `pthread_join()`；这直接违反 Homebrew ABI 的
    “No leftover threads” 要求；
  - 对照证据：IHSlib 自身线程封装使用 `pthread_join()`，`IHS_ClientThreadedJoin()` /
    `IHS_SessionThreadedJoin()` 也已经在项目 cleanup 中调用；
  - 上一轮自动 stream 启动时打印过前一轮遗留 `previous watchdog: reason=main_stall ... stream_start_ms=0`
    与旧 exception 摘要，支持“上一轮返回前/后仍有清理证据残留”这个调查方向；
  - 修正版首次运行日志出现 `cleanup: join watchdog`、`cleanup: join stream worker`、
    `media shutdown: SDL_Quit done` 和完整 cleanup；用户随后连续多次启动验证通过，并确认
    “没问题了，这就是原因”。
- 结论：
  - 已证实根因：probe 返回 loader 前没有 join 本程序创建的 detached 线程，违反 Homebrew ABI
    “No leftover threads” 要求，导致返回 hbmenu 后下一次 NRO load 被旧状态污染并被 OS 关闭；
  - 这不是证明 Mesa/SDL 永远没问题，也不是证明 hbmenu/netloader 永远没问题；它证明本轮二次启动
    崩溃由本项目线程生命周期错误触发。
- 决定：
  1. `stream_worker` 不再 detach；退出时 `stream_worker_stop()` 后 `pthread_join()`，再 destroy
     mutex/cond；
  2. watchdog 不再 detach；主循环结束后设置 stop 并 `pthread_join()`，早期 socket init 失败路径也 join；
  3. safe cleanup 中先 join 本程序线程，再清理 IHS client、`IHS_Quit()`、SDL renderer/window、
     debug socket、nxlink socket、`socketExit()`；
  4. `probe_media_shutdown()` 后立即 drain log queue，让下一轮日志能看到 `media shutdown: SDL_Quit done`；
  5. 当前证据版 `switch-stream-probe.nro` sha256
     `2c3c900504fb4ed434d12db97b96ab4a5103af27a82c0d0d73c502dcedf3e03b`。
- 验收：
  - 单次运行日志必须出现 `cleanup: join watchdog`、`cleanup: join stream worker`、
    `media shutdown: SDL_Quit done` 和完整 cleanup；
  - 真机必须连续运行至少两次：第一次正常返回 hbmenu 后，第二次启动不被 OS 关闭。
- 回归结果：
  - 用户已连续测试确认不再出现“第一次返回 hbmenu 后，第二次启动被 OS 关闭”；
  - D-023 作为 Switch NRO 生命周期规范长期生效，后续线程/退出路径改动必须按此验收。

---

## D-024 M3.5 正式 app 先复用已验证 probe 链路，避免双份实现漂移

- 日期：2026-08-25
- 背景：M3.4 已经在 `switch-stream-probe` 中验证了 auth/discovery/stream/session/FFmpeg
  NVTEGRA/SDL2 NV12 显示和完整 cleanup；而 `app/src/main.c` 仍只是 skeleton。如果立刻复制并大规模
  重构这些代码，会让正式 app 与刚通过真机回归的 probe 产生两份实现，增加无证据回归风险。
- 证据：
  - M3.4 真机 PC 侧日志出现 `socketInitialize custom ... udpRx=1048576 ... sampleRcvbuf=1048576`；
  - 同轮日志出现 `SDL video texture ready: NV12 1280x720`、`first frame displayed ... fmt=23`、
    3600 帧 auto-stop、`converted=0`、`return path: safe_cleanup=1`、`media shutdown: SDL_Quit done`；
  - 用户随后手动二次启动并反馈没问题，满足 D-023 的二次启动验收；
  - 本地构建证据：`build/switch/app/nsteamlink.elf` 同时存在正式 `main` 与
    `nsteamlink_stream_main`，并包含 `probe_media_*` 符号；`build/switch/app/nsteamlink.nro`
    sha256 为 `bf9977cf0e5b8055e38e21b12378285401d0524757498fa4efe2ece8c947e497`。
- 结论：
  - M3.5 的最低风险合入方式是让正式 app target 复用同一份已验证 probe 源文件，而不是立即复制成
    新模块后再调试一轮；
  - 这不是最终架构，只是把已证实链路变成正式 `nsteamlink.nro` 的第一步。
- 决定：
  1. Switch 版 `app` target 编译 `tools/switch-stream-probe/main.c` 和
     `tools/switch-stream-probe/media.c`；
  2. 只在 app target 内把 probe `main()` 源级重命名为 `nsteamlink_stream_main()`，由
     `app/src/main.c` 的正式 `main()` 调用；
  3. `app` target 链接与 probe 相同的 `ihslib`、FFmpeg、SDL2、`nx`，保持真机已验证的依赖组合；
  4. `switch-stream-probe` 保留为证据工具，不删除、不改成正式 UI；
  5. 后续做 UI、音频、输入前，再把共享链路拆成 `app` 内的稳定模块，拆分时必须保持二次启动回归。
- 待验证：
  - `nsteamlink.nro` 本身仍需真机跑一轮：首帧、3600 帧 auto-stop、完整 cleanup 返回 hbmenu，
    然后二次启动成功。不能用 probe 的真机结果直接替代 app target 的最终验收。
- 首轮回归：
  - PC 侧确认推送产物为 `nsteamlink.nro`，日志出现 `streaming success`、`session connected`、
    `video decoder opened: h264 (nvtegra)`、`SDL video texture ready: NV12 1280x720` 与
    `first frame displayed ... fmt=23`；
  - 3600 帧摘要为 `frames=3600 decoded=3600 displayed=3598 mediaDrop=1 gaps=0 maxGap=0`
    `transferFrames=3600 converted=0`；
  - 退出日志出现 `return path: safe_cleanup=1`、`cleanup: join watchdog`、
    `cleanup: join stream worker`、`cleanup: IHS_Quit`、`media shutdown: SDL_Quit done` 和
    `exiting ...`；
  - 二次启动 PC 侧证据：再次推送 `nsteamlink.nro` 成功进入应用、建立 session、显示首帧；
    debug `exit` 在 `frames=2105 decoded=2105 displayed=2099 converted=0` 时被接收，随后日志再次
    出现 `session stop: join`、`session stop: destroy`、`return path: safe_cleanup=1`、
    `cleanup: join watchdog`、`cleanup: join stream worker`、`media shutdown: SDL_Quit done`；
  - 用户要求后续不要默认重复测试回 hbmenu。后续若只是普通功能改动，不再默认要求二次启动；
    若触及线程、SDL/Mesa、socket 或退出生命周期，先说明风险与证据价值，再决定是否测试。

---

## D-025 M4 第一版 UI 使用 SDL2 overlay 与内置 5x7 英文字体

- 日期：2026-08-25
- 背景：用户已指出 Switch console 没有中文字库，中文输出会乱码；正式 app 需要在不依赖 debug
  console 的情况下显示 host、状态和 PIN 输入。当前阶段不应为了 UI 引入字体库或复杂渲染栈，
  以免重新扩大 M3 刚稳定下来的 SDL/Mesa/FFmpeg 风险面。
- 证据：
  - 真机观察：console 中文显示乱码，只有英文数字正常；
  - M3.5 已验证 SDL2 renderer/texture 可稳定显示视频，正式 app 已链接 SDL2；
  - 当前本地构建通过，`nsteamlink.nro` sha256
    `e5866b27171af7556e6d11aecdee6b95264840a65e379f6c9f6de78c07ce7d6d`。
- 决定：
  1. M4 第一版 UI 全部使用英文 ASCII；
  2. SDL2 overlay 使用内置 5x7 bitmap 字体，以矩形绘制字形，不引入 TTF/fontconfig 等依赖；
  3. 菜单/PIN 页面使用暗底大面板，串流中只显示左上小 HUD，避免遮挡主画面；
  4. 正式 app 默认进入菜单，不再自动开始 stream；`switch-stream-probe` 保留自动 3600 帧长跑；
  5. PINRequired 进入四位数字输入：`LEFT/RIGHT` 选位，`UP/DOWN` 改数字，`A` 提交，`B` 取消。
- 待验证：
  - 真机可读性和按键手感仍需实际体验反馈；这不是线程/退出生命周期改动，不默认要求重复
    hbmenu/二次启动测试。

---

## D-026 M4 输入回传复用 ihslib SDL HID provider，在 Switch 上用 SDL2 compatibility build

- 日期：2026-08-25
- 背景：M4 需要把 Switch 手柄输入回传给 Steam host。IHSlib 已有 `src/hid/sdl` provider，若重新在
  app 里手写 HID report，会绕开上游已有枚举、feature report、delta report 和 event flush 逻辑，
  增加协议 bug 风险。
- 证据：
  - `third_party/ihslib/src/hid/sdl` 已实现 `IHS_HIDProviderSDLCreateManaged()`、
    `IHS_HIDHandleSDLEvent()`、`IHS_HIDResetSDLGameControllers()` 与 48 字节 SDL HID report；
  - `third_party/ihslib/src/hid/sdl/include/ihslib/hid/sdl.h` 明确说明 SDL 事件只累计状态，调用方应按帧
    flush `IHS_SessionHIDSendReport()`，避免 stick/gyro 高频事件淹没可靠控制通道；
  - Switch target CMake cache 中 `SDL3_FOUND` 为空，`/opt/devkitpro/portlibs/switch/include` 只有
    `SDL2`，`/opt/devkitpro/portlibs/switch/lib/pkgconfig` 只有 `sdl2.pc` 而没有 `sdl3.pc`；
  - 本地裸 `pkg-config sdl3` 命中的是宿主机 `/usr/include`，不是 Switch portlibs，不能作为 Switch
    可链接 SDL3 的证据；
  - ihslib CMake 注释已记录 SDL2/SDL3 同进程会因相同 `SDL_*` 符号 cross-bind 而破坏线程，因此不能在
    当前 SDL2 渲染 app 中直接再链接宿主/SDL3 provider；
  - 用户 2026-08-25 真机反馈：菜单界面按键有效，但进入 stream 后按键对 Steam/game 没有效果；
  - `third_party/ihslib/src/session/channels/control/control_hid.c` 中
    `IHS_SessionChannelControlSendHIDMsg()` 与 `IHS_SessionHIDSendReport()` 都会先检查
    `IHS_SessionInputEnabled()`；
  - `third_party/ihslib/src/session/channels/ch_control.c` 中 `IHS_SessionInputEnabled()` 返回 host
    下发的 `streamingInput` 状态；
  - 旧实现只在 streaming request 里设置 `input=true`/`gamepadCount=1`，但 session negotiation 没有显式
    发送 `CStreamingClientConfig.enable_input_streaming=true`；
  - 2026-08-25 真机测试新现象：开始 stream 时画面帧数在走，一旦按键，overlay 帧数马上卡住，
    随后任意按键和 `+` 都无反应；
  - 同期 nxlink 日志显示 `hid summary` 有事件且 `send_fail=0`，随后控制通道出现大量
    `Retransmission Giving up on Packet(channelId=1...)`；
  - 代码证据：`tools/switch-stream-probe/main.c` 主循环在渲染前同步 `logq_drain()`，`logline()`
    直接 `dprintf(nxlink_fd, ...)`；因此 nxlink/stdout 背压或高频 IHS 日志会卡住主循环，
    造成画面不刷新和本地 `+` 无法处理。
  - 本地 Switch 构建通过：`cmake --build build/switch --target nsteamlink_nro switch-stream-probe_nro -j$(nproc)`。
- 结论：
  - 当前 Switch 环境不能直接使用 SDL3 版 provider；
  - 也不应该在 app 中另写一套 HID report；
  - 最小证据化路径是复用 ihslib SDL provider 源码，并为 Switch SDL2 portlibs 增加兼容编译层。
- 决定：
  1. Switch 根 CMake 强制 `IHSLIB_HID_SDL=ON`、`IHSLIB_HID_SDL_USE_SDL2=ON`；
  2. `ihslib-hid-sdl` 默认仍走 SDL3；仅在 `IHSLIB_HID_SDL_USE_SDL2` 下启用 SDL2 shim；
  3. SDL2 shim 只做 API 名称兼容：`SDL_Gamepad`/event/type/function 映射到 SDL2
     `SDL_GameController`/controller events，不改 ihslib HID 协议逻辑；
  4. `nsteamlink.nro` streaming request 打开 `input=true` 与 `gamepadCount=1`，session negotiation
     显式发送 `enable_input_streaming=true`；`switch-stream-probe` 仍保持 input disabled；
  5. app session connected 后 `IHS_SessionHIDNotifyDeviceChange()`；media present loop 把 SDL controller
     events 交给 `IHS_HIDHandleSDLEvent()` 并每帧 flush；
  6. session stop 前调用 `IHS_HIDResetSDLGameControllers()`，再 disconnect/join/destroy session，
     最后 destroy provider；
  7. 历史决定：串流中本地 stop/exit 曾改为 `MINUS+B` / `+`，用于先保证有稳定本地退出路径。
     该热键决定已由 2026-08-27 的 D-033 追记四取代：`+` / `-` 恢复给 Steam/game，本地控制迁移到
     音量组合键。
  8. stream 中加入低频 `hid summary` 日志，记录 SDL HID event 数、report send 成功数和失败数，
     避免下一次输入问题只能靠主观观察定位。
  9. nxlink 日志 fd 设置为 non-blocking，主循环每帧最多 drain 8 条日志，控制通道 retransmission
     日志按秒抑制；诊断输出不得再阻塞渲染、输入和本地退出路径。
- 补丁：
  - `third_party/patches/ihslib/0006-sdl2-hid-provider-compat.patch` 记录本轮 ihslib SDL2 HID provider
    兼容层改动；该 patch 已验证可应用到当前 ihslib HEAD。旧 `0002` 对当前 HEAD 的可重放性需要后续
    单独重排补丁栈，不能把它的失败归因到本轮输入回传改动。
  - `third_party/patches/ihslib/0007-enable-input-streaming-negotiation.patch` 记录 session negotiation
    的 `enable_input_streaming=true` 修正。
- 当前产物：
  - `build/switch/app/nsteamlink.nro` sha256
    `9d4a46a50eb2178218a95df0441bee45b35575861c10fcc5e41a34cf657c281b`；
  - `build/switch/tools/switch-stream-probe/switch-stream-probe.nro` sha256
    `8bf93a53ce469199a61960f4ae2c919e34ba91dbfd1bdb0142ba0b82dac4a6f6`。
- 待验证：
  - 真机需要验证 Steam host 能收到按键/摇杆输入；
  - 若输入仍不可用，第一优先证据是 `hid device change notified` 日志、`streamingInput` 是否为 true、
    Steam host 是否 open device、SDL controller event 是否进入 `IHS_HIDHandleSDLEvent()`，不直接跳到自写
    HID report。
  - 真机需确认按键后 overlay/视频不再卡住，`+` 本地退出仍可用。

---

## D-027 M4 输入问题先加 HID 诊断证据，不继续猜协议根因

- 日期：2026-08-25
- 背景：`enable_input_streaming=true` 与 nxlink 非阻塞/限流修正后，需要复测 stream 内手柄输入。
- 证据：
  - 用户真机观察：本轮“不会卡死”，按 `+` 能退出；但 stream 内普通按键仍“没有任何作用”；
  - 旧日志证据只能证明 `IHS_HIDHandleSDLEvent()` 有事件且 `IHS_SessionHIDSendReport()` 返回成功，
    不能证明 Steam host 已经 open 设备、start input reports、ACK/消费 report；
  - `third_party/ihslib/src/session/channels/control/control_hid.c` 旧实现对 `DeviceOpen` 成功/失败有
    debug 日志，但 `StartInputReports` / `RequestFullReport` 成功路径没有日志；
  - 不跑 `nxlink -s` 时仍可用 UDP debug server 查询状态；这是后续减少人工盲测的更稳路径。
- 结论：
  - 卡死/本地 `+` 失效问题已由真机观察证实改善；
  - stream 内输入无效的根因仍待验证，不能直接归因到 report 格式、caps、`active_input` 或设备位置字段。
- 决定：
  1. 在 app 侧新增 UDP `hid` 命令，输出 `hidEvents/hidSendOk/hidSendFail` 与
     `openOk/openFail/start/startLen/full/getFeature/getStrings/noDevice/ctrlRetrans/ctrlWarn`；
  2. 在 `ihs_log()` 过滤 debug 日志前解析 HID/control 诊断计数，避免依赖 `nxlink -s`；
  3. 在 ihslib 补 `StartInputReports(id, length)` 与 `RequestFullReport(id)` 成功路径 debug 日志；
  4. 下一次真机测试若输入仍无效，先采集 `hid` 输出，再按证据决定是改设备枚举字段、report 长度/内容、
     control reliable packet 还是其他路径。
- 补丁：
  - `third_party/patches/ihslib/0008-hid-diagnostic-logs.patch`。
- 当前产物：
  - `build/switch/app/nsteamlink.nro` sha256
    `b14d584da42808b42a9b6f761801e3fd8b123ff64f4bf3c035d8e99b4b2e4f49`；
  - `build/switch/tools/switch-stream-probe/switch-stream-probe.nro` sha256
    `525e44f3d75e8eff5e5086f3c453e85bc423ba99c0517b47e1a2b8264bd35859`；
  - `build/switch/tools/switch-stream-probe/switch-stream-probe-core.nro` sha256
    `fb0fcaef25c591dd7538c19fc3f89ff4d273b04243f86c7b2e987cf9a8465953`。

---

## D-028 M4 输入回传改用 app-owned single-controller unmanaged SDL HID provider

- 日期：2026-08-25
- 背景：73 字节 wire report 与 `active_input=true` 后，用户真机观察 stream 内按键仍无效果。
- 证据：
  - 真机 UDP `hid` 曾显示 `hidEvents=928 hidSendOk=478 openOk=8 start=8 startLen=73 ctrlWarn=0
    activeInput=1`，说明本地 SDL event、HID send、host open/start、wire length、control warning 均不能单独解释
    “没有效果”；
  - `third_party/ihslib/samples/stream/stream.c` 只创建 session、设置 callbacks 并 connect/join，没有
    `IHS_SessionHIDAddProvider()`，不能作为真实 HID 输入端到端可用的证据；
  - `third_party/ihslib/tests/hid/sdl/test_sdl_hid_device_managed.c` 和
    `test_sdl_hid_device_unmanaged.c` 只验证 SDL provider 本地枚举、open、feature/report 行为，没有真实
    Steam host；
  - devkitPro SDL Switch 后端 `/tmp/devkitpro-sdl-switch-2.28-573101/src/joystick/switch/SDL_sysjoystick.c`
    固定 `JOYSTICK_COUNT=8`，`SWITCH_JoystickGetCount()` 无条件返回 8；index 0 使用
    `padInitializeDefault()`，1-7 使用 `HidNpadIdType_No1 + i`；
  - 同一后端设备名固定为 `Switch Controller`，SDL gamecontrollerdb 有对应 mapping；
  - 本项目 streaming request 只 reserve `gamepadCount=1`，和 managed provider 上报 8 个 SDL game controller
    存在槽位/绑定不确定性；
  - `sdl_hid_write.c` 中 `SetPlayerIndex` 会写入 `sdl->playerIndex`，但旧 `DeviceFeatureReport` 只读取
    SDL player index；Switch SDL 后端 player-index setter 是空实现。
- 结论：
  - 撤回“直接使用 managed SDL provider 就足够”的隐含结论；上游 sample/test 没有证明该组合在 Switch
    + Steam host 上端到端可用；
  - 当前最小、证据化修正是继续复用 ihslib SDL HID report/event 逻辑，但由 app 打开并只暴露一个默认
    Switch controller，和 `gamepadCount=1` 对齐。
- 决定：
  1. `nsteamlink.nro` 的 media init 打开 `SDL_GameControllerOpen(0)`，记录 SDL joystick count、GUID、
     mapping、controller type 和 instance id；
  2. app session 改用 `IHS_HIDProviderSDLCreateUnmanaged()`，device list 只返回这个 app-owned controller；
  3. session destroy 时只 destroy unmanaged provider，controller 生命周期归 media 层，media shutdown 再 close；
  4. UDP `hid` 增加 `providerDevices/sdlJoy/sdlIndex/sdlInstance/sdlType/lastEvent/sdlName/sdlGuid`；
  5. ihslib SDL `DeviceFeatureReport` 优先使用 `sdl->playerIndex`，并输出 `FeatureCaps(...)` debug log。
- 补丁：
  - `third_party/patches/ihslib/0010-hid-active-input-player-index.patch` 记录 ihslib 内
    `active_input=true` 与 player-index feature report 修正；app-owned unmanaged provider 是本项目
    app 代码改动，不属于 ihslib patch。
- 本地验证：
  - `cmake --build build/switch --target nsteamlink_nro switch-stream-probe_nro -j$(nproc)` 通过；
  - `git diff --check` 与 `git -C third_party/ihslib diff --check` 通过。
- 当前产物：
  - `build/switch/app/nsteamlink.nro` sha256
    `6633ec3bf68163936a5938f31f1d12fb3f8735ba2548ac389f4f2b90937faa4b`；
  - `build/switch/tools/switch-stream-probe/switch-stream-probe.nro` sha256
    `346b68dd3839fe2909ff8273965ea2fa2a868e35cf08417c27a95fa11a963b7e`。
- 待验证：
  - 真机验证 Steam/game 是否实际响应按键；
  - 若仍无效，先采集 UDP `hid` 与 `FeatureCaps(...)`，判断是 controller type/caps/report 内容还是 Steam
    host 绑定策略问题。

---

## D-029 M4 修正 Switch face-button mapping，并让 video channel 支持 host 侧重启

- 日期：2026-08-25
- 背景：用户真机确认输入已经能被 Steam/game 消费；新观察是 `A/B` 在 Steam/game 中反了
  （`X/Y` 未完全确认），以及在 Steam UI 内选定游戏启动时，Steam host 停止当前串流、游戏在 PC 上
  独立运行，Switch 端停在最后一帧但进程未死。
- 证据：
  - 用户真机观察：输入有效，但 `A/B` 映射似乎反了；
  - devkitPro SDL Switch 后端
    `/tmp/devkitpro-sdl-switch-2.28-573101/src/joystick/switch/SDL_sysjoystick.c` 的
    `pad_mapping_default[]` raw 顺序是 `HidNpadButton_A, B, X, Y`，即 `b0=A b1=B b2=X b3=Y`；
  - 同一 SDL 版本的 `SDL_gamecontrollerdb.h` 对 `Switch Controller` 的默认 mapping 是
    `a:b1,b:b0,x:b3,y:b2`，说明 SDL logical face buttons 按 Xbox/Nintendo 语义交换；
  - `third_party/ihslib/src/session/channels/ch_control_video.c` 旧代码收到
    `k_EStreamControlStartVideoData` 时，若已有 `IHS_SessionChannelTypeDataVideo`，直接 `break`，不会记录也不会
    重建 video channel；
  - `third_party/ihslib/src/session/channels/channel.c` 旧 `IHS_SessionChannelRemove()` 删除非最后一个动态
    channel 时只 `memmove`，没有递减 `numChannels`，会让 channel 数组尾部保留已销毁指针；
  - `CMsgRemoteDeviceStreamingRequest` protobuf 本身有 `gameid` 字段，但当前 `IHS_StreamingRequest` 和 UI
    没有游戏 ID 来源。
- 结论：
  - `A/B` 反向是 SDL Switch 默认 gamecontroller mapping 与本项目希望“Steam 看到 Switch 面壳字母”不一致导致；
  - `IHS_SessionChannelRemove()` 的计数错误是确定 bug，必须修；
  - host 侧启动游戏时是否一定通过 `StopVideoData` / 新 `StartVideoData` 切换，还需要真机日志验证；
    不能把 `gameid` 缺失或某一种 Steam 启动策略直接当作已证根因。
- 决定：
  1. app 启动时调用 `SDL_GameControllerAddMapping()` 覆盖 `Switch Controller` 为
     `a:b0,b:b1,x:b2,y:b3`，并在日志里打印 override 结果和最终 mapping；
  2. 修正 `IHS_SessionChannelRemove()`：无论删除位置是否在末尾，都递减 `numChannels` 并清空尾槽；
  3. `StartVideoData` 先解析并记录 channel/codec/size/codecData；若已有 video channel，先 remove 再按新消息
     create/add，避免 host 侧重启/切换 video channel 被静默丢弃；
  4. `StopVideoData` 记录当前 video channel，若没有 active channel 也记录 ignored；
  5. app 侧增加首帧后停帧检测：超过 2500ms 无新帧时，overlay/status 显示 `Video stalled`，UDP `state`
     输出新增 `lastFrameAgeMs`。
- 补丁：
  - `third_party/patches/ihslib/0011-video-channel-restart-cleanup.patch`。
- 本地验证：
  - `cmake --build build/switch --target nsteamlink_nro switch-stream-probe_nro -j$(nproc)` 通过；
  - `git diff --check` 与 `git -C third_party/ihslib diff --check` 通过。
- 当前产物：
  - `build/switch/app/nsteamlink.nro` sha256
    `b3ba34d9debf3ee0d52816681ae2b10ed13621251a1ada1ab4ee8e29f787059a`；
  - `build/switch/tools/switch-stream-probe/switch-stream-probe.nro` sha256
    `e602cac58c6e730aa01fe8dded8b59b9d925de3e9b0a109b0b0a240622849b91`。
- 待验证：
  - 真机验证 `A/B/X/Y` 是否符合 Switch 面壳字母；
  - 真机在 Steam UI 内启动游戏，观察日志是否出现 `StopVideoData`、`StartVideoData`、`Replacing active video channel`
    或 `Video stalled`，再决定是否需要新增按 gameid/appid 直接发起 stream 的功能。

## D-030 输入报告周期性强制全量心跳，修复可靠通道丢包后的按键状态发散

- 背景（2026-08-26 真机症状）：串流中间歇性输入完全断流；断流前按住的键在 Steam/game 侧
  保持按下（角色持续奔跑），断流期间新按键也全部无响应。
- 证据链（均源码/日志级）：
  - `third_party/ihslib/src/hid/sdl/src/sdl_hid_event.c`：每个 SDL 变化调用
    `IHS_HIDDeviceReportAddDelta(previous, current)` 且立即推进 `previous=current`——
    `src/hid/report.c` holder 注释明言 delta 是链式语义："the host applies each to the state
    the previous one left it in"；链上丢一环即永久缺一环；
  - `third_party/ihslib/src/session/channels/ch_control.c:110`：HID 报告走可靠控制通道，
    `maxRetransmit=HID_RETRANSMIT_ATTEMPTS`（3 次×10ms）；`retransmission.c:178-188`
    放弃后不再补发；
  - `tools/switch-stream-probe/media.c`：app 仅在有新 SDL 事件的帧调用 flush；SDL provider
    未实现 poll()，`manager.c HIDPollTick` 对我们空转——事件之间通道完全静默；
  - 真机日志：激烈画面时段大量 `Giving up on Packet(channelId=1)`（channelId 1 为 control），
    而全程 `hidSendFail=0`、视频满速（本地提交零失败），证明丢失在网络/主机侧；
  - 同场会话主机发送 `DeviceRequestFullReport` 次数为 0——协议内建的全量重同步请求
    （ihslib 双端已实现，见 `control_hid.c HandleDeviceRequestFullReport` 与
    `sdl_hid_device.c DeviceRequestFullReport`）未被主机自动使用，不能依赖它兜底。
- 根因定性：ihslib 上游注释假定的模型是"每帧都有新的全量快照在路上，丢了由下一帧纠正"
  （`ch_control.c:104` 注释、"once per rendered frame is a good rate"，`sdl.h` 注释），
  而现实是"事件驱动增量 + 无任何状态收敛机制"。缺失的是收敛层，不是某个参数。
- 同族实践佐证：
  - Moonlight（GameStream/IHS 同族）：输入走不可靠数据报的同时，以 `inputSendPeriodUs`
    周期性全量重发手柄状态防 UDP 丢包（moonlight-common-c ControlStream.c）；
  - 官方客户端形态（ihslib 反汇编镜像注释 `manager.c:207` 引用官方二进制地址）：专用报告
    线程每 8ms 轮询设备、有变化批量发送；THALIUM 逆向文章证实官方亦用 SDL 类抽象手柄，
    但未公开传输节奏细节。
- 决定：
  1. 实现 ihslib 公开头文件已预留的 `IHS_HIDRefreshSDLGameControllers()`（契约见
     `ihslib/hid/sdl.h`）：对已 StartInputReports 的 SDL 设备打包当前 wire 状态
     `AddFullForced` 入队并发送，单次调用原子完成"刷新+flush"；不动 baseline 之外的状态语义
     （与 RequestFullReport 的处理逻辑一致）；
  2. app streaming present 循环每 100ms 心跳调用一次（约 90B×10/s ≈ <1KB/s 上行）；
     事件驱动路径保持不变（正常情况低延迟不受影响）；
  3. 每秒 hid summary 与 UDP debug `hid` 输出新增 `stateFull` 计数用于真机核验；
  4. 不采用更激进方案：把 k_EStreamControlRemoteHID 改为不可靠通道+每帧全量（Moonlight 式）
     需要改变对真实 Steam host 的包序/可靠性语义，未经真机验证，风险不成比例；若 100ms 心跳
     后仍有可感知卡键再评估。
- 补丁：`third_party/patches/ihslib/0012-sdl-hid-full-state-refresh.patch`（主题记录），
  权威重建仍以 `0020-switch-port-cumulative.patch` 为准。
- 本地验证：
  - `cmake --build build/switch --target nsteamlink_nro switch-stream-probe_nro -j$(nproc)` 通过；
  - 补丁簿记：0020 重生成后对 pristine HEAD 应用结果与工作区逐字节一致（脚本 diff 验证通过）；
  - 产物 sha256：
    - `nsteamlink.nro` `bc7ef74b79938c2b4978133730869369660c6b01d3ec041f1b2920b90f38d31e`
    - `switch-stream-probe.nro` `845b622d94319358752ea3f14bed1304e9e05591095b250fc63fc3eb0d86b93d`
- 待验证（下一轮真机）：
  - 复现原症状场景：长时间游玩确认卡键是否消失或显著缩短（预期：断流时长被限制在一个
    心跳周期 + 当前丢包窗尾部之内）;
  - 心跳有效性核验：`stateFull` 应随时间线性增长（~10/s），丢包窗后第一次落地的心跳应解除
    键位残留；
  - 若仍出现长时间完全断流：抓取期间每秒 summary 曲线区分"本地事件停摆"
    （events 停止增长→另查渲染循环/SDL 队列）与"线上持续丢弃"（events/sendOk 正常但
    Steam 无响应→评估加大心跳频率或改用不可靠输入通道的 D-030 第 4 点激进方案）。

## D-031 stream 探针更名：目录 tools/switch-stream-probe → client，独立 NRO → switch-stream-selftest

- 背景：M3.5/M4 之后正式 `nsteamlink.nro` 在编译期直接复用该目录的 main.c/media.c（D-024），
  它实际是客户端实现本体；"probe"命名低估其角色并暗示临时性。
- 更名映射（2026-08-27 起）：
  - 目录：`tools/switch-stream-probe/` → `client/`
  - 独立证据 NRO 目标与产物：`switch-stream-probe(-core)` → `switch-stream-selftest(-core)`
  - 函数/类型/宏前缀：`probe_media_* / probe_runtime / probe_mode / PROBE_MEDIA_*`
    → `stream_media_* / stream_runtime / stream_mode / STREAM_MEDIA_*`
  - 构建变量：app/CMakeLists.txt `NSL_STREAM_PROBE_MAIN/MEDIA` → `NSL_CLIENT_MAIN/MEDIA`
  - 运行时横幅："nsteamlink M3 stream probe" → "nsteamlink stream selftest"
- 历史记录策略：M3_STATUS/M4_STATUS/decisions 早前条目中的旧路径、旧 NRO 名与当日 sha256
  为当时事实记录，一律不改写；涉及操作命令的段落已就地更新。对照旧日志时按本表翻译。
- 真 probe 保持原名：`tools/switch-gfx-probe`（图形基准对照工具）语义仍是探针，不动。

### D-030 追记（2026-08-27）：第 4 点激进方案按预定触发条件落地

事件级探针版真机死窗数据满足既定触发线：连续整秒心跳 100% 放弃（packetId 连号）+
channelId=2 可靠消息 20 次重试耗尽 + 视频 stall 与输入失灵同窗。可靠通道在此场景下
"重试+放弃"对自足快照毫无收益，反而放大队头压力。故实现：
`IHS_SessionChannelControlSendDatagram()`——CHID reports 走 Unreliable 数据报
（`0013-hid-input-unreliable-datagram.patch`），设备生命周期消息仍走可靠通道；
加密序列照常推进。本地 SDL 捕获停摆嫌疑（SDL_IsTextInputActive 短路门等）继续以
每秒 `sti=` 探针并行观测，两条根因链允许并存。

### D-030 追记（2026-08-27 第二条）：取代上一追记的 Unreliable 帧类型决定

- Evidence：提交 `702db14` 记录后续真机结果，Steam host 不接受 `Unreliable` 帧类型承载
  `k_EStreamControlRemoteHID`，表现为会话秒断；当前源码 `third_party/ihslib/src/session/channels/ch_control.c`
  仍用 `IHS_SessionPacketTypeReliable` 初始化线缆帧，只在 `IHS_SessionChannelQueueFrame(channel, &frame, reliable)`
  处对 HID input report 传 `reliable=false`，跳过本地重传队列。
- Conclusion：上一追记中"CHID reports 走 Unreliable 数据报"已撤回。当前落地方案是
  **Reliable 类型帧 + fire-and-forget 本地发送 + 100ms full heartbeat 自愈**；设备 open/start/
  feature/read/write 等生命周期消息仍走完全可靠通道。
- Hypothesis：若后续仍出现长时间按键静默，不能再直接归因到线上可靠通道重传；需要用每秒
  `ax/btn/rawAx/rawBtn/styFl` 对照判断 SDL 捕获层、devkitPro SDL Switch 后端 style/attribute
  早退、或 libnx HID sharedmem 是否停摆。

### D-030 追记（2026-08-27 第三条）：事后轮询不能证明已过去的卡住窗口

- Evidence：用户澄清本次“刚复现一次”指的是发消息之前已经有一段卡住；发消息后再转左摇杆时
  输入已经恢复。当时 PC 端 nxlink 日志已停止，正在运行的 NRO 也没有保存每秒 HID 历史。
- Conclusion：发消息后的 UDP `hid/state/stats` 轮询只能说明恢复后窗口里视频、heartbeat、累计
  HID 计数的状态，不能回放或证明卡住期间 SDL 是否拒收事件。旧版 direct raw 探针曾输出 `sty=0/0`，
  只能证明该探针路径不可作为本轮 raw HID 证据。
- Decision：新增 app 内 60 秒 HID history ring，并暴露 UDP `hidlog [n]`；raw 采样改用与主循环同源的
  libnx `PadState`，`sty` 字段解释为 `style/attrs`。下一次复现后即使用户稍后通知，也先取
  `hidlog` 再下结论。
- Additional evidence：随后新版启动时读取到 SD 卡上一条持久 watchdog 记录：
  `reason=main_stall ... main_stall_ms=8006 ... displayed_frames=9589`。`client/main.c` 只在启动时
  `read_text_summary(WATCHDOG_PATH, ...)` 并打印 `previous watchdog`，没有清除文件；因此该记录能证明
  曾有一次主循环停跳超过 8s 并触发 `appletRequestExitToSelf()`，但单独不能证明它就是用户本次口述
  卡住窗口。若与用户时间线吻合，嫌疑应从“SDL 单独拒收输入”提升为“主循环停摆导致 SDL pump、UDP
  debug、本地退出处理一起停止”。
- Smoke evidence：新版启动后 `hidlog` 真机可读；旋左摇杆期间 `e/ax` 与 `raw` 同时增长、
  `sendFail=0`、`sty=0:2/3` 稳定，说明新版诊断能区分正常输入窗口。期间曾见一次
  `Frames window overflow` 导致 session 断开后重连；该现象发生在高频输入仍被 SDL/raw 捕获时，
  先作为 control window 旁支记录，不并入“输入静默”结论。

### D-030 追记（2026-08-27 第四条）：右摇杆保持态问题先挂已知 bug

- Evidence：用户重新澄清本次复现时间线：先观察到游戏输入卡住，随后持续旋转左摇杆约 10+ 秒，
  再回电脑发消息，之后过一会关闭游戏。用户补充 host/game 侧表现像是持续按住右摇杆某方向，
  画面不停旋转；此时左摇杆没有动静，A/B 也可能没有动静，但未再试一次右摇杆能否恢复。
- Evidence：按该时间线重读，本次 `hidlog` 中用户持续旋左摇杆的窗口应对应连续约 10 秒
  `e/ax/raw/sendOk` 增长，而后续零事件窗口更可能是用户停手并回电脑后的时段。
- Conclusion：本轮复现不支持“卡住期间 SDL 必然拒收输入”这个结论；它只证明 Switch 侧在诊断性
  左摇杆输入期间仍能捕获 SDL/raw 事件并排队发送 HID report。Steam Remote Play 当前 protobuf
  只有传输层 ACK/NACK 与 host 发起的 `DeviceStartInputReports` / `DeviceRequestFullReport`，
  没有可直接证明 host 已把某个 report 应用到虚拟手柄/game 的应用层确认。
- Decision：将该残留症状记为 `BUG-M4-HID-001`，暂缓继续根因化，不阻塞音频输出、UI/stream 模块
  拆分等 M4 主线。以后若顺手复现，优先记录“重新移动/松开右摇杆是否让旋转恢复”，再决定是否增加
  HID report packetId、ACK/NACK、CRC 与关键轴值摘要诊断。

## D-032 M4 正式 app 开启 Opus 音频输出

- Evidence：ihslib 已实现 audio control/data channel：`StartAudioData` 创建 data audio channel，
  `ch_data_audio.c` 将 `IHS_StreamAudioConfig` 与 payload 交给应用注册的
  `IHS_StreamAudioCallbacks`。Negotiation 路径在 `enableAudio=true` 时选择 host 提供的 Opus，
  并发送 `enable_audio_streaming=true` / `audio_channels=2`。
- Evidence：Switch portlibs 提供 `opus.pc` 与 SDL2 audio；本地 `pkg-config` 与 Switch CMake
  configure 均能找到 Opus。
- Conclusion：M4 第一版音频不需要改 Steam 协议；缺的是应用侧解码/播放回调，以及正式 app
  request/config 中打开 audio。
- Decision：
  1. 正式 `nsteamlink.nro` 的 streaming request 设 `audio=true`、`audioChannelCount=2`；
  2. session configuring 在正式 app 下启用 audio，selftest 继续 audio off；
  3. app 注册 audio callbacks，`start` 创建 libopus decoder 和 SDL queued audio device，`submit`
     解码 Opus 为 S16LE PCM 并 `SDL_QueueAudio`，`stop` 清队列并关闭 decoder/device；
  4. SDL audio queue 上限约 300ms，超限清队列并累计 drop，第一版优先避免无限延迟；
  5. `state`/`stats`/streaming overlay 与 UDP `audio` 命令输出音频 active、codec、freq、channels、
     frames、queued bytes、drops 和 errors。
- Verification：
  - `cmake --build build/switch --target nsteamlink_nro switch-stream-selftest_nro -j$(nproc)` 通过；
  - `cmake --build build/switch --target switch-stream-selftest-core_nro -j$(nproc)` 通过；
  - 待真机确认：有声、无明显爆音/持续延迟，stop/exit 后音频停止。

## D-033 BUG-M4-HID-001 需要跨退出持久诊断

- Evidence：用户再次复现“host/game 侧输入卡住、画面持续旋转”后，先旋转左摇杆数次，等恢复后
  退出串流程序，再要求查看日志。旧版只提供进程内 60 秒 `hidlog` ring 和 UDP debug；退出后
  `state/hid/audio/hidlog` 均无法访问，且当前没有写入 SD 卡的 HID 秒级历史。因此这次复现窗口
  没有可恢复日志，不能据此得出 SDL、host virtual controller 或协议 ACK 路径的新结论。
- Conclusion：60 秒内存 ring 只适合 app 仍在运行时取证，不适合真实游玩中“复现、观察、恢复、
  退出后再复盘”的流程。继续依赖它会系统性丢证据。
- Decision：
  1. app 启动时将 `sdmc:/switch/nsteamlink/stream_diag.log` 轮转为
     `sdmc:/switch/nsteamlink/stream_diag_prev.log`；
  2. 启动后台 joinable 诊断线程，每秒从内存 snapshot 与 HID history 拷贝摘要，append 到
     `stream_diag.log` 并 flush/fsync；
  3. 诊断线程只读快照并写盘，输入事件、渲染、present 路径不直接 fopen/write；
  4. 退出清理时先 stop/join 该线程，再进入 media/SDL/socket teardown；
  5. UDP debug 新增 `diag [current|prev|status]`，用于读取当前/上一轮日志尾部或诊断线程状态；
  6. HID 秒级 history 增加左右摇杆四轴和按钮 mask，供下次判断 Switch 本地右摇杆状态是否已回中。
- Impact：下一次 BUG-M4-HID-001 复现后，即使用户等到恢复或退出 app，仍可通过下一次启动后的
  `diag prev` 或直接读 SD 卡文件复盘。该改动仍不是根因修复，只是补齐证据链。

### D-033 追记：`-` / `MINUS` 作为输入故障 marker

- Evidence：用户说明真实复现流程通常是先发现 host/game 输入失灵，再做一段诊断性输入，随后才
  回电脑通知；因此读取“通知后的当前尾部”仍会错过真正操作窗口。
- Decision：
  1. streaming 中将 `-` / `MINUS` 定义为故障 marker：用户发现输入失灵时按住该键；
  2. HID 秒级 history 增加 `minus=sdlHeld/sdlSamples/rawHeld/rawSamples`；
  3. 诊断线程只在 marker 出现时额外写 `stream_diag_markers.log`，并随主诊断一起轮转为
     `stream_diag_markers_prev.log`；
  4. UDP debug 增加 `diag marker current|prev`，用于直接读取 marker 记录；
  5. 本小节最初只取消 `MINUS+B` 本地停流；2026-08-27 的 D-033 追记四进一步取代该热键约定：
     `+` / `-` 都恢复给 Steam/game，`-` marker 只被动记录、不吞键。
- Evidence rule：如果故障窗口中 marker 出现，说明 Switch 侧对应输入路径至少看到了 `-`；若同秒
  `sendOk/stateFull` 也正常而 host/game 仍无响应，嫌疑转向 host virtual controller/apply 路径。
  如果用户明确按住 `-` 但 marker 完全不出现，才把嫌疑收敛到本地 SDL/libnx 输入捕获或 pump 路径。

### D-033 追记二：marker 复现支持下游输入应用问题

- Evidence：用户在一次 BUG-M4-HID-001 复现中，故障时按了几次 `-` 并摇左摇杆，恢复正常后又摇
  左摇杆；随后退回 hbmenu，经重新 `nxlink` 启动后读取上一轮 `diag marker prev`。
- Evidence：`stream_diag_markers_prev.log` 返回 `markMinus` seq 365-369/373；其中
  `minus=sdlHeld/sdlSamples/rawHeld/rawSamples` 均有非零样本，`ax` 在 366/367/368/369/373 非零，
  `raw` 轴/按钮变化也有非零记录，`ok` 为 3/21/13/17/13/25，`f=0`，`h=9-10/s`。
- Conclusion：这次故障窗口中，Switch 侧 SDL controller 状态、SDL event/pump、libnx raw sample
  与 HID report 本地排队发送均未整体停摆。该证据不支持“本地完全没收到输入”或“主循环当秒死锁”
  作为本次复现结论。
- Hypothesis：用户观察的 host/game 端无响应更可能在 Switch 本地 send 之后：HID report packet
  传输/ACK、host virtual controller apply、report delta/full 语义或 Steam/game 侧输入状态。下一轮
  若继续根因化，应把 packetId/ACK/NACK、report CRC/axis/button摘要和 host apply 线索纳入 marker
  同窗日志。
- Limitation：当前 marker 日志只记录按钮事件总数和最终 SDL button mask，不能精确区分用户按的
  `A/B` 事件；若需要验证 A/B 本身，需新增 per-button sample/count。

### D-033 追记三：Wi-Fi 断流作为待验证假设

- Evidence：同一 marker 复现中，Switch 侧看到 `-` marker、左摇杆变化和 HID send ok；但这些
  `ok` 计数只来自本地 `IHS_SessionHIDSendReport()` 返回，不是 host 收到或虚拟手柄应用确认。
  旧 marker 行没有保存同秒视频帧、音频帧、控制通道 retrans/warn 或 last-frame age。
- Conclusion：这次证据不能证明“Wi-Fi 一定断流”，也不能排除 Wi-Fi/局域网短暂停顿。用户观察到
  host/game 侧画面持续旋转且左摇杆/A/B 无效，与“本地继续采样，网络或 host 侧暂时没有应用新 report”
  兼容。
- Decision：在 marker 诊断中为每个 `markMinus` seq 追加一行 `markNet`，记录同一秒的
  `frames/displayed/audio` 累计值与每秒增量、`mainAgeMs`、`lastFrameAgeMs`、`gaps/maxGap`、
  `audioQ/audioDrop/audioErr`、`ctrlRetrans/ctrlWarn` 及其增量。
- Evidence rule：若下一次故障 marker 同窗里 `markMinus` 显示输入存在，同时 `markNet` 显示
  视频/音频增量停住、`lastFrameAgeMs` 明显拉长或 control warn/retrans 跳变，则 Wi-Fi/stream
  断流假设获得直接支持。若媒体增量正常、`mainAgeMs` 正常且 control 计数平稳，而 host/game 仍不响应，
  嫌疑继续留在 HID report 传输细节、host virtual controller apply 或 Steam/game 输入状态。

### D-033 追记四：`+` / `-` 还给游戏，本地控制迁移到音量组合键

- Evidence：用户确认实际游戏仍需要 `+` 和 `-`；因此之前把 `+` 作为本地退出、把 `-` 组合键作为本地
  停流/marker 控制，会干扰真实游玩。
- Evidence：上一轮启动读取到 `previous exit_stage: cleanup:skip_blocking:return`、
  `previous boot_stage: cleanup:skip:done`，`diag_tail` 末尾出现 `thread_stop` 且状态处在
  `mode=stream-ready session=0` 附近。该证据说明上一版曾在退出路径跳过完整 cleanup，但不能证明
  退出源一定是 `+`、debug exit、SDL_QUIT、appletMainLoop 结束或其他路径。
- Conclusion：`+` / `-` 不应继续作为正式 app 的本地控制键；无论 exit 源是什么，NRO 返回 hbmenu 前
  都必须走完整 stop/join/destroy cleanup，不能再走 `cleanup:skip_blocking:return` 这种风险分支。
- Decision：
  1. `+` / `-` 恢复为普通 Steam/game 输入；`-` marker 只被动写诊断，不吞键、不触发本地动作；
  2. 本地退出改为按住 `L3+R3` 时点按 `VOL+`；
  3. 本地停流改为按住 `L3+R3` 时点按 `VOL-`；
  4. 每次退出请求持久记录 `exit:source:<reason>`，`state/diag` 增加 `stopReq/exitReq/exitReason`；
  5. 退出 cleanup 去掉 skip 分支，按 `stream worker stop -> watchdog join -> session stop/destroy -> worker join
     -> IHS client stop/join/destroy -> IHS_Quit -> diag/media/debug/audctl/nxlink/socket` 顺序清理。
- Limitation：当前 libnx/SDL 路径没有直接暴露物理音量键按下状态；实现通过 audctl 轮询音量值变化
  判断 `VOL+`/`VOL-`。如果系统音量已经到顶或到底，对应方向可能不触发；日志会记录
  `local_hotkeys: ... audctl/volumeReady` 以便判定本地热键是否可用。

## D-034 重写 control reliable/HID 发送状态机

- Evidence：旧 `IHS_SessionChannelControlSendDatagram()` 仍创建
  `IHS_SessionPacketTypeReliable` 并消耗 control packet ID，只是向
  `IHS_SessionChannelQueueFrame(..., false)` 关闭本地重传登记。该包丢失时，发送端不会补发，却继续
  发送更大的可靠 packet ID。
- Evidence：`tests/session/window_head_gap.c` 确定性证明 control 接收窗口缺少 head packet ID 时，
  后续包即使已经到达也不能被 `Poll()` 交付；control 路径没有 data channel 的超时丢弃机制。
- Evidence：旧重传登记发生在 send worker 完成首次 `sendto()` 之后，存在 ACK 先到、pending 后登记的
  竞态；ACK/NACK 共用 cancel 路径，NACK 反而停止重传；`IHS_SessionChannelPacketAck()` 没有回显
  收包 `fragmentId`。这些都是独立于真机症状、可由源码直接证明的可靠性错误。
- Evidence：D-033 marker 真机记录证明至少一次故障窗口中 SDL、libnx raw、input pump 和本地 HID
  submit 均继续工作，但旧 `hidSendOk` 只表示本地入队，不表示 host ACK 或应用。
- Evidence（后续真机反证）：用户观察 Steam/game 端所有按钮均无效果；退出后从 SD 持久日志读到
  `rel=68/67 retry=420 out=1 oldest=41647ms@1/15/0#416 maxAck=17ms` 与
  `hidSM=1498/1497/2/1/1/1@15`。这表示 packet 15 的 ACK 缺失 41.647 秒并已重传 416 次；同期
  1498 次 HID 快照提交中 1497 次被合并，只发送 2 次、确认 1 次，pending 和 in-flight 均为 1。
- Evidence（源码）：重传项在可靠包进入 send queue 前就把 `nextRetryMs` 设为登记时间加 10ms，
  send worker 真正完成初发后没有重置该期限。发送队列延迟超过期限时，timer 可在初发之前直接发送
  `retransmitCount=1` 的副本；该乱序窗口是独立的状态机错误。
- Evidence（双 lane 后续真机）：一轮 211.5 秒日志结束时为
  `rel=5084/5083 retry=2056 out=1 oldest=205495ms@1/71/0#2044 maxAck=89ms`、
  `hidSM=4860/520/4837/4836/0/1@71`。packet 71 的精确 ACK 始终缺失并被重传约 2044 次，但后续
  4836 个 HID 完整快照仍得到确认。这证明双 lane 已消除 admission 全局锁死，同时证明“被更新完整
  状态取代的旧 HID 包仍永久每 100ms 重传”是独立残留错误。
- Evidence（2026-08-28 marker 复现）：用户发现 host/game 不响应后按了数次 `-`。marker 前后的
  `minus` 同时出现在 SDL 与 libnx raw 采样；约 4.4 秒内 `hidSM` 从
  `3867/414/3826/3825/0/1@519` 推进到 `3975/422/3934/3933/0/1@519`，即新增 108 次提交、
  93 次发送和 93 次精确 ACK，最大 ACK 延迟保持 63ms。同期视频约 50–63fps、音频约 100 帧/秒，
  没有链路断流。旧 packet 519 已在 marker 前重传 1365 次，marker 内继续重传，但没有阻止新包确认。
- Conclusion：此前 D-030 的“Reliable 类型 + fire-and-forget 可以靠后续 full heartbeat 自愈”结论
  **撤回**。在可靠有序 packet ID 空间里跳过任意一个包会制造接收窗口无法跨越的缺口；后续 full
  snapshot 也排在缺口后面，不能承担自愈作用。
- Limitation：目前没有故障窗口的逐包抓包能直接证明某个具体 HID packet ID 丢失后恰好造成用户观察
  的每一次约 10 秒卡住。packet 15 日志已直接证明本次“全部按钮无效”由 admission 等待 ACK 造成，
  但“已彻底修复所有真机卡键”仍是待验证命题。
- Retraction：本节最初采用的“正常只允许一个 HID 完整快照在途并无限等待精确 ACK”已被 packet 15
  真机日志否定。精确可靠重传仍保留，但 HID admission 不得再把全局输入推进绑定到单个 ACK。
- Retraction：本节第二版仍让“已被更新完整快照取代的 HID 包”无限等待精确 ACK。packet 71/519
  真机记录证明这会制造数千次无收益重传；该规则只继续适用于不能由更新状态替代的一般可靠控制包。
- Conclusion：2026-08-28 marker 窗口不支持 SDL 拒绝输入、Switch 主循环停摆、HID admission 堵塞、
  新 control 包没有到达 host，或 Wi-Fi 整体断流。Steam 的 transport ACK 是收包确认，不是 host
  virtual controller/game 已应用输入的确认；因此本次约 10 秒无响应仍位于 transport 收包之后的
  host 输入应用路径，不能声称由本次旧包退休修正解决。
- Decision：
  1. 可靠包在初次发送进入 worker 队列前复制进 session pending 表，消除 ACK-before-registration；
     此时不启动重传时钟，必须等 send worker 完成初发后再以 25ms 首次等待启动，避免重传先于初发；
  2. 每 session 只使用一个 5ms 扫描任务；25/50/100ms 退避后保持 100ms 重发。一般可靠控制包直到
     精确 `(channelId, packetId, fragmentId)` ACK 或 session 销毁，不恢复旧的任意次数 give-up；
  3. ACK 删除 pending，NACK 将该包立即置为 due；分片 ACK 回显收到的 fragmentId；
  4. HID report admission 允许两个可靠完整快照在途，窗口满时的新输入只覆盖“最新待发快照”；任一
     lane ACK 后立即发送最新值。若确认的是较新完整快照，更老在途 HID 快照标记为 superseded；旧包
     总计完成至少三次 25/50/100ms 补洞重传后退休，不再永久污染发送路径。精确 ACK 与 superseded
     分开计数。退出时可额外提交最终 neutral snapshot，并保证它排在 StopRequest 前；
  5. SDL event handler 只更新 canonical controller state；每次提交先清除旧 delta 条目，再生成单个
     forced full report，线上不再依赖 delta 链；
  6. 删除 `ControlSendDatagram`、HID 三次重试上限、per-packet timer/cancelled ring 与 give-up 日志解析；
     持久诊断改为直接采样 reliable tracked/acked/superseded/retry/failure/outstanding/oldest 和
     HID submitted/coalesced/sent/acked/superseded/pending/in-flight。
- Verification：
  - ihslib SDL2 host tests 27/27 通过；新增测试覆盖错误 fragment ACK、NACK 立即重发、超过旧 20 次
    上限仍保留、重复 ACK、HID 最新值合并、delta 被 full snapshot 替换、初发前禁止重传，以及第一个
    HID ACK 永久缺失时第二 lane 仍持续确认并推进最新快照；后续补充 superseded HID 仍完成三次
    补洞重传、随后退休且不计作精确 ACK；
  - ASan+UBSan 27/27 通过；TSan 27/27 通过；
  - Switch `nsteamlink_nro`、`switch-stream-selftest_nro`、`switch-stream-selftest-core_nro` 均构建通过；
  - 2026-08-27 用户在真机启动新版串流并实际测试，反馈“没有任何问题”；这是新版状态机的首轮
    真机 smoke evidence，支持当前实现可用，但不替代后续长时间游玩验证；
  - 待真机：长时间游玩确认 BUG-M4-HID-001 是否消失；若仍复现，用持久日志中的 `relOut/oldest` 与
    `hidSM` 判断是 host ACK 停止、HID admission 等待，还是故障已移到状态机之外。

## D-035 session receive 必须有界唤醒，避免本地退出卡在 join

- Evidence：用户在真机串流中按 `L3+R3+VOL+`；Steam host 已停止串流，但 Switch 保持最后一帧，
  所有本地输入均无响应，最终只能 HOME 后强杀。这证明本地热键和 host StopRequest 路径已生效，不能
  把症状归因于组合键未识别；Switch 是否进入哪个具体 cleanup 子阶段仍需代码/测试证据判断。
- Evidence：新增 host 回归用例启动真实 session receive/send worker，在没有 host ACK 的情况下调用
  `IHS_SessionDisconnect -> IHS_SessionThreadedJoin -> IHS_SessionDestroy`。修复前该用例稳定超过 6 秒
  不返回；gdb 显示主线程阻塞在 `IHS_SessionThreadedJoin()`，session worker 阻塞在 UDP `recvfrom()`，
  timer worker仍正常运行。
- Evidence：源码中 `IHS_SessionInterrupt()` 只设置 `base.interrupted` 并唤醒 send queue，不能唤醒
  已进入阻塞 `recvfrom()` 的 receive worker。`ClientInitialized()` 已给 discovery client socket 设置
  10ms `SO_RCVTIMEO`，但 `SessionInitialized()` 没有对应设置。
- Conclusion：本次退出挂死的确定性代码根因是 streaming session socket 缺少有界 receive timeout。
  StopRequest 使 host 停止发送后，本地 transport timer虽然设置 interrupted，receive worker仍等不到
  下一包，`IHS_SessionThreadedJoin()` 因而无限等待。这与真机“host 已断、Switch 停在最后一帧”一致。
- Decision：`SessionInitialized()` 给 session UDP socket设置 10ms receive timeout。超时只让 worker
  回到循环检查 interrupted，不把 `EAGAIN/EWOULDBLOCK/ETIMEDOUT` 当作网络失败；保留现有 250ms
  StopRequest ACK 等待和 discovery disconnect 重试语义。
- Verification：同一无 host ACK 用例修复后约 1.5 秒完成；ihslib host 27/27、ASan+UBSan 27/27、
  TSan 的 timer/disconnect/concurrent HID/retransmission/admission 5/5 通过。Switch 构建与真机退出
  仍分别作为集成证据和最终行为证据，不用 host 测试替代。
- Real-device verification：修复版真机收到 `hotkey:vol_up+sticks` 后，日志依次出现 StopRequest、
  `session stop: join`、`session disconnected`、video/audio worker stop、session destroy、watchdog/stream
  worker join、IHS client stop/join/destroy、`IHS_Quit`、诊断线程 join、`SDL_Quit done` 与 `exiting`；
  用户确认 Switch 端正常退出，不再停在最后一帧。该结果闭环本次 `L3+R3+VOL+` 回归。

## D-036 NVTEGRA 下载先切换到 256B 对齐 VIC 传输

- Evidence：当前显示链仍是 `AV_PIX_FMT_NVTEGRA -> av_hwframe_transfer_data() -> CPU NV12 ->
  SDL_UpdateNVTexture()`；既有真机摘要约为 `transferAvgUs=1.6ms`、`uploadAvgUs=2.1ms`，并曾由
  FFmpeg 打印 `Frame address/pitch not aligned to 256, falling back to cpu transfer`。
- Evidence：本机 `switch-ffmpeg-7.1-5` 的 `libavutil.a` 包含同一 fallback 文本；averne FFmpeg
  `nvtegra` 分支 `libavutil/hwcontext_nvtegra.c` 的 `nvtegra_transfer_data()` 明确检查每个软件平面的
  地址和 pitch 是否均按 256B 对齐，满足时调用 VIC，不满足时执行 CPU block-linear 解块拷贝。
- Evidence：Moonlight-Switch 的 deko3d renderer 会从 `AV_PIX_FMT_NVTEGRA` 帧取得
  `AVNVTegraMap`，用其 CPU 地址创建 deko3d memory block，并把 luma/chroma 映射为 GPU image；这证明
  Switch 上硬件帧直显可行，但该实现运行在完整 deko3d 图形后端，不是 SDL texture 扩展。
- Conclusion：当前 SDL renderer 没有接收 `AVNVTegraMap` 的接口，直接零拷贝需要把视频及 overlay 的
  图形所有权迁移到 deko3d，不能作为一次局部 SDL texture 修改完成。当前可独立落地的优化是让
  FFmpeg 用 VIC 将 block-linear NVDEC surface 转为线性 NV12，先消除 CPU 解块成本。
- Decision：
  1. 硬件帧下载前按 `AVHWFramesContext.sw_format` 创建 4KB 对齐 backing、256B pitch 的目标 frame；
  2. 运行时再次检查所有 plane 地址和 pitch，对齐且 transfer 成功才累计 `vicTransfers`；
  3. 对齐准备失败、VIC transfer 失败或非预期格式均重试旧的 FFmpeg 自动 transfer，并累计
     `transferFallback`；
  4. 保留 `SDL_UpdateNVTexture()` 和 IYUV fallback，因此本阶段不称为 zero-copy；
  5. 后续若迁移 deko3d，必须同时迁移窗口/swapchain、视频 YUV shader、overlay、applet lifecycle
     和 cleanup，不能与当前 SDL/Mesa renderer 并行占用图形生命周期。
- Verification：Switch app/selftest/core 三目标构建通过；ihslib host 27/27、ASan+UBSan 27/27
  通过。真机待确认日志出现 `NVTEGRA transfer path: VIC 256B-aligned`，且摘要满足
  `vicTransfers == transferFrames`、`transferFallback=0`；实际耗时收益只以同场景真机
  `transferAvgUs/MaxUs` 对照为准。
- Real-device evidence：本轮命中 `vicTransfers=1963`、`transferFallback=0`，但
  `transferAvgUs=1658` 未优于既有约 1.6ms 基线，因此当前没有性能收益证据。同轮按钮失效已由
  `rel/hidSM` 精确定位为 packet 15 ACK 缺失触发的单在途 admission 锁死，不能把它归因于 VIC。

## D-037 IHSlib 改用本项目 GitHub fork，废弃 patch 文件工作流

- 日期：2026-08-28
- Evidence：
  - 子模块 `third_party/ihslib` 在 pin `8c5a17c` 之上累积了 44 文件 +1338/−333 的
    未提交改动（内容 = 历史补丁 0001–0013 全部 + D-034/D-035/D-036 后续工作），
    双目标构建与 ihslib 27/27（host / ASan+UBSan / TSan）测试均在该工作区状态通过；
  - 2026-08-28 `git fetch origin plume` 后 `FETCH_HEAD == 8c5a17c`：上游 plume 分支
    在 pin 之后零新提交，短期内不存在我们状态机重写被上游吸收的可能；
  - 上游对 HID 重传的处理（b10c319：3 次后放弃、依赖"下一个快照取代"）已被本项目
    真机证据否定（D-030/D-034：输入事件稀疏时丢失的快照没有后继，状态永久发散）；
  - patch 工作流已有事故记录：分层补丁与工作区漂移曾导致"补丁真相"问题，
    靠 c8b7bdf 补录 0010/0011 索引并新增 0020 权威累计补丁才收敛。
- Conclusion：fork + 分支直提可以把"改动真相"收敛到单一 git 历史里，消除
  patch 重放/漂移核对成本；在上游不活跃且取舍冲突的现状下，维护自有 fork 是
  诚实且成本最低的方案。
- Decision：
  1. fork `beudbeud/ihslib` 为 `kxn/ihslib`，创建 `nsteamlink` 分支；
  2. 把 `8c5a17c` 之上的全部改动以单提交 `263fd5d` 固化并推送 fork
     （提交信息按主题记录全部改动，树与已验证工作区逐字节一致）；
  3. 父仓库 `.gitmodules` 的 submodule URL 切至 `https://github.com/kxn/ihslib.git`，
     并设 `branch = nsteamlink`；
  4. 删除 `third_party/patches/ihslib/`（历史补丁从本仓库 git 历史取回）；
  5. 后续 ihslib 改动直接在 `nsteamlink` 分支提交推送（`remote fork`），
     父仓库同步更新 pin；若上游恢复活动，以 PR 反哺独立主题后再评估回归上游。
- 影响：
  - 新克隆流程不变（`git clone --recursive`），但 ihslib 拉到的是本项目 fork；
  - DEVELOPMENT.md §7"第三方库禁止就地修改"规则对 ihslib 变更为
    "改动进 fork 分支"；其余第三方库仍走 patch 流程；
  - D-002 的"若上游日后吸收补丁可评估切回"继续有效；fork 分支的存在使
    上游/本地对比与反哺更直接；
  - submodule pin 从 `8c5a17c` 前进到 `263fd5d`，属预期变化，非版本回退。

## D-038 开发模式迁移：issue 为核心，文档不承载进度

- 日期：2026-08-28
- 背景：此前以文档承载进度（M2/M3/M4_STATUS、README 状态段），每轮开发后需同步
  多处文档，维护成本高且易漂移；2026-08-28 私有仓库 `kxn/nsteamlink` 开通后
  具备了 Issues/milestone 跟踪条件。
- Decision：
  1. 进度、任务、验收状态、待办一律只记 GitHub Issues（含 milestone）；开发完成后
     的记录动作是关 issue / 写 decisions / 必要时更新使用说明，不写状态文档；
  2. 仓库文档只保留三类：宏观设计与规范（kickoff、DEVELOPMENT、decisions）、
     使用说明（README、SWITCH_SETUP、UDP_DEBUG、third_party/README）、
     协议/平台封闭参考（STEAM_REMOTE_PLAY_AUTH、M3_RESEARCH_PLAN、GFX_MESA_INVESTIGATION）；
  3. 禁止在任何文档维护"当前状态 / 下一步 / 待验证"章节；
  4. 删除 docs/M2_STATUS.md / M3_STATUS.md / M4_STATUS.md，证据时间线从 git 历史
     取回；BUG-M4-HID-001 的浓缩证据链在 issue #1。
- 影响：新会话开工顺序改为"kickoff → decisions → DEVELOPMENT → Issues"；
  AGENTS.md 同步登记；decisions.md 本身 append-only，属设计资产，不受本条约束。

## D-039 可靠包 3 秒有界放弃（部分取代 D-034 的"不按次数放弃"）

- 日期：2026-08-28
- Evidence：真机游玩轮（2026-08-28）marker 数据显示 channel 1 packet 1875 自会话 ~30s 起无 ACK，
  `relOldest=189609ms`，relRetry 以 +40~50/s 重传至会话结束（8000+ 次）。期间后续包均正常
  ACK（hidSup 持续增长、视频音频不断）——host 传输层并未卡死；且 8000 次重传不可能全部
  丢失，说明 host 端解密序列 resync 越过洞之后，重传副本作为过期重放被静默丢弃，
  永远不可能获得 ACK。D-034 的"不按次数放弃"在该场景下退化为无限重传黑洞。
- Decision：所有已初发成功的可靠包，`firstTrackedMs` 起 3 秒（RETRANSMISSION_GIVE_UP_MS）
  仍未精确 ACK 即退休，计入 `giveUps`/`reliableGiveUps`；被新快照取代的 HID 包照旧走
  superseded 退休。状态收敛依赖既有 100ms 全量心跳。取代 D-034 中"保留到精确 ACK、
  不按次数放弃"的无限重传部分；精确 ACK 删除、NACK 立即重发、双在途 lane 均不变。
- 可测试预言：若"输入卡死"的机制是有序通道的洞导致 host 端 apply 停滞，则本修复后
  卡死时长被封顶在 ~3 秒（洞放弃 → host 序列前进 → 心跳恢复状态）；若仍出现远超 3 秒
  的卡死，则洞假设被否证，嫌疑收敛到 host 虚拟控制器 apply，转向 host 侧取证。
- 影响：ihslib fork 新提交 `d5645e4`（submodule pin 随父仓库更新）；测试
  `retransmission_state_machine` 同步改写为新策略；`rel=` 调试输出新增 giveups 计数。

## D-040 HID 改单在途串行发送 + 槽位随放弃回收（#1 根因候选）

- 日期：2026-08-28
- Evidence：关键约束——同一 host/网络下官方 Steam Link 客户端从未出现输入卡死，说明
  host 对丢包的容错已被官方客户端验证，问题在客户端特有行为。marker 数据：HID 包
  `hidWait=0/1@6096` 在途 6 秒未轮转（心跳 10/s 正常应 100ms 换手）；packet 1875 失联
  189 秒（D-039）。代码证据：`hidInFlightIds` 槽位仅由 ACK 回收，D-039 的重传放弃
  不会通知控制通道——每个永失包永久泄漏一个槽，丢两个 HID 即完全静默；双在途允许
  报告乱序到达 host，这是官方串行客户端从不产生的模式。
- Decision：
  1. `IHS_CONTROL_HID_MAX_IN_FLIGHT` 2 → 1：HID 严格串行，与官方客户端一致；
     提交时合并进 pending 全量快照，host 永远按序看到最新状态；
  2. `ControlSendPendingHIDLocked` 发送前清扫：重传层已放弃（IsTracked=false）的
     最老在途 id 直接回收槽位，丢包代价封顶 ≈3 秒 + 一个 RTT；
  3. 线上真值 tap：`IHS_HIDSDLGetLastSubmittedReport()` 暴露最近提交报告的轴/按键/
     seq，hidsec 诊断行新增 `sent=` 字段——下次卡死可直接分辨"发了回中"还是"发了旧值"。
- 影响：部分取代 D-034 双在途设计（其动机"单 ACK 丢失锁死"已由 D-039 放弃窗口 +
  本条槽位回收共同覆盖，且不再有乱序副作用）；ihslib fork `e17e697`；admission 测试
  重写为单在途语义；hidsec 行格式扩展。

## D-041 输入报告恢复 delta 编码，对齐官方客户端输入路径

- 日期：2026-08-29
- Evidence（逆向 docs/OFFICIAL_INPUT_RE.md，可复核）：
  - 官方 Android 客户端 v1.3.32 libmain.so 中 `set_full_report` 的 PLT 全二进制零调用——
    官方输入报告全部为 delta_report（掩码差分 + size + CRC32），经
    `BCollectReports → SendBuffer → 队列 → 专用报告线程` 发送，实测 31 批/s（30fps 逐帧）；
  - 官方 `OnNegotiationInit` 读取 host 宣告的 reliable_data 存入客户端状态（0x7ad6fc）；
  - ihslib 的 `IHS_HIDReportHolderAddDelta`（report.c:129）已实现与官方一致的
    ComputeDelta 掩码差分 + CRC32 + delta_report/size/crc 三字段——基础设施完整但被
    D-034 时代停用（事件路径的 AddDelta 调用被移除，改为每帧强制 full）；
  - 上游 ihslib 与 plume 即运行在该 delta 路径上。
- Decision：
  1. 新增 `IHS_HIDFlushSDLGameControllers()`：逐设备 AddDelta（previous→current 掩码
     差分，无变化跳过）+ 发送，作为每帧一次的常规输入发送路径（plume 同构）；
  2. `IHS_HIDRefreshSDLGameControllers()`（强制 full）保留，仅用于 100ms 心跳锚点与
     RequestFullReport 响应——**与官方的残留差异**（官方从不发 full_report 字段），
     因为我方 host 接受 full_report 已被现网会话证实；
  3. 事件处理器保持只更新 canonical state（与官方 BInjectGamepadState 同构）。
  部分推翻 D-034 的"SDL 线上只发完整状态"。
- 验证判据：输入包尺寸/速率对齐官方 pcap 基线（98B 级批量 @ 帧率）；**对 20 秒卡死的
  影响未知**（hold 在包序号层面，与包内容无关——不做修复承诺）。
- 影响：ihslib fork e17e697→新提交；SD 诊断 hidsec 的 sent= 线上真值字段继续有效；
  delta 语义（链式基于 previous）要求 previous 推进与 flush 严格成对，代码已保证。

### D-041 附录（同日补充）：心跳与恢复态也走全掩码 delta，输入线上不再出现 full_report

> **已撤回**：下述“零调用”与 0x7d03b8 的直接调用矛盾。以 D-042 为准。

- Evidence：官方二进制 `set_full_report` 零调用（全量反汇编交叉引用），恢复态/心跳
  以全掩码 delta 表达（掩码覆盖全部状态字节，host 经 delta_report_crc 校验）。
- Decision 补充：100ms 心跳与 Reset 中性态同步从 full_report 字段改为全掩码 delta
  （`IHS_HIDDeviceReportAddForcedFullMaskDelta`，掩码覆盖全部状态字节 + CRC32）。
  输入线上不再出现 full_report 字段，与官方 wire 形态完全对齐。
- 判据：真机输入功能回归正常（对齐本身），host 拒收/无响应即回退。


## D-042 以可复核调用链修正可靠输入和时钟编码

日期：2026-09-07。取代 D-039 的可靠包放弃、D-040 的单在途策略，以及 D-041 附录
的“full_report 零调用”和周期全掩码心跳。证据原件、哈希及地址见
[协议参考 §14](STEAMLINK_PROTOCOL_RE.md#14-独立汇编复核与协议反例2026-09-07)。

Evidence：HandleAck/HandleNack 确认累计水位和选择位；缺失包必须保留。
SendBuffer 0x7d0368–0x7d03b8 在 delta 不划算时发送 full_report。
InputDisabled 对话框的两个手柄处理函数返回 false，不能推导为禁止 HID 提交。
Save 0x7f4c7c/0x7f4cac 分别加时钟偏移和减前一事件。

Decision：可靠包持续重传直到有效确认/会话结束，NACK 空洞与累计确认分开；
HID 收集到入队整体串行，普通状态变化使用 delta/full 自适应，显式重置发 full，
相同状态不额外发 100ms 心跳。active_input 来自实际按钮/轴活动。
帧时间采用单调 16.16 秒、ACK 估计的 peer−local 偏移及事件间 delta。
诊断有界且不阻塞输入；线程及 timer 的所有权必须覆盖最后一次回调。

限制：这些决策有汇编或本地生命周期证据；不能据此宣称 20 秒锁键的唯一根因已找到。
ACK 指标只表示传输确认；实际 HID 解密、重建、游戏应用仍需 Host/真机证据。

## D-043 普通用户 UI 定稿与一次性旧 UI 替换

日期：2026-09-08。取代 D-033 追记四的产品音量组合键设计，及旧行式 UI／idle 动画作为正式
界面的安排；不改变 D-042 的输入编码、ACK、重传和证据约束。完整目标规格见
[UI_UX_DESIGN](UI_UX_DESIGN.md)，实施与验收状态见 [#9](https://github.com/kxn/nsteamlink/issues/9)。

Evidence：用户认可最终精简 mock，要求按此定稿、对照代码决定接线，旧 UI 和 SDL 动画全部删除，
仅保留可通过专用按键呼出的高级诊断浮层。用户已观察到音量极值会影响旧热键；之前 mock 的
根容器 data-focus 点击错误已由鼠标／触摸复现，证明纯按键测试不能代替触摸验收。

Evidence：父仓 `9a4c829` 的 `app/CMakeLists.txt` 把 `client/main.c` 宏改名后链接入正式 app；
`client/main.c:4069/1792` 将启动与发现错误地绑定到已有授权；`client/media.c:1089` 的
`draw_idle_indicator` 移动条和橙块被 init／无帧 present 正常调用；`media.c:930` 直接转发触摸
与 HID，而 `main.c handle_input` 独立处理 libnx UI 按键。`media.c:2111` 在无新帧时不绘制视频，
原菜单不能只靠替换八行字符串获得完整交互。

Decision：

1. 首页直接持续发现、按广播 hostname 展示设备；配对前不虚构账号或游戏，授权与主机／账号历史
   独立存储。手动添加仅在设置的高级页面。配对确认并保存后自动继续连接；安全码是独立流请求事件。
2. 串流占满应用画布，隐藏上下栏；本地菜单覆盖视频，悬浮菜单入口提供完整触摸路径。
   使用同一 renderer，无新帧也重绘本地界面，重复绘制不增加已显示视频帧计数。
3. 共用 C11 model/layout/actions 与统一输入 router 经平台 runtime 接入现有媒体／协议服务。
   正式应用不再借用自测 main；SDL_ttf 与平台字体 provider 替换旧 ASCII 点阵字库。
4. −/+ 长按打开本地菜单，单键有明确上限的组合识别等待；菜单接管和释放有中性状态与 release barrier。
   Debug 仅在本地菜单中长按 L+R+X 切换，默认关闭、只读、会话内有效；游戏中的 L/R/X 不引入等待。
5. 旧 UI、动画、点阵表、音量轮询／热键、正式入口的固定 IP fallback 和自测行为必须从源码与
   构建链接路径删除，不保留 legacy 模式。独立图形动画验证目标一并移除，历史证据从 git 取回。
   协议／生命周期自测可以消费新的 runtime 服务，但不能继续携带旧产品 UI。
6. 最近游戏直启、Steam 菜单调用与真实图片各自按能力开放，不把 HTML 演示行为当成底层支持。
   Debug 读现有计数的有界快照；本机 submit→present 时长不命名为网络或端到端延迟。

影响：定稿文档与交互附件是设计资产；runtime 替换、legacy 删除与真机证据由 issue 追踪。
新 SDL_ttf 链接依赖接入时更新 DEVELOPMENT 依赖表；系统共享字体运行时读取，不打包系统字体。
不得用删除文档历史或第三方上游测试的方式制造“旧 UI 零残留”，也不得用仅隐藏旧控件代替删除。

### D-043 追记：Debug 改为菜单内单键长按

日期：2026-09-08。

Evidence：用户明确反馈 L+R+第三键的组合难按，要求更容易操作且不容易影响游戏。

Decision：撤回上述 L+R+X 组合，改为仅在本地游玩菜单中单独长按 X 1000 ms 切换 Debug。
该菜单内短按 X 无动作；游戏中的 X 直接转发，不增加识别等待。必须在进入菜单后重新按下 X，
松开、离开菜单或失焦取消计时；触发一次后关闭菜单，消耗 X 至释放。再次进入菜单长按 X 关闭浮层。
用菜单状态隔离游戏输入，避免通过增加同时按键数量防误触。手感仍需真机验证。

### D-043 接线证据：共用 runtime 与活动元数据

Evidence：IHSlib `discovery.proto` 的 streaming request 已定义可选 `gameid`，原公共 request
未传递该字段；`remoteplay.proto CSetActivityMsg` 含 `gameid/game_name`，控制通道此前忽略该消息。
`session/channels/ch_control.c` 已通过 input callbacks 交付其他主机 UI 元数据。

Decision：在 fork 增加可选 request.gameId，并用 input.activity callback 交付有效活动的 ID/名称。
不从 appid 猜测非 Steam 游戏 ID，不推断完整游戏库或图片源；零 ID 保持原 Steam 入口请求。
此变更不改变配对、安全码、HID 编码与重传语义。真实主机是否接受具体游戏直启仍由实际响应决定。

Evidence：旧 media video-stop 回调中包含 SDL_DestroyTexture，且原正式入口在 UI 主循环执行 session join。
Decision：将媒体服务抽到 `app/platforms/common/`，SDL 纹理由主线程释放，协议/session 创建和清理
由可 join 的 runtime owner 执行。共用 POSIX/SDL adapter 由两平台链接；业务 model/layout/router
不包含平台 SDK。诊断采用有界缓存和独立日志线程，SDL 输入拥有者在转发前统一仲裁。


#### D-043 实现补充：发现任务所有权与退出顺序

证据：桌面原生集成测试在 TSan 下报告 `base.c` 的 interrupted 跨线程读写，以及
`client/discovery.c` 的 discoveryTimer / discoveryInterval 竞争和 base-lock → timer-lock →
base-lock 环路。发现任务改用已有 Owned timer API，周期在任务私有上下文中保持不变；
停止同步移除任务，接收线程读取 interrupted 使用同一把锁。未改变广播或认证报文语义。

设备 v1 身份（deviceId、secret、name）原样迁移；旧记录没有可验证的主机 clientId，
因此保留 auth.bin、要求重新配对，不把旧 Steam 账号授给新发现主机。
日志线程仅消费复制后的文本，无 IHS/SDL 引用；在协议工作线程 stop/join/destroy、IHS_Quit、
媒体及字体释放后排空并 join，最后关闭平台 socket/font 服务，以保留清理日志。
UDP 调试接口保留只读诊断，产品操作统一进入 UI 状态机；不保留旧音量控制、旧 UI 或动画入口。


#### D-043 真机反馈修正：保留原 UDP 配置与摇杆整体方向

证据：2026-09-08 用户观察到新版首页无法发现 Steam、旧版可以；无启动存储报错。
补充非阻塞 nxlink 日志后实际打印 `runtime: debug UDP fd=-1 errno=105`；工具链 errno.h
将 105 定义为 ENOBUFS。新版 system.c 将 UDP RX/TX/sb 改为 2MiB/256KiB/4，
旧 client/main.c init_socket_for_stream 只将 UDP RX 改为 1MiB，其余保留平台默认。
撤回“新版网络配置已由桌面发现测试充分验证”的任何推断；恢复旧配置及初始化失败回退。
缓冲配置是造成真机 UDP 创建失败的首要解释，恢复后的发现行为须以真机回调确认。

输入证据：input_router 原先用每个轴事件直接更新同一个 repeat；中性 X 轴清空 Y 轴连按，
下一个 Y 事件再次立即移动。改为从两轴整体状态选择方向，加入保持阈值，沿用 300ms/160ms
连按节奏；不改变串流发送的原始摇杆值。

发现路径补充证据：旧 `client/main.c send_discovery_once` 和
`tools/switch-discover/main.c maybe_send_fallback_discovery` 在广播之外，向固定地址发送
同一种 Discovery protobuf；新版只保留了广播。恢复 UDP 配置后真机 debug socket=5、
ping 有回复，但用户仍未发现 Steam，证明 socket 修复不足以证明发现恢复。
产品不恢复硬编码地址：只对已保存主机地址、身份匹配的旧 auth.bin 上次地址做周期定向发现。
旧地址只是候选，不产生 UI 主机、不导入授权；收到真实 discovery callback 才更新列表。
这是对“完全丢弃旧 lastHost”实现的修正，设备 ID/secret 必须匹配后才读取候选。

#### D-043 配对事务修正

用户证据：选择配对后 code 快速变更数次，最后显示无法保存配对。日志同时出现连续
client stop/create，不能把它仅归因为 SD 卡或单次写盘失败。
源码证据：runtime_submit 把每个命令的 store 快照标为 save_pending；worker 在切换命令
世代之前先写盘，错误归到旧世代。ui_events 不限制授权成功的页面和重复消费，Unauthorized
可反复转配对。分离“更新快照”与“要求写盘”，授权回调每次事务只消费一次，UI 只接受配对/
保存阶段的成功，同一连接意图不在配对失败后无限自动再配对，code 仅显式新尝试时重置。

存储证据：[libnx fsdev_rename](https://github.com/switchbrew/libnx/blob/master/nx/source/runtime/devices/fs_dev.c)
直接调用 Horizon fsFsRenameFile；不能把 POSIX 覆盖重命名作为平台共同保证。
保留普通 rename 的快速路径，目标存在时将旧完整文件移到 profile.bak，再发布完整临时文件；
发布失败尝试回滚，启动遇到主文件缺失则校验并恢复 backup，不生成新设备身份。
该回退是可恢复事务，不宣称两次 rename 整体原子。真实保存失败步骤由 stage/errno 日志确认，
不把主机授权拒绝解释为文件错误，也不记录配对 code/secret。
