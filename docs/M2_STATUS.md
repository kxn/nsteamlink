# M2 状态整理

> **本文件已归档（2026-08-28）：M2 已验收完成。当前任务见 GitHub Issues（kxn/nsteamlink），本文件仅作历史证据追溯。**


> 目标：Switch 真机上完成 Steam 主机发现与 pairing code 授权，并保存客户端身份，给 M3 串流请求打底。

**当前状态：M2 主路径已在真机跑通：发现、pairing code 授权、`auth.bin` 身份持久化和 debug exit
退出均已验证。B 取消授权路径仍可补充回归。**

## 当前结论

- 默认发现路径使用 IHSlib UDP 广播；`gamesRunning=0` 只表示 Steam 当前没有运行游戏，不代表发现失败。
- 单播发现/手动 `IHS_HostInfo` 直连保留为 fallback，不再作为主发现策略。
- PIN/Code 必须分清：首次 pairing 是 Switch 生成并显示 authorization code，让用户输入到 Steam host；
  host security/connect PIN 是串流阶段输入项，不能传给 `IHS_ClientAuthorizationRequest()`。证据见
  `docs/STEAM_REMOTE_PLAY_AUTH.md` 与 D-016。
- 配对后需要保存客户端身份材料到 `sdmc:/switch/nsteamlink/auth.bin`，避免每次测试重新配对。
- 现阶段持久化的是 `deviceId` 与 `secretKey`，不是 PIN。
- 2026-08-24 真机反馈确认：旧版 PLUS 退出会在倒计时后崩溃；本地代码证据显示旧退出路径没有等待
  IHS worker 退出就调用 `socketExit()`，这是一个真实退出竞态。
- 2026-08-24 后续真机反馈纠正：PC 端 `press PLUS` 后，nxlink 日志虽然完整走到
  `cleanup: destroy IHS client`、`cleanup: IHS_Quit`、`cleanup: close nxlink fd`、`exiting ...`，
  但 Switch 屏幕随后进入 Atmosphere fatal。截图证据：`2144-0001 (0x290)`，
  `Program: 0100000000001000`，`Firmware: 22.5.0 (Atmosphere 1.11.2-master-5388824be)`。
  之前写成“未复现/回归通过”是错误结论，必须撤销。
- 已证实：`0100000000001000` 在 libnx applet ID 表中是 qlaunch/SystemAppletMenu；这只能说明 fatal
  由 hbmenu/qlaunch 宿主进程报告，不能单独证明根因在 qlaunch、本 NRO、nxlink 或 socket cleanup。
- 待验证假设：旧代码用 `nxlinkStdio()` 重定向 stdout/stderr 后又手动 close 返回 fd，可能让后续
  stdio/runtime cleanup 碰到已关闭 socket。当前代码已改为 `nxlinkConnectToHost(false, false)`，日志直接写
  nxlink socket，stdout/stderr 保持 console 所有权；2026-08-24 真机回归显示 debug `exit`
  已返回成功且用户确认无 Atmosphere fatal。
- 2026-08-24 D-017 真机回归证据：`nxlink` 成功启动 `switch-discover.nro`，日志显示
  `loaded auth.bin`、`StartDiscovery -> 1`、发现 `kxn-pc (10.10.10.166) gamesRunning=1`、
  `pairing code for kxn-pc: 3383`，随后 authorization response 从 `result=5` 进展到
  `result=0 steamid=76561198217069647`，并写入 `auth.bin`。
- 同次回归中，PC 端 debug `state` 返回
  `mode=done hosts=1 selected=1 host=kxn-pc ip=10.10.10.166 games=1 paired=1 steamId=76561198217069647`。
- 同次回归中，debug `exit` 触发标准退出路径；nxlink 日志完整走到
  `cleanup: close nxlink log socket` 和 `exiting ...`，用户随后确认退出成功。

## 已完成

- devkitPro / devkitA64 双目标构建骨架已打通，可产出 `.nro`。
- IHSlib 已选定 `beudbeud/ihslib` 的 `plume` 分支并作为 submodule 引入。
- protobuf-c 的 Switch portlibs 安装策略已定，IHSlib libnx 兼容补丁已落在 `third_party/patches/ihslib/`。
- IHSlib SDL3 HID provider 已改为可选，Switch 全量构建不再被 SDL3 头文件阻塞。
- `switch-discover` 已升级为 M2 配对工具：初始化 socket、IHSlib、nxlink/console 日志和手柄输入。
- 广播发现已在真机日志中确认能发现运行 Steam 的主机。
- 探针已处理几个已证实问题：`IHS_Init()` 顺序、console 单写者、ASCII-only console UI、
  IHS worker `Stop -> ThreadedJoin -> Destroy` 标准清理、applet exit lock 成对释放。
- 退出修复已真机回归：不再使用 `nxlinkStdio()` 接管 stdout/stderr，改为手动 nxlink socket
  日志，并在退出阶段写 `exit_stage.txt`；debug `exit` 已确认无 fatal。
- `switch-discover` 会生成/读取 `sdmc:/switch/nsteamlink/auth.bin`，复用稳定的 `deviceId` 与 `secretKey`。
- `switch-discover` 已按 D-016 改成 Switch 端生成/显示 pairing code；旧 PIN 输入页已移除，
  `pin/submit` debug 命令只返回 deprecated 错误。
- `switch-discover` 已接入 `progress / success / failed` 授权回调；授权成功后会记录 `steamId`
  与最近主机信息，并把身份文件写回 SD 卡。
- IHSlib 已补日志：authorization response 会输出 `result`、`steamid`、`auth_key` 长度与
  `device_token` 长度；message type 14/15/16 会被解码/记录，但目前不赋予成功/失败语义。
- M2 主路径已真机验证：发现 Steam host、显示 pairing code、Steam 授权成功、`auth.bin` 保存、
  debug state 可确认 `mode=done paired=1`。
- `switch-discover` 已加入 libnx userland exception dump，崩溃时尝试写入
  `sdmc:/switch/nsteamlink/exception_dump.txt`，配合 `build/switch/tools/switch-discover/switch-discover.elf`
  做 `addr2line` 定位。
- `switch-discover` 已加入开发用 UDP debug command 入口，PC 端可用
  `tools/switch-debugctl.py` 查询状态、列主机、触发配对、读取 code、触发退出，减少手动按键测试。

## 操作方式

- 构建：`./scripts/build-switch.sh`
- M2 工具产物：`build/switch/tools/switch-discover/switch-discover.nro`
- 调试 ELF：`build/switch/tools/switch-discover/switch-discover.elf`
- 主机发现页：
  - `UP/DOWN` 选择主机
  - `A` 生成并显示 pairing code，同时发起 `IHS_ClientAuthorizationRequest()`
  - `Y` 删除 `auth.bin`（重启工具后生成新身份）
  - `PLUS` 返回 hbmenu
- 授权中：
  - 屏幕显示 `Enter this code in Steam on the host` 和四位 code
  - `B` 取消授权
  - `PLUS` 返回 hbmenu
- PC 端自动化调试：
  - `tools/switch-debugctl.py <Switch IP> state`
  - `tools/switch-debugctl.py <Switch IP> hosts`
  - `tools/switch-debugctl.py <Switch IP> select 1`
  - `tools/switch-debugctl.py <Switch IP> pair`
  - `tools/switch-debugctl.py <Switch IP> code`
  - `tools/switch-debugctl.py <Switch IP> exit`
  - 也可发 `press A/B/Y/PLUS/UP/DOWN/LEFT/RIGHT` 模拟 UI 按键。
- 如果真机仍崩溃，先看 `sdmc:/switch/nsteamlink/exit_stage.txt` 的最后阶段；若存在
  `sdmc:/switch/nsteamlink/exception_dump.txt`，再把其中 `pc`/`lr` 交叉映射：
  `aarch64-none-elf-addr2line -f -C -e build/switch/tools/switch-discover/switch-discover.elf <pc> <lr>`

## M2 剩余

- M2 主路径已完成；保留以下补充回归项：
  - B/授权取消路径仍需在授权中状态验证。
  - 若 host 后续要求 security/connect PIN，必须在 streaming 阶段单独输入并发送。
  - Steam 未运行游戏时仍应正确显示发现结果，不把 `gamesRunning=0` 当失败。
  - 若未来退出再次崩溃，保留 nxlink `cleanup:` 日志、`exit_stage.txt`、Atmosphere fatal 截图和 SD 卡
    exception dump。

## 完成 M2 后进入 M3

M2 收口后再做串流请求与第一帧视频：使用已持久化身份发起 `IHS_ClientStreamingRequest()`，然后接 FFmpeg/NVDEC 与 SDL2 渲染。
