# NSteamLink

Switch 自制软件（homebrew）版 Steam Link 客户端：通过 Steam Remote Play 协议串流 PC 上的 Steam 游戏。

> 进度、任务与验收状态一律见 GitHub Issues（仓库 `kxn/nsteamlink`，含 milestone）；
> 本仓库文档只承载设计、规范与使用说明，不维护进度状态。

## 文档索引

| 文档 | 内容 |
|---|---|
| `SWITCH_STEAMLINK_KICKOFF.md` | 调研结论、总体架构、里程碑定义、已知坑 |
| `DEVELOPMENT.md` | 开发规范（目录结构、命名、构建、Git、许可证、调试、文档边界） |
| `docs/decisions.md` | 工程决策记录（ADR-lite，append-only） |
| `docs/UI_UX_DESIGN.md` | 普通用户界面定稿、输入与 Debug 浮层、现有代码接线及旧 UI 删除契约（目标设计） |
| `docs/STEAM_REMOTE_PLAY_AUTH.md` | Steam Remote Play 认证流程证据整理 |
| `docs/M3_RESEARCH_PLAN.md` | M3 串流第一帧调研与实施计划（已归档设计记录） |
| `docs/GFX_MESA_INVESTIGATION.md` | Mesa/SDL2 applet 崩溃调研（平台证据，已封闭） |
| `docs/UDP_DEBUG.md` | UDP 调试命令参考（28772 端口命令集与字段释义） |
| `docs/SWITCH_SETUP.md` | Switch 真机环境准备指南（刷自制系统 / hbmenu / nxlink） |
| `third_party/README.md` | 第三方依赖与 IHSlib fork 工作流 |

## 安装与游玩

从 [Releases](https://github.com/kxn/nsteamlink/releases/latest) 下载 NRO，放到 SD 卡的
`switch/nsteamlink/nsteamlink.nro`。按住 R 启动一个游戏，进入全内存 hbmenu 后打开 NSteamLink。
相册 applet 模式不受支持，应用会在图形初始化前提示并允许按 B 返回。

电脑上开启 Steam Remote Play，保持电脑与 Switch 在同一局域网。首次运行自动发现电脑，
选择后按屏幕提示完成配对。可在 **X 选项 → 添加到 HOME 菜单** 中安装启动入口，
无需提供密钥；入口依赖上述 NRO，后续更新只需替换该文件。需要 CFW 支持自制应用安装与启动。

English: Download the NRO from [Releases](https://github.com/kxn/nsteamlink/releases/latest) and place it at
`switch/nsteamlink/nsteamlink.nro` on your SD card. Hold R while launching a game to enter full-memory
hbmenu, then launch NSteamLink. Enable Steam Remote Play on your PC and pair on the same LAN.
The app supports English and Chinese. **Options → Add to HOME Menu** installs a shortcut without
requiring a key file; keep the NRO at that fixed path. Applet mode is not supported.

## 从源码构建

环境要求见 `DEVELOPMENT.md` 附录 A。

```bash
# 桌面目标
./scripts/build-desktop.sh
./build/desktop/app/nsteamlink

# Switch 目标（需 DEVKITPRO 环境变量）
./scripts/build-switch.sh
# 产物 build/switch/app/nsteamlink.nro → SD 卡 sd:/switch/，
# 经 Title Redirection 启动 hbmenu 后运行。

# 自动测试（含真实 SDL 事件、存储、协议及输入可靠性）
ctest --test-dir build/desktop --output-on-failure

# 无网络桌面预览（需以 -DNSL_DIAGNOSTICS=ON 构建）；数据目录可隔离
NSL_DATA_DIR=/tmp/nsteamlink-preview ./build/desktop/app/nsteamlink --offline
```

启动后自动查找电脑。选择电脑并点击“配对并连接”，把 Switch 显示的四位码输入电脑的 Steam。
配对保存后会继续连接；如果电脑要求连接安全码，再用屏幕数字键盘输入。每台电脑分别保存授权和最近游戏。
最近游戏来自实际串流期间主机报告的活动；有记录后可直接请求启动该游戏和串流，没有记录时显示“开始游玩”。

首页 **L/R** 切换电脑，方向键移动、**A** 确认、**B** 返回，**X** 选项、**Y** 打开 Steam。
首页及本地菜单支持触摸操作。串流全屏显示；同时长按 **− 和 + 0.8 秒**打开本地菜单。开流时显示一次快捷键提示，随后渐隐，画面上不保留常驻按钮。
菜单内可选择“断开连接”（电脑游戏继续运行），或“结束游戏”（请求电脑退出游戏）。回首页后按 B 可退出应用。
仅诊断构建提供高级 Debug：在本地游玩菜单里单独长按 **X 一秒**开关，只读浮层不接管游戏输入。

桌面预览支持鼠标、手柄和键盘：方向键、Enter/A、Esc/B、X、Y，Q/E 对应 L/R，Minus/Equals 对应 −/+。
桌面实际串流可使用 SDL 手柄；没有手柄时仍能使用本地界面和触摸／鼠标指针路径。

配对与设置保存在 Switch 的 `sdmc:/switch/nsteamlink/profile.bin`；桌面默认 `~/.nsteamlink/`，
可用 `NSL_DATA_DIR` 指定独立目录。旧 `auth.bin` 的设备身份会保留；由于旧文件没有可信的主机唯一标识，
升级后首次选择电脑需重新确认配对。损坏文件不会被自动覆盖。

开发工具 `switch-stream-selftest.nro` 运行同一界面和 runtime，默认绘制 600 帧后清理退出；
不自动选择电脑或开启游戏。独立 `switch-discover` 保留作为协议取证工具，正常使用无需运行它。

构建 NSP/NRO、关闭诊断和 GitHub Actions 发版见 [发版说明](docs/RELEASING.md)。
