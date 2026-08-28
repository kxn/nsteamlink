# nsteamlink

Switch 自制软件（homebrew）版 Steam Link 客户端：通过 Steam Remote Play 协议串流 PC 上的 Steam 游戏。

> 进度、任务与验收状态一律见 GitHub Issues（私有仓库 `kxn/nsteamlink`，含 milestone）；
> 本仓库文档只承载设计、规范与使用说明，不维护进度状态。

## 文档索引

| 文档 | 内容 |
|---|---|
| `SWITCH_STEAMLINK_KICKOFF.md` | 调研结论、总体架构、里程碑定义、已知坑 |
| `DEVELOPMENT.md` | 开发规范（目录结构、命名、构建、Git、许可证、调试、文档边界） |
| `docs/decisions.md` | 工程决策记录（ADR-lite，append-only） |
| `docs/STEAM_REMOTE_PLAY_AUTH.md` | Steam Remote Play 认证流程证据整理 |
| `docs/M3_RESEARCH_PLAN.md` | M3 串流第一帧调研与实施计划（已归档设计记录） |
| `docs/GFX_MESA_INVESTIGATION.md` | Mesa/SDL2 applet 崩溃调研（平台证据，已封闭） |
| `docs/UDP_DEBUG.md` | UDP 调试命令参考（28772 端口命令集与字段释义） |
| `docs/SWITCH_SETUP.md` | Switch 真机环境准备指南（刷自制系统 / hbmenu / nxlink） |
| `third_party/README.md` | 第三方依赖与 IHSlib fork 工作流 |

## 快速开始

环境要求见 `DEVELOPMENT.md` 附录 A。

```bash
# 桌面目标
./scripts/build-desktop.sh
./build/desktop/app/nsteamlink

# Switch 目标（需 DEVKITPRO 环境变量）
./scripts/build-switch.sh
# 产物 build/switch/app/nsteamlink.nro → SD 卡 sd:/switch/，
# 经 Title Redirection 启动 hbmenu 后运行；当前显示英文 UI。
# 菜单：A 开始串流，X 切换 game/desktop，Y 刷新 host，B 停流
# 串流中：普通手柄输入转发给 Steam；+ / - 不再作为本地控制键
# 本地控制：L3+R3+VOL+ 退出程序，L3+R3+VOL- 停流

# M2 发现/配对工具
# 产物 build/switch/tools/switch-discover/switch-discover.nro
# PC 端 debug 命令：state / hosts / select <n> / pair / code / exit
# pair 不接收 PIN；Switch 会生成 code，并显示在屏幕与 debug state/code 输出里

# 流程自检 NRO（正式 app 复用同一实现）
# 产物 build/switch/client/switch-stream-selftest.nro
# 保留为证据工具；正式 app 现在复用同一条已验证串流链路
# PC 端 debug 命令：state / hosts / select <n> / stream game / stats / audio / hid / hidlog / diag current / diag prev / diag marker current / diag marker prev / stop / exit
```
