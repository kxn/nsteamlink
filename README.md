# nsteamlink

Switch 自制软件（homebrew）版 Steam Link 客户端：通过 Steam Remote Play 协议串流 PC 上的 Steam 游戏。

**当前状态：M0 完成** —— devkitPro 工具链就绪，双目标构建管线打通，可产出 `.nro`。
下一步 M1：编译参考实现 plume 并与 Windows Steam 配对串流验证。

## 文档索引

| 文档 | 内容 |
|---|---|
| `SWITCH_STEAMLINK_KICKOFF.md` | 调研结论、总体架构、里程碑定义、已知坑 |
| `DEVELOPMENT.md` | 开发规范（目录结构、命名、构建、Git、许可证、调试） |
| `docs/decisions.md` | 工程决策记录（ADR-lite） |
| `docs/SWITCH_SETUP.md` | Switch 真机环境准备指南（刷自制系统 / hbmenu / nxlink） |
| `third_party/README.md` | 第三方依赖引入计划 |

## 快速开始

环境要求见 `DEVELOPMENT.md` 附录 A。

```bash
# 桌面目标
./scripts/build-desktop.sh
./build/desktop/app/nsteamlink

# Switch 目标（需 DEVKITPRO 环境变量）
./scripts/build-switch.sh
# 产物 build/switch/app/nsteamlink.nro → SD 卡 sd:/switch/，
# 经 Title Redirection 启动 hbmenu 后运行
```
