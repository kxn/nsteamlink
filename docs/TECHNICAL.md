# NSteamLink 技术与开发指南

本页面向希望理解实现、构建源码或参与开发的读者。
安装与常用操作见 [项目介绍](../README.md)；贡献代码前请阅读 [开发规范](../DEVELOPMENT.md)。

## 实现结构

NSteamLink 通过 Steam Remote Play 协议连接电脑上的 Steam。协议与会话层基于项目维护的
IHSlib fork；Switch 与桌面目标共享界面、输入和业务状态，只在平台接口处区分实现。

| 模块 | 职责 |
|---|---|
| `app/src/ui/` | 页面状态、控件布局、按键与触摸动作 |
| `app/src/input/` | 本地操作、游戏输入和菜单热键的仲裁 |
| `app/src/services/` | 主机记录、授权存储和中英文文本资源 |
| `app/src/platform/` | 平台抽象接口 |
| `app/platforms/common/` | SDL 界面、媒体、IHS 会话工作线程、封面与标题缓存 |
| `app/platforms/switch/` | libnx 初始化、applet 门禁、原生振动和 HOME 入口安装 |
| `app/platforms/desktop/` | 桌面平台实现与开发预览支持 |
| `third_party/ihslib/` | Steam Remote Play 协议、发现、认证、会话与 HID |
| `app/tests/` | 业务、输入、媒体与平台适配回归测试 |

视频通过 FFmpeg 解码，Switch 使用 nvtegra 硬件路径；音频使用 Opus 解码与 SDL 输出。
UI 使用 SDL2 / SDL2_ttf。封面及本地化游戏名通过后台 HTTP 请求获取并缓存。
具体平台限制和依赖版本以源代码、开发规范和对应参考文档为准。

HOME 入口复用 nx-hbloader，加载固定路径的 NRO。构建机生成不含生产密钥的模板，
Switch 本机完成封装与安装；完整独立 NSP 则是另一种产物。详见 [构建与发版](RELEASING.md)。

## 获取源码

```sh
git clone --recursive https://github.com/kxn/nsteamlink.git
cd nsteamlink
```

已有检出在更新后执行 `git submodule update --init --recursive`。
子模块固定到项目 fork 的提交，不能随意替换成上游版本。

## 桌面构建与测试

依赖及环境说明见 [开发规范](../DEVELOPMENT.md)，CI 的具体安装命令见
[Build and release](../.github/workflows/build.yml)。

```sh
./scripts/build-desktop.sh
./build/desktop/app/nsteamlink
ctest --test-dir build/desktop --output-on-failure
```

离线预览需要启用诊断构建。可用独立数据目录隔离配对与设置：

```sh
./scripts/build-desktop.sh -DNSL_DIAGNOSTICS=ON
NSL_DATA_DIR=/tmp/nsteamlink-preview ./build/desktop/app/nsteamlink --offline
```

桌面支持鼠标、SDL 手柄和键盘：方向键、Enter/A、Esc/B、X、Y；Q/E 对应 L/R，
Minus/Equals 对应 −/+。桌面平台可用于实际串流和 UI 验证，但不能替代 Switch 生命周期验证。

## Switch 构建

安装 devkitPro 和依赖后：

```sh
./scripts/setup-switch-deps.sh
./scripts/build-switch.sh -DNSL_DIAGNOSTICS=OFF -DNSL_BUILD_TOOLS=OFF
```

产物为 `build/switch/app/nsteamlink.nro`。构建工具、模板所需 Python 包、NSP 目标、
版本标识与 GitHub Actions 配置统一见 [构建与发版](RELEASING.md)。

正式构建关闭高级 Debug、日志采集和开发工具。使用 `-DNSL_DIAGNOSTICS=ON` 开启诊断后，
可在游玩菜单单独长按 X 一秒切换只读 Debug 浮层；诊断接口见 [UDP_DEBUG](UDP_DEBUG.md)。
`NSL_BUILD_TOOLS=ON` 额外构建探针；正常使用不需要运行它们。

## 数据与认证

Switch 的配对与设置位于 `sdmc:/switch/nsteamlink/profile.bin`；桌面默认目录为
`~/.nsteamlink/`，可由 `NSL_DATA_DIR` 覆盖。旧 `auth.bin` 的设备身份可迁移，但旧格式
没有可信的逐主机身份，因此迁移后首次连接需要重新确认配对。损坏记录不会被自动覆盖。

Steam 的配对授权码与连接安全 PIN 是两个不同概念。修改认证流程前必须核对
[认证语义参考](STEAM_REMOTE_PLAY_AUTH.md)。每台电脑分别保存授权与最近游戏；
最近游戏来自实际串流期间主机报告的活动，并非拉取完整 Steam 游戏库。

## 参考文档

| 文档 | 内容 |
|---|---|
| [开发规范](../DEVELOPMENT.md) | 代码组织、构建约定、依赖、许可证与清理规则 |
| [工程设计](../SWITCH_STEAMLINK_KICKOFF.md) | 目标、架构与选型背景 |
| [设计决策](decisions.md) | 各项技术决定及证据 |
| [界面与交互设计](UI_UX_DESIGN.md) | 页面、输入与视觉设计 |
| [认证语义](STEAM_REMOTE_PLAY_AUTH.md) | 配对、授权和连接安全 PIN |
| [协议研究](STEAMLINK_PROTOCOL_RE.md) | 官方行为与报文参考 |
| [官方输入研究](OFFICIAL_INPUT_RE.md) | 控制器与输入协议参考 |
| [平台图形研究](GFX_MESA_INVESTIGATION.md) | SDL/Mesa 与 applet 环境的证据 |
| [早期媒体研究](M3_RESEARCH_PLAN.md) | 媒体方案的历史研究背景 |
| [Switch 环境参考](SWITCH_SETUP.md) | 开发测试环境、启动和设备操作 |
| [第三方组件](../third_party/README.md) | 来源、许可证与 IHSlib fork 工作流 |

任务、缺陷和验收状态统一记录在 [GitHub Issues](https://github.com/kxn/nsteamlink/issues)。
报告运行问题时附上界面版本、复现步骤、实际错误文字及可用的截图或日志。
