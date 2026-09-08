# nsteamlink 开发规范

> 适用范围：本仓库全部代码与文档。
> 调研结论与里程碑定义见 `SWITCH_STEAMLINK_KICKOFF.md`（下称 kickoff），本文与其冲突时以 kickoff 为准。
> 选型类决定记录在 `docs/decisions.md`（下称 decisions），改规范前先查有没有相关决策。

---

## 1. 策略铁律

1. **先桌面后掌机**：一切协议 / 媒体逻辑先在桌面目标上调通；**M1 完成前不写 Switch 特有功能代码**
   （唯一的例外是骨架里用于验证交叉编译管线的 HAL stub，见 decisions D-006）。
2. **单代码库双目标**：desktop 与 switch 共享 `app/src` 全部业务代码，只有平台后端各写一份。
3. **不重造轮子**：协议层用 IHSlib，解码走 FFmpeg(NVDEC)，平台实现参考 Moonlight-Switch；
   排除项见 kickoff §1"已排除的死路"。

## 2. 目录结构

```
app/src/            业务代码，平台无关。禁止任何平台条件编译
app/src/platform/   HAL 接口头文件（.h）。只定义接口，不含实现
app/platforms/<plat>/  平台后端实现（desktop / switch），只允许被 HAL 接口约束
docs/               决策记录等文档
cmake/              构建身份、素材嵌入和依赖构建适配
packaging/switch/   独立 NSP 应用描述
assets/branding/    原创图标/背景与来源提示词
.github/workflows/  双目标测试与双格式发版
scripts/            构建脚本（唯一构建入口）
third_party/        第三方库（submodule / vendored），禁止就地修改（IHSlib 例外见 §7/D-037）
```

规则：

- `app/src` 下禁止出现 `#ifdef __SWITCH__` 等平台宏；平台差异一律通过
  `app/src/platform/*.h` 的接口下沉到 `app/platforms/<plat>/`。确需破例，必须先写入 decisions。
- `app/platforms/<plat>/` 允许 include 业务头文件与平台 SDK 头文件，但不得反向被业务层直接引用。
- 新目录的增设需在本文档同步登记职责说明。

UI 替换的目标模块边界见 `docs/UI_UX_DESIGN.md` §5：`app/src/ui/` 负责状态、布局与命中，
`app/src/input/` 负责输入仲裁，`app/src/services/` 负责主机／授权／历史，
`app/src/diagnostics/` 负责有界统计快照，平台 runtime 与 renderer 仍经 HAL 接口约束。
`app/platforms/common/` 提供双目标共用的 SDL2/FFmpeg/IHS runtime adapter，平台初始化与字体来源
位于 `app/platforms/<plat>/system.c`。`app/tests/` 包含业务状态与原生事件／媒体测试。实施任务只在 Issue #9 维护。

## 3. 语言与命名

- **语言标准**：ISO C11（顶层 CMake 已锁定 `CMAKE_C_STANDARD 11`）。禁用 VLA，变长缓冲显式分配。
- 符号前缀统一 `sl_`：
  - 公开类型：`sl_<模块>_<名字>`，如 `sl_session`；不透明句柄用 `typedef struct sl_x sl_x;`
  - 函数：`sl_<模块>_<动词宾语>`，如 `sl_session_start`
  - 宏 / 枚举常量：全大写 `SL_` 前缀
  - 模块内部 static 函数不加前缀
- 文件名 snake_case；一个公开头对应一个同名 `.c`；头文件守卫统一 `#pragma once`。
- 回调函数一律携带 `void *userdata`（对齐 IHSlib 风格）。
- 错误处理：返回 `int`（0 成功，负值为错误码）或 `bool`；禁止静默吞错；
  资源的申请与释放放在同一抽象层级，成对出现。
- 内存策略：谁分配谁释放；跨模块移交所有权必须在函数名或注释中明示（如 `_take` / `_free`）。

## 4. 格式化与静态检查

- 提交前对改动文件执行 `clang-format -i <file>`（配置 `.clang-format`：4 空格、列宽 100）。
- 桌面目标构建保持 `-Wall -Wextra` 无新增告警；确需保留的告警在代码处注明原因。
- `.editorconfig` 已配置缩进与换行，编辑器插件应启用。

## 5. 构建系统

| 命令 | 产物 |
|---|---|
| `./scripts/build-desktop.sh` | `build/desktop/app/nsteamlink` |
| `./scripts/build-switch.sh` | `build/switch/app/nsteamlink.nro`（诊断工具需显式开启） |

- CMake ≥ 3.22；Switch 目标使用 `$DEVKITPRO/cmake/Switch.cmake` 工具链文件，
  nro 产出用官方 `nx_create_nro()`，不要手写 elf2nro 调用。
- **环境变量纪律**（decisions D-003）：shell 配置里只导出 `DEVKITPRO / DEVKITA64 / PATH`；
  交叉编译的 `CC/CFLAGS/LDFLAGS` 由脚本按需 source `$DEVKITPRO/switchvars.sh`，
  严禁写入全局 shell 配置。
- Switch 目标链接 portlibs 库时，include/lib 路径用 `$DEVKITPRO/portlibs/switch` 下
  的 `aarch64-none-elf-pkg-config` 或显式 `target_include_directories`，不借用桌面 pkg-config 结果。
- 新增第三方依赖流程：submodule/vendored → decisions 记录版本与理由 → 更新 §7 依赖表。

版本、诊断选项、NSP 目标与 Actions 发版见 `docs/RELEASING.md`。

## 6. Git 规范

- 远程：`origin = https://github.com/kxn/nsteamlink.git`（私有）。单人开发当前直接提交
  `main`（保持可构建可运行）；风险较大的主题仍应开 `feat/<主题>` / `fix/<主题>` 分支。
- Commit message 用 Conventional Commits：
  `feat|fix|docs|build|refactor|test|chore: <摘要>`；正文写动机与影响，一行不超过 72 列。
- 克隆必须 `git clone --recursive`；submodule 有更新时 `git submodule update --init --recursive`
  （kickoff §7.2：漏加会静默回退上游版本且行为不对）。
- 禁止提交：构建产物、个人本地配置、无来源的二进制文件。

## 7. 第三方依赖与许可证

| 库 | 来源/版本 | 许可证 | 用途 | 引入里程碑 |
|---|---|---|---|---|
| IHSlib | `kxn/ihslib` `nsteamlink` 分支（fork 自 `beudbeud/ihslib` plume pin `8c5a17c`，D-002/D-037） | LGPL-3.0 | 发现/配对/串流协议 | M2 |
| plume | beudbeud/plume | GPL | 参考实现，仅对照学习不链接 | M1 参考 |
| FFmpeg(Switch) | Moonlight-Switch 预编译（averne NVDEC fork） | LGPL/GPL | H264 硬解 | M3 |
| SDL2 | 系统 2.32.4 / `switch-sdl2` | zlib | UI / 渲染 / 音频输出 | M3 起 |
| SDL2_ttf | 系统 2.24.0 / devkitPro `switch-sdl2_ttf` | zlib | 中文与平台共享字体、字形缓存 | M5 |
| mbedTLS | 系统 2.28 / `switch-mbedtls` | Apache-2.0 | IHSlib 加密后端 | M2 |
| libopus | 系统 1.5.2 / `switch-libopus` | BSD-3 | 音频解码 | M4 |
| libcurl | 系统 / devkitPro switch-curl 7.69.1-5（libnx SSL） | curl | 封面 HTTPS | M5 |
| libjpeg-turbo | 系统 / devkitPro 2.1.2-2 | BSD/IJG | 后台 JPEG 解码 | M5 |
| jsmn | vendored 25647e6 | MIT | 有界商店 JSON 解析 | M5 |
| protobuf-c | 系统 1.5.1 / M2 自行交叉编译 | BSD-2 | IHSlib 依赖 | M2 |

- 项目整体以 **GPLv3** 发布（复用 Moonlight-Switch 材料所致，kickoff §7.1 / decisions D-004）。
- 复用第三方代码必须保留原版权与许可声明，并在上表登记。
- `third_party/` 内代码禁止就地修改；一般库的改动以 patch 文件放
  `third_party/patches/<库名>/` 并记入 decisions。
- **IHSlib 例外（D-037）**：协议层用本项目 fork `kxn/ihslib`（submodule 指向它，
  track `nsteamlink` 分支）。改动直接在 `third_party/ihslib` 内提交并
  `git push fork nsteamlink`，父仓库同步更新 submodule pin；不再产 patch 文件。
  流程细节见 `third_party/README.md`。

## 8. 日志与调试

- 日志经统一宏 `SL_LOG(level, fmt, ...)` 输出（公共代码封装，输出通道由 HAL 提供）：
  desktop → stderr；switch → stderr（nxlink USB 输出）。
  级别 error/warn/info/debug；**帧处理热路径禁止 info 及以上日志**。
- 协议联调用 Wireshark/tshark 抓包：发现流量过滤 `udp.port == 27036`，
  完整端口清单见 kickoff §5；两端抓包对照分析。
- 发现广播异常时直接手动构造 HostInfo 连 IP（IHSlib 支持），不在发现问题上空转（kickoff §7.4）。
- 调试期 host 本地与客户端各响一遍音频不是 bug，静音一边即可（kickoff §7.5）。
- Windows host 流不通先查防火墙端口放行（TCP 27036/27037，UDP 27031–27036）。
- Switch 固件行为、applet 生命周期、hbmenu/netloader 退出语义等平台结论必须有明确证据：
  libnx/switchbrew 文档、上游源码、真机日志/错误码、可复现实验或已保存的专家结论。没有证据时
  只能标成“假设/待验证”，不得当成结论写入实现或汇报。

## 9. 性能与内存纪律

- 性能基准：默认目标 **720p60**（decisions D-005）；优化以实测帧时间/端到端延迟数据为准，
  不做无数据驱动的优化。
- 视频帧路径：优先零拷贝 / 原地操作；禁止每帧堆分配、每帧格式化日志、每帧系统调用探测。
- Switch 内存按 Title Redirection 全内存模式设计；行为异常时先确认不是误从 applet 模式启动
  （kickoff §7.3），再谈内存问题。

## 10. 测试与验收

- 合入 `main` 的最低门槛：两个目标均可构建，桌面目标冒烟运行通过。
- 里程碑验收标准一律以 kickoff §6 为准，本文档不重复维护副本。
- 真机测试流程：`.nro` 复制到 SD 卡 `sd:/switch/` → **经 Title Redirection 启动 hbmenu**
  → 运行 → nxlink 抓日志。
- 代码不得把超频当前提条件（sys-clk/4IFIR 属高风险用户自担操作，kickoff §7.6）。

## 11. 文档

- README 的命令必须始终可直接复制执行；构建步骤变更时同步更新。
- 所有选型 / 翻案级决定进 `docs/decisions.md`，格式见该文件头部说明。
- **文档边界（issue 为核心开发，2026-08-28 定）**：文档只承载三类内容——
  1. 宏观设计与规范：`SWITCH_STEAMLINK_KICKOFF.md`、本文、`docs/decisions.md`（append-only，
     写完不改，属设计资产而非进度）、`docs/UI_UX_DESIGN.md` 与 `docs/ui-final.html`
     （交互／接线规格与可交互设计附件，不作为运行时或任务状态文件）；
  2. 使用说明：`README.md`、`docs/SWITCH_SETUP.md`、`docs/UDP_DEBUG.md`、`third_party/README.md`；
  3. 协议/平台参考：`docs/STEAM_REMOTE_PLAY_AUTH.md`、`docs/M3_RESEARCH_PLAN.md`、
     `docs/GFX_MESA_INVESTIGATION.md`（封闭的调研记录，不再更新）。
- **进度、任务、验收状态、待办一律只进 GitHub Issues（含 milestone）；禁止在任何文档中
  维护"当前状态 / 下一步 / 待验证"章节**。开发完成后的记录动作是：关 issue / 写 decisions /
  必要时更新使用说明，而不是写状态文档。历史进度文档 M2/M3/M4_STATUS 已于 2026-08-28
  从仓库删除，需要时从 git 历史取回。
- 新会话开工顺序：读 kickoff → 读 decisions → 读本文档 → 在 GitHub Issues 取任务。

## 12. Switch Homebrew 生命周期与退出规范

本节是 2026-08-25 M3.3 二次启动崩溃的复盘规范。背景见 decisions D-023。

### 12.1 退出不是进程重置

- hbmenu 通过 Homebrew ABI / nx-hbloader 启动 NRO。NRO 正常返回 hbmenu，不等价于系统已经把所有
  进程状态清空。
- Homebrew ABI 要求应用返回 loader 前必须清理自己：不泄漏 handle、不依赖未重置的 MemoryState、
  不留下后台线程。
- 因此 `nxlink` 正常退出、PC 日志出现 `exiting ...`，只能说明 PC 侧连接结束；不能单独证明真机
  lifecycle 安全。

### 12.2 线程规则

- Switch NRO 代码禁止默认使用 `pthread_detach()`、裸后台线程或“只 signal 不 join”的 worker。
- 新增线程必须有明确 owner，并实现完整生命周期：`start -> request_stop -> join -> destroy`。
- 线程依赖的 mutex/cond、socket、SDL/FFmpeg/IHS 对象，必须在线程 join 后再释放。
- 如果确实需要 detached 线程，必须先写 decisions，证明它会在返回 hbmenu 前终止，且有真机日志或
  上游源码证据支持。

### 12.3 Cleanup 顺序

Switch 端 probe/client 默认 cleanup 顺序：

1. 停止新的业务请求入口，置退出标志；
2. 停止并 join 本项目自己创建的线程，例如 stream worker、watchdog；
3. 停止 active session：`IHS_SessionDisconnect()` -> `IHS_SessionThreadedJoin()` ->
   `IHS_SessionDestroy()`；
4. 停止 IHS client/discovery：`IHS_ClientStopDiscovery()` / `IHS_ClientStop()` ->
   `IHS_ClientThreadedJoin()` -> `IHS_ClientDestroy()`；
5. `IHS_Quit()`；
6. 释放媒体/图形资源：FFmpeg decoder/frame/packet、SDL texture/renderer/window、`SDL_Quit()`；
7. 关闭 debug/nxlink socket；
8. `socketExit()`；
9. 销毁主线程仍持有的 mutex/cond/state；
10. 从 `main()` 正常 return。

顺序如需改变，必须在 decisions 写明证据和风险。

### 12.4 真机验收

- 涉及线程、socket、SDL/Mesa、applet lifecycle、loader ABI 或退出路径的改动，必须至少连续启动两次。
- 合格标准不是“第一次跑完”，而是：第一次返回 hbmenu 后，第二次从 hbmenu/netloader 启动不被
  Switch OS 关闭。
- 退出日志至少应覆盖关键阶段，例如 `join watchdog`、`join stream worker`、`IHS_Quit`、
  `media shutdown: SDL_Quit done`、`socketExit`。
- 若 PC 侧日志和 Switch 屏幕矛盾，以 Switch 屏幕、fatal 截图、错误码、SD 卡 stage 文件为准。

### 12.5 已踩坑反模式

- 不能把 PC 侧 `nxlink` 退出、debug command 超时、端口状态当成 Switch 屏幕状态的替代证据。
- 不能因为第二次启动失败就先怀疑 netloader、NRO 大小或 SD 文件，除非有对应错误码、日志或对照
  实验。先检查本程序返回 hbmenu 前是否留下线程、handle、socket、SDL/Mesa 或 IHS 状态。
- 不能默认使用 `pthread_detach()`。本轮已证实的二次启动崩溃就是 detached stream worker/watchdog
  未 join 导致。
- 不能把 applet mode 与 full application mode 的图形资源限制混在一起下结论。SDL2/Mesa 路线只在
  full application 环境作为 M3 主线；applet mode 现象必须单独标注。
- 不能偏离 devkitPro/SDL 官方示例生命周期后再用碎片化试验补洞。若需要偏离，先写 evidence /
  conclusion / hypothesis，再写 decisions。
- 不能混淆 Steam pairing authorization code 和 connect/security PIN。认证流程结论以
  `docs/STEAM_REMOTE_PLAY_AUTH.md` 为准。
- 不能把 `gamesRunning=0` 写成广播失败。那只表示 Steam 被发现，但当时没有游戏在跑。

---

## 附录 A：本机环境清单（2026-08-23 搭建）

| 组件 | 版本 | 备注 |
|---|---|---|
| OS | Debian 13 (trixie) x86_64 | 主力开发机 |
| devkitPro pacman | 6.0.2 | 经官方 apt 仓库安装 |
| devkitA64 gcc | 16.1.0 | `/opt/devkitpro/devkitA64` |
| libnx / switch-dev | 当前最新 | `dkp-pacman -S switch-dev` |
| switch-portlibs | 含 SDL2/ttf/mbedtls 2.28/opus 1.3 | `dkp-pacman -S switch-portlibs` |
| SDL2 (desktop) | 2.32.4 | apt |
| FFmpeg (desktop) | libavcodec 61.19 | apt |
| libcurl | 系统 / devkitPro switch-curl 7.69.1-5（libnx SSL） | curl | 封面 HTTPS | M5 |
| libjpeg-turbo | 系统 / devkitPro 2.1.2-2 | BSD/IJG | 后台 JPEG 解码 | M5 |
| jsmn | vendored 25647e6 | MIT | 有界商店 JSON 解析 | M5 |
| protobuf-c | 1.5.1（含 protoc-c） | apt |
| mbedTLS (desktop) | 2.28.x | apt |
| clang-format / tshark | 系统 | 格式化 / 抓包 |

新机器复现要点：
1. `wget https://apt.devkitpro.org/install-devkitpro-pacman && sudo bash 安装脚本路径`
   （注意：devkitpro.org 主站有 Cloudflare，curl 默认 UA 可能被拦，脚本内 wget 用了专用 UA 不受影响）
2. `sudo dkp-pacman -S switch-dev switch-portlibs dkp-toolchain-vars`
3. bashrc 追加 `DEVKITPRO/DEVKITA64/PATH`（见 §5 环境变量纪律）
4. 验证：`./scripts/build-switch.sh` 产出 `.nro`
