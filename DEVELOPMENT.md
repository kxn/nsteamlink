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
scripts/            构建脚本（唯一构建入口）
third_party/        第三方库（submodule / vendored），禁止就地修改
```

规则：

- `app/src` 下禁止出现 `#ifdef __SWITCH__` 等平台宏；平台差异一律通过
  `app/src/platform/*.h` 的接口下沉到 `app/platforms/<plat>/`。确需破例，必须先写入 decisions。
- `app/platforms/<plat>/` 允许 include 业务头文件与平台 SDK 头文件，但不得反向被业务层直接引用。
- 新目录的增设需在本文档同步登记职责说明。

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
| `./scripts/build-switch.sh` | `build/switch/app/nsteamlink.nro` |

- CMake ≥ 3.22；Switch 目标使用 `$DEVKITPRO/cmake/Switch.cmake` 工具链文件，
  nro 产出用官方 `nx_create_nro()`，不要手写 elf2nro 调用。
- **环境变量纪律**（decisions D-003）：shell 配置里只导出 `DEVKITPRO / DEVKITA64 / PATH`；
  交叉编译的 `CC/CFLAGS/LDFLAGS` 由脚本按需 source `$DEVKITPRO/switchvars.sh`，
  严禁写入全局 shell 配置。
- Switch 目标链接 portlibs 库时，include/lib 路径用 `$DEVKITPRO/portlibs/switch` 下
  的 `aarch64-none-elf-pkg-config` 或显式 `target_include_directories`，不借用桌面 pkg-config 结果。
- 新增第三方依赖流程：submodule/vendored → decisions 记录版本与理由 → 更新 §7 依赖表。

## 6. Git 规范

- 分支模型：`main` 保持可构建可运行；开发分支 `feat/<主题>`，修复分支 `fix/<主题>`。
- Commit message 用 Conventional Commits：
  `feat|fix|docs|build|refactor|test|chore: <摘要>`；正文写动机与影响，一行不超过 72 列。
- 克隆必须 `git clone --recursive`；submodule 有更新时 `git submodule update --init --recursive`
  （kickoff §7.2：漏加会静默回退上游版本且行为不对）。
- 禁止提交：构建产物、个人本地配置、无来源的二进制文件。

## 7. 第三方依赖与许可证

| 库 | 来源/版本 | 许可证 | 用途 | 引入里程碑 |
|---|---|---|---|---|
| IHSlib | 上游 mariotaku/IHSlib 或 beudbeud fork（D-002 待定） | LGPL-3.0 | 发现/配对/串流协议 | M1 |
| plume | beudbeud/plume | GPL | 参考实现，仅对照学习不链接 | M1 参考 |
| FFmpeg(Switch) | Moonlight-Switch 预编译（averne NVDEC fork） | LGPL/GPL | H264 硬解 | M3 |
| SDL2 | 系统 2.32.4 / `switch-sdl2` | zlib | UI / 渲染 / 音频输出 | M3 起 |
| mbedTLS | 系统 2.28 / `switch-mbedtls` | Apache-2.0 | IHSlib 加密后端 | M2 |
| libopus | 系统 1.5.2 / `switch-libopus` | BSD-3 | 音频解码 | M4 |
| protobuf-c | 系统 1.5.1 / M2 自行交叉编译 | BSD-2 | IHSlib 依赖 | M2 |

- 项目整体以 **GPLv3** 发布（复用 Moonlight-Switch 材料所致，kickoff §7.1 / decisions D-004）。
- 复用第三方代码必须保留原版权与许可声明，并在上表登记。
- `third_party/` 内代码禁止就地修改；需要的改动以 patch 文件放
  `third_party/patches/<库名>/` 并记入 decisions。

## 8. 日志与调试

- 日志经统一宏 `SL_LOG(level, fmt, ...)` 输出（公共代码封装，输出通道由 HAL 提供）：
  desktop → stderr；switch → stderr（nxlink USB 输出）。
  级别 error/warn/info/debug；**帧处理热路径禁止 info 及以上日志**。
- 协议联调用 Wireshark/tshark 抓包：发现流量过滤 `udp.port == 27036`，
  完整端口清单见 kickoff §5；两端抓包对照分析。
- 发现广播异常时直接手动构造 HostInfo 连 IP（IHSlib 支持），不在发现问题上空转（kickoff §7.4）。
- 调试期 host 本地与客户端各响一遍音频不是 bug，静音一边即可（kickoff §7.5）。
- Windows host 流不通先查防火墙端口放行（TCP 27036/27037，UDP 27031–27036）。

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
- 新会话开工顺序：读 kickoff → 读 decisions → 读本文档 → 从里程碑表取任务。

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
| protobuf-c | 1.5.1（含 protoc-c） | apt |
| mbedTLS (desktop) | 2.28.x | apt |
| clang-format / tshark | 系统 | 格式化 / 抓包 |

新机器复现要点：
1. `wget https://apt.devkitpro.org/install-devkitpro-pacman && sudo bash 安装脚本路径`
   （注意：devkitpro.org 主站有 Cloudflare，curl 默认 UA 可能被拦，脚本内 wget 用了专用 UA 不受影响）
2. `sudo dkp-pacman -S switch-dev switch-portlibs dkp-toolchain-vars`
3. bashrc 追加 `DEVKITPRO/DEVKITA64/PATH`（见 §5 环境变量纪律）
4. 验证：`./scripts/build-switch.sh` 产出 `.nro`
