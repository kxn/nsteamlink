# NSteamLink 构建与发版

## 版本

根 `CMakeLists.txt` 的 `project(VERSION ...)` 是语义版本唯一来源。标题栏、NACP 和
产物文件名统一使用 `0.1.0+abcdef0`（版本 + Git short hash）。已跟踪文件有未提交修改时
追加 `.d`；未跟踪的个人文件不影响标识。构建时自动刷新，无需重新运行 configure。
NACP 最多容纳 15 字节版本文本，超长会明确报错，不能静默截断。
`build_identity.json` 同时记录完整提交哈希。正式发版拒绝 dirty 或 unknown 来源。
应用内更新（D-060）读取最新正式 Release 的 `NSteamLink-X.Y.Z+hash.nro` 与 `SHA256SUMS`：
不要改变这两个附件的命名或校验和格式，也不要把未完成的版本发布为正式 Release。

## 本地构建

需要 devkitPro、CMake、Python 3.9+（cryptography 包）、Git 与 make。已有 SDK 的开发机不必重新安装依赖。
干净环境可在 `devkitpro/devkita64:20260219` 容器中执行：

```sh
scripts/setup-switch-deps.sh
scripts/build-switch.sh -DNSL_DIAGNOSTICS=OFF -DNSL_BUILD_TOOLS=OFF
```

默认产物为 `build/switch/app/nsteamlink.nro`，构建不需要任何机器密钥。
NRO 内含 HOME 入口安装功能；构建需要 setup 脚本提供的 hacBrewPack。
Debian/Ubuntu 构建机可用 `apt-get install python3-cryptography`。
已有 CMake 缓存时可显式传 `-DHACBREWPACK="$PWD/build/deps/hacBrewPack/hacbrewpack"`。
protobuf-c 固定 v1.5.0，hacBrewPack 固定提交；devkitPro 包的实际版本由 CI 附件记录。
容器标签和 portlibs 仓库不是完整的可复现依赖锁，升级后仍需真机验证。

项目只发布 NRO，不再构建独立 NSP（D-059）。NRO 的本机 HOME 入口安装不要求用户提供 keyset；
它通过本机 SPL 在内存完成封装，密钥不导出、不落盘。

## GitHub Actions

日常 push / PR / 手动执行 `Build and release`：测试诊断 ON/OFF 两种桌面构建，交叉构建
Release NRO。仅上传明确列出的用户产物与构建元数据。工作流不使用任何 keyset Secret。

正式发布：修改根版本，更新 `CHANGELOG.md`（中文）、`CHANGELOG.en.md`（英文）及
`.github/RELEASE_NOTES.md`（完整中英双语发布说明，包含对应贡献者致谢）。发布说明首行必须为
`# NSteamLink vX.Y.Z`，工作流会核对它与标签一致，并用此文件发布 Release Notes。
提交并完成测试后，推送与版本一致的 `vX.Y.Z` 标签。
标签工作流发布带本机 HOME 安装功能的 NRO。测试失败或版本不一致都会停止。
所有检查通过后先创建带全部附件的草稿，再公开 Release。手动运行分支工作流只构建；
要重跑已存在标签的发布流程，在 Actions 中重跑该标签运行。上传失败留下的草稿需先检查
并删除后重跑，避免覆盖用户已经下载的正式版本。

附件：带版本和 short hash 的 `.nro`、完整哈希 JSON、诊断排除报告、SDK 包版本清单、SHA256SUMS。
发版默认关闭诊断，不发布测试工具。源码由对应标签与 submodule 固定提交追溯。
标签工作流仍构建诊断版本来执行排除反例检查，但不上传诊断包附件；分支工作流保留诊断制品。

## 诊断构建

`-DNSL_DIAGNOSTICS=ON` 编译高级浮屏、UDP 28772 调试入口、nxlink/文件日志、HID 历史采样
及桌面截图/限帧参数。`NSL_BUILD_TOOLS=ON` 额外构建独立诊断工具。
默认两项关闭；CMake 缓存会记住旧选项，切换用途时明确指定，或使用不同构建目录。
`CMAKE_BUILD_TYPE=Release` 只选择优化级别，不代表关闭诊断。普通包同时要求
`NSL_DIAGNOSTICS=OFF`、`NSL_BUILD_TOOLS=OFF`、`NSL_TEST_FORCE_1080=OFF`；
父项目强制让 `IHSLIB_DIAGNOSTICS` 跟随 `NSL_DIAGNOSTICS`。关闭诊断时，SDK 也不采集原始
HID 历史，不创建对应环形缓冲/互斥锁，不向 stderr 直写 UDP 接收缓冲诊断。
正常 Steam 协议 socket、串流首帧、超时、音视频状态、输入发送线程和错误对话框仍保留。

普通产物只能从干净源码收集，输出目录必须为空：

```sh
python3 scripts/check-release-diagnostics.py build/switch
python3 scripts/collect-release.py --build build/switch --output build/release
python3 scripts/check-release-bundle.py build/release
```

收集入口会重新执行排除门禁，核对实际链接的产品库翻译单元、SDK 诊断对象、最终 ELF 的
诊断符号/特征和 NRO 的三个可加载段。NRO 段必须逐字节对应受审 ELF（除了 elf2nro 生成的头部）。
`diagnostic_exclusion.json` 固定通过检查的 NRO 哈希，上传及发布前再次核对该哈希和文件允许列表。
不能用诊断包改名或把旧输出目录中的测试工具混进普通附件。

CI 使用真实 ON/OFF 构建运行 `test-release-exclusion.py`，验证诊断配置、替换的诊断 ELF/NRO、
对象污染、NRO 修改和残留工具都会被拒绝；检查在 `python -O` 下也必须生效。
这些检查证明指定诊断能力从普通制品排除，不构成对所有网络协议或第三方库的全面安全证明。

## 格式与运行验证的边界

`validate-artifacts.py` 检查 NRO 的实际嵌入图标、名称、版本和程序标识。
结构校验不能证明真机启动成功。

NACP 不要求选择 Nintendo 用户；配置仍使用项目既有 SD 卡路径。


## NRO 内的 HOME 入口

在全内存 hbmenu 启动 NRO，选项 → 添加到 HOME 菜单 → A 添加。
会将当前 SD 上的 NRO 保存到 `sdmc:/switch/nsteamlink/nsteamlink.nro`。
若 netloader 的来源文件不可读，按提示手动将 NRO 放到该路径并从 hbmenu 打开后添加。
该入口使用独立 ID `01004e534c4b1000`，依赖上述 NRO。
安装需要 CFW 支持自制应用安装与启动；程序不改动系统验证策略。

HOME 入口只需添加一次，后续更新替换固定路径下的 NRO。删除入口用系统数据管理，
不影响项目 SD 配置。不要移动或删除目标 NRO；文件缺失时入口直接退出。
封装模板只存在于 build 目录和 NRO 内部，不作为 `.nsp` 发布。
自动算法/失败注入测试不等于真机安装、启动和返回 HOME 的验证。
