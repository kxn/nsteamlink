# NSteamLink 构建与发版

## 版本

根 `CMakeLists.txt` 的 `project(VERSION ...)` 是语义版本唯一来源。标题栏、NACP 和
产物文件名统一使用 `0.1.0+abcdef0`（版本 + Git short hash）。已跟踪文件有未提交修改时
追加 `.d`；未跟踪的个人文件不影响标识。构建时自动刷新，无需重新运行 configure。
NACP 最多容纳 15 字节版本文本，超长会明确报错，不能静默截断。
`build_identity.json` 同时记录完整提交哈希。正式发版拒绝 dirty 或 unknown 来源。

## 本地构建

需要 devkitPro、CMake、Python 3.9+、Git 与 make。已有 SDK 的开发机不必重新安装依赖。
干净环境可在 `devkitpro/devkita64:20260219` 容器中执行：

```sh
scripts/setup-switch-deps.sh
scripts/build-switch.sh -DNSL_DIAGNOSTICS=OFF -DNSL_BUILD_TOOLS=OFF
```

默认产物为 `build/switch/app/nsteamlink.nro`，不需要任何密钥。
protobuf-c 固定 v1.5.0，hacBrewPack 固定提交；devkitPro 包的实际版本由 CI 附件记录。
容器标签和 portlibs 仓库不是完整的可复现依赖锁，升级后仍需真机验证。

安装包目标使用同一个 ELF 生成独立 NSO 应用，不依赖 SD 卡上的另一个 NRO：

```sh
scripts/setup-switch-deps.sh --packager-only
export NSL_KEYSET=/absolute/path/to/prod.keys
export HACBREWPACK="$PWD/build/deps/hacBrewPack/hacbrewpack"
cmake --build build/switch --target nsteamlink_release
```

`nsteamlink_nsp` 仅生成 NSP，`nsteamlink_release` 同时生成 NRO 和 NSP。
也可 configure 时传入 `-DNSL_KEYSET=/path/to/prod.keys -DHACBREWPACK=/path/to/hacbrewpack`。
keyset 需要 `header_key` 和 `key_area_key_application_00`，只用于打包，不嵌入应用或发布附件。
工程不会下载或生成替代 keyset。NRO 不受此依赖影响。

## GitHub Actions

日常 push / PR / 手动执行 `Build and release`：测试诊断 ON/OFF 两种桌面构建，交叉构建
Release NRO；配置 Secret 后也构建 NSP。仅上传明确列出的用户产物与构建元数据。

维护者在仓库 Actions Secret 中配置 `NSL_SWITCH_KEYSET`，内容为 keyset 文件文本。
也可以在本地运行 `gh secret set NSL_SWITCH_KEYSET < /path/to/prod.keys`，不要把内容写进命令行。
密钥只在 NSP 步骤写入权限 0600 的临时文件，退出时删除；日志不回显打包工具的原始输出。

正式发布：修改根版本、提交并完成测试后，推送与版本一致的 `vX.Y.Z` 标签。
标签工作流缺少 keyset、缺少任一格式、测试失败或版本不一致都会停止，不能发布半套产物。
所有检查通过后先创建带全部附件的草稿，再公开 Release。手动运行分支工作流只构建；
要重跑已存在标签的发布流程，在 Actions 中重跑该标签运行。上传失败留下的草稿需先检查
并删除后重跑，避免覆盖用户已经下载的正式版本。

附件：带版本和 short hash 的 `.nro` / `.nsp`、完整哈希 JSON、SDK 包版本清单、SHA256SUMS。
发版默认关闭诊断，不发布测试工具。源码由对应标签与 submodule 固定提交追溯。

## 诊断构建

`-DNSL_DIAGNOSTICS=ON` 编译高级浮屏、UDP 28772 调试入口、nxlink/文件日志、HID 历史采样
及桌面截图/限帧参数。`NSL_BUILD_TOOLS=ON` 额外构建独立诊断工具。
默认两项关闭；CMake 缓存会记住旧选项，切换用途时明确指定，或使用不同构建目录。
关闭诊断不移除串流首帧、超时、音视频状态、输入发送线程和错误对话框。

## 格式与运行验证的边界

`validate-artifacts.py` 检查 NRO 的实际嵌入图标、名称、版本和程序标识；NSP 必须包含三个
哈希正确的 NCA（program/control/CNMT）。这会拒绝把只有 main/main.npdm 的 ExeFS PFS0
误当成可安装 NSP。结构校验不能证明 keyset 正确或真机启动成功。

NSP 应在支持自制应用的 Switch 上验证安装、HOME 图标、启动、发现/配对、串流、退出。
它使用独立应用启动路径；NRO 则经 hbmenu 加载，两者不能互相代替运行证据。

安装标识固定为 `01004e534c4b0000`；这是项目选择的自制 Title ID，并非官方分配。
NACP 不要求选择 Nintendo 用户；配置仍使用项目既有 SD 卡路径。
