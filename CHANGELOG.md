# 更新日志

[English](CHANGELOG.en.md)

## [0.4.0] - 2026-10-19

上一正式版：**v0.3.0**。本版：**v0.4.0**。目标分支：`main`；对应源码：[`v0.4.0`](https://github.com/kxn/nsteamlink/tree/v0.4.0)。运行代码沿用已试玩的 `d05abab`，IHSlib 固定为 `afed70e`；发版提交仅更新版本和中英说明。

### 主要变化

- **媒体恢复与传输**：按已核实的官方客户端路径调整视频丢包反馈、关键帧恢复、解码重置与帧呈现时序，以及可靠传输的确认、重发和接收窗口处理；接入 FEC 接收与保存的 FEC 设置。
- **音频播放**：调整 Opus 丢包恢复、抖动缓冲、原始音频播放及播放器启停，改善音视频数据与设备的生命周期管理。
- **连接测网与设置**：接入首次及手动测网、结果保存和推荐预设，保留完整客户端配置；连接等待区分传输、认证和媒体阶段，移除固定视频停顿自动断开。
- **Switch 能力**：按实际后端声明 720p60 / H.264，省略未经确认的最大解码码率。相册 applet 模式可通过确认界面安装 HOME 入口，并显示安装活动与用时；串流仍需全内存模式。
- **协议参考**：补充 Steam Link Anywhere / SDR 客户端策略、协议 schema 及可复现离线审计；这部分研究本身不提供可直接使用的完整公网串流后端。

### 按类型分组的提交

- **功能**：`1a49cca`，applet 模式安装 HOME 入口（[Issue #44](https://github.com/kxn/nsteamlink/issues/44)）；`c4de796`、`2512fb1`、`d6fab25`，FEC 接收、连接生命周期与完整配置持久化。
- **修复与集成**：`7c3b220`、`a3fe641`、`d095563`，关键帧、内容模式与加密分片；`1e8e542`、`87e6c4f`，音频恢复及缓冲；`59eebda`、`697f9b9`、`40dd5b3`，测网、连接等待与已退休会话处理。完整集成见 [PR #53](https://github.com/kxn/nsteamlink/pull/53)。
- **研究与文档**：[PR #50](https://github.com/kxn/nsteamlink/pull/50)，Anywhere / SDR 策略与 schema；[PR #53](https://github.com/kxn/nsteamlink/pull/53)，官方媒体、传输、设置和测网路径对照。

### 验证与证据范围

维护者已对 `d05abab` 主线试玩包进行真机试玩并反馈使用良好；主线 CI 的桌面诊断 ON/OFF 各 170 项测试、Switch 普通及诊断构建通过。标签工作流会再次执行这些检查，并核验版本、正式包诊断排除、NRO 结构、构建来源和附件校验和后发布。

离线原指令回放与受控 peer 测试仅证明对应输入和边界。真实 Steam 的 FEC 启用、不同网络和主机的长期表现、硬件错误及 hbmenu 返回生命周期仍需进一步验证，不能据此断言此前偶发卡顿或 Steam 大屏闪烁已根治。后续逆向开发分支的未合并改动不包含在本版中；其余协议差异由 [Issue #52](https://github.com/kxn/nsteamlink/issues/52) 跟踪。

### 致谢

感谢提供试玩反馈和问题线索的用户、提供初代 Nintendo Switch 的 **Sven**，以及 **Simone Caronni（[@scaronni](https://github.com/scaronni)）**、IHSlib、FFmpeg、Opus、SDL、libnx、devkitPro、deko3d 与 nx-hbloader 的作者和维护者。

### 下载与更新

从[本版 Release](https://github.com/kxn/nsteamlink/releases/tag/v0.4.0) 下载 `.nro`；v0.3.0 起从 SD 卡启动时可使用应用内更新，netloader 启动不检查更新。已添加 HOME 入口时，其固定目标为 `sdmc:/switch/nsteamlink/nsteamlink.nro`。正式包关闭高级诊断，附件包含 `SHA256SUMS`、`build_identity.json` 和 SDK 包清单；仅发布 NRO，不发布独立 NSP 或测试工具。

[完整变更：v0.3.0 → v0.4.0](https://github.com/kxn/nsteamlink/compare/v0.3.0...v0.4.0)

## [0.3.0] - 2026-10-15

上一正式版：**v0.2.1**。本版：**v0.3.0**。目标分支：`main`；对应源码：[`v0.3.0`](https://github.com/kxn/nsteamlink/tree/v0.3.0)。

### 主要变化

- **应用内更新**：Switch 启动后在后台检查最新正式版，有更新时在首页询问是否安装；每次启动最多提示一次。X 选项中的“检查更新”默认开启，关闭后下次启动生效。网络查询失败时静默跳过。
- **下载与校验**：仅通过校验证书的 HTTPS 获取本仓库正式 Release，下载大小及 SHA-256 校验通过后才替换 NRO；文件替换失败时尝试恢复该文件的旧副本。同步更新启动文件与已存在的 HOME 入口目标，完成后提示退出并重新启动。
- **简化发布**：移除从未实际发布过的独立 NSP 构建与密钥配置，只发布 NRO。NRO 内的“添加到 HOME 菜单”功能继续保留，无需用户提供打包密钥。

### 按类型分组的提交

- **功能**：`0a93607`，启动检查、更新设置、下载校验及更新界面（[PR #41](https://github.com/kxn/nsteamlink/pull/41)）。
- **构建与清理**：`6df4b21`、`8b45610`，移除独立 NSP 打包及仅服务于该路径的代码（[PR #42](https://github.com/kxn/nsteamlink/pull/42)）。
- **文档**：`4c0e8c0`、`68fd88d`，记录 NRO 发布与应用内更新的设计及证据边界。

### 致谢

感谢 **Simone Caronni（[@scaronni](https://github.com/scaronni)）** 贡献 PR #41 / #42，实现应用内更新、简化打包流程，并补充自动测试和验证记录。感谢 **Sven** 提供初代 Nintendo Switch，支持开发与实机测试；感谢 IHSlib、FFmpeg、SDL、libnx、devkitPro、deko3d 与 nx-hbloader 等开源项目的作者和维护者。

### 验证与证据范围

已审阅上述两个 PR 的更新器、UI、线程清理和打包改动。诊断 ON/OFF 两套桌面测试各 56 项及发布工具测试通过；合并后上游 CI 的桌面与 Switch 构建通过。标签工作流还会核对版本、正式包诊断排除、NRO 结构、构建来源及附件校验和，全部通过后才公开发布。

贡献者记录了主机端连接 GitHub、下载并校验 v0.2.1 的测试。Switch 上完整的查询、下载、替换、重新启动，以及断网、SD 卡空间不足和 hbmenu 返回生命周期仍待真机验证；桌面测试与交叉构建不证明这些设备行为。

### 下载与更新

v0.2.1 及更早版本没有应用内更新，请从[本版 Release](https://github.com/kxn/nsteamlink/releases/tag/v0.3.0) 下载 `.nro` 完成本次升级。已添加 HOME 入口时，替换其固定目标 `sdmc:/switch/nsteamlink/nsteamlink.nro`。从 v0.3.0 起，从 SD 卡启动时可使用应用内更新；netloader 启动不检查更新。正式包关闭高级诊断，附带 `SHA256SUMS`、`build_identity.json` 和 SDK 包清单。

[完整变更：v0.2.1 → v0.3.0](https://github.com/kxn/nsteamlink/compare/v0.2.1...v0.3.0)

## [0.2.1] - 2026-10-11

上一正式版：**v0.2.0**。本版：**v0.2.1**。目标分支：`main`；对应源码：[`v0.2.1`](https://github.com/kxn/nsteamlink/tree/v0.2.1)。

### 主要变化

- 修复现代 Steam 的首次配对：支持配对码掩码的 X25519 密钥交换，按电脑保存协商密钥，重新启动应用后可复用配对。旧 v2/v3 配置迁移时保留原有身份与配对信息。首次配对码与连接安全 PIN 仍是两个独立概念。
- 改善局域网主机发现：发现请求同时发送到本地 IPv4 子网广播地址，修复已记录的 Switch 与 Linux Steam 主机之间仅全局广播无应答的问题。
- 修复 Switch 打开“手动添加电脑”时退出：将 deko 每帧 quad 上限从 4096 提高到 8192，并在诊断构建中记录超限原因。
- 同步 IHSlib 官方更新：解码器报告丢帧后清理待处理数据并等待关键帧；串流能力由应用提供实际平台与解码器信息，省略未经确认的 Switch 系统类型与设备形态。

### 按类型分组的提交

**修复**

- `4a7973d`：按主机保存配对协商密钥，并保留 UI 快照缺失的密钥（[PR #36](https://github.com/kxn/nsteamlink/pull/36)）。
- `63075fc`：提高 deko quad 上限，修复手动添加电脑页面退出（[PR #37](https://github.com/kxn/nsteamlink/pull/37)，[Issue #35](https://github.com/kxn/nsteamlink/issues/35)）。
- `1f55e51`：同步官方解码恢复，并由应用提供平台串流能力（[Issue #38](https://github.com/kxn/nsteamlink/issues/38)）。

**构建与依赖**

- `689ecd8`、`d09e63f`：更新 IHSlib，接入配对密钥交换和子网广播发现。
- `552c839`：统一 IHSlib fork 的维护分支并固定依赖提交。

**文档**

- `2c85f49`、`7861d68`：记录官方客户端密钥交换、Switch 配对与主机发现的源码和真机证据。

### 致谢

- 感谢 **Simone Caronni（[@scaronni](https://github.com/scaronni)）** 完成 PR #36 / #37 及相关 IHSlib 工作，修复配对密钥交换、按主机保存密钥、子网发现与手动添加电脑页面退出，并提供 Switch / Linux Steam 主机验证证据。
- 感谢 **[@akiriroll](https://github.com/akiriroll)** 在 Issue #35 中报告发现失败及手动添加电脑退出的问题，提供设备环境与复现信息。
- 感谢 **Mariotaku（[@mariotaku](https://github.com/mariotaku)）** 与 **[@skwizzy222](https://github.com/skwizzy222)** 提供本版吸收的上游解码丢帧恢复工作与原始思路（[IHSlib 提交 6721ecc](https://github.com/mariotaku/ihslib/commit/6721ecc1a31ed2a39af5a84a0df43158816b0dc6)）。
- 感谢 **Sven** 提供初代 Nintendo Switch，支持开发与实机测试；感谢 IHSlib、FFmpeg、SDL、libnx、devkitPro、deko3d 与 nx-hbloader 等开源项目的作者和维护者。

### 验证与证据范围

PR #36 记录了 Switch 发现 Linux Steam 主机、成功配对，以及应用重启后无需重新配对即可再次串流的真机结果。后续集成提交 `1f55e51` 通过诊断 ON/OFF 桌面测试（各 55 项）、Switch 正式/诊断构建及发布工具检查。标签工作流会再次运行桌面测试、Switch 构建、正式包诊断排除与附件结构/来源校验，全部通过后才公开发布。

新平台能力字段与解码恢复在不同 Steam 主机、真实网络丢帧和 NVDEC 错误中的效果仍待验证；上述构建和测试不代表这些场景或 hbmenu 返回生命周期已获真机证明。

### 下载与更新

从[本版 Release](https://github.com/kxn/nsteamlink/releases/tag/v0.2.1) 下载 `.nro` 附件。若已添加 HOME 入口，更新其固定目标 `sdmc:/switch/nsteamlink/nsteamlink.nro` 即可。正式 NRO 关闭高级诊断，包含本机 HOME 入口安装功能；独立 `.nsp` 仅在发布构建配置了打包密钥时提供。`SHA256SUMS`、`build_identity.json` 与 SDK 包清单用于核验附件和构建来源。

[完整变更：v0.2.0 → v0.2.1](https://github.com/kxn/nsteamlink/compare/v0.2.0...v0.2.1)
