# NSteamLink v0.2.1

## 简体中文

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

---

## English

## [0.2.1] - 2026-10-11

Previous stable release: **v0.2.0**. This release: **v0.2.1**. Target branch: `main`; tagged source: [`v0.2.1`](https://github.com/kxn/nsteamlink/tree/v0.2.1).

### Highlights

- Fix pairing with modern Steam: support the PIN-masked X25519 key exchange and persist the negotiated key for each computer, so pairing can be reused after restarting the app. Migration from v2/v3 profiles retains existing identity and pairing data. The initial pairing code and the connection security PIN remain separate concepts.
- Improve LAN discovery: also send discovery requests to local IPv4 subnet broadcast addresses, addressing the recorded Switch/Linux Steam host case where global broadcast alone received no response.
- Fix the app exiting when opening “Add PC manually” on Switch: raise the deko per-frame quad limit from 4096 to 8192 and report limit exhaustion in diagnostic builds.
- Integrate upstream IHSlib updates: flush pending data and wait for a keyframe after decoder-reported frame loss; report actual platform and decoder capabilities supplied by the app, omitting unverified Switch OS type and form factor.

### Commits by type

**Fixes**

- `4a7973d`: persist each host's negotiated pairing key and retain keys missing from UI snapshots ([PR #36](https://github.com/kxn/nsteamlink/pull/36)).
- `63075fc`: increase deko quad capacity to prevent the manual PC page from exiting ([PR #37](https://github.com/kxn/nsteamlink/pull/37), [Issue #35](https://github.com/kxn/nsteamlink/issues/35)).
- `1f55e51`: integrate upstream decoder recovery and supply platform streaming capabilities from the app ([Issue #38](https://github.com/kxn/nsteamlink/issues/38)).

**Build and dependencies**

- `689ecd8`, `d09e63f`: update IHSlib for pairing key exchange and subnet broadcast discovery.
- `552c839`: consolidate IHSlib fork maintenance on one branch and pin the dependency commit.

**Documentation**

- `2c85f49`, `7861d68`: document official-client key exchange and source/device evidence for Switch pairing and host discovery.

### Thanks

- Thank you to **Simone Caronni ([@scaronni](https://github.com/scaronni))** for PRs #36 / #37 and the related IHSlib work: pairing key exchange, per-host key persistence, subnet discovery, and the manual PC page fix, with Switch/Linux Steam host validation evidence.
- Thank you to **[@akiriroll](https://github.com/akiriroll)** for reporting discovery failure and the manual PC page exit in Issue #35, including the device environment and reproduction details.
- Thank you to **Mariotaku ([@mariotaku](https://github.com/mariotaku))** and **[@skwizzy222](https://github.com/skwizzy222)** for the upstream decoder-loss recovery work and original idea integrated in this release ([IHSlib commit 6721ecc](https://github.com/mariotaku/ihslib/commit/6721ecc1a31ed2a39af5a84a0df43158816b0dc6)).
- Thank you to **Sven** for providing an original-model Nintendo Switch for development and device testing, and to the authors and maintainers of IHSlib, FFmpeg, SDL, libnx, devkitPro, deko3d, and nx-hbloader.

### Validation and evidence scope

PR #36 records device results for discovering a Linux Steam host from Switch, pairing successfully, and streaming again after restarting the app without re-pairing. Integration commit `1f55e51` passed desktop tests with diagnostics ON/OFF (55 each), Switch release/diagnostic builds, and release tooling checks. The tag workflow repeats desktop tests, Switch builds, release diagnostic-exclusion checks, and artifact structure/provenance validation before publication.

The effects of the new capability fields and decoder recovery across different Steam hosts, real network loss, and NVDEC errors still require device validation. These builds and tests do not establish device proof for those cases or the hbmenu return lifecycle.

### Download and update

Download the `.nro` attachment from [this release](https://github.com/kxn/nsteamlink/releases/tag/v0.2.1). If you already installed a HOME shortcut, update its fixed target at `sdmc:/switch/nsteamlink/nsteamlink.nro`. The release NRO excludes advanced diagnostics and includes on-device HOME shortcut installation; a standalone `.nsp` is provided only when packaging keys are configured for the release build. Use `SHA256SUMS`, `build_identity.json`, and the SDK package list to verify artifacts and build provenance.

[Full changelog: v0.2.0 → v0.2.1](https://github.com/kxn/nsteamlink/compare/v0.2.0...v0.2.1)
