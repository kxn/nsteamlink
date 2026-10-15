# NSteamLink v0.3.0

## 简体中文

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

---

## English

## [0.3.0] - 2026-10-15

Previous stable release: **v0.2.1**. This release: **v0.3.0**. Target branch: `main`; tagged source: [`v0.3.0`](https://github.com/kxn/nsteamlink/tree/v0.3.0).

### Highlights

- **In-app updates**: Switch checks for the latest stable release in the background at startup and offers installation on the home page, at most once per launch. “Update check” in X Options defaults to On; disabling it takes effect on the next launch. Failed checks are silently skipped.
- **Download verification**: only use certificate-verified HTTPS for this repository's stable releases. Check the download size and SHA-256 before replacing an NRO; if replacing a file fails, attempt to restore its old copy. Update the launched file and any existing HOME shortcut target, then ask the user to exit and relaunch.
- **Simpler releases**: remove the standalone NSP build and its key configuration, which never produced a published release asset. Releases contain the NRO; its “Add to HOME Menu” feature remains available without user-supplied packaging keys.

### Commits by type

- **Feature**: `0a93607`, startup checks, update settings, verified downloads, and update UI ([PR #41](https://github.com/kxn/nsteamlink/pull/41)).
- **Build and cleanup**: `6df4b21`, `8b45610`, remove standalone NSP packaging and code used only by that path ([PR #42](https://github.com/kxn/nsteamlink/pull/42)).
- **Documentation**: `4c0e8c0`, `68fd88d`, record NRO release and in-app update decisions and evidence limits.

### Thanks

Thank you to **Simone Caronni ([@scaronni](https://github.com/scaronni))** for PRs #41 / #42: implementing in-app updates, simplifying packaging, and adding automated tests and validation records. Thank you to **Sven** for providing an original-model Nintendo Switch for development and device testing, and to the authors and maintainers of IHSlib, FFmpeg, SDL, libnx, devkitPro, deko3d, and nx-hbloader.

### Validation and evidence scope

Reviewed both PRs' updater, UI, thread cleanup, and packaging changes. Desktop suites with diagnostics ON/OFF passed all 56 tests each, along with release tooling tests; upstream desktop and Switch CI passed after the merges. The tag workflow also verifies the version, release diagnostic exclusion, NRO structure, build provenance, and attachment checksums before publication.

The contributor recorded a host-side test that connected to GitHub, downloaded v0.2.1, and verified its checksum. The full check/download/replace/relaunch flow on Switch, network interruption, insufficient SD space, and the hbmenu return lifecycle still require device validation. Desktop tests and cross builds do not prove those device behaviors.

### Download and update

v0.2.1 and earlier have no in-app updater: download the `.nro` from [this release](https://github.com/kxn/nsteamlink/releases/tag/v0.3.0) for this upgrade. If a HOME shortcut is installed, replace its fixed target at `sdmc:/switch/nsteamlink/nsteamlink.nro`. Starting with v0.3.0, in-app updates are available when launched from the SD card; netloader launches skip update checks. Release builds exclude advanced diagnostics and include `SHA256SUMS`, `build_identity.json`, and the SDK package list.

[Full changelog: v0.2.1 → v0.3.0](https://github.com/kxn/nsteamlink/compare/v0.2.1...v0.3.0)
