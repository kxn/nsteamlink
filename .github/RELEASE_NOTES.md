# NSteamLink v0.5.0

## 简体中文

## [0.5.0] - 2026-10-19

上一正式版：**v0.4.0**。本版：**v0.5.0**。目标分支：`main`；对应源码：[`v0.5.0`](https://github.com/kxn/nsteamlink/tree/v0.5.0)。

### 主要变化

- **1080p 串流**：新增自动、720p、1080p 三种分辨率选择。自动在连接时按掌机选择 720p、底座选择 1080p；掌机也可手动选择 1080p，解码后缩放至内屏。底座呈现保留原生 1080p 细节。
- **设置分类**：首页 X 直接打开设置，分为画面与声音、网络、主机管理、应用。画面偏好、分辨率、带宽和语言入口显示当前值；声音、网络纠错和自动检查更新统一使用图形开关。只有进入子页的项目显示箭头。
- **精简串流菜单**：标题改为“串流”，只保留继续游玩、结束游戏并断开、断开连接。串流期间不再提供设置入口；确认框明确区分关闭主机游戏与保留游戏运行。
- **界面整理**：统一“主机”称呼，移除菜单内重复的生效时机说明，调整中英文排版、返回焦点及禁用项的手柄和触摸交互。

### 按类型分组的提交

- **功能**：`3560194`，可选分辨率、自动底座协商和原生 1080p 呈现（[PR #60](https://github.com/kxn/nsteamlink/pull/60)，[Issue #12](https://github.com/kxn/nsteamlink/issues/12)）；`719deef`，设置分类与串流菜单重组。
- **修复**：`be19b8a`，分辨率入口和侧栏布局；`1e74f71`，真机探针的 nxlink 参数顺序。
- **开发测试**：`1e4e13c`，独立的强制 1080p 测试构建；正式发布包使用自动分辨率默认值。

### 验证与证据范围

本地 173 项回归最终通过，Switch 正式构建及诊断排除检查通过，中英文菜单经过实际渲染检查。Switch 的 12 组硬件解码与原生 1080p 像素检查通过，测试资源清理无堆增长；维护者对掌机强制 1080p 串流进行了试玩并反馈正常。

目前没有底座，HDMI 输出与真实底座插拔尚未实测；上述结果也不代表持续 1080p60 性能或完整延迟基准已验证。标签工作流会重新执行桌面诊断 ON/OFF 测试、Switch 正式及诊断构建，并校验版本、NRO 结构、源码身份和附件校验和后发布。

### 下载与更新

从[本版 Release](https://github.com/kxn/nsteamlink/releases/tag/v0.5.0) 下载正式 `.nro`，或通过现有应用内更新升级。已添加 HOME 入口时，固定目标为 `sdmc:/switch/nsteamlink/nsteamlink.nro`。分辨率位于 **设置 → 画面与声音 → 分辨率**，自动检查更新位于 **设置 → 应用**。netloader 启动不检查更新。

附件包含正式 NRO、`SHA256SUMS`、`build_identity.json`、SDK 包清单及许可证；不发布强制 1080p 测试包或独立 NSP。

感谢用户提出 1080p 需求和菜单反馈、Sven 提供初代 Switch，以及 IHSlib、FFmpeg、Opus、SDL、libnx、devkitPro、deko3d 与 nx-hbloader 的作者和维护者。

[完整变更：v0.4.0 → v0.5.0](https://github.com/kxn/nsteamlink/compare/v0.4.0...v0.5.0)

---

## English

## [0.5.0] - 2026-10-19

Previous stable release: **v0.4.0**. This release: **v0.5.0**. Target branch: `main`; tagged source: [`v0.5.0`](https://github.com/kxn/nsteamlink/tree/v0.5.0).

### Highlights

- **1080p streaming**: choose Auto, 720p, or 1080p. Auto requests 720p in handheld mode and 1080p when docked at connection time. Handheld mode also supports manually selected 1080p, decoded at full resolution and scaled to the internal screen. Docked presentation preserves native 1080p detail.
- **Settings categories**: X on the home screen opens Settings directly, with Video & audio, Network, Host management, and Application. Quality, resolution, bitrate, and language entries show the saved value. Sound, error correction, and update checks use consistent graphical switches. Only entries that navigate to another page show arrows.
- **Simpler streaming menu**: Streaming offers only Resume game, End game and disconnect, and Disconnect. Settings are available from the home screen. Confirmations distinguish closing the host game from disconnecting while leaving it running.
- **Interface cleanup**: consolidate host terminology, remove repeated timing explanations, and revise Chinese/English layouts, return focus, and controller/touch behavior for disabled actions.

### Commits by type

- **Features**: `3560194`, selectable resolution, automatic docked negotiation, and native 1080p presentation ([PR #60](https://github.com/kxn/nsteamlink/pull/60), [Issue #12](https://github.com/kxn/nsteamlink/issues/12)); `719deef`, settings categories and streaming menu reorganization.
- **Fixes**: `be19b8a`, resolution navigation and drawer layout; `1e74f71`, nxlink argument ordering for device probes.
- **Development tests**: `1e4e13c`, an isolated forced-1080p test build. The published application defaults to automatic resolution.

### Validation and evidence scope

All 173 local regression tests ultimately passed, along with the ordinary Switch build and release diagnostic exclusion check. Chinese and English menus were inspected using actual rendering. All 12 Switch hardware-decode/native-1080p pixel cases passed, with clean test resources and no heap growth; the maintainer reported successful handheld playtesting of forced-1080p streaming.

A physical dock was unavailable, so HDMI output and physical dock hotplug remain untested. These results do not establish sustained 1080p60 performance or a complete latency baseline. The tag workflow repeats desktop diagnostics ON/OFF tests, ordinary and diagnostic Switch builds, and checks the version, NRO structure, source identity, and attachment checksums before publishing.

### Download and update

Download the ordinary `.nro` from [this release](https://github.com/kxn/nsteamlink/releases/tag/v0.5.0), or use the existing in-app updater. An installed HOME shortcut targets `sdmc:/switch/nsteamlink/nsteamlink.nro`. Resolution is under **Settings → Video & audio → Resolution**; automatic update checks are under **Settings → Application**. Netloader launches skip update checks.

Attachments contain the ordinary NRO, `SHA256SUMS`, `build_identity.json`, the SDK package list, and license text. Forced-1080p test packages and standalone NSPs are not published.

Thanks to users for the 1080p request and menu feedback, Sven for the original-model Switch, and the authors and maintainers of IHSlib, FFmpeg, Opus, SDL, libnx, devkitPro, deko3d, and nx-hbloader.

[Full changelog: v0.4.0 → v0.5.0](https://github.com/kxn/nsteamlink/compare/v0.4.0...v0.5.0)
