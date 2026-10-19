# NSteamLink v0.4.0

## 简体中文

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

---

## English

## [0.4.0] - 2026-10-19

Previous stable release: **v0.3.0**. This release: **v0.4.0**. Target branch: `main`; tagged source: [`v0.4.0`](https://github.com/kxn/nsteamlink/tree/v0.4.0). Runtime code is unchanged from the tested `d05abab` candidate, with IHSlib pinned to `afed70e`; the release commit only updates the version and bilingual notes.

### Highlights

- **Media recovery and transport**: adjust video loss feedback, keyframe recovery, decoder resets, frame presentation timing, and reliable transport acknowledgements, retransmission, and receive windows against verified official-client paths. Integrate FEC reception and the saved FEC setting.
- **Audio playback**: adjust Opus loss recovery, jitter buffering, raw audio playback, and player startup/shutdown, with revised ownership of media data and playback devices.
- **Connection tests and settings**: integrate first-time and manual network tests, saved results, recommended presets, and complete client configuration persistence. Distinguish transport, authentication, and media connection waits; remove automatic disconnects based on a fixed video-stall timeout.
- **Switch capabilities**: report the actual backend's 720p60 / H.264 support and omit unverified maximum decode bitrates. Album applet mode can install the HOME shortcut through a confirmation screen with activity and elapsed-time feedback; streaming still requires full application mode.
- **Protocol references**: add Steam Link Anywhere / SDR client policies, protocol schemas, and reproducible offline audits. This research does not itself provide a complete, usable Internet streaming backend.

### Commits by type

- **Features**: `1a49cca`, HOME shortcut installation in applet mode ([Issue #44](https://github.com/kxn/nsteamlink/issues/44)); `c4de796`, `2512fb1`, `d6fab25`, FEC reception, connection lifecycle, and complete configuration persistence.
- **Fixes and integration**: `7c3b220`, `a3fe641`, `d095563`, keyframes, content modes, and encrypted fragments; `1e8e542`, `87e6c4f`, audio recovery and buffering; `59eebda`, `697f9b9`, `40dd5b3`, network tests, connection waits, and retired sessions. See [PR #53](https://github.com/kxn/nsteamlink/pull/53) for the full integration.
- **Research and documentation**: [PR #50](https://github.com/kxn/nsteamlink/pull/50), Anywhere / SDR policies and schemas; [PR #53](https://github.com/kxn/nsteamlink/pull/53), official media, transport, settings, and network-test comparisons.

### Validation and evidence scope

The maintainer tested the `d05abab` main-branch candidate on a real Switch and reported that it worked well. Main-branch CI passed 170 desktop tests each with diagnostics ON/OFF, plus ordinary and diagnostic Switch builds. The tag workflow repeats these checks and verifies the version, release diagnostic exclusion, NRO structure, build provenance, and attachment checksums before publishing.

Offline original-instruction replays and controlled-peer tests prove only the corresponding inputs and boundaries. FEC activation with real Steam, long-term behavior across networks and hosts, hardware errors, and the hbmenu return lifecycle need further validation. This does not establish that the previously reported intermittent stalls or Steam Big Picture flickering are fully resolved. Unmerged changes on the continuing reverse-engineering branch are excluded; remaining protocol differences are tracked in [Issue #52](https://github.com/kxn/nsteamlink/issues/52).

### Thanks

Thank you to users who provided playtest feedback and issue reports, **Sven** for the original-model Nintendo Switch, **Simone Caronni ([@scaronni](https://github.com/scaronni))**, and the authors and maintainers of IHSlib, FFmpeg, Opus, SDL, libnx, devkitPro, deko3d, and nx-hbloader.

### Download and update

Download the `.nro` from [this release](https://github.com/kxn/nsteamlink/releases/tag/v0.4.0). Starting with v0.3.0, SD-card launches support in-app updates; netloader launches skip update checks. An installed HOME shortcut targets `sdmc:/switch/nsteamlink/nsteamlink.nro`. Release builds exclude advanced diagnostics and include `SHA256SUMS`, `build_identity.json`, and the SDK package list. Only the NRO is published, with no standalone NSP or test tools.

[Full changelog: v0.3.0 → v0.4.0](https://github.com/kxn/nsteamlink/compare/v0.3.0...v0.4.0)
