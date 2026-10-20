# NSteamLink v0.5.1

## 简体中文

## [0.5.1] - 2026-10-20

上一正式版：**v0.5.0**。本版：**v0.5.1**。目标分支：`main`；对应源码：[`v0.5.1`](https://github.com/kxn/nsteamlink/tree/v0.5.1)。

### 主要变化

- **串流恢复与退出**：改进视频丢失反馈、关键帧恢复、解码队列和帧所有权处理；停止串流时保留应处理的最后一批数据，正常关闭不再误报为提交失败。
- **发现与重试**：发现广播全部发送失败时执行有界 socket 重建；修正接收批次、发现发送和开流重试的先后顺序，保留当前主机身份和请求。发现完整轮与快速重试沿用已核验的官方期限和序号规则。
- **授权续接与凭据**：改进同一开流请求的自动授权续接、确认前的凭据保存，以及按所选 Steam 身份保存密钥；连接安全码与配对授权码仍分别处理。
- **正式包精简**：明确关闭应用与 SDK 诊断。正式 NRO 排除调试 UDP 入口、nxlink/文件日志、HID 历史采样、高级诊断浮屏、故障注入和测试探针。发布流程校验实际对象、ELF/NRO 对应关系和附件允许列表；标签流程保留诊断排除测试，但不上传诊断包。

### 按类型分组的提交

- **恢复与生命周期修复**：`3be848b`，UDP 接收边界；`07ed493`，正常停止时取消提交；`a94d163`、`c5a7cfb`，解码停止批次与最后一帧组装。
- **发现修复**：`8fad3ca`、`9f193c8`，接收恢复和启动失败清理；`6c7a02d`、`e1274b5`，广播重建及发现轮次；`fe5bc32`、`e46cf75`、`9de506c`，操作、回调和联合重试顺序（[PR #87](https://github.com/kxn/nsteamlink/pull/87)）。
- **授权与发布检查**：`a3000a4`、`eeeb684`、`b51680d`、`03bf16e`，授权和凭据生命周期；`55fcf98`，SDK 诊断排除与产物门禁。
- **验证与参考**：补充官方原指令对照、音频断序/停止、跨组和跨通道 FEC、容量边界及独立 Switch 探针。研究和测试素材不进入正式 NRO。

### 验证与证据范围

已验证的 `9de506c` / IHSlib `bfb7100` 通过桌面普通构建 239 项、诊断构建 245 项、相关 ASan/UBSan/leak 9 项，以及两轮完整 CI。Switch 正式构建的 45 个产品翻译单元、SDK 对象和最终 NRO 已检查诊断排除，15 类污染及 9 类探针产物/调用错误均被门禁拒绝。标签工作流会对正式发版提交重新构建并运行这些检查。

真实 Steam→Switch 会话已验证单个丢失分片的 FEC 重建，以及超过修复能力的整组丢失恢复：客户端实际发送恢复请求，随后接受并提交关键帧，继续播放 30 秒。本次受控局域网测试从丢失到关键帧提交约 40 毫秒，提交错误为 0（[实机记录](https://github.com/kxn/nsteamlink/issues/69#issuecomment-6281073775)）。这不是所有网络环境的延迟保证，也不代表原有偶发卡顿或 Steam 大屏闪烁的根因已经确定。网络切换、会话完全断开和公网连接保留为独立课题。

### 下载与更新

从[本版 Release](https://github.com/kxn/nsteamlink/releases/tag/v0.5.1) 下载正式 `.nro`，或使用应用内更新。已有 HOME 入口继续使用 `sdmc:/switch/nsteamlink/nsteamlink.nro`。附件仅包含正式 NRO、源码身份、诊断排除报告、SDK 包清单、许可证及 `SHA256SUMS`。

感谢提供试玩与实机测试反馈的用户、提供初代 Switch 的 **Sven**，以及 **Simone Caronni（[@scaronni](https://github.com/scaronni)）**、IHSlib、FFmpeg、Opus、SDL、libnx、devkitPro、deko3d 和 nx-hbloader 的作者与维护者。

[完整变更：v0.5.0 → v0.5.1](https://github.com/kxn/nsteamlink/compare/v0.5.0...v0.5.1)

---

## English

## [0.5.1] - 2026-10-20

Previous stable release: **v0.5.0**. This release: **v0.5.1**. Target branch: `main`; tagged source: [`v0.5.1`](https://github.com/kxn/nsteamlink/tree/v0.5.1).

### Highlights

- **Streaming recovery and shutdown**: improve video-loss feedback, keyframe recovery, decoder queues, and frame ownership. Preserve the final eligible receive batch during shutdown and treat normal close-time cancellation separately from submission failures.
- **Discovery and retries**: use bounded socket recreation when every discovery broadcast destination fails. Correct the order of receive batches, discovery sends, and launch retries while preserving host identity and the current request. Full discovery rounds and fast retries follow the verified official deadlines and sequence rules.
- **Authorization and credentials**: improve automatic authorization within the original launch request, credential-save attempts before confirmation, and key storage under the selected Steam identity. Pairing authorization codes and connection security codes remain separate.
- **Ordinary release build**: explicitly disable application and SDK diagnostics. The published NRO excludes the debug UDP endpoint, nxlink/file logging, HID history capture, advanced diagnostic overlays, fault injection, and test probes. Publication gates inspect actual objects, ELF/NRO consistency, and the attachment allowlist. Tag workflows retain diagnostic exclusion tests without uploading diagnostic packages.

### Commits by type

- **Recovery and lifecycle fixes**: `3be848b`, UDP receive boundaries; `07ed493`, close-time submission cancellation; `a94d163` and `c5a7cfb`, decoder stop batches and final frame assembly.
- **Discovery fixes**: `8fad3ca` and `9f193c8`, receive recovery and failed-startup cleanup; `6c7a02d` and `e1274b5`, broadcast recreation and discovery rounds; `fe5bc32`, `e46cf75`, and `9de506c`, operation, callback, and joint retry ordering ([PR #87](https://github.com/kxn/nsteamlink/pull/87)).
- **Authorization and release checks**: `a3000a4`, `eeeb684`, `b51680d`, and `03bf16e`, authorization and credential lifetimes; `55fcf98`, SDK diagnostic exclusion and artifact gates.
- **Validation and references**: original-instruction comparisons, audio gap/stop cases, cross-group and cross-channel FEC, capacity boundaries, and isolated Switch probes. Research and test fixtures are excluded from the ordinary NRO.

### Validation and evidence scope

The verified `9de506c` / IHSlib `bfb7100` passed 239 ordinary desktop tests, 245 diagnostic tests, nine related ASan/UBSan/leak checks, and two full CI runs. Switch checks covered diagnostic exclusion in 45 product translation units, SDK objects, and the final NRO, with 15 contamination cases and nine probe artifact/call-path faults rejected. The tag workflow rebuilds the final release commit and repeats these checks.

Real Steam→Switch sessions verified FEC reconstruction after one missing data shard and recovery after an entire group was erased beyond its repair capacity: an actual recovery request was sent, a later keyframe was received and submitted, and playback continued for 30 seconds. Loss-to-keyframe-submission was about 40 milliseconds in this controlled LAN run, with zero submission errors ([device evidence](https://github.com/kxn/nsteamlink/issues/69#issuecomment-6281073775)). This is not a latency guarantee for other networks or proof of the original intermittent-stall/Steam Big Picture flicker cause. Network switching, complete session disconnection, and Internet connectivity remain separate work.

### Download and update

Download the ordinary `.nro` from [this release](https://github.com/kxn/nsteamlink/releases/tag/v0.5.1), or use the in-app updater. Existing HOME shortcuts continue to target `sdmc:/switch/nsteamlink/nsteamlink.nro`. Attachments contain only the ordinary NRO, source identity, diagnostic exclusion report, SDK package list, license text, and `SHA256SUMS`.

Thanks to users providing playtesting and device-test feedback, **Sven** for the original-model Switch, **Simone Caronni ([@scaronni](https://github.com/scaronni))**, and the authors and maintainers of IHSlib, FFmpeg, Opus, SDL, libnx, devkitPro, deko3d, and nx-hbloader.

[Full changelog: v0.5.0 → v0.5.1](https://github.com/kxn/nsteamlink/compare/v0.5.0...v0.5.1)
