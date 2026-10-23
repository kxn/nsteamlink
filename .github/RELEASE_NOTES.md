# NSteamLink v0.7.1

## 简体中文

## [0.7.1] - 2026-10-23

上一正式版：**v0.7.0**。目标分支：`main`；源码：[`v0.7.1`](https://github.com/kxn/nsteamlink/tree/v0.7.1)。

### 主要变化

- 串流中可短按截图键发送 **Steam Guide**。默认开启；在 **设置 → 应用 → Steam Guide 键** 中选择“截图键”或“关闭”。关闭后保留系统截图功能，首页和非串流状态也保留截图。
- 设置保存兼容旧版开关；输入尚未就绪、失焦或会话结束时不会发送 Guide。按下和释放沿用现有手柄输入通路，普通按键与陀螺仪输入保持原有映射。
- 正式包排除 Capture 自测、HOME 能力探针、虚拟手柄注入与相关诊断入口。HOME 键继续由 Switch 系统处理。

### 验证与已知限制

自动回归覆盖设置保存、输入就绪门控、Guide 按下／释放和清理。Switch 离线实测确认 Capture 通知接管、两次虚拟 Capture 通知与资源清理；这不等于实体按键或 Steam 浮层的端到端验证。用户曾观察到实体截图键首次按下仍截图、之后生效，原因尚未确认，本版不声称已修复该首次按键现象。

### 提交分组

- 输入与设置：`5c0d283` 截图键映射和关闭设置；`27a4b3b` 移至“应用 → Steam Guide 键”，补充有界诊断。
- 测试与文档：`11f00d6` 系统按键及 Guide 协议依据；`23cf2c3` 避免清除共享 HOME 事件；`a29a7ac` 记录真机证据与未验证范围。
- 发布：更新版本、双语说明与按键诊断排除检查。画质自适应研究保留在研究分支。

从 [Release](https://github.com/kxn/nsteamlink/releases/tag/v0.7.1) 下载正式 NRO，或使用应用内更新。现有配对资料保留。

[完整变更：v0.7.0 → v0.7.1](https://github.com/kxn/nsteamlink/compare/v0.7.0...v0.7.1)

---

## English

## [0.7.1] - 2026-10-23

Previous stable release: **v0.7.0**. Target: `main`; source: [`v0.7.1`](https://github.com/kxn/nsteamlink/tree/v0.7.1).

### Highlights

- Short-press Capture during streaming to send **Steam Guide**. Enabled by default; choose Capture or Off under **Settings → Application → Steam Guide key**. Off preserves system screenshots; screenshots also remain available outside streaming.
- Preserve the previous toggle when loading settings. Gate Guide on input readiness, focus and session lifetime, and send its press/release through the existing controller path without changing ordinary button or gyro mappings.
- Exclude Capture self-tests, HOME capability probes, virtual-controller injection and their diagnostic entry points from the ordinary package. HOME remains a Switch system button.

### Validation and known limits

Regression coverage includes settings persistence, input-readiness gates, Guide press/release and cleanup. Offline Switch tests verified Capture notification ownership, two virtual Capture notifications and resource cleanup; these do not establish physical-button or host-overlay behavior. A user previously observed a physical first press taking a screenshot before subsequent presses worked. Its cause remains unconfirmed; this release does not claim to fix that first-press behavior.

### Commits by type

- Input/settings: `5c0d283` Capture mapping and opt-out; `27a4b3b` Application settings placement and bounded diagnostics.
- Tests/documentation: `11f00d6` system-button and Guide protocol references; `23cf2c3` observe HOME without clearing the shared event; `a29a7ac` record hardware evidence and validation limits.
- Release: version, bilingual notes and button-diagnostic exclusion checks. Adaptive-quality research remains on the research branch.

Download the ordinary NRO from [this release](https://github.com/kxn/nsteamlink/releases/tag/v0.7.1), or use the in-app updater. Existing pairing data is retained.

[Full changelog: v0.7.0 → v0.7.1](https://github.com/kxn/nsteamlink/compare/v0.7.0...v0.7.1)
