# NSteamLink v0.7.0

## 简体中文

## [0.7.0] - 2026-10-23

上一正式版：**v0.6.0**。目标分支：`main`；源码：[`v0.7.0`](https://github.com/kxn/nsteamlink/tree/v0.7.0)。

### 主要变化

- 支持免登录云端配对、云端发现与公网串流，自动尝试直连和 Valve SDR 中继。主机列表右侧增加“增加”入口，提供手动地址和配对码两种添加方式；主机状态区分局域网、互联网、离线与待配对。
- 改进受限网络下的 DNS 与 TLS 建连：并发查询多家公共 DNS，按网段分散尝试候选地址，首答即可开始连接；目录和 CM TLS 最多并行三个候选，保持证书校验。该兼容策略用于缓解部分出口能 ping 通但 HTTPS 不通的情况，不保证所有网络均可达。
- 将独立信令准备与媒体连接期限分开，明确准备、IHS 与 SDK 启动顺序；修复本地发现被云端查询拖慢、回包转发、Switch 辅助 UDP 缓冲及结束游戏确认问题。准备阶段可等待至多 90 秒；开始媒体连接后仍使用各自连接期限。
- 统一 HTTP/DNS 资源所有权、取消与线程回收，修复 Switch 已存在配置缓存的替换和恢复。保留 v0.6.0 的陀螺仪支持。
- 正式包排除调试日志 HTTP/UDP 服务、nxlink/持久日志、故障注入和独立探针；发布门禁检查实际编译对象和最终 ELF/NRO。

### 验证与范围

用户在热点上确认发现、串流、手柄和正常时间内结束均可用。`d6dcce4` 保存日志确认实际使用 **Valve SDR 中继**：信令准备约 2.9 秒后才创建 IHS，手柄报告获得 ACK，“结束游戏并断开”约 2.9 秒完成。该记录验证这次热点的 SDR 路径，不代表所有 NAT 类型、出口或延迟表现；日志仍有重传和画面恢复，网络质量仍会影响体验。最终标签工作流重新运行桌面诊断 ON/OFF 回归、Switch 构建及诊断排除反例检查。

### 提交分组

- 公网功能与 UI：见 [PR #54](https://github.com/kxn/nsteamlink/pull/54) 的配对、发现、SNS/SDR、状态呈现及集成提交。
- 连接与恢复：`d294b91` 回包转发；`6e427e9`、`7a30734` 多 DNS 和并发约束；`5d28638`、`16cd183`、`4eb9804` 发现及辅助 socket；`ebe0cde` 初始化重构；`d6dcce4` 保留 HTTPS 失败时的局域网启动。
- 主线整合：`8bddbd0` 保留陀螺仪与公网两套功能。

从 [Release](https://github.com/kxn/nsteamlink/releases/tag/v0.7.0) 下载正式 NRO，或使用应用内更新。配对资料保留。附件不包含诊断包。

[完整变更：v0.6.0 → v0.7.0](https://github.com/kxn/nsteamlink/compare/v0.6.0...v0.7.0)

---

## English

## [0.7.0] - 2026-10-23

Previous stable release: **v0.6.0**. Target: `main`; source: [`v0.7.0`](https://github.com/kxn/nsteamlink/tree/v0.7.0).

### Highlights

- Add account-free cloud pairing, host discovery and Internet streaming, with automatic direct/Valve SDR routing. The Add host page offers manual address and pairing-code flows; host status distinguishes LAN, Internet, offline and unpaired devices.
- Query multiple public DNS providers and rotate HTTPS candidates across subnets. Start on the first answer and allow at most three concurrent directory/CM TLS candidates while retaining certificate verification. This compatibility policy addresses observed reachable-IP/unreachable-HTTPS paths; it cannot guarantee reachability on every network.
- Separate signaling preparation from the media connection deadline, explicitly hand off IHS/SDK ownership, and fix discovery responsiveness, reply forwarding, auxiliary Switch UDP buffers and end-game completion. Preparation has a bounded 90-second budget; media retains its own connection deadlines.
- Share in-flight DNS work with independent cancellation, manage HTTP lifetime and joined workers, and recover Switch cache replacement. Retain v0.6.0 gyro support.
- Exclude diagnostic HTTP/UDP endpoints, nxlink/persistent logging, fault injection and probes from ordinary packages, with object and ELF/NRO publication gates.

### Validation and limits

The user confirmed hotspot discovery, streaming, controller input and timely shutdown. Saved `d6dcce4` logs identify **Valve SDR relay** routing, about 2.9 seconds of signaling preparation before IHS admission, acknowledged controller reports and about 2.9 seconds to complete end-game/disconnect. This validates that hotspot SDR session, not every NAT type or network. Retransmission and video recovery remain visible; experience still depends on network quality. Tag CI reruns diagnostic ON/OFF desktop tests, Switch builds and diagnostic-exclusion counterexamples.

### Commits by type

- Internet functionality and UI: pairing, discovery, SNS/SDR, status and integration commits in [PR #54](https://github.com/kxn/nsteamlink/pull/54).
- Connection/recovery: `d294b91` reply forwarding; `6e427e9`/`7a30734` DNS fanout; `5d28638`/`16cd183`/`4eb9804` discovery and auxiliary sockets; `ebe0cde` initialization ownership; `d6dcce4` LAN startup when HTTPS initialization fails.
- Mainline integration: `8bddbd0` retains both gyro and Internet support.

Download the ordinary NRO from [this release](https://github.com/kxn/nsteamlink/releases/tag/v0.7.0), or use the in-app updater. Pairing data is retained. Diagnostic packages are not published.

[Full changelog: v0.6.0 → v0.7.0](https://github.com/kxn/nsteamlink/compare/v0.6.0...v0.7.0)
