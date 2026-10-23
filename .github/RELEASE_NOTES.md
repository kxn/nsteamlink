# NSteamLink v0.6.0

## 简体中文

## [0.6.0] - 2026-10-23

上一正式版：**v0.5.1**。本版：**v0.6.0**。目标分支：`main`；对应源码：[`v0.6.0`](https://github.com/kxn/nsteamlink/tree/v0.6.0)。

### 主要变化

- **Switch 陀螺仪输入**：将 libnx 六轴采样传给 Steam Input。在 Steam 的手柄桌面布局中将陀螺仪配置为鼠标，即可通过转动 Switch 控制指针；此用法已由用户实机确认。
- **补齐 Host 传感器协议**：声明 motion capability，按 Generic RAW V3 发送普通传感器的新样本标志及时间戳。相同角速度在不同采样时刻仍会上报；仅按键、摇杆或加速度变化时不会重放已提交的 gyro，尚未发送的样本则保留。
- **减少试错**：加入固定 Steam Host DLL 的原始机器码离线审计，以及使用生产打包器的 full/delta 对照；删除混淆普通/左传感器的实验开关，修正逆向文档中的错误推论。

### 按类型分组的提交

- **功能**：`d13ff0c`，Switch 六轴采样、单位转换及 HID 注入。
- **修复**：`b6421a2`，完整 RAW V3 传感器契约、事件合并、能力声明和 Host 验证；IHSlib 固定至 `0bc7087`。
- **测试**：`0dd07e5`，独立六轴探针与方向查看工具；`b6421a2`，生产 C 报告与 Host 原始指令交叉验证。测试工具不进入正式 NRO。
- **文档**：记录用户实机桌面鼠标输出，更新中英文使用说明，明确撤回“remote Generic 拒绝 0x400”的早期结论。

### 验证与证据范围

相关桌面回归 8 项通过，Switch 修复构建成功；原始 DLL 离线审计覆盖 full/delta、CRC 错误拒绝、普通传感器 slot、开关/能力门控，以及分段的四元数积分和 gyro source 取值。

用户已确认：修改 Steam 手柄桌面布局后，陀螺仪可以操控鼠标。**游戏内效果和兼容性尚未验证**，需要按各游戏的 Steam Input 布局配置；此次结果也不代表所有手柄形态或校准精度均已验证。旧实验按键失效的根因仍未确定。

标签工作流对正式提交重新执行桌面诊断 ON/OFF 测试、Switch 正式和诊断构建、诊断排除反例及产物身份检查；所有检查通过后才公开正式包。

### 下载与更新

从[本版 Release](https://github.com/kxn/nsteamlink/releases/tag/v0.6.0) 下载正式 `.nro`，或使用应用内更新。已有 HOME 入口继续使用 `sdmc:/switch/nsteamlink/nsteamlink.nro`，无需重复添加。
附件包含正式 NRO、源码身份、诊断排除报告、SDK 包清单、许可证及 `SHA256SUMS`；不发布诊断/六轴探针包。

感谢提供试玩与陀螺仪实机反馈的用户、提供初代 Switch 的 **Sven**，以及 **Simone Caronni（[@scaronni](https://github.com/scaronni)）**、IHSlib、FFmpeg、Opus、SDL、libnx、devkitPro、deko3d 和 nx-hbloader 的作者与维护者。

[完整变更：v0.5.1 → v0.6.0](https://github.com/kxn/nsteamlink/compare/v0.5.1...v0.6.0)

---

## English

## [0.6.0] - 2026-10-23

Previous stable release: **v0.5.1**. This release: **v0.6.0**. Target branch: `main`; tagged source: [`v0.6.0`](https://github.com/kxn/nsteamlink/tree/v0.6.0).

### Highlights

- **Switch gyro input**: forward libnx motion samples to Steam Input. Configure gyro as a mouse in Steam's desktop controller layout to move the pointer by rotating the Switch. A user has verified this on hardware.
- **Complete the host sensor protocol**: advertise motion capability and include normal-sensor freshness and timestamps in Generic RAW V3 reports. Identical angular velocities at different sample times are still reported. Button, stick, or acceleration-only changes do not replay an already submitted gyro sample, while pending samples are preserved.
- **Reduce device trial and error**: add offline execution of a pinned Steam Host DLL and full/delta fixtures from the production C packer. Remove experimental switches that confused normal and left sensor slots, and correct the earlier reverse-engineering conclusions.

### Commits by type

- **Feature**: `d13ff0c`, Switch motion sampling, unit conversion, and HID injection.
- **Fix**: `b6421a2`, the complete RAW V3 sensor contract, event merging, capability declaration, and host verification; IHSlib pinned to `0bc7087`.
- **Tests**: `0dd07e5`, isolated motion probes and an axis viewer; `b6421a2`, production C reports checked against original host instructions. Test tools are excluded from the ordinary NRO.
- **Documentation**: record the user's desktop mouse result, update Chinese and English usage instructions, and explicitly retract the earlier claim that remote Generic rejects 0x400.

### Validation and evidence scope

Eight related desktop regression tests passed, and the fixed Switch build succeeded. Offline original-DLL checks cover full/delta decoding, invalid CRC rejection, normal sensor slot selection, enable/capability gates, and isolated quaternion integration and gyro-source consumption.

The user confirmed that gyro controls the mouse after changing Steam's desktop controller layout. **In-game behavior and compatibility have not yet been verified** and depend on each game's Steam Input layout. This result does not establish support for every controller configuration or calibration accuracy. The cause of input loss in earlier experimental builds remains undetermined.

The tag workflow rebuilds the release commit, runs desktop diagnostics ON/OFF tests, builds ordinary and diagnostic Switch configurations, and checks diagnostic exclusion counterexamples and artifact identity. Publication follows successful checks.

### Download and update

Download the ordinary `.nro` from [this release](https://github.com/kxn/nsteamlink/releases/tag/v0.6.0), or use the in-app updater. Existing HOME shortcuts continue to use `sdmc:/switch/nsteamlink/nsteamlink.nro` and do not need reinstalling.
Attachments contain the ordinary NRO, source identity, diagnostic exclusion report, SDK package list, license text, and `SHA256SUMS`; diagnostic builds and motion probes are not published.

Thanks to users providing playtesting and gyro feedback, **Sven** for the original-model Switch, **Simone Caronni ([@scaronni](https://github.com/scaronni))**, and the authors and maintainers of IHSlib, FFmpeg, Opus, SDL, libnx, devkitPro, deko3d, and nx-hbloader.

[Full changelog: v0.5.1 → v0.6.0](https://github.com/kxn/nsteamlink/compare/v0.5.1...v0.6.0)
