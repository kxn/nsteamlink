# 更新日志

[English](CHANGELOG.en.md)

## [0.7.2] - 2026-10-24

上一正式版：**v0.7.1**。目标分支：`main`；源码：[`v0.7.2`](https://github.com/kxn/nsteamlink/tree/v0.7.2)。

### 主要变化

- 修复设置项右侧文字重复绘制造成的重影，例如“均衡”“自动”“中文”。
- “配对码”入口改为“显示配对码”。云端会话未就绪时置灰并显示“云端服务不可用”，隐藏箭头、压暗背景和文字；连接成功后自动恢复。手动输入地址仍可使用。
- 更新提示增加“此版本不再提示”复选项。按 X 或触屏切换，勾选后主按钮改为“不再提示”；按 A 确认后保存，按 B 取消不保存。后续启动跳过该版本，遇到更高版本仍会提示。

### 验证与范围

已核对中英文实际渲染；回归覆盖云端状态切换、禁用入口、忽略版本的重启回读、后续版本提示，以及文件替换失败恢复。本版没有新增真机测试，也不声称修复 #93 中尚未定位的公网连接问题。

### 提交分组

- 界面修复：`1a94f48` 消除设置文字重影；`e36771f` 按云端会话状态禁用配对码入口；`054cf01` 隐藏禁用箭头并强化灰态。
- 更新体验：`ad40898` 支持忽略指定版本的更新提示。
- 发布：更新版本号和中英双语发布说明。

感谢 [@jiaruisme](https://github.com/jiaruisme) 在 [#93](https://github.com/kxn/nsteamlink/issues/93) 提交问题反馈。

[完整变更：v0.7.1 → v0.7.2](https://github.com/kxn/nsteamlink/compare/v0.7.1...v0.7.2)

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
