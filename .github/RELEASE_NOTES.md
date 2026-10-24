# NSteamLink v0.7.2

## 简体中文

## [0.7.2] - 2026-10-24

上一正式版：**v0.7.1**。目标分支：`main`；源码：[`v0.7.2`](https://github.com/kxn/nsteamlink/tree/v0.7.2)。

### 主要变化

- 修复设置项右侧文字重复绘制造成的重影，例如“均衡”“自动”“中文”。
- “配对码”入口改为“显示配对码”。云端会话未就绪时置灰并显示“云端服务不可用”，隐藏箭头、压暗背景和文字；连接成功后自动恢复。手动输入地址仍可使用。
- 更新提示增加“此版本不再提示”复选项。触屏勾选后主按钮改为“不再提示”；按 A 确认后保存，按 B 取消不保存。后续启动跳过该版本，遇到更高版本仍会提示。

### 验证与范围

已核对中英文实际渲染；回归覆盖云端状态切换、禁用入口、忽略版本的重启回读、后续版本提示，以及文件替换失败恢复。本版没有新增真机测试，也不声称修复 #93 中尚未定位的公网连接问题。

### 提交分组

- 界面修复：`1a94f48` 消除设置文字重影；`e36771f` 按云端会话状态禁用配对码入口；`054cf01` 隐藏禁用箭头并强化灰态。
- 更新体验：`ad40898` 支持忽略指定版本的更新提示。
- 发布：更新版本号和中英双语发布说明。

感谢 [@jiaruisme](https://github.com/jiaruisme) 在 [#93](https://github.com/kxn/nsteamlink/issues/93) 提交问题反馈。

[完整变更：v0.7.1 → v0.7.2](https://github.com/kxn/nsteamlink/compare/v0.7.1...v0.7.2)

---

## English

## [0.7.2] - 2026-10-24

Previous stable release: **v0.7.1**. Target: `main`; source: [`v0.7.2`](https://github.com/kxn/nsteamlink/tree/v0.7.2).

### Highlights

- Fix doubled settings values such as quality, resolution and language selections.
- Rename the pairing entry to “Show pairing code”. Disable it with “Cloud unavailable” until the cloud session is ready; hide its arrow and dim its surface and text. Restore it on connection. Manual address entry stays available.
- Add “Skip this version” to the update dialog. Select it using the touchscreen, then confirm with A; B cancels without saving. The selected version stays hidden across restarts, while later versions can still prompt.

### Validation and scope

Checked actual Chinese and English renders. Regression coverage includes cloud availability, disabled activation, ignored-version persistence across restart, later-version prompts and failed file-replacement recovery. No new hardware testing was performed for this release. The unresolved Internet connectivity report in #93 is not claimed fixed.

### Commits by type

- UI fixes: `1a94f48` remove doubled settings text; `e36771f` gate pairing-code entry on cloud availability; `054cf01` hide disabled arrows and strengthen disabled styling.
- Updater: `ad40898` allow opting out of a specific release notification.
- Release: version and bilingual release notes.

Thanks to [@jiaruisme](https://github.com/jiaruisme) for reporting [#93](https://github.com/kxn/nsteamlink/issues/93).

[Full changelog: v0.7.1 → v0.7.2](https://github.com/kxn/nsteamlink/compare/v0.7.1...v0.7.2)

