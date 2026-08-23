# 决策记录（ADR-lite）

每条记录包含：日期、背景、决定、理由、影响。**新条目追加在文件末尾，禁止改写历史结论**；
推翻旧决策时新增一条并在开头注明"取代 D-xxx"。

---

## D-001 统一使用 SDL2 作为两个目标的 UI / 渲染 / 音频输出层

- 日期：2026-08-23
- 背景：plume 桌面端用 SDL3；devkitPro 侧只有 `switch-sdl2`（SDL2）。
- 决定：本项目两目标统一 SDL2，不引入 SDL3。
- 理由：跨目标 API 一致是薄 HAL 策略的前提；SDL3 在 Switch 上无维护的 portlib。
- 影响：桌面端放弃 SDL3 新特性；plume 的 SDL3 用法仅作参考，不能照抄。

## D-002 IHSlib 用上游还是 beudbeud fork —— M1 开工时对比补丁后定

- 日期：2026-08-23（挂起）
- 背景：plume 使用其自有 fork `beudbeud/ihslib`（`plume` 分支带补丁），fork 是否含关键修复未知。
- 决定：M1 克隆 plume 时先 `diff` 上游与 fork 的补丁差异再定；结论回填本条。
- 影响：在结论出来前，`third_party/` 不引入 IHSlib。

## D-003 环境变量策略：bashrc 只放路径，交叉编译变量按需加载

- 日期：2026-08-23
- 背景：devkitPro 官方建议 source `switchvars.sh`，但那会全局导出交叉 `CC/CFLAGS/LDFLAGS`。
- 决定：`~/.bashrc` 只导出 `DEVKITPRO / DEVKITA64 / PATH`；构建脚本按需 source
  `$DEVKITPRO/switchvars.sh`。
- 理由：避免污染本机其他桌面项目的编译环境（全局 CC 指向 aarch64 交叉编译器是隐蔽事故源）。
- 影响：任何直接调用 `make`/`cmake` 构建 Switch 目标的人，必须先 source switchvars.sh 或走 scripts/。

## D-004 许可证定位：项目整体 GPLv3

- 日期：2026-08-23
- 背景：计划复用 Moonlight-Switch 的预编译库与解码代码（GPL-3.0），IHSlib 为 LGPL-3.0。
- 决定：接受 GPLv3 开源，不做闭源尝试（kickoff §7.1）。
- 影响：复用第三方代码必须保留版权声明并在依赖表登记。

## D-005 性能目标：默认 720p60，1080p 属于 M5 打磨项

- 日期：2026-08-23
- 背景：Tegra X1 NVDEC 硬解能力对齐 Moonlight-Switch 实测；1080p 高码率需超频。
- 决定：M3/M4 验收一律以 720p 为准；1080p/超频相关优化推迟到 M5（kickoff §6）。
- 影响：代码必须在默认频率下达成 720p60，不得把超频当前提条件。

## D-006 骨架中 platforms/switch/hal.c 是"M1 前不写 Switch 代码"的例外

- 日期：2026-08-23
- 背景：kickoff §6 要求 M1 完成前不碰 Switch 特有代码；M0 需要打通交叉编译管线。
- 决定：允许一个约 10 行的 HAL stub（仅返回平台名）随骨架提交，用于验证
  devkitA64 + CMake 工具链 + nro 产出全链路；不含任何协议/媒体/UI 逻辑。
- 影响：真正的 Switch 功能代码仍从 M2 开始。
