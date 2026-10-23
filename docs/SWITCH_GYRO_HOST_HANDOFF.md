# Switch 陀螺仪 / Steam Windows Host 协议证据

本文保存可复核的协议和逆向证据；任务状态放在 GitHub Issues。
地址均针对下述固定 DLL，不能直接套到另一版本。

## 1. 撤回与证据边界

**Retraction（2026-10-23）：** 撤回旧版本文和 D-064 的“remote Generic 拒绝
wire `0x400`”“只能设置 Host 内部位”“应放弃 Generic 转 DS4”结论。
原始 DLL 的 remote full/delta 解码器接受 `0x406`，Generic builder 将它的
普通 IMU 送入 slot 1；`0x400` 本来就是 RAW V3 的每报告 freshness 位。

**Evidence：** 用户实际观察到的 `switch-gyro400` 构建 Gyro UI 消失、按键/摇杆
全部失效仍成立。不能用离线模拟否定这次实机失败。
但留存的 `build/switch-gyro400/CMakeCache.txt` 是
`NSL_HID_GYRO_FLAG_400=ON`、`NSL_SWITCH_HOST_CAPS=OFF`，因此它不是
“motion capability 不变、仅改变 flags”的独立对照。UI 消失有能力位缺失这一
混杂因素；**按键失效的根因仍未确定**。留存 `controller.txt` 的时间范围也不覆盖
那次早上的失败会话，不能用它编造 Host 拒绝报告的日志证据。

**Conclusion：** 原始客户端没有完整实现 RAW V3 的正常传感器契约：默认报告
只有 presence `0x6`，缺 freshness；设备声明缺 motion capability；packer
还丢弃了两个时间字段。前两项各自能阻断 Host 的 IMU 处理。时间戳缺失使
Host 使用回退时序，但没有证明它单独导致完全无输出。

## 2. 固定材料

- Windows `steamclient64.dll`，FileVersion `11.12.30.07`，ImageBase `0x138000000`。
- SHA-256：`e9045710ec7ee47d7b7488d1c5dda2d933dec7e251e965967a5c48f4df68eb4e`。
- 内嵌源文件：`hiddevicesdl.cpp`、`hiddeviceremote.cpp`、
  `controllerabstraction.cpp`、`controller_source_gyro.cpp`、`controller_gyroprocessing.cpp`。
- 历史真机探针、方向/单位依据：[OFFICIAL_INPUT_RE.md](OFFICIAL_INPUT_RE.md) §19。
  完整 Host 复核见该文 §21；原始错误推论保留在 §20 并标注已撤回。
- 历史 VDF：`controller_generic.vdf` 的 group 7 和
  `controller_switch_pro.vdf` 的 group 8 均为 active `gyro_to_mouse`，
  `controller_caps=0x8B4BFF`。这证明文件内有绑定，不能证明失败会话加载了该绑定。

## 3. 普通单手柄的 wire 契约

报告保持 Generic RAW，version 字节 `+0x1b=3`，payload 72 字节。
`StartInputReports` 订阅长度 73 时 delta mask 是 10 字节，不能按 payload 长度
擅改掩码宽度。CRC 使用消息声明的数据长度；生产 report holder 和原始 Host
解码器已交叉验证。

| 字段 | 偏移/值 | 含义 |
|---|---|---|
| axes | `+0x00`，6×s16 | 既有按键/摇杆格式不变 |
| flags | `+0x0c`，u32 | gyro presence `0x2`，accel presence `0x4`，普通样本 freshness `0x400` |
| buttons | `+0x10`，u32 | SDL button positions |
| version | `+0x1b`，u8=3 | RAW V3，无旧版 freshness 自动补位 |
| gyro | `+0x1c`，3×s16 | ±2000°/s，即 ±34.90659 rad/s |
| accel | `+0x22`，3×s16 | ±2g，即 ±19.6133 m/s² |
| event time | `+0x30`，u32 | 微秒，截断到 32 位 |
| sensor time | `+0x34`，u32 | 100ns，截断到 32 位 |
| 左传感器区域 | `+0x38..0x47` | 普通单手柄置零 |

有新普通六轴样本时 flags 为 `0x406`。freshness 不是永久能力位：只有按键、
摇杆或 accel 变化时，不重放上次已提交的 gyro；尚未提交的 gyro 必须保留。
相同角速度在新的采样时刻仍是新样本，不能只比较量化后的六轴数值。

设备 `caps_bits` 的 motion 位是独立的 `0x800`，与报告中的 `0x800` 不是同一
字段。Switch 的 `InfoFromHID` 基线 `0x8343ff` 加此位为 `0x834bff`；没有根据
把 VDF 中的额外 `0x80000` 一起照抄。报告里的 `0x800` freshness 配合
`0x200` presence 才对应左传感器，不能用于普通 gyro。

SDL3 event/sensor 时间单位均为 ns；SDL2 event 为 ms，2.26 起 sensor 的
`timestamp_us` 为 µs。分别换算；libnx 注入使用单调观察时钟。
参照 [SDL3 事件定义](https://wiki.libsdl.org/SDL3/SDL_GamepadSensorEvent) 和
[SDL2 事件定义](https://wiki.libsdl.org/SDL2/SDL_ControllerSensorEvent)。

## 4. Host 从报告到 gyro source 的证据链

| 阶段 | 固定样本地址 | Evidence / Conclusion |
|---|---|---|
| Remote 接收 | `0x1386cfd80` | full 复制；delta 调 `0x1386cef00` 重建并经 `0x138cfa3e0` 验 CRC。unknown-report-type 检查 protobuf full/delta presence，不读 RAW flags |
| Generic Read | `0x13867b060` | 将 HID Read 字节存入对象 `+0x18` |
| RAW builder | `0x1386793e0` | 72 字节复制。version<3 在 `0x1386795ae` 自动 OR `0xc00`；version=3 没有该补偿 |
| IMU 填充 | `0x1386796f0` | 普通 slot 1 要 `0x400` 和 gyro presence `0x2`；左 slot 0 要 `0x800` 和 `0x200` |
| source factory | `0x13866ebe0` | source type 10 传 slot=1，type 16 传 slot=0；构造入口是 `0x13866fac0` |
| 采样时序 | `0x13863bc00` | 使用 `+0x34` 的 100ns 时间戳，输出 µs 周期；零 timestamp 走回退 |
| 传感器开关 | `0x13867c110`、`0x13867c1d0` | 设置 `57 00 aa` 置对象 `+0x1f4=1`，转为客户端 `08 01`；`57 00 bb` 关闭。不是额外的输入报告类型 |
| 姿态处理入口 | `0x13867d830` | 要求对象启用、caps `0x800`、sensor enabled、新 packet、新鲜 IMU。普通单 slot 配置有两组各 15 次 warmup，随后到校准/积分 |
| 四元数积分 | `0x13863d990` | 校准/滤波后的六轴及 dt 更新四元数；可离线执行原始数学指令 |
| gyro source | `0x1386702d0` | 先检查 6 个 IMU word，再检查 fresh/enable/四元数；只有非零 IMU 不足以证明完整通过 |

builder 输出的每 slot 大小 `0x34`。普通 slot 1 的 accel 位于 `state+0x58`、
gyro 位于 `state+0x5e`，四元数（w,x,y,z）位于 `state+0x64`。
数值转换为 accel `(ax,-az,ay)`、gyro `(gx,gz,gy)`。
旧文直接写 base+0x24/base+0x2a，漏掉了 slot stride。

**Evidence：** 离线执行缺 motion cap、sensor disabled、fresh mask 清零三个
负例均到不了校准入口；有完整报告的正例可以到达。另以合成的已初始化单位姿态
隔离执行原始积分器，C packer 的 `(1,-2,3) rad/s` 输入在 4ms 下产生非单位姿态
（单位长度四元数）；gyro source 随后复制正确角速度。去掉姿态数据则原始
`Update` 在 `0x138670780` 返回。

**Boundary：** 校准入口门控与四元数积分是分段验证，不伪称完整 Steam 进程闭环。
合成对象/配置、时钟及容器/锁/设备 Write 桩均在工具中明确列出。未覆盖校准
收敛、实际网络调度、action 选择、最终鼠标/游戏输出及 hbmenu 生命周期。

## 5. 可复核的离线方法

工具不修改 DLL、不连接 Steam、不部署 Switch；固定 SHA 不匹配即拒绝执行。
Python 环境需要 `pefile` 和 `unicorn`。C oracle 使用实际的 packer、delta
report holder、CRC，覆盖按钮释放、相同数值的新样本、合并事件和 full refresh。

```bash
cmake --build build/desktop --target ihs-gyro-wire-oracle -j8
python tools/steam-gyro-host-audit.py \
  --binary /path/to/the/pinned/steamclient64.dll \
  --native build/desktop/third_party/ihslib/tests/hid/sdl/ihs-gyro-wire-oracle \
  --output /tmp/steam-gyro-host-audit.json
```

不得用“模拟通过”改写历史真机观察，也不得用 `nxlink` 退出推断屏幕状态。
设备地址遵循 `AGENTS.md` 或用户本次明确确认的地址，不能从 ICMP/邻居表推断。

## 6. 实机输出证据

2026-10-23，用户明确指定 `10.10.10.66`，测试 SHA-256 为
`db3234bafeac32344e951eea2f910d5c502d94ce2029bedff9afc34a2ebe78f4` 的修复 NRO。
**Evidence：** 用户修改 Steam 手柄桌面布局后，确认陀螺仪可以操控鼠标。
**Conclusion：** 此构建的真实远端 Generic gyro 通路已有桌面鼠标输出证据。
**Boundary：** 用户明确表示游戏内是否实际可用尚不清楚；不能扩大为游戏兼容性
或生命周期验证。原始反馈和运行日志摘要见 `OFFICIAL_INPUT_RE.md` §21.2。
