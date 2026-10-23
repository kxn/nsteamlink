# Switch 陀螺仪 / Steam Windows host 逆向交接

本文是给后续接手者的研究交接，不是进度汇报。只写可复核的材料、地址、真机结果、
已证实的结论和仍未解决的问题。`Evidence` / `Conclusion` / `Hypothesis` 分开标注。

## 0. 一句话现状

- NX 侧六轴采样、单位/轴向转换、wire IMU 打包已经工作；host 会请求
  `SetSensorEnabled`，也承认 Gyro 能力/显示 Gyro UI。
- Steam Windows host 里真正消费 gyro 的函数已定位到
  `CGyroSource::Update @ 0x1386702d0`，输入字段和填充循环也已对上。
- 但 **remote Generic wire flags 里直接加 `0x400` 会让 host 拒绝整个
  Generic 报告**：Gyro 选项消失、按键/摇杆全部失效。因此不能靠“补
  wire flag”解决。
- 目前没有实机验证通过的 Switch gyro 方案。稳定可用构建仍是 Generic、
  flags `0x6`（无 gyro 输出）。

## 1. 材料

### 1.1 Host 二进制

- 文件：`steamclient64.dll`
- FileVersion：`11.12.30.07`
- 编译时间：`2026-10-14`（PE TimeDateStamp `0x6ace7cc5`）
- SHA-256：
  `e9045710ec7ee47d7b7488d1c5dda2d933dec7e251e965967a5c48f4df68eb4e`
- 镜像基址：`0x138000000`
- 内嵌源码路径：
  - `src/common/hiddevicesdl.cpp`
  - `src/common/hiddeviceremote.cpp`
  - `src/clientdll/controllerabstraction.cpp`
  - `src/clientdll/controller_sources/controller_source_gyro.cpp`
  - `src/clientdll/controller_gyroprocessing.cpp`

### 1.2 官方 Linux 客户端

- `steamlink` 1.3.9.258
- SHA-256（此前记录）：
  `191cc079f795cfdff69a8b51041360a2164b3ec64647e9419af2e2d00fc149e4`

### 1.3 Host VDF

- `controller_switch_pro.vdf`：
  - `controller_caps = 0x8B4BFF`（含 `0x800`）
  - group 8 = `gyro_to_mouse`
  - preset 绑定 `"8" "gyro active"`
  - `gyro_natural_sensitivity = 483`
- `controller_generic.vdf` 也是 `controller_caps = 0x8B4BFF`，group 7 =
  `gyro_to_mouse`，绑定 `"7" "gyro active"`。
- 这证明 VDF 的 Gyro 行为确实是启用的，不是“没保存”。

### 1.4 真机

- Switch 地址：`10.10.10.66`（ICMP 可达；`10.10.10.17` 当前不可达）。
- hbmenu netloader + `nxlink` 推送；不要用 TCP 连接探测 `28280`。
- 当前默认稳定构建：`build/switch/app/nsteamlink.nro`（flags `0x6`）。

## 2. 客户端侧已实现/已验证

### 2.1 采样

- `app/platforms/switch/sensors.c`：
  - 从 `pump_sdl_events`（媒体线程）调用；
  - 按 `HidNpadStyleTag` 取 handheld/FullKey/JoyDual/JoyLeft/JoyRight 句柄；
  - 每 4ms 取最新 `sampling_number`；
  - 会话停止/input gate 关闭/退出时 `hidStopSixAxisSensor`。
- `app/platforms/common/sensor_math.c`：
  - libnx angular velocity 是 rev/s → `×2π` 得 rad/s；
  - acceleration 是 g → `×9.80665` 得 m/s²；
  - 轴向：`sdl_gyro = (av.x, av.z, -av.y) * 2π`，
    `sdl_accel = (-acc.x, -acc.z, acc.y) * g`。
- 真机 handheld 探针：约 194 Hz；YAW→raw Z、PITCH→raw X、ROLL→raw Y；
  详见 `docs/OFFICIAL_INPUT_RE.md` §19。

### 2.2 注入与 wire

- `third_party/ihslib/src/hid/sdl/src/sdl_hid_event.c`：
  `IHS_HIDSDLInjectSensor(session, joystickId, gyro, accel)` 在设备锁内把样本
  合并进 canonical state；发送仍走既有 flush 线程。
- `third_party/ihslib/src/hid/sdl/src/sdl_hid_report.c`：
  - `SetGyro`：`flags |= 0x2`；gyro s16 @ `+0x1c`；
  - `SetAccel`：`flags |= 0x4`；accel s16 @ `+0x22`；
  - `ClearSensors` 清 `0x6`。
- `IHS_HIDReportSDLPackWire` 的 RAW V2 布局：
  - axes `0..0x0b`
  - flags `0x0c..0x0f`
  - buttons `0x10..0x13`
  - version `0x1b = 3`
  - gyro `0x1c..0x21`
  - accel `0x22..0x27`
  - tail（含 touch/备用 sensor）`0x28..0x47`
- 真机日志已多次看到：

  ```text
  HID.SDL: sensor inject motion=0.117 flags=0x406 wire_gyro=96,12,0
  ```

  说明 gyro 确实进入了 canonical state 和 wire；host 也发
  `host sensor enable=1/0`。

## 3. Host 侧逆向结果

### 3.1 `CHIDDeviceSDLGamepad`

- RTTI `.?AVCHIDDeviceSDLGamepad@@` @ `0x17ce878`；
  vtable @ `0x1392fa7a8`。
- `OnSensorEvent` @ `0x1386d30e0`：
  - 正常分支：gyro s16 @ `state+0x1c`，`flags |= 0x402`；
    accel s16 @ `state+0x22`，`flags |= 0x4`。
  - 备用分支（SDL sensor type 3/4，ACCEL_L/GYRO_L）：gyro @ `state+0x38`、
    accel @ `state+0x3e`，`flags |= 0xa00`。
  - 分支由 `[event+0x14]` 的 SDL sensor type 选，不是由 wire flags 选。
- 结论：host 本地 SDL state 的 gyro 布局是 `+0x1c`，与 ihslib 一致；
  `0x400/0x800` 是 host 内部 state 的 sensor slot 位。

### 3.2 真正消费函数 `CGyroSource::Update`

- RTTI `.?AVCGyroSource@@` @ `0x17cb270`；
  vtable @ `0x1392e5218`；
- `CGyroSource::Update` @ `0x1386702d0`（vtable slot 9）。
- 输入 state（`rdx` 指向）：
  - accel s16 @ `+0x24/+0x26/+0x28`
  - gyro s16 @ `+0x2a/+0x2c/+0x2e`
- 它先检查 6 个 word；全 0 时跳到 `0x138670788` 直接返回，不产生四元数、
  不更新 prediction、不通知 Gyro mode。
- `CGyroSource` 用 `[this+0xc0]` 选择输入 slot（0/1）；构造函数
  `0x13866fad0` 从 `edx` 参数写 `[this+0xc0]`。具体哪个控制器源传 0/1，
  尚未定位到调用点。

### 3.3 填充循环 `CGenericGamepadControllerAbstraction`

- RTTI `.?AVCGenericGamepadControllerAbstraction@@` @ `0x17cb5d8`；
  vtable @ `0x1392ea3d0`。
- 候选 `ProcessState` @ `0x1386793e0`：HID state 在对象 `+0x18`，
  version 在 `+0x33`（HID `+0x1b`），RAW 分支从 `+0x18` 拷贝 `0x48`
  字节到局部 state。
- 填充循环 `0x1386796f0`：
  - slot 0：要求内部 `flags & 0x800`，从 `+0x38` 读 gyro、`+0x3e` 读 accel；
  - slot 1：要求内部 `flags & 0x400`，从 `+0x1c` 读 gyro、`+0x22` 读 accel；
  - accel 两条路都要求 `flags & 0x4`；
  - 通过后写 `CGyroSource` 输入 `+0x2a/+0x2e/+0x2c`（gyro）和
    `+0x24/+0x26/+0x28`（accel），并做一次 y/z 交换和 y 取反。

### 3.4 官方 Windows packer 的交叉证据（有边界）

- `CHIDDeviceSDLGamepad` pack 函数 @ `0x1386d35e0`。
- version != 0 时走 RAW 分支 `0x1386d37a6`：
  `eax=0x48`；`len=min(requested,0x48)`；
  `memcpy(dest, source_state, len)`。
- 即 **本地 SDL state 的 0..0x47 原样进入 wire**；同一 DLL 的
  `OnSensorEvent` 正常 gyro 分支是 `+0x1c`、`flags=0x402`。
- **边界**：这证明本地 SDL 内部 state 的 flags 会原样进入本地 packer 的
  wire，**不证明 remote Generic parser 接受同样的 flags**。真机已经证明
  remote Generic 不接受 `0x400`（见 §4）。

### 3.5 Remote HID

- `hiddeviceremote.cpp` 的断言字符串：
  `CHIDDeviceRemote::ProcessInputReport(): Received unknown report type`
  @ `0x1392f9b30`。
- 相关代码区：`0x1386cf580`、`0x1386d0031`。
- 这条路径按 report type 分发并构造 `CHIDDeviceInputReport`，不是把
  Generic V2 tail 直接当连续 IMU 流。**remote Generic 的 flags→内部
  state 映射尚未完全逆清**，这是当前最关键的空白。

### 3.6 官方 Linux 客户端

- `BParseGamepadStateSwitch @0x2da140` 只解析 Switch 原生报告的按键/摇杆，
  **不读 IMU**。
- 客户端唯一的 IMU 路径是 `CHIDDeviceSDLGamepad::OnSensorEvent @0x269740`。
- 所以“改成 Switch 原生报告”不会自动带来 gyro；不要把原生 Switch 报告
  当成显然更优的方案。

## 4. 真机实验表

| 配置 | 布局/Gyro UI | 按键 | 震动 | gyro 输出 |
|---|---|---|---|---|
| Generic `0000:0000`，caps `0x8043ff`，flags `0x6` | 4 项，无 Gyro | 正常 | 正常 | 无 |
| Generic + caps `0x800`，Steam Input 开 | Gyro 出现 | 正常 | 正常 | 无 |
| Generic + caps `0x800` + wire flags `0x400`（`0x406`） | **Gyro 消失** | **全部失效** | — | — |
| Switch Pro `057e:2009` + caps `0x800` | 6 项，Gyro/校准 | 正常 | 正常 | 无 |
| Switch Pro + caps `0x800` + flags `0x400` | — | **全部失效** | — | — |
| DS4 `054c:09cc` + caps `0x800` | 6 项（含触控板），Gyro | 正常 | 正常 | 无 |

关键反证：

- Generic 下加 wire `0x400` 不是“只多一个 sensor 位”，而是让 host
  直接不认这个手柄：Gyro 选项消失、按键/摇杆失效。
- 因此 `0x400` 只能作为 **host 内部 state** 位；remote Generic wire
  不能用它。
- 校准成功只说明 accel（`0x4`）路径通；不能证明 gyro 被消费。
- 震动正常只说明 host→client 的 Write/rumble 路径通，和 IMU 上行无关。

## 5. 结论与未决问题

### Conclusion

1. NX 侧采样、单位、轴向、wire IMU 打包没有丢数据。
2. host 确实有 gyro 消费函数 `CGyroSource::Update`；它要求输入
   `+0x2a/+0x2c/+0x2e` 非零，否则提前返回。
3. 填充循环用内部 flags 的 `0x400`/`0x800` 选 slot；`0x400` 对应
   `+0x1c/+0x22`，`0x800` 对应 `+0x38/+0x3e`。
4. **不能把 `0x400`/`0x800` 直接写进 remote Generic wire flags**；
   `0x400` 实测会让 host 拒绝整个手柄。
5. 因此“补一个 wire flag 就能让 Generic Switch gyro 工作”的假设不成立。

### Hypothesis / 待验证

- remote Generic parser 可能根据 **report type/长度/版本** 或
  `SetSensorEnabled`/`GetFeatureReport` 握手来设置 host 内部 sensor 位，
  而不是读 wire flags。
- 也可能 Steam 的 remote Generic 路径根本不支持 Switch gyro；官方
  Windows packer 的 `0x402` 只适用于本地 SDL/native 控制器。
- `CGyroSource[+0xc0]` 对单 Pro/handheld 到底是 0 还是 1，尚未定位到
  创建点；这决定 slot 0/1。
- DS4/DualSense 原生报告模拟是另一条可能路径（host 对 DS4 有 gyro 支持），
  但尚未实现，不能保证。

## 6. 建议后续工作

1. **优先逆 remote parser**：从 `CHIDDeviceRemote::ProcessInputReport`
   （`0x1386cf580`/`0x1386d0031`）和 `DeviceInputReports` 消息处理入手，
   找到 wire flags 被读取/解释的位置，解释为什么 `0x400` 会让按钮失效。
2. 找 **host 内部 `0x400`/`0x800` 的设置点**：搜索对内部 state `+0xc`
   的 OR 0x400/0x800，或 `SetSensorEnabled` 的 ack/后续消息；确认 remote
   路径是否有独立的 sensor report。
3. 动态对照：用 x64dbg 在 `0x1386796f0` 和 `0x1386702d0` 下断，分别看
   官方客户端（本地带 gyro 手柄）和我们的 Generic 流，比较 state flags /
   `+0x1c`/`+0x38` / `+0x2a` 的值。这是最快区分“parser 没填”与
   “builder 没读”的方法。
4. 如果 remote Generic 确认无解，再评估 **DS4/DualSense 原生报告模拟**；
   不要先在 Switch 原生报告上花时间，官方 Switch parser 本身忽略 IMU。
5. 不要再做这些已排除的事：
   - 给 Generic 加 caps `0x800` 当“修复”（只出 UI）；
   - 给 wire flags 加 `0x400`/`0x800`（实测破坏输入）；
   - 用 Switch Pro/DS4 身份伪装来“接近”Generic（会切 native 路径，混淆）；
   - 把校准成功、Gyro UI 出现当成 gyro 已被消费。

## 7. 构建/源码/文档

- 稳定 Generic：`build/switch/app/nsteamlink.nro`（flags `0x6`）
- Bad 对照（勿再用）：`build/switch-gyro400/app/nsteamlink.nro`（wire `0x406`，
  实测 Gyro 消失/按键失效）
- 未测兜底：`build/switch-alt/app/nsteamlink.nro`（`+0x38/+0x3e` + `0x800`）
- 未测 caps 对照：`build/switch-hostcaps/app/nsteamlink.nro`
  （caps 补到 `0x8B4BFF`）
- 源码/文档：
  - `docs/OFFICIAL_INPUT_RE.md` §19（六轴接入）、§20（host 逆向/反证）
  - `docs/decisions.md` D-063（六轴）、D-064（host gyro 结论与撤回）
  - ihslib 六轴打包/注入：`third_party/ihslib/src/hid/sdl/src/sdl_hid_report.c`、
    `sdl_hid_event.c`、`sdl_hid_common.h`
  - NX 采样：`app/platforms/switch/sensors.c`、
    `app/platforms/common/sensor_math.c`

## 8. 快速复现命令

```bash
# 默认稳定构建
cmake --build build/switch --target nsteamlink_nro -j32

# 推送（Switch IP 以用户当前确认为准；当前记录 10.10.10.66）
/opt/devkitpro/tools/bin/nxlink -a 10.10.10.66 -s build/switch/app/nsteamlink.nro
```

host 侧诊断：`streaming_log.txt`、`controller.txt`、`controller_ui.txt`；
VDF 路径示例：
`G:\Steam\steamapps\common\Steam Controller Configs\256803919\config\413080\controller_switch_pro.vdf`。
