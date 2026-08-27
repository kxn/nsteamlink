# Switch 真机环境准备（本机已定版，照做即可）

> 本文档只保留**这台机器**的路线，所有分支情况已裁剪。
> 机器档案：未打补丁初代机（Erista）｜专用调试机（放弃原系统、接受封号、不装 emummc）｜
> 注入器：RCM Loader 多槽位｜SD 卡：16GB FAT32｜电池老化：必须挂 PD 充电器运行。
> 通用参考：https://nh-server.github.io/switch-guide/ ｜风险自担，仅用于自己拥有的机器。

## 第 1 步：SD 卡（文件已备好，直接拷）

开发机上 `/data/dl/switch-setup/sd-root/` 已按最终结构摆好（Hekate 6.5.3 + Atmosphère 1.11.2）：

```
sd-root/                        → 拷到 SD 卡根目录
├── bootloader/                 ← Hekate 配套文件（含 Minerva/LP0 库，就是上次报错缺的）
│   └── hekate_ipl.ini          ← Launch 菜单的启动项定义（Hekate 6.x 用 pkg3= 键，老教程的 fss0 已废弃）。
│                                 注意：Hekate 会在此文件里自动生成 [config] 设置段——
│                                 加启动项时在文件**末尾追加**新段，不要整文件覆盖
├── atmosphere/                 ← Atmosphère CFW 本体
├── hbmenu.nro                  ← 自制软件启动器（必须在卡根目录）
└── switch/                     ← 自制软件目录（含 daybreak/haze 等系统工具，nsteamlink 以后放这）
    同目录下 hekate_ctcaer_6.5.3.bin ← 这个不进 SD 卡，是给 RCM Loader 用的（第 2 步）
```

操作：SD 卡（FAT32 单分区）插电脑，把 `sd-root/` 里**除 `hekate_ctcaer_6.5.3.bin` 外**的所有内容拷到卡根目录。完成后卡根目录应有 `bootloader/ atmosphere/ switch/ hbmenu.nro`。

## 第 2 步：更新 RCM Loader 的 payload

注入棒拔出来插电脑 USB 口 → 识别成 U 盘 → 找到当前在用槽位的 payload 文件，
用 `hekate_ctcaer_6.5.3.bin` **保持原文件名覆盖**（多个槽位可以都换成同一份，防选错）。
带按键的型号记住当前选中的槽位。完成后注入棒插回底座充电。

> payload 版本必须与 SD 卡里的 `bootloader/` 同发行包——上次那三条
> `Missing Minerva/LP0` 报错就是版本不配套。

## 第 3 步：首次注入与启动

1. 机器插 PD 充电器开机进入原系统一次，确认 SD 卡插好；
2. 关机，拆右 Joy-Con，拨片顶住轨道顶部针脚；
3. 按住 **音量+** 不放 → 按 **电源** 1 秒 → 松开电源 → 屏幕全黑 = 进入 RCM；
4. 拔充电器，插上 RCM Loader 注入棒 → LED 闪约 2 秒 → Hekate 启动（蓝色菜单）；
5. **Launch → Atmosphere (sysNAND)**（启动项由 `bootloader/hekate_ipl.ini` 提供；
   若显示 no main boot entries found，说明 SD 卡缺这个文件）；
6. 拔回充电器。

## 第 4 步：验证与一次性设置

- **验证 hbmenu**：系统里**按住 R 不放，再按 A 启动任意应用图标** → hbmenu 弹出即成功
  （这就是全内存 Title Takeover 模式，串流应用以后必须这样启动）。
  **机器没装游戏也能用**：eShop 图标本身就是 Application 类型 title，按住 R 启动它即可，
  且 takeover 时不会真的进商店、不联网。注意相册相反：不带 R 开相册 = applet 版 hbmenu（内存受限）；
  按住 R 开相册 = 打开真相册；
- **开 AutoRCM**：回 Hekate（重启注入一次）→ **Tools** → 页面最底部一行
  "Arch Bit • AutoRCM • Touch • Pkg1/2" → 点 **AutoRCM**，显示 ON 即开启。
  （注意：不在 Options 菜单里。）
  从此断电重启自动进 RCM，拨片永久退休，插一下注入棒即恢复系统；
- **连 WiFi**：系统设置里连上家里路由器（串流必需；不飞行模式，ban 随它去）。

## 日常开机（定型后）

断电重启 → 黑屏（自动 RCM）→ 插一下注入棒 → Hekate → Launch → Atmosphère →
回充电器。调试间歇直接按电源睡眠，不彻底断电就永远不用重新注入。

## 供电规则（电池老化机）

| 场景 | 供电 |
|---|---|
| 运行系统 / 串流 / hbmenu | PD 充电器（15V 档；PC USB 和普通 5V 充电宝都不够，会关机） |
| RCM 等待注入 | 注入棒或 PC USB 均可（RCM 功耗极低） |
| nxlink 调试 | 充电器（nxlink 走 WiFi 不占 USB 口） |

电池若出现鼓包迹象（后盖/屏幕被顶起）立即停用；可拆电池纯 PD 运行（Y00 螺丝刀，拆前放电关机）。

## 开发迭代（本项目专用）

```bash
./scripts/build-switch.sh                                        # 产出 nro
cp build/switch/app/nsteamlink.nro <SD卡>/switch/                # 手动部署
$DEVKITPRO/tools/bin/nxlink -a <Switch的IP> -s build/switch/app/nsteamlink.nro   # 网络部署+日志回传

# M2 配对工具（发现 + pairing code 授权 + auth.bin 持久化）
cp build/switch/tools/switch-discover/switch-discover.nro <SD卡>/switch/
$DEVKITPRO/tools/bin/nxlink -a 10.10.10.77 -s build/switch/tools/switch-discover/switch-discover.nro

# NRO 跑起来后，PC 端控制 M2 工具（UDP debug port 28772）
tools/switch-debugctl.py 10.10.10.77 state
tools/switch-debugctl.py 10.10.10.77 hosts
tools/switch-debugctl.py 10.10.10.77 select 1
tools/switch-debugctl.py 10.10.10.77 pair       # Switch 生成 code；把 code 输入 Steam host
tools/switch-debugctl.py 10.10.10.77 code       # 重新读取当前 code/state
tools/switch-debugctl.py 10.10.10.77 exit

# M3 串流/session/video/第一帧显示 probe（复用 M2 auth.bin）
$DEVKITPRO/tools/bin/nxlink -a 10.10.10.77 -s build/switch/app/nsteamlink.nro

# 串流证据 selftest（保留为排障工具；正式 app 复用同一条串流链路）
$DEVKITPRO/tools/bin/nxlink -a 10.10.10.77 -s build/switch/client/switch-stream-selftest.nro
tools/switch-debugctl.py 10.10.10.77 state
tools/switch-debugctl.py 10.10.10.77 hosts
tools/switch-debugctl.py 10.10.10.77 select 1
tools/switch-debugctl.py 10.10.10.77 stream game  # 默认 3600 帧后自动 stop；desktop 用 stream
tools/switch-debugctl.py 10.10.10.77 stats
tools/switch-debugctl.py 10.10.10.77 exit

# 若 switch-discover 崩溃，读取 SD 卡上的 exception dump 后映射源码行
$DEVKITPRO/devkitA64/bin/aarch64-none-elf-addr2line -f -C \
  -e build/switch/tools/switch-discover/switch-discover.elf <pc> <lr>
```

- nxlink 用法：hbmenu 界面按 **L** 开网络接收，屏幕显示 IP 填到 `-a`；
- nro 一律用 **Title Takeover**（按住 R 启动 eShop 或任意游戏）方式运行，applet 模式内存不足秒退。
- `switch-discover` 退出时会写 `sdmc:/switch/nsteamlink/exit_stage.txt`，用于确认 fatal 前最后
  完成的 cleanup 阶段。程序自身 userland exception handler 触发时还会尝试写
  `sdmc:/switch/nsteamlink/exception_dump.txt`；其中 `pc` 和 `lr` 是优先映射的地址。
- 本机 Switch 调试地址固定为 `10.10.10.77`；hbmenu netloader 端口是 `28280`。不要用空 TCP
  探测 netloader 端口，直接用 `nxlink -a 10.10.10.77` 上传。
- `switch-discover` 的 UDP debug 入口只用于开发测试，端口 `28772`；通过 nxlink 启动时优先只接受
  nxlink host 发来的命令。可用命令：`ping`、`state`、`hosts`、`select <n>`、`press <button>`、
  `pair`、`code`、`delete-auth`、`exit`。`pair` 不接收 PIN；Switch 生成并显示 pairing code。
  旧 `pin/submit` 命令只返回 deprecated 错误，不能作为 pairing 验收路径。
- 当前 `nsteamlink.nro` 启动后显示英文 UI：菜单中 `A` 启动 stream，`X` 切换 game/desktop，
  `Y` 刷新 host，`UP/DOWN` 选择 host，`B` 停流；streaming 中普通游戏按键会转发给 Steam，
  `+` / `-` 不再作为本地控制键，会恢复给 Steam/game 使用。`-` / `MINUS` 的 marker 日志仍是被动
  记录，不吞键、不触发停流。本地控制改为 `L3+R3+VOL+` 退出程序、`L3+R3+VOL-` 停流；该实现通过
  audctl 观察音量值变化，音量已到顶/到底时对应方向可能不会触发。Steam 返回 streaming PIN 时，
  `LEFT/RIGHT` 移动数字位，`UP/DOWN` 调整数字，`A` 提交，`B` 取消。
- `nsteamlink.nro` 与 `switch-stream-selftest` 使用同一个 UDP debug 端口 `28772`。可用命令：
  `ping`、`state`、`stats`/`perf`、`audio`、`hid`、`hidlog [n]`、`diag [current|prev|status]`、
  `hosts`、`select <n>`、`press <A|B|X|Y|MINUS|PLUS|MINUS+B|MINUS+PLUS|UP|DOWN|LEFT|RIGHT>`、
  `stream [desktop|game] [short|long|frames=N|seconds=N|hold] [pin]`、`stream-pin <pin>`、
  `stop`、`exit`。这里的 `stream-pin` 是串流阶段 host PIN，不是 M2 pairing code。
- `hidlog [n]` 返回最近若干秒 HID 诊断环形历史；字段中 `e/ok/f/h/p` 分别是 SDL HID 事件、
  input report 成功发送、发送失败、100ms full-state heartbeat、pump 调用计数，`raw=x/y`
  是 libnx `PadState` 原始摇杆/按钮变化计数，`sty=flips:style/attrs` 是 style/attribute 抖动计；
  `sticks=lx/ly/rx/ry` 与 `b=0x...` 是当秒结束时 SDL controller 的摇杆轴和按钮 mask；
  `minus=sdlHeld/sdlSamples/rawHeld/rawSamples` 是故障 marker。
- `diag current` 读取 `sdmc:/switch/nsteamlink/stream_diag.log` 尾部；`diag prev` 读取上一轮
  `stream_diag_prev.log` 尾部。正式 app 会每秒在后台 append+flush state/hid/audio 摘要，退出后
  仍可通过下一次启动的 `diag prev` 或直接读 SD 卡文件复盘；`diag status` 返回诊断线程状态与
  文件/线程错误码；`diag marker current` / `diag marker prev` 只返回看到 `-` / `MINUS` marker
  的秒级记录。marker 日志中 `markMinus` 是输入同窗，`markNet` 是同一 seq 的视频/音频/control
  同窗摘要，用来判断 Wi-Fi/stream 是否同时断流。新版 `hid`/marker 网络字段中的
  `rel=tracked/acked`、`retry/fail/out/oldest/maxAck` 来自可靠发送状态机本身；
  `hidSM=submitted/coalesced/sent/acked/pending/inFlight` 用于判断输入是在本地等待 ACK、已合并还是已确认。
- `audio` 返回 Opus/SDL 音频状态：是否 active、codec/frequency/channels、解码帧数、SDL queued
  bytes、queue drop 与 decode/queue 错误计数。
- M3.3 接入 FFmpeg/SDL2 后 `switch-stream-selftest.nro` 约 19MB，nxlink/netloader 传输会明显慢于 M2/M3.2
  的 487KB probe。传输慢只说明 NRO 大，不能单独作为程序卡死或协议失败证据。

## 可选远程调试

Atmosphère 提供 standalone gdbstub，可用 devkitPro 的 `aarch64-none-elf-gdb` 连接到 Switch
的 `22225` 端口。启用需要改 SD 卡 `/atmosphere/config/system_settings.ini` 并重启：

```ini
[atmosphere]
enable_htc = u8!0x0
enable_standalone_gdbstub = u8!0x1
```

```bash
/opt/devkitpro/devkitA64/bin/aarch64-none-elf-gdb -nx
```

```gdb
target extended-remote <Switch的IP>:22225
info os processes
attach <pid>
```

注意：Atmosphère 官方 changelog 提醒，调试使用 socket 的进程时 gdbstub 本身可能引入 hang；
本项目默认先用 nxlink 阶段日志 + SD 卡 exception dump 定位，只有 dump 不够时再启用 gdbstub。

## 排错速查

| 现象 | 处理 |
|---|---|
| `Missing Minerva/LP0 / Update bootloader folder!` | Hekate 报的：SD 卡 `bootloader/` 缺失或版本不配套。重做第 1、2 步，两处必须同版本。别无视报错硬启动 |
| 应用秒退/初始化失败 | applet 模式内存不足，改 Title Takeover（按住 R 启动 eShop/游戏） |
| nxlink 找不到机器 | 只能说明当前 IP 没有 netloader 接收端或网络不可达；先看 hbmenu 是否按 L，并核对屏幕 IP，不要据此推断 NRO 没运行 |
| 本地退出后崩溃 | 以 Switch 屏幕 fatal 为准；保留 nxlink `cleanup:` 日志，查看 `sdmc:/switch/nsteamlink/exit_stage.txt`，若存在 `exception_dump.txt` 再用上面的 `addr2line` 命令映射 `pc/lr` |
| 进不了 RCM | 拨片没顶到位（多试姿势）；确认机器是未打补丁型号 |
| 机器用一会儿就关机 | 没挂 PD 充电器，或充电器只有 5V 档——换支持 PD 15V 的头 |
| 机器已被任天堂 ban（eShop 打不开） | **不影响本项目**：Title Takeover 不真正启动 eShop、不联网；串流走局域网。若按 R 无反应，先确认当前系统是 Atmosphère（设置→系统版本行带 `\|AMS` 字样），再检查 R 是否全程按住 |
| SD 卡在电脑上读写异常 | 文件系统损坏（`wipefs -a` 后重建 FAT32 分区）/ 假卡（`f3write`+`f3read` 验容量）/ 主控报废（写操作报 I/O 错，换卡） |

## 已跳过项（不用做，留档说明）

- **NAND 备份**：约 30GB 需大卡；本机已放弃原系统，跳过。想补随时借大卡在 Hekate 里做；
- **emummc / incognito / 防封号设置**：专用调试机不需要；
- **电脑端 fusee-launcher**：RCM Loader 已替代；仅在注入棒没电时才需要
  （`pip3 install pyusb` + reSwitched/fusee-launcher 发 Hekate）。
