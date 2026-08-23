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
│   └── hekate_ipl.ini          ← Launch 菜单的启动项定义（Hekate 6.x 用 pkg3= 键，老教程的 fss0 已废弃）
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

- **验证 hbmenu**：系统里**按住 R 不放，再启动任意一个已安装的官方游戏** → hbmenu 弹出即成功
  （这就是全内存 Title Redirection 模式，串流应用以后必须这样启动）；
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
```

- nxlink 用法：hbmenu 界面按 **L** 开网络接收，屏幕显示 IP 填到 `-a`；
- nro 一律用 **Title Redirection**（按住 R 启动游戏）方式运行，applet 模式内存不足秒退。

## 排错速查

| 现象 | 处理 |
|---|---|
| `Missing Minerva/LP0 / Update bootloader folder!` | Hekate 报的：SD 卡 `bootloader/` 缺失或版本不配套。重做第 1、2 步，两处必须同版本。别无视报错硬启动 |
| 应用秒退/初始化失败 | applet 模式内存不足，改 Title Redirection 启动 |
| nxlink 找不到机器 | hbmenu 没按 L；或路由器隔离/防火墙拦 UDP |
| 进不了 RCM | 拨片没顶到位（多试姿势）；确认机器是未打补丁型号 |
| 机器用一会儿就关机 | 没挂 PD 充电器，或充电器只有 5V 档——换支持 PD 15V 的头 |
| SD 卡在电脑上读写异常 | 文件系统损坏（`wipefs -a` 后重建 FAT32 分区）/ 假卡（`f3write`+`f3read` 验容量）/ 主控报废（写操作报 I/O 错，换卡） |

## 已跳过项（不用做，留档说明）

- **NAND 备份**：约 30GB 需大卡；本机已放弃原系统，跳过。想补随时借大卡在 Hekate 里做；
- **emummc / incognito / 防封号设置**：专用调试机不需要；
- **电脑端 fusee-launcher**：RCM Loader 已替代；仅在注入棒没电时才需要
  （`pip3 install pyusb` + reSwitched/fusee-launcher 发 Hekate）。
