# Switch 真机环境准备指南（自制系统 / homebrew）

> 目的：让一台**未刷自制系统的原版 Switch** 达到能运行本项目 `.nro`（含 hbmenu 全内存模式、
> nxlink 网络调试）的状态。对应 kickoff §4.3 / §7.3。
> 风险自担声明：修改游戏机可能违反当地法规与 Nintendo 用户协议，可能失去官方网络服务资格；
> 请只用在自己拥有的机器上。本指南不提供任何盗版资源。

---

## 0. 先搞清楚你的机器属于哪一类（决定走哪条路）

看 Switch 底部（或包装盒）的**序列号**（形如 `XAW10000000000`）：

| 机器类型 | 判断方法 | 入口成本 |
|---|---|---|
| **未打补丁的初代机（Erista，2018 年中以前生产）** | 序列号在 https://ismyswitchpatched.com 查询显示 "Unpatched" | **免费**，只需一个 RCM 拨片（几块钱）+ USB-C 线 |
| 已打补丁的初代机（"Patched"） | 同上查询显示 "Patched" | 需要早期低系统版本或硬改（modchip），成本高 |
| Mariko 机型（2019 年后的初代 / Lite / OLED） | 查询显示 "Possibly patched" 或确定 Mariko | **只能 modchip 硬改**（焊接，风险与门槛高） |

- 查询网站打不开就搜序列号前缀对照表，或直接试 RCM（见 §2，试了没反应基本就是 patched）。
- **如果是 Mariko/Lite/OLED 且不想焊接**：不建议硬改。替代方案是收一台二手未打补丁初代机
  （买前让卖家报序列号查一下），这是自制软件圈最常规的做法。
- 本项目只需要"能进 hbmenu"这一件事；**不需要**破解系统、不需要装盗版游戏。

## 1. 需要准备的硬件（未打补丁初代机路线）

- [ ] microSD 卡：≥32GB，**FAT32 格式**（exFAT 在自制环境下问题多）
- [ ] RCM 拨片（jig，几块钱）；应急可用回形针自制，但有短路风险，不推荐常用
- [ ] USB-C 数据线（连 Switch 与 Linux 开发机，必须支持数据传输，不能是纯充电线）
- [ ] **USB-PD 充电器（本机必备）**：官方充电器，或任何 30W+ 支持 PD 15V 档的头 + C to C 线；
      注意普通 5V 充电宝/电脑 USB 口功率不够，机器会关机
- [x] RCM 注入器：已有 RCM Loader（用法见 §3.3.3）
- [ ] （可选）Y00 三角 + PH00 十字螺丝刀：电池彻底报废时可拆电池，纯 PD 供电运行

> **专用调试机简化路线（本项目实际情况）**：本机已是未打补丁初代机、且用户明确表示
> 不再使用原系统、接受封号风险。因此：**不需要 emummc、不需要 incognito/防封号设置**，
> §3.2 第 5 步与 §3.4 可整体跳过。注意：**不要开飞行模式**——串流依赖 WiFi 连局域网，
> 保持 WiFi 可用、正常连家里路由器即可。

## 2. 系统与自制的总体架构（心里有数再动手）

```
RCM 漏洞（硬件入口，机器每次冷启动都要重新进入）
  └─ 注入 payload：Hekate（引导器，负责启动选择/备份/emummc 管理）
       └─ Atmosphère（自制系统 CFW，本体；每次重启后消失，不留在机器里）
            └─ hbmenu（自制软件启动器）
                 └─ sd:/switch/nsteamlink.nro  ← 我们的项目
```

关键认知：

1. **CFW 不刷进机身存储**——每次开机临时加载，原系统分区不动。拔掉 SD 卡、不注入 payload
   就恢复纯原版，这是 RCM 路线最大的安全垫。
2. **emummc（强烈推荐）**：把 SD 卡划一个分区当"虚拟机身存储"，自制软件的一切痕迹都留在
   emummc 里；真实 sysnand 保持干净继续正常玩正版 + 联网。只要不把 CFW 痕迹带进 sysnand，
   ban 机风险极低。
3. 系统版本**不用降级**，Atmosphère 支持现行最新版本。

## 3. 操作步骤（未打补丁初代机）

详细图文以官方 NH 指南为准：**https://nh-server.github.io/switch-guide/**（本节是速览 + 我们的补充）。

### 3.1 备份 NAND（做任何事之前）

Hekate 里 `Tools → Backup eMMC` 完整备份，存到电脑。这是唯一后悔药。

### 3.2 SD 卡准备

1. SD 卡 FAT32 格式化。
2. 从 GitHub 下载两样（Release 页，均选最新版）：
   - **Atmosphère**（`AMS-…-RELEASE.zip`，内含 CFW 与 `hbmenu.nro`）
   - **Hekate**（`hekate_ctcaer_…\.zip`）
3. 按 NH 指南把文件摆到 SD 卡对应位置；`hbmenu.nro` 放 SD 卡**根目录**。
4. 建 `sd:/switch/` 目录（放我们的 nro）。
5. （推荐）用 Hekate 创建 **emummc 分区**，之后所有自制活动都在 emummc 里进行。

### 3.3 进入 RCM 并注入（Linux 开发机上）

```bash
# 一次性安装注入工具（Python 版 fusee-launcher）
sudo apt install python3-pip libusb-1.0-0-dev
pip3 install --user pyusb
git clone https://github.com/reSwitched/fusee-launcher.git
```

进 RCM 的手法（第一次多试几次）：

1. 主机完全关机，Joy-Con 拆下；
2. 拨片插入**右 Joy-Con 轨道顶部**（顶住第 9、10 针脚）；
3. 按住 **音量+** 不放，再按 **电源** 1 秒，松开电源——屏幕全程黑屏 = 成功进入 RCM；
4. USB-C 连电脑：

```bash
cd fusee-launcher
sudo python3 fusee-launcher.py hekate_ctcaer_xxx.bin   # 注入 Hekate
# 也可直接注入 Atmosphère 的 fusee.bin，跳过 Hekate；但 Hekate 有备份/启动菜单，推荐
```

5. Hekate 里选 `Launch → Atmosphere`（或 emummc）。进系统后按住 **R + 打开相册** 即可验证
   hbmenu 能否弹出。

> 手机党：Android 装 "NX Loader" App 也能发 payload，免电脑。

### 3.3.1 调试机常驻便利设置（针对本机"必须插电"的情况）

本机不插充电器很快关机 → 常年插电当台式调试机用。配合两个设置把"每次冷启动都要手工进 RCM"
的麻烦消掉：

1. **AutoRCM**（Hekate → Options → AutoRCM 开启）：机器每次开机自动进入 RCM，
   之后**不再需要拨片**。注意副作用：拔电彻底断电后必须连电脑/注入器才能开机——
   对常插电的调试机无影响。
2. **自动注入**（二选一）：
   - USB 常连 Linux 开发机 + udev 规则：RCM 设备一出现自动跑 fusee-launcher 发 Hekate；
   - 或买个十几块钱的 **RCM 注入器 U 盘**（NS-Atmosphere / RCM Loader 之类），
     插一下自动发 payload，完全脱离电脑。
3. **睡眠代替关机**：CFW 下睡眠正常工作，调试间歇直接按电源睡眠即可，
   只要不彻底断电就不需要重新注入。加上 AutoRCM 后即使断电也只用再插一下注入器。

> 电池老化机的额外提醒：NAND 备份（§3.1）和 emummc 操作耗时较长且不可断电，
> 务必插着充电器做；备份文件在电脑上留底，这台机器随时可能硬件性罢工。

### 3.3.2 供电策略（本机现状：不插充电器秒关机，PC USB 也不够）

本机电池已老化到无法补偿负载缺口，供电规则如下：

| 场景 | 供电 | 说明 |
|---|---|---|
| 日常调试 / 串流测试 | **PD 充电器（15V 档）** | PC USB 的 5V/0.9A 带不动运行负载，缺口的电全得电池顶 |
| RCM 等待注入的几分钟 | PC USB 或注入器 | RCM 待机功耗极低，够用，不会中途断电 |
| nxlink 调试 | 充电器 | nxlink 走 WiFi，不占 USB 口 |

- **换插顺序**：充电器顶住电 → 拔下、装拨片进 RCM → 插电脑（或注入器）注入 payload →
  拔下立刻回充电器。每次冷启动才需要一次。
- 电池**鼓包迹象**（后盖/屏幕被顶起）立即停用并拆电池：Switch 拔掉电池后可纯 PD 运行，
  恰好适合当常插电的台式调试机（开盖：Y00 拆四角螺丝、拔电池排线，动手前先彻底关机放电）。
- 装好 AutoRCM + 注入器后，"换插"环节只剩"断电后插一下注入器"。

### 3.3.3 RCM Loader 使用方法（本机已备）

RCM Loader 是自带电池的 payload 注入器：插到处于 RCM 状态的 Switch 上，
约 2 秒内自动把内置 payload 发进去，不需要电脑。

**一次性设置（在电脑上做）**

1. 把 RCM Loader 的**注入棒**从底座里拔出来，插到电脑 USB 口上；
2. 它会识别成 U 盘，里面有一个 payload 文件（通常叫 `payload.bin`，以你机器实际为准）；
   部分型号带按键/多槽位，每个槽位对应一个文件；
3. 下载最新版 Hekate（`hekate_ctcaer_x.x.x.bin`），**改名覆盖**原 payload 文件——
   保持原文件名不变，机器只认这个名字；出厂自带的 payload 版本太老，务必更新；
4. 注入棒插回底座充电（底座随便找个 USB 口充电，LED 亮即充电中）。

**第一次使用（还没开 AutoRCM 时）**

1. 拨片顶住右 Joy-Con 轨道针脚，按住 音量+ 再按 电源 → 黑屏即 RCM；
2. 把注入棒插进 Switch 的 USB-C 口 → LED 闪烁约 2 秒 → Hekate 启动；
3. Hekate → Options → 开启 **AutoRCM**（从此不再需要拨片）。

**日常（开了 AutoRCM 之后）**

断电重启 → 机器自动进入 RCM（黑屏）→ 插一下注入棒 → Hekate 启动 →
选 Launch → Atmosphère → 拔回充电器完事。全程不需要电脑和拨片。

### 3.4 防封号设置（emumnc 模式下）

- 系统设置开**飞行模式**（本项目是局域网串流，不需要任天堂网络）；
- Atmosphère `atmosphere/config/system_settings.ini` 可开 `incognito`（隐藏证书序列号）；
  或安装官方工具 "Incognito_RCM"。

## 4. 本项目的部署与调试（每次开发迭代）

### 4.1 手动部署（最朴素）

```bash
./scripts/build-switch.sh
cp build/switch/app/nsteamlink.nro /media/$USER/<SD卡卷标>/switch/
```

### 4.2 全内存启动（Title Redirection，串流应用必用）

**不要**从相册/hbmenu 直接打开串流应用（那是 applet 模式，只有数百 MB 内存，不够用）。
正确姿势：

> 在 HOME 菜单**任选一个已安装的官方游戏/软件，按住 R 再按 A 启动** → hbmenu 以
> 完整内存模式弹出 → 从里面启动 `nsteamlink`。

前提：机器里至少装有一个官方 title（任何免费软件都行）。

### 4.3 nxlink 网络部署 + 日志回传（开发期首选，不用来回拔 SD 卡）

Switch 与开发机在同一局域网，hbmenu 界面按 **L** 打开网络接收，屏幕会显示 IP；然后：

```bash
NRO=build/switch/app/nsteamlink.nro
SWITCH_IP=192.168.x.x        # hbmenu 按 L 后屏幕上显示的地址
$DEVKITPRO/tools/bin/nxlink -a $SWITCH_IP -s "$NRO"
#        -a 指定机器地址；-s 推送并启动后，把应用的 stdout/stderr 回传到本机终端
```

我们的 `SL_LOG` 日志走 stdout，配合 `-s` 就能直接在开发机终端看运行日志（DEVELOPMENT.md §8）。

## 5. 常见坑（对应 kickoff §7）

| 现象 | 原因 / 处理 |
|---|---|
| 注入后屏幕显示 `Missing LP0 <sleep>lib! / Missing Minerva lib! / Update bootloader folder!` | 这是 **Hekate** 的提示：SD 卡上 `bootloader/` 文件夹缺失或与注入的 Hekate 版本不配套（Minerva=内存训练库，LP0=睡眠库，均在 `bootloader/sys/` 下）。处理：下载最新 Hekate，把 zip 里的 `bootloader` 文件夹整体拷到 SD 卡根目录，并同步更新 RCM Loader 槽位里的 payload 为同一版本——**payload 与文件夹必须同发行包**。**不要无视报错继续启动**，缺 Minerva 时内存参数未训练，不稳定 |
| 应用秒退或初始化失败 | 大概率 applet 模式内存不足——回到 §4.2 用 Title Redirection 启动 |
| nxlink 找不到机器 | hbmenu 里没按 L 开 netloader；或防火墙拦 UDP 43653 |
| RCM 拨片插了没反应 | 针脚没顶到位；换拨片姿势重试；确认是未打补丁机型 |
| 串流卡顿 | 默认频率下 720p60 是基准；1080p 高码率留到 M5 且涉及超频，风险自担（kickoff §7.6） |

## 6. M2 之前你要完成的事（清单）

- [x] 确认机器类型：未打补丁初代机（2026-08-23 已确认）
- [ ] 备件到位：SD 卡（FAT32）、RCM 拨片、USB-C 数据线（可选：RCM 注入器 U 盘）
- [ ] 按 §3 走通到 hbmenu（专用调试机可跳过 emummc/防封号，见 §0 注）
- [ ] 开 AutoRCM + 常插电（§3.3.1）
- [ ] 真机上验证：按住 R 启动任意游戏能弹出 hbmenu（全内存模式）
- [ ] 机器连上家里 WiFi，把 hbmenu 按 L 显示的 IP 告诉开发机侧（nxlink 用）
