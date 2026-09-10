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
./scripts/build-switch.sh -DNSL_DIAGNOSTICS=ON
# hbmenu 开启网络接收后上传；不要先探测 28280 端口。
$DEVKITPRO/tools/bin/nxlink -a 10.10.10.17 -s build/switch/app/nsteamlink.nro
# 或复制到 SD 卡 switch/ 目录后手动启动。

tools/switch-debugctl.py 10.10.10.17 state
tools/switch-debugctl.py 10.10.10.17 stats
tools/switch-debugctl.py 10.10.10.17 hid
tools/switch-debugctl.py 10.10.10.17 diag current
```

- 使用 Title Takeover 启动 hbmenu；在 hbmenu 按 L 开启网络接收。
- 正式应用中直接完成发现、配对和串流，不需先运行另一个 NRO。
- 首页 L/R（LB/RB）换电脑，左右摇杆／方向键直接选择游戏，A 启动所选游戏，Y 打开 Steam，B 返回，X 选项。无游戏记录时 A 也可连接。卡片支持触摸横向滑动，轻点启动；IP 与配对状态直接显示在主机标签下。
- 串流中同时长按 −/+ 0.8 秒；在游玩菜单中断开，返回首页后 B 退出。
- 仅诊断构建：游玩菜单内单独长按 X 一秒切换 Debug 浮层。完整诊断接口见 [UDP_DEBUG](UDP_DEBUG.md)。
- 设备身份、逐电脑授权和设置保存在 `sdmc:/switch/nsteamlink/profile.bin`。
  旧 `auth.bin` 迁移保留设备身份；旧格式无法证明主机唯一身份，因此首次连接需重新配对。
- `switch-stream-selftest.nro` 使用同一 runtime，默认 600 个渲染帧后清理退出，无自动串流。
- 本机 Switch 调试地址为 `10.10.10.17`，netloader 端口为 `28280`；直接使用 nxlink，不发空 TCP 探测。
- 涉及生命周期的验证要区分日志清理完成和屏幕返回 hbmenu；后一项必须由实机观察确认。

## HOME 菜单入口与 applet 拦截

应用首页 X 选项 → 添加到 HOME 菜单 → A 添加。确认前会显示固定 NRO 路径，
安装期间保留等待动画，结束后按 B 返回。需要支持自制应用的 CFW；无需填写密钥。
入口依赖 `sdmc:/switch/nsteamlink/nsteamlink.nro`，后续更新只替换此文件。
如果提示无法保存 NRO，请手动放到该路径，再从全内存 hbmenu 打开并添加。
重复添加不会覆盖已存在的入口；完整 NSP 与此入口是不同的应用标识。
从入口启动后，在应用内退出返回 HOME。可以用系统设置的数据管理删除入口，配置仍保留。

从相册 applet hbmenu 打开时，程序在 SDL/Mesa、网络和串流线程启动前拦截，
用英文软件控制台提示：按住 R 打开一个游戏进入全内存 hbmenu，重新运行 NSteamLink。
按 B 返回；这张提示不使用 Mesa 或中文字体渲染。

普通 Release NRO 不包含诊断入口。NSP 安装包与发版构建方法见 [RELEASING](RELEASING.md)。

## 最近游戏封面

首页自动为已记录的普通 Steam 游戏获取横版封面，无需登录或填写 API key。
首次取图需要能访问 Steam 商店/CDN；成功后保存在 `sdmc:/switch/nsteamlink/artwork/`，
之后即使无法访问互联网也能使用缓存。图片不会改变按电脑/账号保存的最近游戏列表。
非 Steam 快捷方式、接口不可用或图片缺失时保留游戏名称和占位，仍可正常启动游戏。
封面缓存最多 32 张；删除 artwork 目录可让应用重新获取，不会清除配对和设置。

### 界面语言

在 **选项 → 设置 → 语言** 中选择 **跟随系统 / 简体中文 / English**，立即生效并记住选择。
串流中打开菜单也可进入此设置。首次运行默认跟随 Switch 系统语言，中文系统使用简体中文，
其他系统语言使用英文；游戏卡片名称会在后台获取对应语言的商店名称，已缓存名称可离线使用。查询失败或非商店游戏
继续显示主机提供的原名，电脑名保持原文。中英文界面资源已包含在 NRO 中。

### 操作音效

菜单确认、返回、设置变化和卡片焦点移动带有轻量提示音，按键与触摸反馈一致。
连续拖动和无效操作不发声。**设置 → 声音**统一开关串流声音与界面提示音。

## 导出系统截图

先区分截图保存到了本体内存还是 SD 卡；在 sysNAND CFW 中运行，不代表截图一定在
sysNAND 内部。无需提取 NAND 镜像。下面的系统菜单路径基于 Nintendo Switch 系统相册功能，
CFW 的相册快捷方式可能由本机配置覆盖；若点击相册进入 hbmenu，可按本机配置按住 R 打开真相册。

### USB 直接复制到电脑

系统设置 → 数据管理 → 管理截图和视频 → 通过 USB 连接复制至电脑。
用支持数据传输的 USB 线连接 **Switch 本体底部 USB-C** 与电脑，不经过底座 USB 口。
Windows 中打开设备 `Nintendo Switch` → `Album`，复制需要的图片。
其他系统需要 MTP 支持，不能假定连接后会自动显示为普通 U 盘。
参见 [Nintendo 官方 USB 说明](https://www.nintendo.com/en-gb/Support/Troubleshooting/How-to-Transfer-Screenshots-and-Video-Captures-from-Nintendo-Switch-to-a-Computer-Via-a-USB-Cable-1886300.html)。

对于本项目记录的、运行时需要 PD 供电的测试机，优先使用下面的无线方式，避免为传图拔掉电源。

### 少量截图：先发到手机

打开系统相册 → 选择截图 → A 共享和编辑 → 发送至智能手机。
按提示扫描两次二维码，连接 Switch 并在手机浏览器保存图片，再传到电脑。
一次可传 10 张截图；这条路径不需要安装额外的 Switch 自制工具。
参见 [Nintendo 相册传输说明](https://support.nintendo.com/jp/switch/data_management/screenshot_movie/index.html)。

### 批量无线复制：SD 卡与 FTP

如果截图在本体内存，先在系统设置 → 数据管理 → 管理截图和视频中，
选择本体保存内存，将截图复制到 microSD 卡。不要选择删除。
普通 sysNAND 的 SD 相册目录为 `Nintendo/Album`；其中的图片可以直接复制到电脑，
无需解密。目录依据见 [Nintendo 的 microSD 图片复制说明](https://support-jp.nintendo.com/app/answers/detail/a_id/34865/)。

可从 [ftpd 官方发布页](https://github.com/mtheall/ftpd/releases) 获取 Switch NRO，
在 hbmenu 中运行。电脑与 Switch 连接同一局域网，用 FTP 客户端连接 ftpd 屏幕显示的
IP 与端口，下载 `Nintendo/Album` 目录；端口以屏幕显示为准。
传输后退出 ftpd。只需读卡复制时，也可以在关机后取出 microSD，用读卡器复制同一目录。


## deko 视频直显诊断构建

Switch 正式版与诊断版统一使用 deko 直显，不再提供 SDL 图形后端选择。
诊断版保留性能采样，正式版默认编译排除；音频、输入和字体继续使用 SDL。示例：

```sh
NSL_BUILD_DIR="$PWD/build/switch-deko" scripts/build-switch.sh \
  -DNSL_DIAGNOSTICS=ON -DNSL_BUILD_TOOLS=OFF
```

该目录生成应用 `app/nsteamlink.nro`、独立 `app/nsl-video-probe.nro` 和
`generated/graphics_manifest.json`。保存 manifest 与 NRO，不能混用不同 SDK/shader 的实测记录。
四份测试视频已经嵌入 probe，无需复制文件到 SD，也无需 Steam。设备进入 hbmenu netloader 后运行：

```sh
python3 scripts/test-switch-video.py --fixture padding720
```

无人值守、只准备一次 netloader 时使用：

```sh
python3 scripts/test-switch-video.py --fixture suite --timeout 900
```

`suite` 在一次 NRO 启动内运行四份视频各三轮，每轮创建并清理 graphics/decoder，
执行 UI、24 组独立颜色检查、512 个在途 glyph 的容量/回收检查、软件与硬件像素比较、
120 次旧帧重画和解码域重建。日志同时核对总解码数、呈现数与 mailbox 替换数：
B 帧在 EOF 批量排出时，latest-frame mailbox 可以替换尚未取走的输出，不能将此计作漏解码。
720p/1080p 首尾两轮附带 CPU 准备耗时对照，交换直接导入与下载后上传的测试顺序。
每条路径预热 8 帧、采样 64 帧，记录中位数、p95、上传次数和字节数；
垂直同步、GPU 等待及诊断回读不进入计时。这不是 SDL/deko 整体串流延迟或整机功耗对照。
进程内重复初始化也不等价于多次 hbmenu 加载，HOME/睡眠与真实串流交互须另行验收。

可选单项 fixture 为 `padding720`、`padding1080`、`sequential`、`reordered`。脚本自动推送 NRO，
接收设备阶段日志，将结果、NRO 哈希和构建 manifest 保存到构建目录的 `probe-runs/`。
日志中断或超时记为 `INCOMPLETE`，不能按 nxlink 退出码判定设备测试成功。
诊断构建链接 `deko3dd`，使 SDK 参数错误可以通过网络回传。SD 日志只是自动保留的副本，
后续启动会自动读取，不要求人工取回。

probe 先验证 UI alpha/atlas/方向，再比较软件 YUV 与硬件导入输出、旧帧重画及两域交替。
`PROBE_FINAL result=PASS` 仅表示这些像素和引用检查通过；是否回到 hbmenu、HOME/睡眠恢复、连续启动以及
整机功耗和帧时间收益需要分别记录。已经故障的 GPU queue 会进入系统 fatal，避免把仍被使用的
内存释放后返回 loader。正式启用 deko 的验收契约见 [渲染设计](VIDEO_RENDERING_DESIGN.md)。
