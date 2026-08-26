# Switch 版 Steam Remote Play 客户端 · 开工文档

> 目标：做一个 Switch 自制软件（homebrew）的 Steam Link 客户端，通过 Steam Remote Play 协议串流 PC 上的 Steam 游戏。
> 本文档汇总了截至 2026-08-23 的全部调研结论，所有事实均已实际查证过源码仓库，非道听途说。
> 在新机器上开工时，先让 AI 通读本文档。
> 状态性结论会随项目推进更新；当前进度以 `README.md`、`docs/M2_STATUS.md` 与 `docs/decisions.md`
> 的最新条目为准。

---

## 1. 可行性结论

**项目可行，三块核心积木都有现成的、活跃维护的开源实现：**

| 积木 | 项目 | 状态 | 许可证 |
|---|---|---|---|
| 协议层（发现/配对/串流） | [mariotaku/IHSlib](https://github.com/mariotaku/IHSlib) | 纯 C，2026-05 仍在更新 | LGPL-3.0 |
| 参考实现（端到端可用证明） | [beudbeud/plume](https://github.com/beudbeud/plume) | ~1500 行 C，2026-08 更新，实测现行 Steam 配对 + 1080p60（树莓派5） | GPL |
| Switch 平台层（硬解/输入/UI 参考） | [XITRIX/Moonlight-Switch](https://github.com/XITRIX/Moonlight-Switch) | 1600+ star，2026-07 仍在推送 | **GPL-3.0** |

**已排除的死路（不要浪费时间）：**
- `ValveSoftware/steamlink-sdk` 只是给已停产的 Steam Link 硬件盒子（ARMv7 单核 / 256MB 内存自定义固件）做插件的 SDK，**不含任何串流客户端源码**，无法移植。
- Valve 从未开源现代 Steam Remote Play 协议客户端。协议知识全部来自逆向工程：
  - [mariotaku/steamlink.py](https://github.com/mariotaku/steamlink.py)（IHSlib 的逆向基础）
  - [SteamDatabase/Protobufs](https://github.com/SteamDatabase/Protobufs)（IHSlib 直接采用其最新 proto 定义，跟得上线上协议）

---

## 2. 总体架构

```
┌─ UI 层：SDL2 界面（主机列表 / 配对码显示 / 串流安全码输入 / 串流中悬浮层）
├─ 应用层：会话管理、分辨率/码率设置、收藏
├─ 协议层：IHSlib —— 发现(UDP 广播) → 配对授权 → 视频音频控制三通道
├─ 媒体层：averne 版 FFmpeg(NVDEC 硬解 H264) → SDL2 渲染
│          libopus 软解音频 → SDL2 audio / audout 输出
└─ 平台层：薄抽象层 HAL（socket、手柄、触摸、时钟），桌面版和 Switch 版各实现一份
```

**最重要的开发策略：写一个薄平台抽象层，整套代码同时能编出两个目标——**

1. **桌面目标**（Linux x86_64）：秒级重编译调试，跑 SDL 窗口版客户端；
2. **Switch 目标**（devkitA64 交叉编译出 `.nro`）：同一套代码换平台后端。

Moonlight-Switch 就是这么组织的（`app/platforms/{windows,linux,mac,psv,...}`），照抄这个结构。

---

## 3. 各积木的关键细节

### 3.1 IHSlib（协议层，直接用）

- 头文件即文档：`include/ihslib/` 下有 `client.h / session.h / enumeration.h / video.h / audio.h / input.h / hid.h / net.h`。
- **已核实的 API 面（client.h）**：

```c
IHS_Client *IHS_ClientCreate(const IHS_ClientConfig *config);
void IHS_ClientSetLogFunction(IHS_Client*, IHS_LogFunction*);
void IHS_ClientSetDiscoveryCallbacks(IHS_Client*, const IHS_ClientDiscoveryCallbacks*, void*);
void IHS_ClientSetAuthorizationCallbacks(IHS_Client*, const IHS_ClientAuthorizationCallbacks*, void*);
void IHS_ClientSetStreamingCallbacks(IHS_Client*, const IHS_ClientStreamingCallbacks*, void*);
bool IHS_ClientStartDiscovery(IHS_Client*, uint32_t interval);   // UDP 广播发现
bool IHS_ClientAuthorizationRequest(IHS_Client*, const IHS_HostInfo*, const char *pin); // 首次 pairing code 授权
bool IHS_ClientStreamingRequest(IHS_Client*, const IHS_HostInfo*, const IHS_StreamingRequest*);
```

- **重要**：配对和串流接口都接受手动构造的 `IHS_HostInfo`，即可以跳过发现流程直接填 IP 连接。调试时发现广播若有问题，直接连 IP 即可，不阻塞。
- 构建依赖：`libprotobuf-c`（必需）、`mbedTLS` 或 `OpenSSL` 二选一做加密后端（Switch 上用 mbedTLS）、SDL2 仅其 samples 需要。
- ⚠️ 注意：plume 用的是**它自己的 IHSlib fork**（[beudbeud/ihslib](https://github.com/beudbeud/ihslib)，`plume` 分支带补丁）。用上游还是该 fork，开工时先对比补丁差异再定。

### 3.2 plume（参考答案，M1 就靠它）

- 结构极简：`src/{ihs.c, main.c, media.c, ui.c}`，IHSlib 全套用法都在里面。
- 桌面构建（Debian/Ubuntu）：

```bash
sudo apt install cmake pkg-config build-essential \
  libsdl3-dev libsdl3-ttf-dev libavcodec-dev libavutil-dev \
  libswscale-dev libswresample-dev libprotobuf-c-dev libmbedtls-dev
git clone --recursive https://github.com/beudbeud/plume.git   # --recursive 必须加
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
./build/plume --pair    # 首次：客户端显示 PIN，在 Windows 的 Steam 里输入该 PIN
./build/plume           # 启动 launcher，手柄/键盘选择主机开始串流
```

### 3.3 Moonlight-Switch（平台层素材库）

- `lib/switch/` 里**直接放着编译好的 Switch 版静态库**：`libavcodec.a / libavformat.a / libavutil.a / libswresample.a / libcurl.a`（来自 averne 的 NVDEC 版 FFmpeg fork）→ M3 可以先拿来用，跳过交叉编译 FFmpeg。
- NVDEC 硬解方案出处：[averne/FFmpeg](https://github.com/averne/FFmpeg)（把 Tegra NVDEC 接进 FFmpeg）。
- UI 框架 borealis（XITRIX fork）、mdns 发现、moonlight-common-c 都在其 `extern/` 子模块里，可按需借鉴。
- 它的代码组织：`app/src/streaming/`（串流会话）、`app/src/crypto/`、`app/platforms/<platform>/`（各平台后端）。

---

## 4. 开发环境搭建（Linux 主力机）

### 4.1 devkitPro 工具链（官方支持 Linux/macOS/Windows，Linux 最顺）

```bash
# 1. 安装 devkitPro 的 pacman（到 releases 页下对应发行版的包）
#    https://github.com/devkitPro/pacman/releases
#    Debian/Ubuntu 用 .deb；Arch 用 .pkg.tar.zst；Fedora 用 .rpm

# 2. 装 Switch 开发组件（portlibs 一并解决 mbedtls/opus/sdl2）
sudo dkp-pacman -Syu
sudo dkp-pacman -S switch-dev switch-sdl2 switch-sdl2_ttf switch-mbedtls switch-libopus

# 3. 环境变量（写入 ~/.bashrc）
export DEVKITPRO=/opt/devkitpro
export DEVKITA64=/opt/devkitpro/devkita64
export PATH=$DEVKITPRO/bin:$PATH

# 4. 验证：编译 hello world
cp -r $DEVKITPRO/examples/switch/templates/application ~/hello-switch
cd ~/hello-switch && make    # 产出 hello-switch.nro
```

- 官方还有预装 portlibs 的 Docker 镜像兜底。
- 入门文档：https://www.switchbrew.org/wiki/Setting_up_Development_Environment ；示例库：https://github.com/switchbrew/switch-examples

### 4.2 需要手动交叉编译的库（仅一个）

- `protobuf-c`：devkitPro 无现成包，但库很小。用 devkitA64 的 CMake 工具链文件 `$DEVKITPRO/cmake/Switch.cmake` 交叉编译安装到 portlibs 目录即可（M2 做）。

### 4.3 真机测试常识

- `.nro` 放 SD 卡 `sd:/switch/` 下，从 hbmenu 启动。
- **串流类应用必须经 Title Redirection 方式启动 hbmenu**（获得完整内存访问；applet 模式内存受限不够用）。Moonlight-Switch README 同款要求。
- 高码率 1080p 需超频（sys-clk 或 4IFIR 整合包）；720p60 默认频率可达。

---

## 5. 调试拓扑（已确定）

```
Linux 开发机（写码 + 编译 + 桌面测试客户端）
        │ 局域网
Windows 游戏PC（纯当 Steam host，游戏都在这）
        │ 局域网
Switch（真机联调阶段加入）
```

- 该拓扑与最终使用形态完全同构，全程真实环境调试。
- Linux 与 Windows 分离 → 客户端注入的手柄输入不会干扰 Windows 正常使用（同机调试的最大坑被天然规避）。
- Windows 防火墙需放行 Remote Play 端口：TCP 27036/27037，UDP 27031–27036（发现走 UDP 27036）。首次配对流不通时先查这里。
- 回环抓包方便：Wireshark 在任一端都能看全量协议流量。

### 性能预期（对齐 Moonlight-Switch 实测）

- 默认目标 **720p60**；1080p 高码率需 CPU/GPU 超频。这是 Tegra X1 的物理限制，不是实现缺陷。
- NVDEC 硬解 H264 是既定路线（软件解不可行），方案已被 Moonlight-Switch 验证。

---

## 6. 里程碑

| 阶段 | 内容 | 验收标准 |
|---|---|---|
| **M0** | Linux 装 devkitPro + switch-dev，hello-world 出 `.nro` | hbmenu 里跑起来 |
| **M1** | Linux 上编译 plume，配对 Windows Steam 并串流 | 桌面窗口看到 PC 画面 ← **最大风险在此消除** |
| **M2** | 交叉编译 protobuf-c + IHSlib 到 devkitA64，网络层接 libnx | Switch 上完成发现+配对码授权 |
| **M3** | 接 averne FFmpeg(NVDEC) + SDL2 渲染 | Switch 出第一帧串流画面（720p30 即可） |
| **M4** | 手柄输入回传 + Opus 音频 + 完整 UI | 可玩性：能正常操作一款游戏 |
| **M5** | 打磨：延迟统计、断线重连、1080p、NSP forwarder | 对标 Moonlight-Switch 体验 |

**关键顺序原则：先桌面后掌机。** 协议层的所有调试都在桌面目标上完成（改一行秒级重编译），Switch 只作为最后集成目标。M1 完成前不要碰任何 Switch 特有代码。

---

## 7. 已知坑清单

1. **许可证**：复用 Moonlight-Switch 的静态库/解码代码 → 项目整体须 GPLv3 开源；IHSlib 是 LGPL（注意其 fork 补丁的差异）。自制软件圈 GPLv3 完全正常，接受即可，别想闭源。
2. **plume 的 submodule**：不带 `--recursive` 克隆会静默回退到上游 IHSlib，能编译但行为不对。
3. **applet 模式内存不足**：真机测试必须 Title Redirection 启动。
4. **发现 vs 直连**：UDP 广播发现问题就用手动 HostInfo 直连（API 支持），不阻塞。
5. **音频双响**：host 本地放一遍 + 客户端放一遍，调试期静音一边，不是 bug。
6. **超频警告**：sys-clk/4IFIR 属于高风险自定义操作，作者自担。
7. **本调研的网络限制**：devkitpro.org 主站当时从调研沙盒无法直连，4.1 的安装步骤以官网/switchbrew 文档为最终准（大方向无误）。

---

## 8. 新会话开工指令（拷贝给 Linux 上的 AI）

> 先通读工作目录下的 `SWITCH_STEAMLINK_KICKOFF.md`、`docs/decisions.md`、`DEVELOPMENT.md`
> 和 `docs/M2_STATUS.md`。当前先做 Switch 真机配对与退出路径回归验收
> （广播发现、配对码授权、重启复用 `auth.bin`、PLUS/B 返回 hbmenu），通过后进入 M3 第一帧串流；
> 不要从 M0/M1 重做。
