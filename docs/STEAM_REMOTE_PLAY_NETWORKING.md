# Steam Link 公网发现、信令与 NAT 穿透参考

证据复核日期：2026-10-16。本文是协议参考，不记录任务进度。

实现入口：§9–§11 定义发现、云端会话和授权/开流事务；§12–§14 定义传输接入、信令桥和
路径选择；§15–§18 定义网络配置、模块契约、固定版本 schema 和底层 SDR 线格式。
§19 明确这些证据能够支持的实现边界，§20 给出原始指令离线复核方法。
协议字段以仓内固定样本导出定义为准，策略以调用点为准。

## 证据范围与结论

- **Evidence**：Valve 官方公告、SteamDatabase 跟踪的协议定义、Valve
  GameNetworkingSockets 源码、下列固定版本的源码和官方 Android ELF 静态反汇编，
  以及本机 Android 模拟器与独立 WebSocket 探针的动态记录（§8）。
- **Conclusion**：官方支持公网连接；公网配对/主机状态/连接信令经过 Steam 服务，
  媒体传输另由 SteamNetworkingSockets 的 P2P/SDR 层处理。我们使用的 plume/IHSlib
  没有这条完整链路，不能通过增加一个 transport 枚举值就启用。
- **Conclusion**：独立探针已实际完成生产服务的会话创建、开始/取消配对，以及复用本设备
  配对身份的云端主机状态订阅。官方 Android 客户端已完成云端配对并进行首次网络测试。
- **未验证**：独立客户端的完整配对/SDR/媒体实现、不同公网出口之间的穿透、
  CGNAT/对称 NAT、稳定游戏串流和 Switch 接入。模拟器 NAT 的上游与主机同在一个局域网。

**证据修订（2026-10-16）**：撤回本文早期静态草稿中“本次没有调用生产配对服务”的描述。
§8 的动态证据替代这一范围声明；不能将动态发现成功扩大解释为任意 NAT 均可穿透。

复核版本：

| 对象 | 固定版本 |
|---|---|
| 本仓 IHSlib | `04688d19951c68bedc4370234cc1752043632cb3` |
| plume（本次远端默认分支 HEAD，亦为此前参考版本） | `7ebd62bbf09c43412dfad86b91885a07ef46c098` |
| plume 的 IHSlib gitlink | `8c5a17cc3da37222eb118550e2d9a62aac9f301b` |
| mariotaku/ihslib（本次远端默认分支 HEAD） | `1881b9a05f2033a9e9c41252515e96b8af8185cf` |
| mariotaku/steamlink.py（本次远端默认分支 HEAD） | `f38fe41fb87dd2ae3c42f9c3e040b2d7812367b3` |
| 官方样本 | Steam Link Android 1.3.32，`lib/arm64-v8a/libmain.so` |

ELF 来自本地 `Steam Link_1.3.32_apkcombo.com.xapk` 内的 `config.arm64_v8a.apk`，
SHA256 为 `50e1d3147d5d47b71ef1970e1867a2fe4f3e1ecf2ea6153f927fac88b88ea38e`，
与 `STEAMLINK_PROTOCOL_RE.md` 的样本一致。下文地址都是该 ELF 的虚拟地址。

动态运行的是同一 XAPK 的 Android x86_64 版本（versionName `1.3.32`、
versionCode `5000315`）。以下 SHA256 区分启动器与播放器：

| ELF | SHA256 |
|---|---|
| `libmain.so` x86_64 | `57e625cdecef4683e019109cea5bf26c67ab7d0e84bbe4c247377a0ba9a11a34` |
| `libshell_x86_64.so` | `195025601c2b17194a4d8b3debd674aca3377290fe3851986656c49bc973f907` |

**Evidence**：发现/配对界面实际走 `libshell_x86_64.so` 的云端实现。
`libmain.so` 中存在同名方法不足以覆盖启动器阶段；Frida 工具同时观察这两类模块，
本次指定配对 trace 的模块记录来自 shell。

## 1. 官方功能的公开证据

Valve 的 [Steam Link build 688 公告（2019-03-14）](https://steamcommunity.com/app/353380/discussions/0/3362406825533023360/)
明确引入 Steam Link Anywhere；入口是添加电脑时选择 Other Computer，随后按提示配对。

Valve 的 [2020-06-01 Steam Client Update](https://store.steampowered.com/news/posts/?enddate=1592347499&feed=rss)
在 Remote Play 条目明确说明：允许共享 IP 并尝试直连；NAT 穿透失败，或者中继路线更快，
仍会使用中继。因此不能把官方策略简化为“必定先直连、仅失败才中继”，也不能把公网成功等同于打洞成功。

## 2. 公网配对和主机发现

### 2.1 客户端连接 Steam Remote Client 服务

**Evidence：官方 ELF 的实际调用和字符串引用，而非只有同名 protobuf 符号。**

| 函数 | 地址 | 静态行为 |
|---|---|---|
| `CRemoteClientSession::StartResolving` | `0x790d68` | 调 `CURLHelper::GetWebAPIURLForUniverse`，以 `%s/ISteamDirectory/GetCMListForConnect/v1/?cellid=0&cmtype=websockets` 构造目录请求；格式串引用在 `0x790dac` |
| `FinishResolving` | `0x790ea4` | 从目录响应中解析 `endpoint`，随后调用 `StartConnectingWebSocket` |
| `StartConnectingWebSocket` | `0x791040` | 使用 `wss://%s/remoteplay/`；格式串引用在 `0x79111c` |
| `StartCreatingSession` | `0x791374` | 构造 `CRemoteClient_CreateSession_Request`，封装进 `CCMRemoteClient_ClientMessage`，在 `0x7913ec` 调 `SendWebSocket` |
| `HandleWebSocketPackets` | `0x7916a0` | 解析 `CCMRemoteClient_ServerMessage` |

**Conclusion**：官方 Link 有独立的云端会话和 WebSocket 控制通道。公网查找不依赖把
UDP 27036 广播发到互联网，也不是扫描公网 IP。

### 2.2 从公网办理配对

**Evidence：**

- `CRemoteClientSession::StartPairing @0x791d24` 创建并通过 WebSocket 发送
  `CRemoteClient_StartPairing_Request`（`session_id`）。服务响应的 proto 有 `pin` 字段。
- `OnStartPairingComplete @0x791a70` 从响应读取 PIN 并通知 delegate。
- `CServerManager::OnPairingStarted @0x79efb0` 使用回传的 PIN，生成密钥交换材料，
  在 `0x79f084` 调 `BCreateAuthorizationRequest`，随后在 `0x79f0ac` 调
  `CRemoteClientSession::SetPairingInfo`。
- `SetPairingInfo @0x791e20` 序列化授权请求，装入包含 `session_id`、`device_id`、
  `request` 的 `CRemoteClient_SetPairingInfo_Request`，通过 WebSocket 发送。
- [服务 proto](https://github.com/SteamDatabase/Protobufs/blob/master/steam/steammessages_remoteclient_service_messages.proto)
  定义 `GetPairingInfo_Request{pin}`，其响应包含 `session_id`、`device_id`、`request`。

**Conclusion**：该样本的公网配对码由服务响应提供，授权请求被发布到云端会话。
这与本项目局域网配对时客户端自行生成四位码的传送路径不同；二者都属于 pairing authorization，
不能与开流阶段的 connect/security PIN 合并。认证语义仍以 `STEAM_REMOTE_PLAY_AUTH.md` 为准。

**Hypothesis / 待验证**：主机依据用户输入的 PIN 调 `GetPairingInfo` 取回授权请求，是协议字段
支持的配对撮合解释；本次未反汇编 PC 主机这一调用点，也未抓取其实际请求，不能把该主机端
调用顺序、所有错误码或防滥用策略写成已经验证。

### 2.3 已配对主机在外网如何出现

**Evidence：**

- `CServerManager::OnConnected @0x79ee30` 遍历持久化的已配对 Steam ID，
  在 `0x79ee98` 调 `RegisterForStatusUpdates(steamid, device_id)`。
- `CRemoteClientSession::RegisterForStatusUpdates @0x79206c` 填充
  `session_id`、`steamid`、`device_id`，并设置 `disable_polling=true`，然后通过 WebSocket 发送。
- `CServerManager::RequestStatus @0x79a278` 构造 discovery 消息，并调用统一的 `SendMessage`。
- `CServerManager::SendMessage @0x79ad64` 将 discovery header/body 序列化。
  可用本地地址的分支在 `0x79b154` 调 `CDiscoverySocket::BSend`；
  云端分支在 `0x79b19c` 调 `CRemoteClientSession::SendMessage`，使用持久化主机记录里的 Steam ID。
- `CRemoteClientSession::SendMessage @0x79229c` 创建
  `CRemoteClient_RemotePacket_Notification`，将目标 Steam ID、session ID 和 payload
  封装进 `CCMRemoteClient_ClientMessage`，在 `0x792400` 调 `SendWebSocket`。
- `CServerManager::OnReplyPacket @0x79f17c` 把云端回包交回统一的 `BProcess`。
  服务 proto 还定义 reply payload 和 offline 通知。

**Conclusion**：公网“发现”有已配对身份和云端状态订阅作为基础，并复用 discovery 消息的
编码/处理逻辑；承载通道可以换成 Steam 服务转发。配对后即使局域网地址不可达，
仍有按 Steam 身份发送控制消息的实现路径。

不能据此推断客户端能任意枚举全网 Steam 主机，或仅凭 Steam ID 就通过主机授权。

## 3. NAT 穿透与中继是另一层

**Evidence：官方 ELF。**

- `CStreamTransportClient::SendTransportSignal @0x7d4640` 构造
  `CMsgRemoteDeviceStreamTransportSignal`，序列化 `CTransportSignalMsg`，调用
  `GenerateHMAC256`（`0x7d4838`），并在 `0x7d493c` 经 `CRemoteClientSession::SendMessage`
  转发。此处是连接信令，不能视为音视频都通过 WebSocket 传输的证据。
- `CStreamTransportSDR` 继承 `CStreamTransportSteamNetworkingSocketsBase`。
  `UpdateState @0x8011f0` 在 `0x801384` 通过虚表偏移 288 调 `ConnectP2PCustomSignaling`；
  `BHandleTransportSignal @0x801754` 通过偏移 296 调 `ReceivedP2PCustomSignal`。
  这两项已核对 ELF 重定位，非仅依据错误字符串（§8.3）。
- `QueueTransportMessage @0x8014f4` 将网络库信令加入 `CTransportSignalMsg.sdr`；
  `BGetPendingTransportSignal @0x801630` 取出待发送消息。
- 同一类有 `GetP2P_Transport_ICE_Enable @0x8011dc` 和 `BUsingRelay @0x801134`。
  因此 transport 名称 SDR 不足以单独证明某次会话实际走了中继。

**Evidence：Valve 开源网络库。**

[GameNetworkingSockets P2P 文档](https://github.com/ValveSoftware/GameNetworkingSockets/blob/master/README_P2P.md)
描述独立信令服务、ICE、STUN 和中继的分工。
[ICE 实现](https://github.com/ValveSoftware/GameNetworkingSockets/blob/master/src/steamnetworkingsockets/clientlib/steamnetworkingsockets_p2p_ice.cpp)
中的 `CheckInitICE` 根据配置收集本地/公网候选地址，配置 STUN，交换候选并尝试连通。
现代开源库可使用自己的 ICE 实现，也可使用 WebRTC ICE；不能把文档中当前的默认实现
倒推为 1.3.32 样本当时的全部行为。

**Conclusion**：有证据支持的架构是：云端撮合/状态/信令 → 网络库交换连接材料并尝试可用
路径 → 直连或 SDR 中继承载串流。STUN 用于获得 NAT 映射等候选信息，ICE 组织连通性检查；
打洞失败不妨碍通过双方主动连接公网中继来通信。实际是否直连受设置、NAT、防火墙及路径质量影响。

**边界**：实测已收到主机返回的证书字段并建立官方网络库连接；证书导入、STUN 配置和
路径选择的静态规则见 §12–§14，不能再笼统称为未知。独立 SDR 服务访问、
CGNAT/对称 NAT 的动态互操作仍未验证。旧独立 WebRTC transport 在本仓 proto 中已标
`OBSOLETE`；这不等于 SteamNetworkingSockets 内部不再使用 ICE，也不证明 SDR 就是标准 TURN。

## 4. 我们参考的上游实现到了哪里

| 实现 | 证据 | 结论 |
|---|---|---|
| plume `7ebd62b` | `src/ihs.c:173–207` 调 `IHS_ClientStartDiscovery`；`wantIp` 仅过滤发现结果；`src/ui.c:632–634` 同样使用 IHSlib 发现 | 没有独立的 Steam 云端会话、公网配对撮合或 NAT 穿透实现；手填 IP 过滤不等于公网发现 |
| plume 所用 IHSlib `8c5a17c` | `src/client/streaming.c:219–221` 只声明 `k_EStreamTransportUDP`；成功回调使用原 host IP 加返回端口 | 普通 UDP 直连实现 |
| mariotaku/ihslib `1881b9a` | `src/client/client.c:152` 起的广播发现；`src/client/streaming.c:213–215` 只声明 UDP | 远端默认分支也没有上述完整公网链路 |
| 本仓 fork `04688d1` | `src/client/client.c:171–185` 向全局/子网广播地址的 UDP 27036 发 discovery；`src/client/streaming.c:334–336` 只声明 UDP；`:208–211` 仍用 host IP 加返回端口 | 本项目的发现和开流仍是直接 UDP 路径 |
| 最早的 `steamlink.py` `f38fe41` | `service/streaming.py:25` 声明 UDP、UDPRelay、SDR；`session/client_impl.py:47–55` 的 Python 会话不使用 transport 参数选择实现，直接开 UDP socket | 有公网传输相关线索，但没有自己的完整 SDR/NAT 实现 |
| 同一 Python 项目的 `--native` 入口 | `session/client_impl.py:25–44` 指向本机官方 `streaming_client`，传 `--transport`、`--sdr_config` 等参数 | 这是调用官方程序的桥接入口，不能算开源重实现了官方网络层 |

IHSlib 的 `protobuf/discovery.proto` 确实定义了 `SDR`、`UDP_SNS`、
`supported_transport`、`relay_server`、`cert` 和 `CMsgRemoteDeviceStreamTransportSignal`；
`protobuf/remoteplay.proto:962–979` 还定义 WebRTC offer/answer/candidate 与 `sdr` 信令。
但本仓 `src/client/client.c` 虽有信令 descriptor，接收 switch 没有对应处理分支。
这是“带有协议定义”，不能作为“支持公网”的证明。

源码链接：

- [plume host discovery](https://github.com/beudbeud/plume/blob/7ebd62bbf09c43412dfad86b91885a07ef46c098/src/ihs.c#L173)
- [plume IHSlib 基线](https://github.com/beudbeud/ihslib/blob/8c5a17cc3da37222eb118550e2d9a62aac9f301b/src/client/streaming.c#L219)
- [mariotaku/ihslib transport 协商](https://github.com/mariotaku/ihslib/blob/1881b9a05f2033a9e9c41252515e96b8af8185cf/src/client/streaming.c#L213)
- [steamlink.py transport 声明](https://github.com/mariotaku/steamlink.py/blob/f38fe41fb87dd2ae3c42f9c3e040b2d7812367b3/service/streaming.py#L25)
- [steamlink.py 会话与官方程序入口](https://github.com/mariotaku/steamlink.py/blob/f38fe41fb87dd2ae3c42f9c3e040b2d7812367b3/session/client_impl.py#L25)

## 5. 接入边界

**Conclusion / 设计约束**：若要兼容官方 Anywhere，需要单独实现 Remote Client 云端会话、
配对撮合与主机状态订阅、控制消息/传输信令桥接，以及兼容的 P2P/SDR 传输后端。
原有会话、认证、音视频和输入逻辑有复用价值，但 UDP socket 的创建、收发和连接生命周期
需要与新传输后端分离；不能仅在 `supported_transport` 中加入 SDR。

[Valve 的 README](https://github.com/ValveSoftware/GameNetworkingSockets/blob/master/README.md)
明确说明开源 GameNetworkingSockets 不包含 Steam 的认证、信令和 SDR 服务访问能力。
移植该库有助于网络层实现，不等于自动获得 Steam Remote Play 的云端身份、票据及兼容性。
Switch 上的可构建性、资源消耗和官方 SDR 接入兼容性均未在本次验证。

VPN/自建隧道与 Steam Anywhere 是不同的接入路线：前者可以提供可路由的主机地址，
但不能自动补齐现有的广播发现，也不能作为已实现官方云端发现/SDR 的证据。

## 6. 静态证据复核方法

从上述 XAPK 的 arm64 split 提取 `libmain.so`，先核对 SHA256，再使用：

```sh
nm -D -C libmain.so
aarch64-linux-gnu-objdump -d -C --start-address=0x790a74 --stop-address=0x79256c libmain.so
aarch64-linux-gnu-objdump -d -C --start-address=0x79ad64 --stop-address=0x79b264 libmain.so
aarch64-linux-gnu-objdump -d -C --start-address=0x79ee30 --stop-address=0x79f240 libmain.so
aarch64-linux-gnu-objdump -d -C --start-address=0x7d4640 --stop-address=0x7d49e8 libmain.so
aarch64-linux-gnu-objdump -d -C --start-address=0x800eb4 --stop-address=0x8018a4 libmain.so
```

字符串须核对其 `adrp/add` 引用和后续调用，不能仅依据 `strings` 或导出符号认定功能。
SDR 网络接口调用有虚表间接调用；本文不把错误字符串单独当作服务接入已成功的证据。

## 7. 其他公开实现的检索边界

复核日期：2026-10-16。**Conclusion：本次没有找到能够直接复用的、独立实现官方
Anywhere 云端发现/配对及 P2P/SDR 串流全链路的第三方开源客户端。**
这是限定检索范围的结论，不是证明全网不存在，也不把支持通用 NAT 穿透等同于兼容 Steam。

检索包括网页和 GitHub 仓库/代码搜索，关键词涵盖 Steam Remote Play client、
Steam Link Anywhere、SDR，以及 `CRemoteClient_StartPairing_Request`、
`CCMRemoteClient_ClientMessage`、`CMsgRemoteDeviceStreamTransportSignal`、
`CTransportSignalMsg` 等协议接口。大量命中是 proto、自动生成绑定或官方日志；
仅出现这些名字不能作为第三方实现的证据。代码搜索索引和 fork 覆盖均有局限。

### 7.1 独立客户端

| 对象 | Evidence | 能支持的判断 |
|---|---|---|
| [IHSplay](https://github.com/mariotaku/ihsplay) `3b38260` | `.gitmodules` 的 `core` 指向 IHSlib；`app/backend/host_manager.c:98` 使用 `IHS_ClientStartDiscovery` | 客户端继续依赖 IHSlib 的发现路径，未找到额外的 Anywhere 后端 |
| [IHSplay Pro](https://github.com/skwizzy222/ihsplay-pro) `3489c92` | `core` 指向 `skwizzy222/ihslib` main；`host_manager.c:101` 同样调用 IHSlib 发现；该库 `src/client/streaming.c:210–212` 仅声明 UDP | 没有取得 SDR 后端的证据 |
| [Locomo](https://github.com/beebono/locomo) `91d497b` | README 明确要求同一局域网；`src/ihs.zig:68` 调 IHSlib 发现；其 `beebono/ihslib` master 开流仅声明 UDP | ARM64/Zig 平台实现有参考价值，非官方公网链路实现 |
| [Steam-Link-PS5](https://github.com/jmelovich/Steam-Link-PS5) `ab1d8c0` | README 明确是 LAN discovery；IHSlib gitlink 为 `scaronni/ihslib` 的 `f68de5f07e0c27ccea9f47f9f5e38fd92c99919e`，其 `src/client/streaming.c:213–215` 仅声明 UDP；本次检视的应用补丁未新增云端/SDR 路径 | 是独立客户端，但没有实现本节所查的完整公网功能 |
| [krzys-h/SteamStreaming](https://github.com/krzys-h/SteamStreaming) | 作者 README 说明原型仅在 localhost 测试、输入尚未实现、视频会停止 | 不能作为已经实现公网链路的证据 |
| [latentdev/SteamRemotePlay](https://github.com/latentdev/SteamRemotePlay) | 手写代码集中在 crypto/pairing；`PairingUtility.cs` 的设备 ID 和 token 仍为 placeholder | 不是可复用的完整公网客户端 |

另外，逐一读取 GitHub 返回的 8 个公开 IHSlib fork 默认分支的
`src/client/streaming.c`：`chunqian`、`beudbeud`、`beebono`、`h4de5`、
`versaloon`、`olebeck`、`ColdThunder11`、`Watch-Later`，均仅声明
`k_EStreamTransportUDP`。此结论只针对本次读取的分支，不覆盖全部历史/其他分支。
Pro 的 main 和 PS5 的固定 gitlink 另按上表复核。

### 7.2 名称相关但解决不同问题的项目

- [RemotePlayWhatever](https://github.com/m4dEngi/RemotePlayWhatever)：README 明确说明
  通过本地 IPC 请求已经运行的 Steam 发起 Remote Play Together；网络功能仍由官方 Steam 提供。
- [X-Stuff/steamlinknat](https://github.com/X-Stuff/steamlinknat)：配置盒子的 Wi-Fi/Ethernet、
  DHCP 和 iptables NAT 转发。它把 Steam Link 硬件用作网络网关，不是协议中的 NAT 穿透实现。
- [LibreRemotePlay](https://github.com/PiterWeb/LibreRemotePlay)：自己的 WebRTC 串流系统，
  支持自定义 STUN/TURN 和信令服务；没有给出兼容 Steam 主机或 Valve SDR 的实现。
  可参考通用穿透架构，但不能直接当作 Steam transport 插件。
- [Klepton](https://github.com/shinyquagsire23/Klepton)：将 Android ARM64 库转换并在
  Apple 平台兼容层运行，Steam VR Link 前端列为 WIP。复用官方二进制不等于开源实现了
  其中的公网协议；本次也没有取得其公网穿透成功的验证证据。
- [SteamKit](https://github.com/SteamRE/SteamKit) 等 Steam 网络库的搜索命中包含服务消息
  自动生成定义；这可以提供编码和通用 Steam 网络通信参考，不能据此宣称已经实现
  Remote Play 的主机发现、媒体会话与 SDR 接入。

**设计推论**：现有公开资料可以减少通用网络库、protobuf、平台适配的工作，
但本次没有找到替代 §5 中 Steam 专属云端/信令/传输整合工作的现成实现。

## 8. 线格式、调用证据与动态实验

### 8.1 Remote Client WebSocket 线格式

**Evidence**：§2 的反汇编、SteamDatabase 服务 proto、官方序列化缓冲区与独立探针相互对应。
每个 WebSocket binary message 直接包含一个 `CCMRemoteClient_*Message` protobuf，
本次会话中没有额外的 Steam CM/EMsg 头。`CreateSession` 请求为 `0a 00`。
fixed64 按 protobuf 的 little-endian 编码；不能误写为普通 uint64 varint。

| 客户端 envelope 字段号 | 消息 | 内层字段（号:类型） |
|---|---|---|
| 1 | CreateSession | 空 |
| 2 | StartPairing | session_id `1:fixed64` |
| 3 | SetPairingInfo | session_id `1:fixed64`，device_id `2:fixed64`，request `3:bytes` |
| 4 | CancelPairing | session_id `1:fixed64` |
| 5 | RegisterStatusUpdate | session_id `1:fixed64`，steamid `2:fixed64`，device_id `3:fixed64`，disable_polling `4:bool` |
| 6 | UnregisterStatusUpdate | session_id `1:fixed64`，steamid `2:fixed64`（proto 定义，本次未发送） |
| 7 | RemotePacket | session_id `1:fixed64`，steamid `2:fixed64`，payload `4:bytes` |

服务端 envelope 的 `1:varint` 是服务 result；本次成功值 **1**。
oneof body：2=CreateSession、3=StartPairing、4=SetPairingInfo、5=CancelPairing、
6=ReplyPacket、7=Offline。CreateSession 返回 session_id `1:fixed64` 和 universe `2:int32`；
StartPairing 返回 pin `1:uint32`；ReplyPacket 的 `1:bytes` 可重复，包含 discovery 包。
注册状态是 notification，本次没有单独的注册成功 RPC，应等待实际 status 回包。

**Conclusion**：需区分三套结果域：服务成功 `1`、authorization 成功 `0`、streaming 成功 `0`。
本次开流先收到 `streaming_result=5`（InProgress），随后才收到 `0`，不能把中间响应的
默认 UDP transport 解释为最终传输选择。异步 ReplyPacket/Offline 也不能当作某个 RPC 的响应。

云端 payload 沿用局域网 framing：

```text
FF FF FF FF 21 4C 5F A0
uint32_le header_length
CMsgRemoteDeviceHeader protobuf
uint32_le body_length
message body protobuf
```

本次验证消息类型：1=status、3=AuthorizationRequest、4=AuthorizationResponse、
5=StreamingRequest、6=StreamingResponse、7/8=ProofRequest/Response、
12=StreamTransportSignal、14=AuthorizationConfirmed。`SetPairingInfo.request` 是授权请求
body 本身；`RemotePacket.payload`/`ReplyPacket.payload` 则携带完整 discovery framing。

### 8.2 官方配对和网络测试序列

**Evidence**：官方 trace `official-pair-02`、`official-pair-cancel`、`official-host-pair`。
用户在主机 Steam 配对窗口输入客户端显示的云端 PIN 后，捕获到：

1. CreateSession → StartPairing → SetPairingInfo，服务 result 均为 1。
2. 授权请求含 device_token 32 字节、encrypted_request 256 字节、auth_key 32 字节和 request_id。
3. ReplyPacket 携 AuthorizationResponse，authorization result=0，auth_key/device_token 均为 32 字节。
4. 客户端注册状态订阅，发送 AuthorizationConfirmed（result=0），收到主机 status。
5. 首次配对自动发起 `network_test=true` 的 StreamingRequest，supported_transport 为 `[1,4]`（UDP/SDR）。
6. 云端往返 ProofRequest/ProofResponse；主机先回 InProgress，后回 Success，最终 `transport=4`、
   `relay_server` 长 18 字节、`cert` 字符串长 279 字节（长度为该次样本值，不是协议常量）。
7. 双向 type=12 信令带 32 字节 token；内层为 `CTransportSignalMsg.sdr`，本次未出现其旧 WebRTC 字段。

Android 日志记录 `Connecting` → `Handshake` → `Authenticating` → `NetworkTest` →
`NetworkTestDone` → `Idle`。SteamNetworkingSockets 先记录 `P2P SDR ... connected`，随后同时出现
本地 ICE 路由及对端 primary transport 在 ICE/SDR 之间变化的日志。
测试报告平均网络时间 78.19 ms、99.83% frame loss、result=poor。

**Conclusion**：官方完成了配对、连接、流会话认证与网络测试状态机；这不是稳定游戏串流的证据。
日志证明 SDR 和 ICE 都参与协商，不能单靠 `transport=4` 或某一行 connected 推断整个测试
始终通过中继，也不能从高丢帧断言是 NAT 穿透失败。丢帧原因仍为**待验证**。

配对和连接 PIN 的区别见 [认证参考](STEAM_REMOTE_PLAY_AUTH.md)。本次没有向主机抓取
`GetPairingInfo` RPC，所以 §2.2 的主机端具体调用顺序仍保留为待验证。

### 8.3 信令完整性、证书与 ICE

**Evidence：arm64 ELF 的数据流及重定位。**

- `CStreamTransportClient` 构造函数 `0x7d42ec` 复制末尾 `CUtlBuffer const&` 参数到
  `this+24`，长度保存于 `this+44`。`SendTransportSignal` 将序列化后的 `CTransportSignalMsg`
  放入外层 payload（字段 2），在 `0x7d4838` 使用该 buffer 作为 HMAC-SHA256 key，
  payload 原始字节为输入，32 字节摘要写入 token（字段 1）。key 的上游在本次网络测试路径
  已由 §8.8 的调用链和实际验签确认，是解密后的 streaming session key。
- 接收 `BProcessReply @0x7d4b30` 校验 framing、长度、类型 12，解外层 proto；
  `0x7d4ce8` 重算 HMAC，`0x7d4d04–0x7d4d38` 要求 token 长 32 并比较，
  校验后才在 `0x7d4d68` 解析内层信令并交给 transport。只转发裸 SDP 不符合这层格式。
- `CStreamTransportSteamNetworkingSocketsBase::BInit @0x7ffd30` 获取 Utils LibV4/Sockets LibV13；
  必要时调 `SteamDatagramClient_Init @0x7ffe18`。`0x7fffc8` Base64Decode 构造参数中的 cert，
  `0x7fffe8` 通过虚表偏移 312 调 `SetCertificate`。
- `CStreamTransportSDR::GetP2P_Transport_ICE_Enable @0x8011dc` 根据配置返回 0 或 `0x7fffffff`；
  Valve 公开头文件将它们分别定义为 Disable 和 All。
- `BUsingRelay @0x801134` 经 `GetConnectionInfo`（偏移 120）读取 flags 的 `16` 位，结果缓存 10 秒。
  Valve 头文件中该位表示 Relayed（SDR 或 TURN），不能仅凭此位区分中继种类。

`CSteamNetworkingSockets` 的虚表符号位于 `0xc46ae0`，Itanium address point 为 `0xc46af0`。
以下槽位由 ELF 的 `R_AARCH64_ABS64` 重定位直接指向具体方法：

| address point 偏移 | 重定位地址 | 方法地址 / 方法 |
|---|---|---|
| 120 | `0xc46b68` | `0x8067c0` GetConnectionInfo |
| 288 | `0xc46c10` | `0x8793c0` ConnectP2PCustomSignaling |
| 296 | `0xc46c18` | `0x8794d4` ReceivedP2PCustomSignal |
| 312 | `0xc46c28` | `0x8048d8` SetCertificate |

**Evidence：动态字段对应。** `sdr` 内部消息能按 Valve 的
[CMsgSteamNetworkingP2PRendezvous](https://github.com/ValveSoftware/GameNetworkingSockets/blob/master/src/common/steamnetworkingsockets_messages.proto)
解释：本次看到 connect_request、connect_ok、sdr_routes、ice_enabled=1、reliable_messages。
其中 `ReliableMessage.ice` 包含 auth 和 add_candidate；候选含 `host` 与 `srflx`。
这支持公开 rendezvous schema 可用于分析该样本，但不证明所有版本字段均兼容。
候选出现不等于该候选连通；仍需网络库实际选择的路径和数据包证据。

其他播放器入口的 key 传递及返回证书的内容已补充于 §12。主机内部签发策略、SDR 私有线路
协议和无官方网络库时的服务接入兼容性仍不由这些观察证明。

### 8.4 NAT 拓扑与互相独立的发现实验

**Evidence**：已有 AVD `api34_test`（Android 34 x86_64）在 `emulator-5580` 启动。
模拟器使用 `10.0.2.*` 用户态 NAT，开发机为 `10.10.10.9`，Steam PC 为 `10.10.10.166`。
测试全部由工具部署/收集，UDP 探针只发 discovery，不申请授权或串流。

| 实验 | 直接观测 | 可支持的结论 |
|---|---|---|
| 开发机 UDP 广播 | 收到 Steam PC 的 3 个回复 | 主机的局域网发现服务可响应 |
| 模拟器 UDP 广播 | 2 秒内 0 回复，无 socket error | 此次广播没有获得回复；不能据此断言任何配置下都不支持广播 |
| 模拟器已知 IP 单播 | 收到相同主机的 2 个回复 | 主机私网地址从该 NAT 内可达 |
| 官方 App 配对后重启 | 新会话注册后，经 WebSocket 收到 status | 云端订阅可在广播无回复的环境发现已配对主机 |
| 独立 Python 探针 | 新建 session，替换已捕获注册的 session_id，收到完整 status 包 | 状态订阅可脱离官方客户端运行 |

**Conclusion**：这组对照把广播发现与云端发现区分开了。独立探针没有登录 Steam 账号，
注册请求只使用本设备先前配对的 steamid/device_id；这不等于绕过媒体授权，
也没有验证任意其他身份是否能订阅。两个独立公网出口、禁止私网直连、强制中继等拓扑
属于不同实验，不能用本表结果代替。

### 8.5 工具与证据复现

依赖：Python 3.11+；生产服务探针/本地 WebSocket 测试使用 `aiohttp`；Android 控制跟踪使用
`frida`（本次 17.18.0）和相同版本的设备端 server。必须显式指定设备/进程；跟踪不替换协议返回值。
原始帧可能含 PIN、身份和密钥材料，只保存到 git 忽略的 `build/`，文件权限 0600。
发布引用使用 `steam-remote-inspect.py` 的字段/长度摘要，不发布原始数据。

```sh
# 临时云端配对槽位：Create → StartPairing → Cancel，finally 中自动取消
python3 tools/steam-remote-probe.py --start-pairing --output build/wan-pair

# 官方进程观察：设备端 server 和 adb forward 准备完毕后
python3 tools/steam-remote-trace.py --spawn com.valvesoftware.steamlink \
  --seconds 30 --output build/wan-official
python3 tools/steam-remote-inspect.py build/wan-official

# 输入必须是自己设备已捕获的完整 RegisterStatusUpdate envelope
python3 tools/steam-remote-probe.py --status-from build/wan-official/003.bin \
  --output build/wan-status

# 本地协议边界/真实 WebSocket 顺序测试，不调用生产服务
python3 scripts/test-steam-remote-probe.py

cc -std=c11 -D_POSIX_C_SOURCE=200809L -Wall -Wextra -Werror \
  tools/steam-discovery-probe.c -o build/steam-discovery-probe
build/steam-discovery-probe 255.255.255.255
```

`003.bin` 只是已配对 app 冷启动的一次文件号示例，须先从摘要确定对应消息。
`--start-pairing` 只测试服务分配/取消，不创建授权请求，不能用它完成设备配对。
输出目录必须不存在，以免覆盖证据。探针每帧限制 64 KiB，RPC 等待最多 32 个通知，
TLS 验证保持开启；Frida 最多记录 512 帧，并明确报告预算耗尽。

本机私有证据目录位于研究 worktree 的 `build/wan-research/`：
`cloud-pair-01`、`cloud-status-01`、`official-pair-02`、`official-pair-cancel`、
`official-host-pair`、`official-rediscovery` 和三组 `discovery-*.jsonl`。
其中 `official-host-pair/005.bin` 是授权成功，`042.bin` 是最终 SDR 成功响应，
`049.bin` 是出向信令、`054.bin` 是入向信令。

**采集限制**：早期配对 trace 的 ParseFromArray hook 还捕获了下游嵌套 protobuf，
不能把所有记录当成 CM envelope；本节只引用能解出完整 envelope/framing 的指定帧。
工具现已加入 ClientMessage/ServerMessage 虚表过滤；修正后的 `official-rediscovery` 捕获
8 个帧、0 解码错误。CM 与 RemotePacket 两层 hook 也会重复记录同一 payload，
不能将记录数当作实际网络包数。模拟器内置 pcap 未覆盖探针的 UDP 路径，
其接口覆盖范围未确认；不能用 pcap 中缺包推翻 socket 接收记录。

### 8.6 网络测试指标的含义与对照边界

**Evidence（2026-10-16，x86_64 `libshell_x86_64.so`，地址不沿用前文 arm64 表）：**

- 首次配对的日志在 `Authenticating → NetworkTest` 约 3.1 秒后打印
  `Timed out waiting for frame, marking test complete`，随后报告 99.83% frame loss。
  此次是官方客户端自行协商并运行；独立探针未发送 StreamingRequest，采集 hook 未替换返回值。
- `CNetworkTest` 构造函数 `0xcfeb90` 在 `0xcfec70` 将预设测试帧数设为 600（`this+0x14c`）。
  `CompleteNetworkTest @0xcff790` 在 `0xcff837–0xcff867` 使用下式生成日志中的 frame loss：
  `100 - 100 * 已记录测试帧数 / 预设测试帧数`。
  分子是 `CNetworkStats` 的计数（`this+0x24`），不是网络库的 UDP 丢包计数。
  `RecordFrameReceived @0xd00d10` 将帧交给 stats；
  `CNetworkStats::RecordFrameReceived @0xcfe000` 在 `0xcfe043–0xcfe050` 递增对应计数。
- `HandleNetworkTest @0xcff630` 在 `0xcff6b6–0xcff6d4` 根据最近帧时间检测超时，
  打印上述日志并结束测试；这不同于统计网络库实际发送和接收的数据包之差。

**Conclusion**：首次配对的 99.83% 与该公式下仅记录到 600 个预设帧中的 1 个相符。
这是根据计数公式与四舍五入数值的推论，不是读取到了实时计数器。
它证明该次测试没有按预期完成测试帧接收/记录，不能直接解释为公网链路有 99.83% UDP 丢包，
更不能由它判定官方协议整体性能或本项目选择了错误协议。

**Evidence：未挂 Frida 的官方手动网络测试。** 冷启动同一 AVD，未启动 Frida server、
未注入进程、未启用模拟器 pcap。在设置的 Computer → Network Test 入口测试同一主机，
日志连接地址为 `10.10.10.166:27031`，没有 SteamNetworkingSockets 初始化/选路记录。
UI 持续绘制测试曲线，并显示测试目标速率达到 125 Mb/s（目标值不等于已测可用吞吐）。
从进入 NetworkTest 至结束约 54 秒，日志报告平均网络时间 8.27 ms、stddev 2.99 ms，
同时报告 **-410.17% frame loss** 和 `excellent`。

**Conclusion**：直接地址与网络库日志支持将该次作为普通内网直连的基线；它展示了持续测试
数据接收。负的 frame loss 无法作为真实丢帧率使用：预设分母 600 用于持续测试时，接收帧数
可超过分母。`excellent` 标签也不能代替实际丢包/吞吐测量。不得把负值截断成 0% 并宣称无丢包。

两次实验同时改变了采集工具、测试模式和传输路径（首次为已捕获的 transport=4，
对照为内网直连），因此它们不构成严格的 Frida 开销 A/B。
**待验证假设**包括首次连接的 SDR/ICE 选路或传输处理、测试模式兼容性、模拟器及采集开销；
需在相同模式/路径下对照后才能归因。相关原始日志和反汇编位于私有目录
`build/wan-research/official-uninstrumented/`。

### 8.7 单一出口下的中继隔离实验

**Evidence（2026-10-16）**：Android 34 AVD 支持 root adb、iptables/ip6tables。
`tools/android-network-sandbox.py` 仅在明确选择的 `emulator-*` 中，按 Steam Link 应用 UID
挂接随机命名的 OUTPUT 子链；阻断 trace 中的 7 个主机/共享出口候选地址（IPv4 5 个、IPv6 2 个）。
DNS、Steam CM 和其他 SDR 节点地址仍允许。未修改开发机或 Steam PC 的防火墙。

同一主机与模拟器、同一个互联网出口，未挂 Frida 的官方手动网络测试记录：

- 云端获得主机状态并收到 StreamingSuccess；网络库选择 `hkg#458` 为 primary。
- 对端 primary 为 SDR，连接日志为 `P2P SDR ... connected`，之后完成 Handshake/Authenticating。
- 进入 NetworkTest 后持续接收约 18 秒，UI 测试目标速率达到 40 Mb/s；
  日志平均网络时间 55.39 ms、stddev 3.56 ms。目标速率不等于已测可用吞吐。
- 未出现 ICE writable/receiving 或转为 `P2P ICE` 的记录；退出仍为 `P2P SDR ... closed by app`，
  同时报告 ICE failure：`No public or relay candidates from remote host`。
- 阻断规则计数：IPv4 271 包、IPv6 108 包。实验结束删除所有自建链与 owner 跳转；
  同一应用 UID 下的 UDP 单播探针恢复收到主机的 2 个回复。

**Conclusion**：单一公网出口不妨碍双方经 Valve SDR 节点通信。上述证据支持这次选中了中继
并有持续测试数据，补上了 §8.4 中纯中继方向的受限网络对照；它仍不能代替两个独立 NAT
之间 ICE 公网打洞的测试，也不构成稳定游戏串流或精确丢包率证明。
连续测试本次仍报告负 frame loss（-51.83%），按 §8.6 处理，不将其解读为无丢包。

```sh
# peer-addresses-private.json 是从自己会话候选地址整理的 JSON 字符串数组。
# 同一出口时也需覆盖双方可能使用的公网回流地址；新增候选需要重新核对。
python3 tools/android-network-sandbox.py --serial emulator-5580 \
  --peer-file build/wan-research/peer-addresses-private.json \
  --output build/wan-research/relay-firewall --seconds 90

# 另一种独立实验：只对该 app 的出向 UDP 施加 2% 随机丢包。
python3 tools/android-network-sandbox.py --serial emulator-5580 \
  --udp-loss 0.02 --output build/wan-research/outgoing-loss --seconds 30
```

随机丢包规则的内核支持已通过实际创建/删除验证；尚未由该规则完成丢包率统计或抗丢包性能验证。
规则只作用于该应用出向流量，不伪装成双向丢包。工具记录原始规则、命中计数及清理结果到私有目录，
正常退出、异常及 SIGINT/SIGTERM 均执行清理；不 flush/restore Android 的全局规则。

### 8.8 信令 key 的来源与独立 codec

**证据修订（2026-10-16）**：撤回早期“本次网络测试的 HMAC key 来源未明”的范围声明。
以下地址均为 x86_64 shell，不能与 arm64 对象偏移混用：

1. `CServerManager::BSaveEncryptedSessionKey @0xd098a0` 在 `0xd09921` 调 SymmetricDecrypt，
   用 manager 的配对 key buffer（`this+0x218`）解密开流响应中的 encrypted_session_key；
   明文存入 `this+0x398`，长度在 `this+0x3ac`。
2. `CPanelConnect::SetPanelStateNetworkTest @0xcc78f0` 在 `0xcc7a1a–0xcc7a2f` 取该明文和长度，
   调 `CNetworkTest::SetAuthToken`；后者写入 network test 的 `CUtlBuffer`（`this+0x90`）。
3. `CNetworkTest::BConnect @0xcff330` 在 `0xcff473–0xcff487` 把此 buffer 作为构造参数传入
   `CStreamTransportClient`，接上 §8.3 的 HMAC 调用链。
4. 使用该设备保存的配对 secret，按本仓既有 AES 加密 IV + CBC/PKCS7 算法解密此前捕获的
   StreamingResponse，得到 **16 字节** session key；独立 HMAC 校验通过 9 个出向信令及
   3 个入向信令（后者分别含 3、2、1 个 rendezvous 消息）。未打印或提交 key。

**Conclusion**：在已验证的网络测试链路，长期 pairing secret 用来解密 session key；
session key 用来认证 transport signal。不能把 32 字节的 HMAC 摘要长度当作 key 长度，
也不能直接拿持久化 pairing secret 对信令做 HMAC。

`tools/steam-remote-signaling.py` 是实验版封装/验签实现：输入 session key 和原始
`CTransportSignalMsg`，输出 type-12 discovery 包；接收时先校验完整 framing 和 HMAC，
再解析内层。GNS rendezvous 按不透明 bytes 保留，交给将来的网络后端。
它和云端探针组成已实现的协议部分；不包含证书服务、GNS 连接或音视频接收后端。

### 8.9 LAN/WAN 的丢包恢复是否共用

**Evidence：** UDP 和 SDR/SNS 对象均传给 `CStreamConnection::Create(IStreamTransport*)`，
该函数在 x86_64 shell `0xd21890` 创建相同的 CStreamSocket/CStreamConnection。
上层 CStreamChannel 可靠窗口、ACK/NACK、帧序号与反馈机制见
[既有协议参考 §9、§14](STEAMLINK_PROTOCOL_RE.md)。IHSlib 的 `session/clock.c`、
`session/retransmission.c` 已按该证据处理 RTT、可靠重传和 NACK；它们不是只因 LAN 就能省略的逻辑。

**Evidence：** `CStreamTransportSteamNetworkingSocketsBase::Send @0xd27760`
在 `0xd277ad` 将 flags 设为 **0x15**，在 `0xd277b6` 经虚表偏移 88 调 SendMessageToConnection。
`CSteamNetworkingSockets` address point `0x146a9b8` 的槽 `0x146aa10` 有 ELF 重定位指向
`SendMessageToConnection @0xd41800`。Valve 公开头文件中 0x15 是
Unreliable + NoNagle(1) + NoDelay(4) + UseCurrentThread(16)，不含 Reliable(8)。

**Conclusion**：该样本将流协议包通过 SNS 不可靠消息发送，上层流协议仍处理自己的可靠通道；
不能因为 GNS 支持可靠消息，就把本项目控制包改成双层可靠传输，或删除上层 ACK/NACK。
ICE 直连与 SDR 中继共用 SNS backend；普通 UDP 与 SNS backend 的封装、加密、MTU、
连接维护和网络库拥塞处理有差异，上层也可依据 RTT/丢帧反馈调整策略。
这支持“共用流会话逻辑、替换传输后端并按测量适配”，不支持“LAN/WAN 所有处理完全相同”，
也没有证据要求重写一套专属公网音视频协议。

**待验证**：所有传输下的参数默认值、主机端码率/FEC/可靠媒体决策与动态变化。
本仓仍未实现官方全部媒体能力，尤其不能把官方 FEC/可靠媒体能力直接声明为本项目已支持。

## 9. 官方客户端行为规格：状态机与策略证据

本节描述固定样本的行为，不将协议字段存在、编解码测试通过或一次成功连接扩大为完整策略兼容。
除明确注明外，地址均为 §1 固定 SHA256 的 arm64 `libmain.so`；x86_64 shell 的交叉核对另列。
**静态证据**证明分支与常量存在；**动态证据**证明指定输入下实际走过该分支。
实现需要依据触发条件、状态迁移、动作和计时规则处理；尚无证据的默认值不得冒充官方策略。

### 9.1 云端会话状态机

`CRemoteClientSession` 的状态保存在 `this+24`：0=Idle，1=Resolving，2=连接 WebSocket，
3=创建服务会话，4=ConnectionFailed，5=Connected。0/4 的名字由 `BConnect` 断言支持，
其余由各 Start 函数及成功分支支持。这套数字不同于 manager、transport 和底层 WebRequest 的状态。

| 触发条件 | 官方动作/迁移 | Evidence | 证据范围 |
|---|---|---|---|
| Idle/ConnectionFailed 调 BConnect | 在 WebSocket 能力可用时进入 Resolving，取 CM 目录 | `0x790ce8–0x790d04`、`0x790d88–0x790dac` | 静态；正常创建有动态记录 |
| 正在连接的底层 WebSocket 尚未就绪 | 底层状态值 2 时继续等待；值 3 时进入创建服务会话；其他值换 CM endpoint | `UpdateWebSocket 0x791c54–0x791c90`、`0x791d04–0x791d10` | 故障分支为静态 |
| CM endpoint 切换 | 先清理旧 WebSocket，再从候选队列取下一个；队列耗尽进入 ConnectionFailed | `StartConnectingWebSocket 0x79106c–0x791100` | 静态 |
| 无可用目录候选/候选耗尽/创建服务会话失败 | 清理 WebSocket；设置重试时刻 `Plat_FloatTime()+10+20*WeakRandomFloat(0,1)` | `0x790fa8–0x790fe4`、`0x7910b0–0x7910f4`、`0x7918cc–0x79190c`；公共失败函数 `0x79125c` | 静态，约 10–30 秒随机等待；不是按尝试次数倍增 |
| ConnectionFailed 到达重试时刻 | 调 BConnect，重新进入目录解析/连接流程 | `0x791cbc–0x791cdc` | 静态 |
| CreateSession 服务成功 | 保存 session_id/universe，进入 Connected，通知 delegate | `0x791800–0x79182c` | 静态＋动态 |
| 已 Connected 的底层 WebSocket 不再报告值 3 | 先通知 delegate 断开，Disconnect 清理，再直接调 BConnect | `0x791c10–0x791c40`、`0x791cd0–0x791cdc` | 静态；此分支本身不使用上面的随机等待 |
| 新的云端会话建立 | manager 按保存的主机 Steam ID/device ID 重新注册状态 | `OnConnected 0x79ee30–0x79eea8` | 静态＋冷启动动态；断线重订阅未单独实测 |

公共失败函数在 x86_64 shell `SetConnectionFailed @0xd01760` 也使用 10、20、
WeakRandomFloat(0,1)，与 arm64 一致。不能由此假定底层 DNS/TLS/HTTP 连接也使用同一个超时；
`CWebRequest::BStart 0x7f1c90–0x7f1f20` 创建 easy handle、设置 URL/回调/redirect/no-signal/
证书回调等并交给 multi manager，这段没有设置独立的 DNS/TLS/总请求 timeout。
因而不能从这里臆造“全部连接统一 10 秒”；未显式配置的底层期限由嵌入 curl 实现决定。

**实现约束**：新连接必须取得新的 session_id 并恢复订阅；持久化配对关系与临时云端 session
分别处理。上述证据不证明正在进行的配对会自动恢复，也不授权把旧 session 的请求原样重放到新 session。

### 9.2 事务与错误不能统一处理

**Evidence：`HandleWebSocketPackets @0x7916a0`。**

- protobuf 解析失败只记录日志并继续消费下一帧（`0x79177c–0x7917c8`）。
- CreateSession 服务失败清理 WebSocket 并进入随机等待（`0x7918cc–0x79190c`）。
- StartPairing、SetPairingInfo、CancelPairing 的服务失败通知 pairing-failed delegate
  （`0x7917ac–0x7917bc`、`0x791830–0x791840`、`0x791914–0x791930`），该分支没有重建云端连接。
- ReplyPacket 失败只记 GetReplies failed；成功则遍历全部 payload 交给 delegate
  （`0x791868–0x7918c8`、`0x791938–0x79193c`）。Offline 走独立 delegate。

**Conclusion**：解析错误、服务会话错误、配对事务错误、主机 offline 是不同事件。
不能给所有错误套同一个“断开→重配对→重试”动作。协议中的三套 result 仍按 §8.1 区分。
这些错误分支的具体 UI 表现、失败后是否由上层触发再次配对仍须另证。

### 9.3 开流请求重试与底层可靠包重传

**Evidence：** `StartStreaming @0x798d94` 仅在不是“同一主机的正在开流事务”时建立新事务，
在 `0x798e80–0x798ea0` 设置 manager 状态 5 并生成/保存 request_id（manager+512）。
`SendStartStreamingRequest` 每次从同一字段读取 request_id（`0x79941c`），
再次调用 `BGetDeviceToken`（`0x7993d8`），发送后将下一次时刻设为 **`time(NULL)+1`**
（`0x79979c–0x7997ac`）。manager Update 仅在状态 5 且到达该时刻重发（`0x798c58–0x798c78`）。

**动态证据：** `official-host-pair` 的三次 CM StreamingRequest（`019.bin`、`025.bin`、`037.bin`）
request_id 相同，相邻采集时刻差 0.299 秒、1.000 秒；body 的变化仅在字段 7（device_token）。
这与按整秒 `time()` 调度、每次重新构造 token 相符。三次响应（`032.bin`、`038.bin`、`042.bin`）
均匹配当前 request_id，结果依次为 InProgress、InProgress、Success。

**Conclusion**：应用级“再次请求开流”保留事务 ID，但可以重建认证材料；它不等于重发完全相同的
网络包。也不能把 `time()+1` 写成“从上次发送完成起精确等待 1000 ms”的官方行为。
底层可靠通道的加密帧/包重传则按既有协议参考处理，不能重新分配加密序号或随意替换密文。

**静态证据：** `HandleStartStreamingResponse 0x79e884–0x79e88c` 比较非零 request_id；
不匹配分支在收到 InProgress 时构造 StreamingCancel（`0x79e94c–0x79e9b8`）。
最终成功后才保存所选 transport/relay/cert，并解密 session key。
不能把迟到响应与当前事务合并，也不能把 InProgress 中的默认 transport 当最终协商结果。
上述迟到响应的取消分支尚无故障注入动态记录。

### 9.4 控制消息承载与传输信令队列

**Evidence：** manager SendMessage 在 `0x79b118–0x79b154` 按 HasIP、port、
本地发送开关和 discovery socket 是否可创建选择 UDP；否则走 `0x79b15c–0x79b19c` 的云端分支。
`BSend` 返回后直接结束该分支（`0x79b158`），此处没有按发送返回值追加一次云端转发。
因此“UDP 发失败便马上自动改走云端”不是此函数已有的策略；更上层的地址失效处理需单独跟踪。

`CStreamTransportClient` 是另一套信令桥接生命周期：

- Update 先更新 transport，再循环取出 backend 已产生的信令（`0x7d451c–0x7d4558`）。
- 云端未 Connected 时，SendTransportSignal 深拷贝内层消息并入 FIFO
  （`0x7d4670–0x7d467c`、`0x7d4730–0x7d4758`）。
- OnConnected 按队列顺序发送并销毁待发消息（`0x7d49e8–0x7d4a60`）；不是仅保留最后一条候选。
- 是否保持云端会话由 backend 是否需要信令或待发队列是否非空共同决定
  （`0x7d455c–0x7d45e4`）。该对象的重连调度还受自身 Update 的调用条件约束，
  不能直接把 manager 的生命周期套到它上面。
- SDR backend 会批量 swap 出 pending `sdr`，然后 Clear 暂存 message
  （`0x801630–0x8016b4`）。每个 cloud payload 可以包含多条 rendezvous，不能当作重复包丢弃。

**证据修订**：不能将本节的云端需求条件理解成“所有调用者遵守 §9.1 的失败退避”。
桥接器在状态 0/4 且仍有需求时会直接 BConnect，覆盖 session 自己等待 deadline 的机会；
完整调度规则、队列及销毁路径见 §13。新增本地资源上限必须标明本项目策略。

### 9.5 SDR 初始化参数与网络库职责

**Evidence：arm64 `UpdateState 0x801330–0x801448`，x86_64 shell `0xd28829–0xd28945` 交叉对应。**
配置编号/语义依据 Valve 公开 `steamnetworkingtypes.h`，数值为样本显式传入的值：

| 配置 | 官方样本值 | 调用证据与边界 |
|---|---|---|
| Unencrypted (34) | 2 | 创建 ConnectP2PCustomSignaling 时的第一个配置；公开 API 表示允许并偏好未加密网络库连接。仍取决于对端协商，不证明某次实际未加密，也不表示可跳过上层认证或证书 |
| P2P_Transport_ICE_Enable (104) | 开关决定 0 / `0x7fffffff` | 创建连接时传入第二个配置；不能一直用库默认值替代用户/配置的 IP-sharing 策略 |
| SendRateMin (10) | 104857600 bytes/s | `0x80139c–0x8013c8`；为网络库发送速率边界，不等于串流目标码率或实际吞吐 |
| SendRateMax (11) | 104857600 bytes/s | `0x8013cc–0x8013f0`；与最小值相同，不能假设采用开源库默认速率即可复现 |
| TimeoutInitial (24) | 20000 ms | `0x8013f4–0x80141c`；这是 SNS 初次连接超时，不是目录、配对、开流请求或等待测试帧的统一超时 |
| EnableDiagnosticsUI (46) | 0 | `0x801420–0x801444`；诊断设置不属于线上消息字段 |

此函数没有自行排序 ICE candidate 或按固定 RTT 差值切换中继；候选检查与路径选择交给网络库。
`ConnectP2PCustomSignaling` 返回无效 handle 时设置 transport 失败状态 3
（`0x801480–0x8014c4`）。收到不能处理的 custom signal 也会关闭连接并设失败
（`0x801800–0x801864`），此处未实现自动换成普通 UDP 的重试。

**Conclusion**：不能只实现相同 API 调用却忽略显式参数，也不能按 SDK 某个接口“支持可靠发送”
就替换样本的 flags=0x15。上层流协议、SNS 网络库和 Steam 服务各自承担一部分策略；
路径切换迟滞已由 §14 静态还原，不能再统称未知；SDR 节点内部排序和主机端媒体/FEC
决策不能凭一份成功 trace 补成固定规则。

### 9.6 复刻范围与验证判据

现有探针的最多 3 个候选、10 秒默认等待、64 KiB 帧限制、32 个异步通知预算，以及 Frida 的
512 帧采集预算，均是**研究工具的运行边界**。它们没有被证明是官方限制，不能直接移入产品状态机。
本地 codec/清理测试通过，只支持相关编解码、验签和工具清理，不支持“策略复刻已经完成”的判断。

行为对照需能判断：故障发生在哪个状态、保留/重建哪些身份和事务、是否通知上层、何时重试、
如何处理迟到/重复消息，以及取消后是否仍有旧 worker/消息影响新连接。
需要偏离官方样本时，记录证据、理由及互操作结果；例如不应把连续测试的负丢帧指标照搬为产品统计。
静态尚未覆盖的部分继续标记待验证，动态实验的单次成功不能扩展为所有异常路径的兼容性。

## 10. 发现、地址缓存与控制消息选路

本节的 `client_id` 是 discovery header 的主机设备标识，`steamid` 是云端路由使用的 Steam
身份；同一个主机记录可以有多个 steamid。二者不能共用一个键。`CServerManager` 使用
client_id 索引状态/持久信息，保存 steamid 列表，并以列表首项发送云端 RemotePacket。
`BAddSteamID @0x79bd74` 把新身份插到首位；已存在的非首项与首项交换。

### 10.1 地址记录不是“所有公布 IP 均可直连”

**Evidence：** `BProcess @0x799e48–0x79a178`、`BAddNetworkAddress @0x79c040`、
`GetAddress @0x79c25c`、比较器 `AddressInfo_t::operator< @0x7a3140–0x7a3258`。
每条地址记录含：是否实际收到该地址回复、是否为 status 中的 remote_ip、最后实际回复时间、
IP/类型/端口。这里给字段取的中文名来自写入调用点，不是恢复出的原始 C++ 成员名。

| 地址来源 | 实际回复标志 | remote_ip 标志 | 用途 |
|---|---|---|---|
| 收到 UDP status 的源地址 | true，并更新 `time()` 和端口 | 不新增此标志 | 可以被选作控制消息直连地址 |
| status.remote_ip | false | true | 加入候选，供后续 discovery 单播探测 |
| status.ip_addresses | false | false | 同上 |
| 持久化地址文件重新加载 | false，时间 0 | false | 重新探测，不直接继承上次运行的可达性 |

比较顺序为：实际回复优先 → IP 类型不同时 IPv4（内部类型 3）优先 → 非 remote_ip 优先 →
回复时间相差超过 3 秒时较新优先 → IPv4 数值/其余地址文本顺序。
更新时间差不超过 3 秒时不会单靠时间决定排序。匹配已有 IP 时不重复插入；实际回复会更新
可达标志、时间、端口；已有 remote_ip 标志只置位不清零。排序是地址管理规则，不是 ICE 候选排序。

**比较器的适用边界**：上述时间容差按每一对地址比较，不是能直接展开成全局 tuple 的排序键。
合成输入 A=(time=104, IPv4=3)、B=(102,2)、C=(100,1)，其余标志相同时，原始比较器返回
`A<C`、`C<B`、`B<A` 均为 true：前一对由时间决定，后两对由 IP 决定。这里存在不传递的
两两比较，不能声称所有地址集合都有唯一的规范顺序；测试只证明比较器结果，不证明某种
标准库 sort 对这组输入的最终排列。实现若改用确定的全局顺序，须注明本项目差异。

`GetAddress` 和 `SendMessage` 的隐式选址只取排序后第一条且要求实际回复标志为 true。
`SendMessage @0x79ae04–0x79ae9c` 仅在调用方没有提供完整 IP+port 且 client_id 非零时查缓存。
选不到则保留空地址，经过 §9.4 的云端分支。显式传入的 IP+port 会跳过缓存选择。
**Conclusion**：云端发现成功后，可以在后台探测公布地址；公布地址本身不等于验证了直连。

`ClearInactiveAddresses @0x79be58–0x79c03c` 删除标志为 false 的地址，而非按固定秒数删除。
首次处理主机 status 会先执行该清理，再加入本次公布地址。可见主机表的 30 秒过期与地址记录
的可达标志是两件事；在上述地址函数中没有“UDP 发送 N 次无回应后清除标志”的计数器。
不得将主机表过期自动解释成按秒失效的地址缓存或已实现的 UDP→云端故障回退。

### 10.2 discovery 调度与在线判定

**Evidence：** `Update @0x798a18–0x798c58`、`RequestStatus @0x79a278–0x79a428`。
计时用整秒 `time(NULL)`，不是网络库的微秒单调时钟：

```text
if now >= next_discovery_round:
    next_discovery_round = now + 12 + WeakRandomInt(1,5)
    discovery_sequence++
    sends_in_round = 1
    next_extra_send = now + WeakRandomInt(1,3)
    RequestStatus()
else if sends_in_round <= 2 and now >= next_extra_send:
    sends_in_round++
    next_extra_send = now + WeakRandomInt(4,7)
    RequestStatus()
```

每轮首发加两次补发；调用 Update 的频率会推迟实际执行，不进行追赶式补发。
`GetRediscoverInterval @0x79a270` 返回 12，只是上述基础值，不等于每次广播都恰隔 12 秒。
`EnableBroadcastDiscovery` 使用引用计数并触发刷新；`AddClientDiscovery` 维护唯一 client_id
列表并将下一轮时间清零。`RequestStatus` 对这些主机的全部保存地址向 **27036** 发 discovery；
另在广播引用计数非零或定向列表非空时发全局广播。广播引用计数为零时，广播消息还携带
定向 client_id 列表。证据地址：`0x79a600`、`0x79a668`、`0x79a6c4`、`0x79a330–0x79a424`。

接收到的 status 每次更新可见表；内容变化才发“主机变化”delegate，时间仍会刷新。
云端到达的 status 会另把主机放入云端在线集合（`0x799e74–0x799ea0`）。
**边界修正**：撤回“超过 30 秒才过期”的严格大于表述；普通记录在 `now-last_status >= 30`
时即从可见表删除（`0x798b48–0x798b50`），恰好 30 秒也删除。在云端在线集合里的记录不受这条规则
删除（`0x798b2c–0x798b50`）。Offline（云端通知或 discovery type 2）清除可见记录和云端在线集合，
通知删除；不会删除长期配对密钥或触发重新配对（`0x79a03c–0x79a0a4`、`0x79f240–0x79f2f0`）。
云端断开清空云端在线集合，随后普通过期规则重新生效（`0x79eef0–0x79ef54`）。

`HandleNetworkChanged @0x79a614` 只在 manager Idle 时清零可见记录时间并立即触发发现；
它不是任何流状态下都重启 ICE 的通用网络变化处理器。

## 11. 配对、开流与 Proof 的完整事务规则

### 11.1 manager 状态域与云端配对

**Evidence：** manager 状态在 `this+8`；由写入和读取调用点还原如下。名称是本文语义名，
不要把这些数字传给 §9.1 的云端 session 或 §12 的 transport。

| 值 | 语义 | 主要迁移 |
|---|---|---|
| 0 | Stopped | BStart 成功→1；Stop→0 |
| 1 | Idle | StartPairing→2；StartStreaming→5 |
| 2 | 等待云端分配配对码 | OnPairingStarted 构造请求并 SetPairingInfo→3 |
| 3 | 等待云端设备授权 | 成功通知 delegate 并停止事务→1；云端断开→失败并回 1 |
| 4 | 已知主机的授权事务 | 重发 AuthorizationRequest；授权成功→5 并立即重发开流 |
| 5 | 等待 StreamingResponse | Success 且 session key 解密成功→6 |
| 6 | 开流材料已就绪 | 上层创建传输/串流对象；不代表已收到媒体 |

`BStart @0x798840` 先 Stop，按开关创建 discovery socket、云端 session，再进入 Idle。
若启用本地发现但 discovery socket 初始化失败，本函数直接失败，不继续云端初始化。
流式应用可选择自己的初始化失败降级方式，但要标为本项目策略。

`StartPairing @0x79c514` 只在云端 session 已 Connected 时发 StartPairing；否则失败，
不会自动保留一笔“联网后再执行”的配对。`OnPairingStarted @0x79efb0` 仅接受 manager 状态 2；
若用户已取消/切换状态，则发送 CancelPairing 清理迟到的配对槽位。
有效 PIN 以 `%4.4u` 格式化，创建新的 X25519 密钥对和临时 32 字节 secret，再调用
BCreateAuthorizationRequest；SetPairingInfo 成功仅表示发布完成，授权成功仍等待主机的
AuthorizationResponse。session 的 SetPairingInfo/CancelPairing 成功 callback 自身无附加动作
（`0x791ac4`、`0x791b00`）。

`CancelPairing @0x79c540` 在云端 Connected 且 manager 为 2/3 时先发服务 CancelPairing，
再 StopStreaming(0)。**边界修正**：撤回可将此处理解为“取消总会清理本地事务”的表述。
session 不存在、未 Connected 或 manager 不在 2/3 时，函数直接返回，连本地 StopStreaming
也不执行（`0x79c540–0x79c594`）。StartPairing 则先写状态 2，未 Connected 时以 error=18
停止事务；两者的离线处理不对称。manager OnDisconnected 仅显式中止状态 3（`0x79ef58–0x79ef6c`）；
OnConnected 只恢复主机订阅，不重放 StartPairing/SetPairingInfo。
**实现约束**：不能靠重新创建 session 延续旧配对 PIN。断线后的 UI 退出/重新开始需有明确事务
归属。为阻止旧 callback 影响新事务而增加 generation 标识，属于本项目并发控制，非线上字段。

### 11.2 授权回复、重复密钥交换及持久化

**证据修订**：撤回此前“只在 manager 3/4 接受当前授权”可被理解为入口已校验当前主机、
以及“带 auth_key 就交换”的泛化规则。`HandleDeviceAuthorizationResponse @0x79d680` 的实际顺序是：

1. 仅 manager 3/4 进入授权处理，其余状态转到过期回复分支。
2. 在检查 auth_key 前先检查 `result==0`（`0x79d6c8–0x79d6cc`）。非 Success 不做密钥交换，
   即使消息带 auth_key，也按下表处理。
3. Success 时读取持久化记录、steamid 和 auth_key。带 auth_key 则调用密钥交换并发送 type 14
   确认；交换函数返回 false 时退出，不推进事务。不带 auth_key 且状态 3 则保存已有 secret，
   属于另一个兼容分支（`0x79d7f8–0x79d830`）。
4. 然后才按 manager 状态分派；状态 4 在此处校验来源 client_id 等于当前目标
   （`0x79d954–0x79d968`）。它不是整函数的入口过滤器。

| authorization_result | manager 3：云端配对 | manager 4：已知主机授权，来源匹配 |
|---|---|---|
| 0 Success | 完成授权、通知 delegate、结束配对事务 | 转状态 5 并立即发送 StreamingRequest |
| 1 Denied | StopStreaming(error=2) | 同左 |
| 2 NotLoggedIn | StopStreaming(error=3) | 同左 |
| 3 Offline | StopStreaming(error=4) | 同左 |
| 4 Busy | StopStreaming(error=5) | 同左 |
| 5 InProgress | **StopStreaming(error=1)** | **保留事务，直接返回** |
| 6 TimedOut | StopStreaming(error=6) | 同左 |
| 7 Failed、8 Canceled、其他值 | StopStreaming(error=1) | 同左 |

表中 result 是 ERemoteDeviceAuthorizationResult，error 是内部 EServerError；不能套用 §11.3 的
StreamingResult。尤其 Busy 在授权路径终止，InProgress 在两种授权事务中的行为也不同。
arm64 的结果比较分支位于 `0x79d92c`、`0x79d998` 起的指令中，并非与开流响应共用跳转表。
实际承担模拟器 UI 的 x86_64 shell 同样先检查 result（`0xd0a100`），两表分别为 `0x518e28`、
`0x518e0c`；InProgress 分别跳到 StopStreaming(1)（`0xd0a643`）和直接返回（`0xd0a65e`）。

过期回复分支对带 auth_key 的消息发送 AuthorizationConfirmed(result=8, Canceled)，无 auth_key
则忽略（`0x79d9c0–0x79da44`）。**函数级观察**：在外部密钥交换桩返回成功的离线输入中，
状态 4 收到非目标来源的 Success+auth_key，会先交换并确认 Success，再因来源不匹配确认 Canceled。
这证明检查顺序，不能据此宣称真实网络可绕过授权；上游分派能否到达该输入、真实密码校验是否
接受，均未作该实测。

密钥交换算法仍按认证参考：

```text
peer_public = response.auth_key XOR SHA256(pairing_pin 的四位 ASCII)
paired_secret = SHA256(X25519(our_private, peer_public))
decrypt(response.device_token, paired_secret) 必须为 8 字节且等于本机 device_id
```

`BHandleKeyExchangeAuthorization @0x79dbfc` 缓存上一次 auth_key 及其校验结果；同一 auth_key
重复到达直接复用结果，不重复执行昂贵的密钥交换。**计数修正**：这里只与最近缓存值比较，
不是维护所有出现过的 key 的集合；A→B→A 会计作三次。每次不匹配缓存值都先递增计数，
旧计数小于 3 才允许计算，否则令输出授权结果为 1 并 StopStreaming(error=2)
（`0x79dc38–0x79dcb0`）。

**重复确认与事务推进必须分开**：缓存命中将缓存结果写入输出参数，但函数 bool 返回 false
（memcmp 的 0 保留到返回，`0x79dd5c–0x79dd64`、`0x79dee4–0x79df0c`）。调用者仍发送 type 14
确认，随后退出，因此重复的成功 auth_key 也不会重复完成配对或再次启动开流。校验新 key 成功后
才按主机 client_id 和 steamid 保存新 secret。不能按收到数据包总数限制三包，也不能重复派生新 secret。
云端配对成功后注册 status，通知授权成功 delegate，再结束当前事务；状态 4 的授权成功则回到
状态 5，保持当前开流事务并再次发送 StreamingRequest（`0x79db80–0x79db90`）。

**持久化界面**：安装 device_id、主机 client_id、steamid 列表、每主机/身份的 secret 和已配对
steamid 列表是不同记录。`SavePairedSteamID @0x79b5e8` 去重后保存列表；
`OnConnected` 据此重建订阅。只保存 secret 而不保存用于重订阅的主机身份，会丢失冷启动云端发现。
不要持久化 pairing PIN、临时 cloud session_id 或正在等待的 request_id 为长期授权材料。

### 11.3 开流响应的分支表

**Evidence：** `HandleStartStreamingResponse @0x79e828` 的跳转表在 `0x447458`，
目标基址 `0x79e8c4`，每个无符号字节乘 4。表与 proto 枚举逐项核对，避免仅凭错误名称猜动作：

| streaming_result | 官方动作 |
|---|---|
| 0 Success | 保存 transport/cert/relay_server/对端身份和连接地址；解密 session key；成功才进入 6 |
| 1 Unauthorized | 调 SendAuthorizeDeviceRequest，进入状态 4；不是立即删除配对记录 |
| 4 Busy、5 InProgress | 返回并保留事务，Update 继续按原计时器重发 |
| 2 ScreenLocked | StopStreaming(error=11) |
| 3 Failed | StopStreaming(error=16) |
| 6 Canceled | StopStreaming(error=7) |
| 7 DriversNotInstalled、8 Disabled | 分别 StopStreaming(error=9、8) |
| 9 BroadcastingActive、10 VRActive | 分别 StopStreaming(error=12、13) |
| 11 PINRequired | StopStreaming(error=14)，由上层处理连接 PIN 交互 |
| 12 TransportUnavailable、14 GameLaunchFailed、15 SteamVRNotInstalled | 分别 StopStreaming(error=15、17、10) |
| 13 Invisible、其他值 | StopStreaming(error=1) |

error 是客户端内部 EServerError，不是直接回传给 Steam 的结果码。特别是 Busy 在此处与
InProgress 同样保留事务；不要将它按英文名称直接归为终止错误。
当前事务只按非零 request_id 比较（`0x79e884`）；旧/零 ID 的 InProgress 会发带旧 ID 的
StreamingCancel，其余迟到结果忽略。Progress 同样要求非零且匹配当前 ID，只通知进度，
不刷新重发 deadline（`0x79e788`）。

SendAuthorizeDeviceRequest 重建授权 body，保持 manager 中的事务信息，重发间隔是整秒
`time()+3`（`0x79a58c–0x79a598`）。StreamingRequest 的 `time()+1` 见 §9.3。
manager Update 本身没有“尝试 N 次/累计 N 秒后中止状态 4/5”的分支；不能把工具默认超时移植进来
当官方常量。x86 shell `CPanelConnect::OnUpdate @0xcc9f00` 的 300001 ms 判断只在等待主机出现的
分支，不是所有开流 RPC 的总超时。

StopStreaming 在非 Idle 状态通知非零错误；状态 4 发 AuthorizationCancel(type 9)，其他
仍有目标主机的事务发 StreamingCancel(type 10，携当前 ID)，然后清空目标和 request_id 并回 Idle
（`0x79987c–0x79998c`）。服务 CancelPairing、type 9、type 10 和 SNS CloseConnection 不能合并。

### 11.4 ProofRequest 可更新长期 secret

**Evidence：** `HandleStreamingProofRequest @0x79e1c0–0x79e594`，proto 的 challenge=1:bytes、
request_id=2:uint32、update_secret=3:bool。处理规则：

1. 来源 client_id 非零且等于当前目标；若携带 request_id，则必须等于当前 request_id。
   不匹配 ID 仅忽略；不是当前目标则回一个空 response 的 type 8，且不修改密钥。
2. 若 update_secret=true 且本事务尚未更新，执行
   `secret = SHA256(old_secret || challenge 原始字节)`，保存到当前主机/身份的长期 secret，
   并设置本事务的已更新标志。此标志在 StartStreaming 建立新事务时清零。
3. 用当前 secret 按既有 SymmetricEncrypt（加密 IV + AES-CBC/PKCS7）加密 challenge。
   回 type 8，request_id=当前事务 ID，updated_secret=请求中的 update_secret。

派生发生在构造 proof 密文之前，所以更新请求必须用新 secret 加密回复，并用新 secret 解密
后续 encrypted_session_key。同一事务重复请求不能反复 hash secret；有 update_secret 位也不等于
每次必派生。证据地址：身份/ID 检查 `0x79e1fc–0x79e240`，派生和持久化
`0x79e454–0x79e530`，加密 `0x79e244–0x79e2b0`。密钥持久化先于发送 proof，不能等媒体连接成功
才落盘，否则重启后的授权材料可能落后于主机。故障中断时主机是否回滚属于主机端规则，不能臆造。

## 12. 从 StreamingSuccess 到可用传输的适配契约

### 12.1 三类密钥与证书数据流

```text
长期 paired_secret ──解密 encrypted_session_key──> 本次 stream_session_key
                                                   ├─ HMAC transport signal
                                                   └─ 流会话 Authentication token
StreamingResponse.cert ──Base64 解码──> CertificateSigned ──SDK SetCertificate
StreamingResponse.relay_server ────────────────────────> P2P_STUN_ServerList
```

**Evidence**：普通播放器的 `CStreamClient::BConnect @0x7a7808–0x7a7968` 将 cert、relay_server
传入 SDR 构造函数，把 `CStreamClient::SetAuthToken @0x7a5f98` 保存的 buffer 传给
CStreamTransportClient；该 buffer 也用于 StartAuthentication 的 HMAC（`0x7a7c38–0x7a7c4c`）。
网络测试入口的数据流已由 §8.8 独立核对。这个结论覆盖两条入口的传递关系，不推导主机的签发算法。

**动态证据补充：** `official-host-pair/042.bin` 的 cert 是不带结尾 padding 的 Base64，补齐一个
`=` 后可解为 `CMsgSteamDatagramCertificateSigned`：字段 1 的 private_key_data 为 32 字节，
字段 4 的 cert 内 key_type=ED25519、key_data 为 32 字节；字段 5 为 CA key ID、字段 6 的签名
为 64 字节。该次证书的 expiry-created=172800 秒，**这是样本有效期，不能硬编码为官方恒定值**。
`049/051/053.bin` 的 connect_request 复制的证书同样带 private_key_data；主机的 connect_ok
（`054/071.bin`）带签名证书但无该字段。样本证明这个 blob 不能按普通公开证书随意输出到日志。
私有证据仅保存字段存在性、长度和时间差，不发布 key/身份。

`InternalSetCertificate @0x804958` 解析 signed cert，检查身份、公钥类型/长度、私钥一致性、
公私钥匹配和 AppID 范围（`0x804b14–0x804d4c`），然后安装身份/证书。
证书没有 private_key_data 时必须已有对应私钥；自行生成一个无关私钥再导入这个证书会失败。
`BThinkCryptoReady @0x8556e4` 使用未到期的本地证书；peer 的 handshake/证书校验交给网络库。
证书导入成功不等于所有远端证书检查已通过；也不等于必须自行调用一个未发现的客户端签发 RPC。

**本机导入与远端验签的区别**：本样本在 CertStore_CheckCert 返回空 scope 时输出
“not currently able to verify our own cert / Continuing anyway”，随后仍执行身份、公钥、私钥和
AppID 等检查（`0x8049dc–0x804a10`、`0x804d38–0x804d4c`）。因此“本机暂不能验证自己的 CA”
不是这里无条件失败的充分条件，也不能据此删除 peer handshake 验证。移植方应保留这两层职责。

### 12.2 初始化的调用顺序

**Evidence：** `CStreamTransportSteamNetworkingSocketsBase::BInit @0x7ffd30–0x8000bc`：

1. 获取 Utils LibV4，设置诊断输出；全局 `SDRClient_SingleSocket(22)=1`。
2. 开启 manual polling；获取 Sockets LibV13，不存在时才 SteamDatagramClient_Init。
3. 参数 relay_server 非空时，设置全局 **P2P_STUN_ServerList(103)**。这是 STUN 配置，
   不可将该字符串直接当作 SDR 媒体 UDP 服务器。
4. 尝试加载 `libsteamwebrtc.so/CreateWebRTCICESession` 并注册 ICE factory。
5. 有预置网络配置 JSON 时交给 ClientSetNetworkConfig；解析失败使 BInit 失败。
6. Base64Decode cert，调用 SetCertificate；有 cert 却无法解码/安装使初始化失败。
7. 调 Sockets::InitAuthentication；再调用 Utils::CheckPingDataUpToDate(10000000000.0f)，
   设置 LogLevel_P2PRendezvous(17)=5。这个很大的浮点实参是 ping 数据允许年龄，不是丢包率。

**槽位复核**：Utils StreamingClient 的 address point 为 `0xc40888`；+216/+224/+232/+240
分别经重定位到 SetManualPollMode `0x822444`、Poll `0x82244c`、SetICESessionFactory `0x822454`、
ClientSetNetworkConfig `0x75dc84`。+56 的重定位 `0xc408c0` 指向 CheckPingDataUpToDate
`0x81f764`；Sockets +176 的重定位 `0xc46ba0` 指向 InitAuthentication `0x8051d0`。
本初始化没有证据表明开启了网络故障注入。

普通播放器只为返回的最终 transport 创建对应对象：1→UDP、4→SDR、5→UDP_SNS；
该入口其余值返回不支持（`0x7a7898–0x7a7930`）。SDR 创建 custom-signaling P2P 连接，
remote identity 参数为空、virtual port=0，初始参数和连接配置见 §9.5。
“声明 supported_transport=[1,4]”与“返回 4 后立即连接某个固定 relay_server”不是同一算法。

### 12.3 transport 状态、收发与 MTU

transport 的 `this+20`：0=初始化后尚未开始连接，1=Connecting/FindingRoute，2=Connected，
3=Failed，4=Closed。`CheckConnection @0x800348` 把 SNS 1/2 映射为 transport 1；
SNS 3 映射为 2；SNS 4（ClosedByPeer）关闭本地句柄并进入 Closed；SNS 5（ProblemDetectedLocally）
先设 Failed 再关闭，保留 Failed。**证据修订**：撤回“句柄失效/查询失败都进入 Failed”。
没有句柄时保留既有 Failed，其余状态变 Closed，返回 false（`0x800374–0x800378`、
`0x80044c–0x80045c`）；GetConnectionInfo 失败或 Connected 后 GetQuickConnectionStatus 失败
才清空句柄并置 Failed（`0x800460–0x8004b8`、`0x800724–0x800780`），这两条分支不调用
CloseConnection。SNS 未识别状态则以 reason=2001 调 CloseConnection；其规则是保留既有 Failed，
其余变 Closed，不能自行改成所有未知状态都设 Failed。已 Connected 时仅在
`now >= last_check+1000000μs` 查询 SDK，否则直接返回 true（`0x80039c–0x8003b4`）。

**证据修订**：撤回此前 BWait 固定 Poll(0)、不按等待参数阻塞的表述。
`BWait(wait_ms) @0x80010c` 把传入的 `wait_ms` 保留在 w1，直接交给 Utils::Poll(int)，
`0x800138–0x800144` 没有清零它。虚表目标 `0x82244c` 将 w1 转给 SteamNetworkingSockets_Poll
（`0x86e12c`），后者进入原生 poll 实现，按该预算、下一个 thinker 期限和单次 1000 ms 上限
收紧 epoll_wait 的 timeout（`0x86e238–0x86e2a0`、`0x86e348–0x86e35c`）。这个 1000 ms 上限
适用于非负 Poll 预算；BWait 的 uint32 参数原样转为 Poll 的 int，`0xffffffff` 会成为 -1，
未到期/没有 thinker 时不会被这个正值上限截断。有到期 thinker 时
timeout=0；未来 thinker 的剩余时间先四舍五入到毫秒、至少 1 ms，再与调用预算取较小值。
获取全局锁本身还按 1 ms 尝试，不能把传 0
解释为整个调用绝对不会阻塞。独立运行线程/主循环必须据此选择等待预算。
实际 x86 shell 的 BWait 同样保留第二参数 esi，直接调用 Utils+224
（`0xd27654–0xd2765b`）；无句柄分支也同样保留 Failed、其余转 Closed
（`0xd27982–0xd2798f`）。30 秒过期边界的 x86 比较是 `<30` 才跳过删除（`0xd05982–0xd05986`），
地址比较器的三秒容差分支也一致（`0xd115c4–0xd115de`）。

Poll 后以最多 128 条为一批取 ReceiveMessagesOnConnection，
每条 SNS message 对应一个 CStreamPacket；满批继续取，进入接收 FIFO。
BWait 返回值只看本地队列非空；无句柄仍会 Poll，且可能因旧队列非空返回 true，但 Recv
会先因无句柄返回 2。不能把 BWait=true 当作连接有效或下一次 Recv 必定成功。
Send **先检查句柄**：无句柄直接返回发送失败(3)，即使状态为
Failed 也不返回终止错误(4)。有句柄才按状态判断：transport<2 时返回稍后重试(1)，2 时用 flags=0x15，
SDK result=1 视为成功，25/41 视为可重试，其余视为发送失败；transport=3 单独返回终止错误
（`0x800224–0x8002bc`），Closed 则发送失败。报文头 bit7 置位时，交给 SDK 的长度为
packet 的已存长度加 4，否则不加；这不是 SNS 自动添加的字节。Recv 同样先检查句柄：无句柄
返回 2，不消费本地已排队包；有句柄但空队列返回 1，出队成功返回 0
（`0x8002c0–0x800324`），传空输出指针也会消费一条包。SDK 25/41 的名称以对应结果枚举为准，
不把两者写成“对端已断开”。

`SetMaximumMTU @0x801084` 设置连接级 MTU_PacketSize(32)，再查询 MTU_DataSize(33)，
返回后者，查询失败返回 -1。应按此结果确定交给 SNS 的应用包预算，不能把普通 UDP 的 MTU
不经扣除地用于 SNS。消息边界、上层包序号/加密/ACK/NACK 保留，见 §8.9。

## 13. 信令桥接：生命周期、队列与失联

### 13.1 两个云端 session 不应混为一个

**Evidence**：`CStreamTransportClient` 构造函数 `0x7d42ec` 为每个 transport bridge 创建自己的
CRemoteClientSession 并立即 BConnect；它复制本次 session key，持有 backend 引用。
它并不借用发现界面 manager 的同一个 WebSocket 或 cloud session_id。
普通 UDP backend 的 BWantsRemoteClientSession 返回 false；SDR 在 transport 状态 0/1/2
返回 true，3/4 返回 false（`0x8016f0–0x801708`）。因此 SDR 进入 Connected 后仍要保留云端信令。

桥接 Update 的精确分派（`0x7d44fc–0x7d45e4`）：

```text
backend.UpdateState()
while backend.PopPendingSignal(message):
    if cloud.state == Connected: wrap_HMAC_and_send(message)
    else: fifo.push(deep_copy(message))
need_cloud = backend.WantsCloudSession() or not fifo.empty()
if cloud.state in {Resolving, WSConnecting, CreatingSession, Connected}:
    if need_cloud: cloud.Update()
    else: cloud.Disconnect()
else:  # Idle / ConnectionFailed
    if need_cloud:
        cloud.BConnect()
        cloud.Update()
```

**Conclusion**：当桥接器有需求时，ConnectionFailed 会直接发起下一次连接，**不会先检查
§9.1 的随机重试时刻**。发现 manager 只是调用 session.Update，遵守该时刻；两个调用者的策略
确实不同。移植时若统一退避，必须作为本项目行为差异记录，不能声称完全照搬官方。
bridge 的 OnDisconnected/OnServerOffline 是空函数（`0x7d4e4c`、`0x7d4e58`），
所以云端失联/offline 通知本身不立即摧毁已工作的媒体 transport；其可用性由 backend 判断。

### 13.2 队列、回调与输入错误

SDK SendSignal 回调在 `0x801998` 只把 bytes 放入 backend pending 队列；队列操作在
`QueueTransportMessage @0x8014f4` 和 BGetPendingTransportSignal 的 mutex 内完成。
取出时批量交换全部 sdr 元素并清空暂存，不在 SDK 回调里直接进行 WebSocket I/O。
外层 bridge FIFO 存内层 CTransportSignalMsg 深拷贝，重连成功后按 FIFO 顺序重封装发送。
此时用**新的 cloud session_id**；信令 HMAC key 仍为同一条媒体连接的 stream_session_key。

在已核对的入队/出队/Update/析构函数内，没有消息时间戳、TTL 淘汰、固定条数/字节上限或
按 candidate 覆盖旧条目的分支。只能据此描述这条队列的行为，不能推断系统永远不会因资源耗尽失败。
SDK 内层 reliable rendezvous 队列另有 ACK/RTO，见 §14.3；外层 FIFO 不代替它。

接收按 framing→header→type→外层 protobuf→32 字节 HMAC→内层 protobuf→backend 的顺序处理。
错误 framing/验签失败/内层 parse 失败返回 false，仅由 OnReplyPacket 记录；不是“所有坏包都断线”。
backend 收到有效 HMAC 的 sdr 后，逐条调用 ReceivedP2PCustomSignal；若某条返回 false，
则终止当前连接并设 transport Failed（`0x8017b0–0x801864`）。外层没有独立的消息序号/重放窗口，
重复/乱序及对端连接 ID 校验由内层网络协议承担。不得自行按 payload 哈希丢掉所有重复信令。

### 13.3 关闭与所有权

**Evidence**：`CStreamClient::ResetConnection @0x7a5294–0x7a52c4` 先关闭 CStreamConnection，
再销毁 bridge。bridge 析构 `0x7d43f0` 先 Release backend，再析构自己的 cloud session，
最后删除 FIFO 全部消息、释放 key buffer。SDR CloseConnection `0x800f94` 先解除 signaling
回调对象与 backend 的双向指针，再以 linger=false 关闭 SNS handle、清空 handle；Failed 保持 3，
其余置 Closed。之后的 signaling SendSignal 在 owner 为空时返回 false，避免回调访问已销毁 backend。

session Disconnect `0x790c20` 在锁内释放目录请求、清空 endpoint 队列、CleanupWebSocket 并置 Idle；
CleanupWebSocket 释放 WebSocket 和待收帧。其析构先 Disconnect，再 StopWebRequests。
WebRequest manager 引用计数降为零后，从非 worker 线程执行 Join(-1)
（`0x7f18dc–0x7f1938`、`0x7f26c4–0x7f272c`）。SNS 在 BInit 开启 manual polling，最后一个
transport 析构才关闭该模式（`0x7ffadc–0x7ffb10`）。

**本项目实现规则**：单独管理 SDK 全局实例/轮询、云端 worker、流会话 worker 和回调 owner。
应用退出须 stop→join→destroy，且在回调失去 owner 前禁止删除依赖对象；不能直接复制 Android
的全局驻留假设到 Switch NRO。新的 attempt 使用新的本地 generation，取消后的旧回调不进入新事务。
这属于资源/并发规则，不新增 Steam 协议字段。

## 14. 网络库的实际路径策略与信令可靠性

### 14.1 源码对照的使用边界

本次取得 Valve 官方开源 GNS 固定提交
`d534c19aa760df3fb75fd20db13ba1932b8a5463`，用于给嵌入 ELF 的字段/算法命名。
以下数值和关键分支均重新核对固定 arm64 ELF，**不以当前源码的默认行为覆盖样本**。
源码入口：`src/steamnetworkingsockets/clientlib/steamnetworkingsockets_p2p.cpp`、
`steamnetworkingsockets_p2p_ice.cpp`、`src/steamnetworkingsockets/steamnetworking_statsutils.h`。
对照版本不代表官方 APK 内嵌库恰好是该提交。

### 14.2 ICE 与 SDR transport 的选择

**Evidence**：`ThinkSelectTransport @0x8755a4–0x875c04`，RouteMetrics 的 current/min/max/penalty/
有效桶数字段依读写数据流与开源同名函数对应。核心算法：

1. 对所有 available transports 更新 route metrics。尚未确认端到端连通性，加罚分 **10000**；
   非 controlling 一方对未被对端选中的路径再加 **100**。
2. 选 `current_score + total_penalty` 最低者。只有一个候选则直接选定；有多个候选而最佳项还
   需要确认连通性，不急于切换，并取消 sticky。
3. 尚未选路径时，controlling 一方可立即选；另一方若选择与对端一致的路径也可立即选，
   否则等待该连接状态起超过 **1 秒**再自行选择。
4. 已有路径且 sticky=false，只要新的评分严格更低便可切换。sticky=true 时，新路径必须满足
   `floor(best_score*11/10)+5 < current_score`。这不是固定“低 5 ms 就切换”。
5. sticky 时再比较近期范围：
   `floor(best.max*11/10)+5+best.penalty < current.min+current.penalty`。
   如果这个更严格条件成立，样本数不足会推迟切换，并主动探测；双方各有至少 **15 个有效时间桶**
   后可切换。如果范围条件不成立，但步骤 4 成立，代码仍可切换，不能改写成任何切换都必须等 15 秒。
6. 15 是时间桶数，桶宽 1 秒，存储 17 个桶；不足时的防抖探测间隔 **200 ms**，还受在途探测超时
   约束。不要把它说成“15 个 ping 包”或恒定等待 15 秒。
7. 正常重新评估间隔 **1 秒**；未稳定/无可用路径/等待确认时收紧到最多 **50 ms**。
   FindingRoute 中有可发送的已确认路径即进入 Connected。

证据位置：评分罚分 `0x8756b8–0x875708`，初选 `0x875940–0x875974`，sticky 阈值
`0x8758b0–0x875910`，15 桶/探测 `0x875914–0x875bfc`，调度 `0x875858–0x87586c`。
开源 PingTrackerBuckets<17,1000000> 与 ELF 同名实例相互支持桶宽；200000 微秒常量也见
`0x875918–0x8759d8`。

ICE metrics `P2PTransportUpdateRouteMetrics @0x87e4c4` 使用端到端平滑 ping 和近期 min/max。
其 very-low-latency 分支要求 min<=4 且网络库传输种类=4（开源名 UDPProbablyLocal）；
否则 current/min/max 各加约 10%，
另加 10 分及配置 P2P_Transport_ICE_Penalty（`0x87e51c–0x87e644`）。这解释了为何不能简单取
裸 RTT 决定 ICE/SDR。SDR 的评分来自 relay route metrics，再结合端到端探测及 SDR penalty
（`0x839028–0x8395ac`），不是仅比较客户端到单个 POP 的 ping。

**Conclusion**：SDR 可能先工作，ICE 后续出现再按评分切换；中继也可能一直优于直连。
网络故障使当前路径重新需要确认时，sticky/评分会变化，因此切换策略不能用固定的先后串行列表替代。
POP 内部路由的评分公式与 P2P transport 之间的选择是两层；使用兼容 SDK 时应让其负责此层，
不在应用中再叠一个“ICE 优先”的选择器。

### 14.3 rendezvous 也有独立可靠流

**Evidence**：QueueSignalReliableMessage `0x877d60`、ScheduleSendSignal `0x874bd0`、
ThinkConnection `0x87527c`、SetRendezvousCommonFieldsAndSendSignal `0x875d5c`、
ProcessSignal `0x877614`。这是候选/认证信令的可靠机制，与媒体 CStreamChannel 的可靠性不同。

- 每个新 reliable message 分配递增 ID；初始 RTO=1（尽快发送）。排队后把发送 deadline
  收紧到 `now+10000μs`；通常相邻实际信令至少间隔 **100000μs**。
- 实际发送时从未确认队列选择到期项；握手 connect_request/connect_ok 可以从队列开头重带
  尚未到 RTO 的项。起点放 first_reliable_msg，其后元素连续。
- 每个已发送项的 RTO 更新到 **now+1000000μs**。发包常带累计 ack_reliable_msg；
  解析 ACK 后删除所有 ID<=ACK 的未确认项。
- 接收 first_reliable_msg 大于期望 ID（last_received+1）时不越过缺口；部分重复则跳过已处理
  前缀，顺序处理后面的新元素。**顺序修正**：ACK 调度在序号缺口/重复检查之前；只要存在
  first_reliable_msg 字段，先安排最迟 now+10000μs 的信令（已有更早 deadline 则保留），再检查
  缺口并处理内容（`0x8778e8–0x877940`）。因此全重复、未来缺口乃至空 reliable_messages
  也会促成累计 ACK，不能把“不处理内容”写成“完全不回复”。不能把 reliable_messages 当无序候选集合。
- 收到/发送 connection_closed 清空未确认队列。特殊 NoConnection 原因码 **9999** 用来阻止
  双方相互无限回复关闭信令（`0x877844–0x877890`）。
- SDK SendSignal 回调返回 false 会置 ProblemDetectedLocally(error=5002)
  （`0x876528–0x8765a4`）。仅仅“放进 SDK 待发送队列”不等于云端已送达。

发送代码里虽有 **800** 字节累计量判断，但判断位于尚未设置 first_reliable_msg 的分支；
设置起点后会继续追加后续项（`0x876128–0x87615c`）。因此不能写成“官方每个信令最大 800 字节”，
也不能把公开源码注释中的“小消息”愿望当样本强制线包上限。

应用只做 §13 的 opaque sdr bytes 桥接时，这些 ID/ACK/RTO 应交给网络后端，不能再由应用重写
或对内层 protobuf 重新序列化。若替换 SDK，自行实现时必须保留这些机制及连接 ID/身份分派。

### 14.4 初始候选收集与 ICE 实现选择

`CheckWaitForInitialRoutingReady @0x875c08` 为首轮信令等待初始路由材料，之后清除一次性标志：
SDR 初始准备可等到状态起 **2 秒**，每次最多等 20 ms 后复查；已有对端 cluster 但尚无 relay
session 的 FindingRoute 分支可等 **100 ms**；ICE 缺 srflx 时等到 **100 ms**，缺本应可枚举的
host 候选时等到 **10 ms**，每次最多 10 ms 后复查。这些是收集窗口，不是穿透总超时。
连接请求重发周期为 **500 ms**（`ThinkConnection_ClientConnecting @0x876c30`）；
SNS 总连接超时仍以 §9.5 的 20000 ms 配置为界。

`CheckInitICE @0x87c36c` 固定本连接的 ICE-enable 配置；<=0 报本地禁用。
根据 Private/Public/Relay 位分别启用候选；STUN 列表按逗号切分，地址缺 `stun:` 前缀则补齐；
TURN 的服务器、用户名、密码使用各自列表。列表为空时清除相应候选类型，不能仅设置 All 就
假定一定能得到 srflx/TURN 候选。ufrag 从本地连接 ID 的低 30 位编码，password fragment 从随机数
编码；通过 reliable ICE auth 消息交换（`0x87c4b0–0x87c528`、`0x87c5cc–0x87c938`、
`0x87d1d8–0x87d428`）。

**版本差异证据**：样本中 ICE_Implementation=0 被设置并锁定为 **2（WebRTC）**，
1 为 Valve 内置实现。2 找不到 factory 时尝试 dlopen/dlsym；失败报 ICEFailed(3999)，
这条分支没有自动改用 1（`0x87d2ac–0x87d368`、`0x87d6e0–0x87d77c`）。
开源对照版本对默认实现/回退的处理不应直接倒灌为 APK 行为。旧独立 WebRTC transport 废弃，
与 SNS 内部仍可使用 WebRTC ICE factory 并不矛盾。

## 15. SDR 网络配置、信任与应用层边界

**Evidence**：`GetNetworkConfigURL @0x8214a0` 使用
`%s/ISteamApps/GetSDRConfig/v1?appid=%u%s`，universe/realm 决定 WebAPI 基址及可能的
`&realm=steamchina` / `&realm=steamglobal` 后缀。地址来自库构造，不能固定某个 POP IP。
`BeginFetchNetworkConfig @0x8210b8` 保证同一时刻只有一个请求，首轮在抽象请求对象设置
`Cache-Control: only-if-cached, max-stale=2678400`；后续按 attempt/realm 切换请求路径。
`OnNetworkConfigFetchCompleted @0x821b14` 增加 attempt，交 SetNetworkConfig 解析配置，
首轮成功后还会请求刷新。失败在前三次完成以内继续尝试；第三次以后已有可用配置则保留，
无配置则置 Failed（`0x821938–0x821b10`）。这是库级配置获取，不是主机配对 RPC 重试。

**调用链限制**：样本的 CSDRHTTPRequest_StreamingClient::SubmitRequest `0x75ddc0`
只把 URL 交给 IWebRequest::BStart；本函数未遍历抽象请求的 header map。
因此这里不能把上面的 Cache-Control 设置宣称为已经在线上发出的 HTTP header。
回调也把 WebRequest 完成粗化为 200/500（`0x75dfc8–0x75e014`），不能由该适配层的状态数值
推断每个真实 HTTP 响应码。

SetNetworkConfig `0x8215d4` 调 SetupFromJSONGlobal，应用版本/POP/route 数据和信任材料；
变更有效时创建共享 cluster 数据并刷新 ping。证书信任材料由
SteamDatagramNetworkConfigCerts::AddToCertStore `0x89a650` 导入，不应通过禁用证书检查来
弥补缺少网络配置。配置 JSON 不是 connect_request 的简单替代，SDR relay session 还要独立建立。

**接入约束**：开源 GNS 没有 Valve 生产 SDR 服务的完整实现；还原公开的 ICE/transport 策略，
以及能够导入主机证书，都不能证明已经补齐这一缺口。使用官方兼容 backend 时，本项目负责
提供 host 返回的材料、信令桥和轮询/生命周期；自行实现 backend 时还需实现对应 relay 协议。
本节不以一句“接 GNS”隐藏后者的工作量。

## 16. 可直接编码的模块边界与行为判据

这里规定实现接口和输入输出，避免每个模块重新猜测策略。带“本项目”字样的是本地设计，
其余依据前述固定样本；不把本地资源限制包装为协议要求。

| 模块 | 持有状态 | 输入/输出与职责 |
|---|---|---|
| IdentityStore | 安装 device_id、每主机身份列表和 secret、paired steamid | 按 §11 保存授权/Proof 后的 secret；本项目用原子写入，不存临时 session 代替长期身份 |
| RemoteClientSession | §9.1 状态、CM FIFO、临时 session_id/universe、待收帧 | TLS WebSocket binary protobuf；异步 status/reply/offline 分派；保留调用者差异 |
| HostDirectory | client_id→status、云端在线集合、地址候选 | §10 的探测、排序、过期和显式地址/云端选路 |
| PairingTransaction | manager 2/3、PIN、X25519 对、auth_key 结果缓存 | Start/Set/CancelPairing；授权结果确认/持久化；迟到 PIN 清理 |
| StreamingTransaction | manager 4/5/6、目标/身份、request_id、PIN 密文、Proof 已更新标志 | §11 的重试/结果分支；只在最终成功后输出 StreamConnectMaterial |
| StreamConnectMaterial | transport、连接地址、cert、STUN 列表、session key、universe/realm/peer | 复制进入单次连接对象；key/cert 不进入普通日志 |
| TransportSignalBridge | 本次 key、peer、独立 cloud session、FIFO、backend 引用 | SDK opaque bytes↔sdr repeated↔HMAC type 12↔RemotePacket；媒体不经此桥 |
| P2P/SDR backend | SNS 状态、证书、候选/路由、内层可靠信令 | §12–§15 的配置/选路/消息边界；向上提供不可靠数据报语义 |
| Existing stream session | CStreamConnection/Channel 对应状态 | 保留流握手、认证、加密序号、ACK/NACK、媒体/输入/统计处理 |

状态迁移核对必须包含以下输入序列。表述的是预期行为，不是声称已有独立客户端通过这些测试：

| 输入序列 | 必须得到的行为 |
|---|---|
| 广播无回复→cloud status→公布 IP 单播回复 | 先可按身份路由；仅实际地址回复后才转为缓存 UDP 直连 |
| 单纯公布 IP→开流 | 不把未探测地址提升成实际可达地址 |
| cloud status 后 30 秒无本地 status | cloud 在线集合保留该主机；Offline 后清除可见记录，保留密钥 |
| CM 中断→新 CreateSession | 新 session_id、恢复订阅；不得原样重放旧 session envelope |
| 等待 PIN 时取消→迟到 StartPairing 成功 | 清理迟到槽位，不把其 PIN 交给新事务 |
| 重复授权 auth_key / 新 auth_key | 前者缓存结果并确认；后者计入三次密钥交换额度 |
| Proof(update_secret=true) 重复→StreamingSuccess | 仅派生一次长期 secret；回复/最终解密使用更新后的 secret |
| Streaming Busy→InProgress→Success | 保持同一事务 ID 重建 token，直到成功；不能 Busy 即终止 |
| 旧 Streaming InProgress | 取消旧 ID，不改变当前事务或接纳旧 key/cert |
| CM 失联但 SDR 已有端到端路径 | bridge 重连信令；不由空 OnDisconnected callback 直接关闭媒体 |
| 多条 sdr / 重复 reliable / reliable 缺口 | 保序转发全部 opaque 消息；由 backend 按累计 ID/ACK/RTO 处理 |
| HMAC 无效 / 合法 HMAC 内部 signal 被 SDK 拒绝 | 前者丢弃并报告解析错误；后者按样本终止 transport |
| SDR 先就绪、ICE 后变好 | backend 依评分和 sticky 条件选路，应用不强制 ICE 优先 |
| 取消→迟到 SDK 回调→再次连接 | 关闭 owner 关联并隔离本地 generation；旧材料不污染新连接 |

**本项目资源策略**：帧/队列字节上限、等待 UI 的可取消超时、错误日志限速，以及针对 Switch
内存预算的批次上限需要显式配置；可改变执行预算，但不能静默丢失可靠信令后继续宣称连接正常。
单个 WebSocket 消息发送需完整或报错；不把短写当完整包成功。SDK ABI、manual polling 和全局
初始化所有权须由适配层封装，业务代码不使用硬编码虚表偏移。

## 17. 固定样本的可编译 wire schema

仓内 [steamlink-1.3.32](protocol/steamlink-1.3.32/README.md) 包含从同一 arm64 ELF 的
`descriptor_table_*` 提取的 **8 个文件、264 个消息（含嵌套消息）**，覆盖 discovery、
RemoteClient service、RemotePlay、SDR、auth、SNS、certificate 和 UDP。
`manifest.json` 对每个原始 FileDescriptorProto 记录表地址、描述字节地址、长度、SHA256 和依赖。
这比依赖随时间更新的外部 master 分支更适合核对样本行为。

**Evidence**：ELF64 LOAD 映射和 R_AARCH64_RELATIVE 重定位共同定位 table+8 的描述字节，
table+24 给长度。工具先检查完整 ELF SHA256，再解析 protobuf；不读取运行进程或会话材料。
提取工具 [steam-remote-descriptors.py](../tools/steam-remote-descriptors.py) 同时输出原始描述字节、
完整 FileDescriptorSet 和可读 proto2。仓内只保存可读 schema 和静态 manifest。

**校验**：8 个可读文件一起通过 protoc 编译。重新编译得到的描述与原始描述逐文件比较，
仅规范化 protoc 补入的 json_name、syntax=proto2 表示和源码位置信息后，**8/8 语义相同**；
全部依赖可装入独立 DescriptorPool。样本 hash 不符被拒绝，已有输出目录不被覆盖。
这验证字段号、类型、默认值、枚举与依赖，**不等于验证了所有消息的运行时分支**。

实现读取 proto2 的 presence，不能把“未携带”统一改成显式默认值。bytes 的签名/HMAC 输入保留
原始字节；对收到的 signed body 重新序列化后再验签会改变 unknown fields/顺序等线格式，不能据此
替换原始签名输入。带 private_key_data 的 SignedCertificate 仍按 §12.1 的敏感凭据处理。

## 18. SDR relay 的直接线格式与会话规则

本节专指客户端与 relay 的 UDP 协议，和 CM 上的 type 12 / sdr rendezvous 是不同包层。
字段的全部类型/编号见固定 schema；以下补齐只读字段名无法得到的封装、加密与状态行为。

### 18.1 控制报文与数据报文分开解析

**Evidence**：`RelayServer::SendMsg @0x81744c–0x8176d4` 发出
`uint8(message_id) || protobuf_bytes`，无额外长度前缀。protobuf 长度必须小于 1300，
即该函数最多发 1300 字节 UDP 负载；这不是所有媒体消息的大小限制。
接收 callback `0x8162c0` 由 BCreateSocket `0x811c80–0x811ce8` 注册，先按 relay 源地址匹配。
输入长度须在 5..1300 之内（无符号减法及 HI 条件，`0x816340–0x81634c`）；
data 分支还要求至少 9 字节。

| 客户端涉及的控制类型 | 样本接收/发送行为 |
|---|---|
| 1 RouterPingRequest / 2 RouterPingReply | 请求使用 §18.2 的固定结构；回复是 protobuf |
| 7 NoSession | 更新 challenge/公网映射，销毁该 relay session，重新评估路径 |
| 24 P2PSessionRequest | §18.3 的 signed body，使用设备证书的签名私钥 |
| 25 P2PSessionEstablished | 保存 opaque relay_routing_token，初始化该 relay session 的序号 |
| **26** P2P stats | 客户端发 ClientToRouter schema；接收方向按 RouterToClient schema 解析 |
| 28 P2PBadRoute | 按 failed_relay_routing_token 失效对应 peer route 并要求重算 |

**枚举名陷阱**：schema 还定义 P2PStatsRelay=27，但这个样本的接收分派明确把 **26** 交给
`CMsgSteamDatagramConnectionStatsP2PRouterToClient`（`0x816488`、`0x816c5c–0x816d80`）；
发送同为 26（`0x835d94–0x835da4`）。不能只凭枚举英文名把收包改成 27。

媒体不使用上面的 message_id=9/12 + protobuf 封装。`SendEncryptedDataChunkGeneric
@0x83ed9c–0x83f0a0` 实际生成 9 字节 packed header：

| 偏移 | 长度 | Client→Router 内容 |
|---|---|---|
| 0 | 1 | 基值 **0xa0**，叠加可选字段 flag |
| 1 | 2 | 端到端包序号低 16 位，little-endian |
| 3 | 2 | client→relay 包序号低 16 位，little-endian |
| 5 | 4 | 本地 connection_id，little-endian |

之后依次为：flag bit0 存在时 `varint(stats_length) || stats_protobuf`；bit1 存在时的可选时间数据；
最后为 SNS 端到端 encrypted data chunk。客户端发送函数在 bit1 时追加一个 uint16_le，值为距前包
微秒数右移 4（只在非负且至多 250000 微秒等条件成立时）；不为每个包强行添加。
stats 编码设置 bit0，空间不足会裁减 quality 字段或省略 inline stats（`0x84ff68–0x850328`）。

Router→Client 的 data 首字节匹配 `(byte0 & 0xe0)==0x40`，同为 9 字节基础头和两个独立序号，
connection_id 位于偏移 5（`0x8163ac–0x81642c`）。bit0 按最多 5 字节 varint 取长度并检查剩余空间；
bit1 **接收 4 字节**、解析两个 uint16，分别左移 4 得微秒数据；最后才调用 DecryptDataChunk，
不能照搬发送方向的 2 字节可选时间字段（`0x819930–0x819980`、`0x819a20–0x819afc`）。
上层流协议不直接解析或拼接此 header。

### 18.2 relay ping 与 challenge

`SendPingRequest @0x8176d8` 的普通请求是 **1300 字节**零填充结构，非 protobuf：

| 偏移 | 类型 | 内容 |
|---|---|---|
| 0 | uint8 | 1 |
| 1 | uint8 | 普通 0x02；短请求 0x82 |
| 2 | byte[6] | ASCII sdping |
| 8 | uint32_le | 当前单调微秒时间低 32 位 |
| 12 | uint32_le | 本 relay 对象持有的 cookie（对象+104） |
| 16 | uint32_le | 0 |
| 20 | uint32_le | network config version |
| 24 | uint32_le | relay IPv4 数值 XOR cookie |
| 28 | uint16_le | relay port XOR cookie 低 16 位 |
| 30 | uint16_le | 协议版本 **13** |
| 32 起 | bytes | 0 填充 |

共享 cluster 的 `+768` 时间戳距当前小于 5 秒时使用 **100 字节**短请求并设 0x82
（`0x8178ec–0x817938`）；不能将所有 ping 固定为最小包。已有 relay session 时，指定探测分支可
改用 session stats 发 ping（`0x817714–0x817760`）。设待回复期限时，有近期 RTT 则取
`min(worst_recent_ping_ms*2000, 1000000)+250000` 微秒；无 RTT 时为 1250000 微秒。
此处只在原待回复期限为空时设置，不用新 ping 无限推迟旧 deadline（`0x817764–0x8177b8`）。

RouterPingReply 提供 server_time、challenge、your_public_ip/port、POP 延迟、penalty、
route exceptions 和 alt_addresses。SaveChallenge `0x812dd4` 保存 challenge/server_time 对及
本地接收时刻，公网映射存在时更新；**不是客户端自行生成并提交任意 challenge**。
NoSession 中相同作用的字段见 `0x81a358–0x81a468`。IP/port XOR 只构成此 ping 结构的编码，
不是设备授权、信令 HMAC 或媒体加密。

申请 session 前，`ThinkSelectServer_PursueSessionsOnClusters 0x81e258–0x81e284` 检查本地
challenge 接收时刻；超过 **10 秒**清零 challenge，先重新探测。这里按本地单调时间计年龄，
不是把 server_time 与本机墙钟比较。已有 challenge 仍可能要求确认最近 **20 秒**是否从该 relay
收过包，以及 cluster 最近样本是否充分；没有在途 ping 才补发确认，申请已 pending 时不重复提交
（`0x81e28c–0x81e334`）。一次申请将该 relay 的 pending deadline 设为当前+**750ms**
（`0x81df90–0x81df9c`、`0x81e2f8–0x81e31c`）。这些是 relay 事务的期限，不替代 20 秒 SNS 总建链期限。

PingReply 校验还接受两种 cookie：relay 自己的 cookie，或该 relay 已有 session 的本地
connection_id；都不匹配时不采纳（`0x8121ac–0x81227c`）。latency_datacenter_ids 与
latency_ping_ms 数量必须一致；client_timestamp 用低 32 位时间差计算 RTT，过旧回复拒绝。
负差值另有至多 2ms 的小偏差分支，不应把时间戳直接解释成 UTC
（`0x8121c4–0x8121e8`、`0x812330–0x812358`）。

### 18.3 签名会话申请与可选身份加密

`ThinkSelectServer_SendSessionRequest @0x8381f4` 使用取得的 challenge/server_time，生成
P2PSessionRequestBody：f1 challenge_time、f2 challenge、f3 本地 connection_id、f5 peer connection_id、
f8 protocol_version=13、f9 network_config_version，以及 platform/build/peer_identity_string。
peer connection_id 非零有 assert（`0x838454–0x8384a0`），所以不能在尚未获知 peer 身份/连接 ID 时
把 relay session request 当作取代端到端握手的第一包。

优先选择 cluster 的有效 X25519 公钥，否则检查全局配置公钥；两者均不可用时保留明文 peer identity
（`0x8384a4–0x8384d8`）。存在有效公钥则：

```text
生成一次申请用的 ephemeral X25519 keypair
shared = SHA256(X25519(ephemeral_private, relay_config_public_key))
context = 本机证书 CMsgSteamDatagramCertificate.identity_string 的原始字符串字节
aes_key = SHA256(shared || context)
nonce = uint64_le(challenge) || uint32_le(0)
plaintext = protobuf EncryptedData{ peer_identity_string }
encrypted_data = AES-256-GCM(aes_key, nonce, plaintext, AAD=empty, tag_length=16)
```

这里 `encrypted_data` 的字节布局是 `ciphertext || 16字节tag`，**不含 nonce 前缀**。
`AES_GCM_EncryptContext::Encrypt @0x74b6dc–0x74b9f0` 先写密文，再把 GET_TAG 的输出写到
密文末尾，并将输出长度加 16。nonce 由 challenge 派生，不沿用 Remote Play CBC 包的 IV 封装。
§20 用原始 wrapper 指令及可控 EVP 桩复核了这一布局；密码 provider 本身不在该测试证明范围内。

同时携带 ephemeral 公钥原始 32 字节（f16）和所选 relay 公钥首字节的整数值（f15），清除外层明文
peer_identity_string（f11）。原始 X25519 的 SHA256 包装由 `CCrypto::PerformKeyExchange
0x7461fc–0x746318` 确认，不能漏掉这第一次 hash。第二次 hash、12 字节 nonce 和 16 字节 tag
见 `SetSteamDatagramSessionRequestCipherContext 0x8a094c–0x8a0a80`。
context 指针从 interface+160 取值：constructor 把 Cert 放在 interface+72，而该 Cert 的 f12
位于其+88（`0x803594–0x80359c`、`0x7276ac–0x727710`、`0x83853c–0x838570`），不是整个证书。

最后先序列化完整 body，再用本机设备证书匹配的 Ed25519 私钥对**序列化 body 原始字节**签名，
输出 64 字节 signature；P2PSessionRequest 外层为 cert=f1、body=f2、signature=f3，并以类型 24 发出
（`0x838894–0x838a24`）。不能使用 pairing secret 或 HMAC session key 代替该签名私钥。

SessionEstablished 类型 25 返回 opaque relay_routing_token。样本按 connection_id 分派并检查一致性，
要求 token 非空，查找或创建 RelaySession，复制 token、清理失败计数，处理可选 shutdown warning 和
seq_num_r2c，再重新评估（`0x83dac8–0x83ddac`）。此时只证明本端 relay session 建立，
仍需交换 peer route 并确认端到端路径，不能直接向业务报告媒体 Connected。

### 18.4 peer routes、两套 revision 与恢复

`CMsgSteamDatagramP2PRoutes` 的 RelayCluster 携带 POP ID、ping、penalty、该 session 的路由令牌；
Route 携带 my_pop_id、your_pop_id 和 interior_score，整个快照有 revision。
它可经 rendezvous.sdr_routes 或 stats.routes 传递；不是 CM 维护的一张全网主机地址表。

- **peer routes revision**：RecvRoutes `0x834df0` 解析成功后仅当新 revision 严格大于已保存 revision
  才替换快照并要求重算。即使旧/重复快照也设置待 ACK 标志。PopulateRendezvousMsg `0x834bc0`
  带 ack_peer_routes_revision；本地快照未获 ACK 且到期时重发，发送后把下次期限设为当前+1秒。
  收到超过自己最新 revision 的 ACK 只报告错误；等于最新值才清除重发期限
  （`0x834c90–0x834cf0`、`0x83d920–0x83da74`）。
- **forward target revision**：对某个本端 RelaySession 选定对端路由令牌后，如果目标令牌发生变化，
  保存新 token、目标 POP，revision 加一，并清除 ACKed 标志（`0x83505c–0x835140`）。发送 stats 时
  只要未获确认就继续带 forward_target_relay_routing_token / forward_target_revision
  （`0x835464–0x8354c4`）。接收 ack_forward_target_revision **等于当前 revision**才置 ACKed；
  不相等的值不能确认新令牌（`0x83d8a8–0x83d9a4`）。
- **BadRoute**：按失败 token 精确匹配保存的 peer RelayCluster，清空该 token 并清除 presence、
  标记必须重算；找不到则记录而不删除所有路由（`0x83cd68–0x83cf60`）。
- **NoSession**：先保存新的 challenge/公网映射和 shutdown warning，销毁所指 RelaySession，
  然后重新调用服务器选择（`0x81a290–0x81a33c`）。它不是要求重新配对设备。
- **网络配置变化/relay shutdown warning/销毁 session**：分别标记 route 重算
  （`0x834ff8–0x835058`）。上层媒体的 connection_id 与该 relay session 的生命周期分开。

两个 revision、CM session_id、开流 request_id 和 SNS reliable message ID 属于不同状态域。
重试时不能把它们合并成一个序列号，也不能收到任意 ACK 就将所有队列标记完成。

### 18.5 POP 评分与失联惩罚

`SessionSelectQualityMetrics::DebugInfo 0x81bbdc` 和 `RouteQualityMetrics::DescribeScoreAndPenalties
0x81bde8` 的字符串引用将指标命名为 front、interior、remote、route/local/remote/other penalty。
结合读写点，metrics 的相对偏移为：

| 偏移 | 含义 |
|---|---|
| +4 / +8 / +12 / +16 | 本地 front 平滑 ping / 近期 min / max / 有效桶数 |
| +20 / +24 | 远端 front ping / interior ping |
| +32 / +36 / +40 | route / local cluster / remote cluster penalty |
| +44 / +48 | 最终 score / other penalty |
| +56 / +64 / +72 | shutdown 剩余秒数 / 有失败时的接收空档微秒 / migration 标志 |

候选总分的实际计算（`0x81c790–0x81c80c`；P2P 对照 `0x83812c–0x838168`）：

```text
internet_ping = front_local + front_remote
score = internet_ping + floor(internet_ping/10) + interior_ping
        + route_penalty + local_cluster_penalty + remote_cluster_penalty + other_penalty
```

P2P override 将远端 front、interior、route/remote penalty 从当前匹配的 peer route 填入
（`0x8380d0–0x8380f0`），因此本地离某 POP 最近不足以决定端到端最优路线。
base metrics `SetSessionSelectQualityMetrics 0x81c3f0` 还执行：

- alternate transport 的 penalty 大于 8190 时排除候选；没有可用 front ping 的 cluster 同样不参与。
- shutdown 剩余秒数大于 29 无额外惩罚；<=0 加 1000；1..29 时加
  `floor((30-seconds)*1000/30)`，另叠加 alternate transport penalty
  （整数实现 `0x81c43c–0x81c4a8`）。
- relay 已记录连续接收失败且距最后接收至少 500001 微秒，记录 connection gap；达到
  1750001 微秒再加 100 分（`0x81c4ac–0x81c4e4`）。单纯媒体没新帧不是该条件的替代。
- migration flag 用于区分迁移目标与发出迁移请求的节点，不是新的设备配对状态。

active session 候选会计算 min-score/current-score/max-score 并排序，然后才考虑保留当前 primary、
新路的接收新鲜度、在途 probe、shutdown、migration 与样本量；存在 10%+10、额外 50 分、
5 秒新鲜度、15 桶及 200 ms 探测分支（`0x81ce68–0x81d278`）。这些是 POP/session 选择这一层的
条件，不能把 §14 的 transport 迟滞阈值不加区分地搬过来。

### 18.6 session 保活与 migration

**Evidence**：`SDRTransportThinkSessions 0x8180a4–0x818580` 逐个维护已建立的 RelaySession，
primary 使用 Active，其他使用 Idle；连接不在可维护状态时改为 Disconnected。
活动级别的数值 0/1/2 分别由 SetActivityLevelInternal 的调用与开源同类型定义对应。

| 条件 | 本次计算的保活/重试 |
|---|---|
| Active、无在途回复期限 | 最后有效收包+10秒到期，发 RelayKeepAlive |
| Idle、无在途回复期限 | 最后有效收包+60秒到期 |
| active session 列表中 index=1 的 backup，且无在途回复期限 | 最后有效收包+45秒到期，发 RelayBackupKeepalive |
| Active 已有接收失败 | 上一次请求立即回复的发送时刻+200ms 到期，发 stats reply request=3 |
| 已有在途 reply deadline | 将 deadline 纳入下次调度，不以无条件 keepalive 重置 |

这些是额外的 session 空闲保活；LinkStatsTracker 的统计/ACK/探测逻辑可要求更早发送。
outer thinker 初始取当前+2秒，再收紧到每个 session 的最早期限；发送后重算 deadline，
不会等到下一次固定 2 秒才处理已经到期的 ACK（`0x8180c8–0x8180d4`、`0x818208–0x818344`、
`0x81843c–0x818548`）。不能把媒体流上层的心跳代替 relay session stats。

migration 由 stats 中 migrate_request_ip/port 触发，客户端分别保存 pending 状态及 target relay index。
`ThinkPendingMigrationRequest 0x8190a8` 先清除待处理标志，然后验证：目标地址必须与当前 relay 不同；
必须属于网络配置中已知 POP，而且与当前节点属于同一 POP；拒绝记录过通信问题的目标地址，以及
关闭节点缓存中 shutdown 时间已过的目标。有效目标可创建/取得 RelayServer，进入等待该 target 的状态
（`0x819148–0x8193c0`）。不是收到任意 IP/port 就转发媒体。

`CheckCancelMigrationRequest 0x818c7c` 在没有 active primary、primary 不再公布迁移目标、
已保存 target 与当前公布地址不符、目标已收到 shutdown warning 或 alternate penalty>=8191 时
清除 migration state/target（`0x818ca4–0x818ed4`）。该状态仍属于同一个端到端连接；
不生成新的配对 PIN、开流 request_id 或 pairing secret。

### 18.7 实现 SDR backend 时的接口限制

§18.1–§18.4 可直接用于编写控制 codec、relay session 建立和 revision/令牌维护。
数据报中的 encrypted chunk、端到端序号窗口、stats ACK 和 SNP 消息分片/重组仍应与 SNS 的
端到端连接实现衔接，不能直接把既有 IHS 包塞在 9 字节 relay header 后。
公开 GNS 固定源码可作为 SNS 端到端加密/SNP/ICE 对照，生产 SDR 扩展需独立补齐。

**尚未形成完整复刻规格的库内策略**：POP 内候选的全部比较、备用 session 的创建/淘汰、
失败地址缓存期限及探测频率的全部分支。`ThinkSelectServer_SelectActiveSessions
0x81c55c–0x81ddb8` 与 P2P override `0x837a90` 表明其还比较 min/current/max、额外 penalty、
当前 primary、待确认探测、样本数与网络配置；不止“取最小 ping”。本文不把未完整命名的对象偏移
硬写为公式。使用自有简化策略时应明确为本项目策略，和 §14 已确认的 transport 选择分开。

## 19. 规格的适用边界

本文与认证参考、既有流协议参考一起，定义了 Android 固定样本**客户端应用层**从发现、授权、
开流、Proof、材料导入、信令桥到传输交接的主要正常/错误/取消/重试行为；§14 给出内嵌网络库
可确认的选路、迟滞和信令可靠性规则。可据此编写这些模块及具有明确契约的 backend 适配，
无需凭字段名称猜测地址选择、密钥来源、Busy 行为或把所有重试统一处理。

以下项目不在“应用层规格完整”这一判断的证明范围内，不能写成已兼容：

- PC 主机/Steam 服务内部的配对槽位寿命、风控、Proof 更新中断后的主机回滚及证书签发策略。
  客户端按实际返回结果处理，不自行伪造服务端政策。
- 不依赖官方网络库的完整生产 SDR 实现。§17–§18 已给出 schema、challenge、签名申请、
  数据封装和 revision/错误恢复规则；§18.7 所列库内调度策略与 relay 服务端内部算法不在完整性证明内。
  §14 的 P2P transport 选择不能替代这些职责。
- 不同出口 NAT/CGNAT/对称 NAT、路径变化及长时间串流的互操作实测；静态分支存在不能证明
  所有路由器/防火墙配置下都可达。
- 主机端码率/FEC 决策及全部媒体能力；由独立流协议参考和实际支持能力约束。

**不应追求的假完整性**：选择兼容 SNS/SDR backend 时，应用层复刻和该库内部全部私有协议的
重新实现是不同交付边界。选择完全自有的 Switch backend 时，必须连同后者定义并实现，不能因
本文已描述上层行为而把一个 codec 冒充可工作的 SDR。相关实现/验证任务仅在 GitHub Issues 维护。

## 20. 原始指令的离线复核与证明边界

仅凭反汇编阅读容易遗漏前置判断、返回寄存器及相邻跳转表。仓内
[`tools/steam-remote-policy-audit.py`](../tools/steam-remote-policy-audit.py) 用 Unicorn 执行固定样本
的原始 AArch64 指令，输入为人工构造对象；不连接 Steam、不使用抓包中的凭据。加载时沿用
descriptor 提取器的 ELF SHA256/架构检查，应用相对重定位；遇到未建模调用、越界控制流或指令
预算耗尽即失败，不能静默跳过未知分支。Python `-O` 被拒绝，以保证断言生效。

```sh
python3 tools/steam-remote-policy-audit.py \
  --elf /absolute/path/to/libmain.so \
  --report build/steam-remote-policy-audit.json
```

依赖 Python 3、google.protobuf、unicorn、cryptography；报告目录须预先存在。
核心覆盖范围如下，精确的输入矩阵和计数由脚本及 JSON 报告给出：

| 原始函数/指令 | 核对内容 |
|---|---|
| AuthorizationResponse `0x79d680`、key-exchange guard `0x79dbfc` | result/状态矩阵、auth_key 前置条件、来源检查顺序、重复确认、三次计算限制 |
| StreamingResponse `0x79e828` | 0–15 及未知结果、session key 解密失败、迟到/零 request_id |
| ProofRequest `0x79e1c0` | 更新标志、SHA 输入、持久化/加密/发送顺序、身份/ID 不匹配、加密失败 |
| Start/CancelPairing `0x79c514`、`0x79c540` | 云端各状态、缺失 session、manager 状态的分派 |
| cloud UpdateWebSocket `0x791bdc`、manager Update `0x79890c` | 连接/重连、deadline 等号、发现补发、30 秒过期与云端在线豁免、重入守卫 |
| 地址查询 `0x79c25c`、比较器 `0x7a3140` | 首地址实际回复标志、IPv4 优先、三秒容差、成环的两两比较 |
| SNS Send/Recv `0x800224`、`0x8002c0` | 句柄/状态优先级、SDK 结果映射、长度附加值、空输出指针出队 |
| SNS CheckConnection `0x800348`、原始 SDR Close `0x800f94` | 状态映射、查询失败、无句柄、一次检查期限及保留 Failed |
| BWait `0x80010c`、Poll wrapper `0x82244c`、内部 wait 计算 `0x86e200` | 等待参数传递、批次 128/129、空/错误接收、旧队列、正/负预算和 thinker 期限 |
| transport selection `0x8755a4`、cloud bridge | 迟滞、15 个采样桶、受控端首次等待边界、队列及重连分派 |
| 初始路由 `0x875c08`、ICE metrics `0x87e4c4` | 2 秒/100ms/10ms 边界及提前就绪、近期范围、低延迟类别与惩罚 |
| reliable ProcessSignal `0x877614` | 累计 ACK 删除、部分/全重复、未来缺口、空消息及先调度 ACK 的顺序 |
| 开流入口 `0x798d94`、网络变化 `0x79a614`、控制发送尾部 `0x79b118` | 重复事务、非 Idle 忽略网络变化、UDP/云端分派、UDP 发送失败不追加云端 |
| POP penalty `0x81c3f0`、relay receive `0x816344` | 30 秒衰减、500000/1750000 us 边界、5–1300 字节长度守卫 |
| relay data `0x83ed9c`、ping `0x8176d8` | 线格式、序号截断、时间差边界、100/1300 字节及未决 deadline |
| cipher context `0x8a094c`、key exchange `0x74610c`、curve25519 `0x8b88fc` | 执行原始 X25519 指令，独立实现对照共享值、两次 SHA256 的输入、context 字节、nonce 和 GCM 参数 |
| GCM wrapper `0x74b6dc` | EVP 调用参数、密文/tag 的目标偏移和输出长度，无 nonce 前缀 |

**Evidence**：断言检查的是这些原始指令在明确输入和外部返回值下的行为；SHA provider 使用
hashlib，X25519 对照和 GCM 桩输出使用 cryptography。日志、容器、内存工具、部分 protobuf
构造/发送、SDK/服务回调和 EVP provider 按测试显式替代。Proof 的 SymmetricEncrypt 也是桩，
不用于证明 CBC 算法；GCM 测试证明 wrapper 的布局与调用，不证明原始 OpenSSL provider。
key-exchange 缓存测试在进入新密码计算前停止，不证明整个授权密码实现。
控制发送测试只执行已完成序列化后的选路尾部，不验证它的完整 header/body 构造；开流入口测试
在进入新事务的随机码/密钥生成前停止。BWait 的 Poll provider 使用桩；内部 wait 测试仅执行
预算计算到 `0x86e2a4`，没有真的等待 socket，因此不证明实际线程调度或墙钟耗时。

**Conclusion**：离线复核支持本文所列分支、顺序和封装规则，并揭示 §11 中已明确撤回的泛化。
它不等于完整客户端执行、主机互操作或真实公网丢包测试，也不能把未覆盖输入当成已验证。
不同架构/版本需要单独核对；本文 x86 shell 的授权分派另有静态指令证据，不能用 arm64 仿真
替代 shell 的全部运行时验证。
