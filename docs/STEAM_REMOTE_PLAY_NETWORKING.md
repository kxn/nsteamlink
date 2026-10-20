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

**完整发送函数的补充 Evidence**：固定 core 样本
`50e1d3147d5d47b71ef1970e1867a2fe4f3e1ecf2ea6153f927fac88b88ea38e` 的
`SendMessage 0x79ad64–0x79b260` 不只是末尾的 UDP/cloud 二选一。
`0x79adf0–0x79ae9c` 在非零目标 client ID、显式 IP/端口不完整时加载持久目录，
只读取首个且已验证的地址，不在此函数中搜索后面的已验证项，也不检查 cloud-online 集合。
`0x79aea0–0x79afe0` 在选出的 IP/端口仍不完整时，重新生成外层 header 的
`device_token`（字段 5）；失败调用 `StopStreaming(error=1)`，不发送报文。
已有完整地址但本地发送关闭时，走云端的 header 仍不带这个字段；不能简单用
“云端报文都加 token”取代地址资格判断。`BGetDeviceToken 0x79c348–0x79c3fc`
读取当前 manager secret（+536/+556），加密本机小端 device ID，独立于 body 中的 token。
云端发送读取该 client 的第一个持久 Steam ID，不按“最后在线账号”另选。

`BStart 0x798840` 先调用 `Stop`，后者 `0x797bf8–0x797c18` 销毁并清空旧 cloud session。
因此 socket 缺失时，不能仅根据 SendMessage 尾部分支推断“BStart 失败后仍可通过旧 session
立即转发”。受控输入中，完整地址、无 socket、既有 Connected session、socket 创建失败，
实际原始调用链没有发送 UDP 或 cloud；成功创建 socket 则发送 UDP。

传输桥接器是独立 producer：`SendTransportSignal 0x7d46a4–0x7d46c4` 的外层 header
只设 `msg_type=12`，没有 client ID 或 manager device token；身份绑定仍由会话目的账号、
内层信令及用**解密后的流密钥**计算的 HMAC 提供。`0x7d47c0–0x7d493c`
序列化内层 `CTransportSignalMsg`、生成 HMAC、封装 body 后调用 cloud SendMessage。
不能复用 manager header 并擅自添加 client ID，也不能把长期配对密钥当作该 HMAC 密钥。
收发头不对称：`BProcessReplyPacket 0x7d4c7c–0x7d4c8c` 要求收到的 header 有非零
client ID，再检查 type12；此后没有将该 ID 与所选电脑比较。
`0x7d4cbc–0x7d4d80` 先验证当前流密钥的 32 字节 HMAC，再解析内层并交给 backend。
原始输入明确覆盖无 ID、零 ID、相同/不同非零 ID、错误 type、坏 HMAC、坏外层 body、
无/空 payload、缺失/短 token、HMAC 正确但内层损坏及重复 SDR 元素。
token 长度仍须为 32；未提供 payload 时取 protobuf 的空串默认值，有效空串 HMAC 和可解析
的空内层可以接受，不额外要求 payload presence bit。
因此不能将客户端自己发出的无 ID 信令包直接当作 Steam host 的回复做回环验收。

`audit-steam-control-route.py` 执行上述完整发送/序列化和桥接器指令。
持久查找、token 字节、会话状态/析构、系统调用及最终 cloud send 是显式提供者；
Stop 的可见/cloud 容器为空，桥接 HMAC 使用独立 Python 标准库提供者。
接收的最终 backend 是记录解析后消息的提供者；不是 SDK 内层信令状态机验证。
该对照不证明持久文件读写、真实密钥选取、服务端接受、所有 caller 的选路或线程时序。

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

#### 控制 owner 的地址与承载边界

**Evidence（同一固定 core）**：开流 `0x799798`、重新授权 `0x79a588`、授权取消
`0x799a70` 和开流取消 `0x799b84` 都以空 CIPAndPort、当前目标 client ID 调用
SendMessage。取消函数先检查可见记录或显式主机 hint，不能仅凭一个持久 ID 无条件发送。
相对地，授权确认 `0x79dff0`、Proof 回复 `0x79e34c/0x79e574` 复制本次收包来源地址。
开流响应的成功分支 `0x79eaa0–0x79eacc` 同样保存本次来源，仅在来源 IP/端口完整时
将端口替换为响应中的流端口；不读取启动时的地址快照。

**Evidence（响应身份与迟到取消）**：`BProcess` 只拒绝零 header client ID，随后直接分派
开流响应；`0x79e884–0x79e88c` 匹配非零 request_id，不比较目标 client ID、instance 或
来源地址。成功时使用回复身份的持久 SteamID，并保存本次来源。迟到/零 request_id 的
InProgress 分支内联构造取消，以收到的 client ID 和来源直接调用 SendMessage；它不是
上面的隐式 `SendCancelStreamingRequest`，因此不受可见记录/hint 的前置门控。
这不改变 Proof 必须匹配当前目标身份的单独规则，也不能推广到授权响应的处理顺序。

**接线约束**：已知主机的 LAN 与 cloud 控制消息应进入同一事务、同一当前 secret 和
同一接收/重试 owner。每次隐式发送查询目录；完整显式回复地址绕过目录。流传输能力与
控制报文采用 UDP/CM 是不同选择，具备 SNS 后端时可同时公布 UDP/SDR，最终按响应材料
创建传输。认证 PIN、connect PIN 密文快照和 Proof 更新规则保持 §11 的独立语义。
传输信令仍由独立桥接连接处理，不将 type12 混入 manager 的设备 token 规则。

发现发送也读取该时刻的地址目录，关注 ID 的操作顺序仍由发现 owner 管理。
不能在当次 Update 已发送后才发布刚接收的 status 地址，也不能绕过旧的待处理关注操作，
用一个新快照反向覆盖它们。跨线程的云端发送必须交给连接 owner；断开后清除旧会话
队列，不能把旧帧重新封装进新 session。停止/join 所有生产者后才能释放队列和目录。

`control_frame_oracle.c` 将实际 IHS sender 的地址空缺、完整显式来源、首个已验证缓存、
不完整显式来源与上述原指令输出比较；保留 UDP send 返回失败而不追加 cloud 的观察。
`control_route_runtime.c` 串起生产 runtime、IHS 接收/定时器/授权队列和 CM framing，
核对同编号跨承载重试、实时发现地址、Proof 轮换与 PIN 快照、CM 会话替换、回复身份及
来源、显式迟到取消和最终 SDR 材料；独立授权计时器另验证跨线程发送交付。
UDP 系统调用、CM 连接工厂/服务边界、墙钟和最终 SDK 构造器均为显式 provider；
清空地址目录是受控输入，不是新增的 NAT/TTL 失效策略。该测试没有真实 Steam、TLS、
NAT、SDK 网络或 Switch，不覆盖 BStart/socket 创建失败、全部授权入站身份规则和持久文件。

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
`BAddSteamID @0x79bd74` 忽略零值、把新身份插到首位；已存在的非首项与首项交换，
但返回 false。status 的 `users` 在 `BProcess @0x799ee8–0x799f10` 中从后向前遍历；
不能把该方法的返回值解释为“列表没有发生变化”。授权回复采用另一种操作，见 §11.2。

### 10.1 地址记录不是“所有公布 IP 均可直连”

**Evidence：** `BProcess @0x799e48–0x79a178`、`BAddNetworkAddress @0x79c040`、
`GetAddress @0x79c25c`、比较器 `AddressInfo_t::operator< @0x7a3140–0x7a3258`。
每条地址记录含：是否实际收到该地址回复、是否为 status 中的 public_ip_address、地址时间字段、
IP/类型/端口。这里给字段取的中文名来自写入调用点，不是恢复出的原始 C++ 成员名。

`BProcess` 在加入公布地址和实际源地址前还检查 `CIPAddress::HasIP @0x8e5e7c`：
IPv4 的数值0、IPv6 的16字节全0均为 false。能被数字解析器接受并不意味着可加入候选；
`0.0.0.0`/`::` 不应产生探测目标。下面实验执行该原始 helper 的7组输入；不据此声称覆盖了
StringView 构造器对 IPv4-mapped、scope、非数字名字等文本的全部规范化行为。

| 地址来源 | 实际回复标志 | remote_ip 标志 | 用途 |
|---|---|---|---|
| 收到 UDP status 的源地址 | true，并更新 `time()` 和端口 | 不新增此标志 | 可以被选作控制消息直连地址 |
| status.public_ip_address（本文原称 remote_ip） | false | true | 加入候选，供后续 discovery 单播探测 |
| status.ip_addresses | false | false | 同上 |
| 持久化地址文件重新加载 | false，时间 0 | false | 重新探测，不直接继承上次运行的可达性 |

比较顺序为：实际回复优先 → IP 类型不同时 IPv4（内部类型 3）优先 → 非 remote_ip 优先 →
回复时间相差超过 3 秒时较新优先 → IPv4 数值/其余地址文本顺序。
更新时间差不超过 3 秒时不会单靠时间决定排序。匹配已有 IP 时不重复插入；实际回复会更新
可达标志、时间、端口；已有 remote_ip 标志只置位不清零。排序是地址管理规则，不是 ICE 候选排序。

**时间字段更正**：撤回“最后实际回复时间”作为全部记录的定义。新增地址不论可达标志
是否为 true，均调用 `time(NULL)` 写入时间（`0x79c0f4–0x79c124`）；已有地址仅在本次
verified=true 时更新时间和端口（`0x79c21c–0x79c23c`）。因此重复的未验证公布地址既不刷新
时间，也不替换已有端口；新增未验证地址的时间并非 0。持久文件重载的 0 是另一个来源的规则。
`BAddNetworkAddress` 返回值仅表示新增了条目；更新可达标志、时间、端口或 remote 标志仍可返回 false。

**比较器的适用边界**：上述时间容差按每一对地址比较，不是能直接展开成全局 tuple 的排序键。
合成输入 A=(time=104, IPv4=3)、B=(102,2)、C=(100,1)，其余标志相同时，原始比较器返回
`A<C`、`C<B`、`B<A` 均为 true：前一对由时间决定，后两对由 IP 决定。这里存在不传递的
两两比较，不能声称所有地址集合都有唯一的规范顺序。早期两两测试只证明比较器结果，
不能证明任意标准库 sort 的最终排列；完整原函数输出见下方向量。实现若改用确定的全局顺序，须注明本项目差异。

完整排序函数为 `std::__ndk1::__introsort<...AddressInfo_t...,false> @0x7a24d8`，
元素为40字节；不是调用系统 qsort。可复现实验执行该函数及其插入、分区、ninther、堆排序
辅助函数（`0x7a24d8–0x7a38c4`），覆盖0–256条地址、非传递三元组全部排列、IPv4/IPv6、
混合标志和显式 depth=0 的堆退路。depth=0 为直接调用排序器的合成输入，不证明常规地址添加
一定能触发这条退路。IP 比较、GetIPv4 和 IPv6 文本格式化也执行样本原始函数，避免用桩的
字节序或系统 inet_ntop 偷换排序键。

复现命令（固定 Android 1.3.32 arm64，SHA256
`50e1d3147d5d47b71ef1970e1867a2fe4f3e1ecf2ea6153f927fac88b88ea38e`）：

```sh
uv run --with unicorn --with pyelftools python scripts/audit-steam-address-cache.py \
  --binary /path/to/libmain-arm64.so \
  --reference scripts/fixtures/steam-address-cache-reference.json.gz \
  --output /tmp/steam-address-cache-replay.json.gz
```

记录查找、预分配容器存储、时钟、strcmp、限长文本复制/printf 为显式 provider；地址添加、
去重更新、清理、排序、GetAddress 由原指令运行。该实验不执行持久文件读写、status protobuf
解析、完整可见表 Update、真实网络或本项目的完整地址目录，不能替代其实现与互操作验证。
`ClearInactiveAddresses` 还处理持久记录 `+56` 的字符串向量；此处将它设为空，没有验证
非空字符串析构/存储，也不把地址列表比较扩展成整个持久记录对象的完整行为证明。

`GetAddress` 和 `SendMessage` 的隐式选址只取排序后第一条且要求实际回复标志为 true。
`SendMessage @0x79ae04–0x79ae9c` 仅在调用方没有提供完整 IP+port 且 client_id 非零时查缓存。
选不到则保留空地址，经过 §9.4 的云端分支。显式传入的 IP+port 会跳过缓存选择。
**Conclusion**：云端发现成功后，可以在后台探测公布地址；公布地址本身不等于验证了直连。

`ClearInactiveAddresses @0x79be58–0x79c03c` 删除标志为 false 的地址，而非按固定秒数删除。
首次处理主机 status 会先执行该清理，再加入本次公布地址。清理从后向前扫描，以尾部元素
覆盖被删位置后缩短数组，不保序、不在该函数里重排；例如 verified 标志为 T,F,T,F,T 的
IP列表1,2,3,4,5清理后为1,5,3。这是合成的交错标志输入，不声称正常排序后的调用者会产生
这种排列；但该清理函数对任意输入并不等价于稳定过滤。随后每次 BAddNetworkAddress 才排序。
status 的加入顺序为 public_ip_address → ip_addresses 的原始顺序 → 实际 UDP 源地址，
这些插入中间都会排序（`0x799f14–0x799fcc`、`0x79a0f8–0x79a11c`）。可见主机表的 30 秒过期与地址记录
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

上面的复现实验还单独执行解析后的 type2 分支 `0x79a03c–0x79a0a4`：可见表存在时先删除、
调用 removed delegate，再删除云端集合；不存在时不发 removed，仍尝试删除云端集合。
四组可见/云端集合存在组合均不改配对/地址记录。该分支没有“用此前局域网 status 立即恢复
在线”的路径；新的 status 可以重新建立可见记录。实验的 map/delegate 是受控 provider，
不声称验证了报文准入、无记录时 UI 的幂等通知实现或云端/UDP 多线程事件调度。

`HandleNetworkChanged @0x79a614` 只在 manager Idle 时清零可见记录时间并立即触发发现；
它不是任何流状态下都重启 ICE 的通用网络变化处理器。

### 10.3 应用接线与可复现边界

`host_addresses.cpp` 管理进程内地址值，按上述三秒容差比较器及独立的 libc++19 非 bitset
排序器执行添加/更新、清理和 GetAddress。不能用平台 std::sort、稳定过滤或全局时间 tuple
替换这些步骤。`address_cache_oracle.c` 直接调用该生产模块，
`check-steam-address-cache.py` 与固定原指令输出比较136组程序/217步，包含逐次添加和
多地址更新、跨 IPv4 字节顺序、三元组排列、显式 depth=0 等输入。八份能正常运行的错误
实现分别被原输出拒绝；编译失败、崩溃、执行器断言不作为策略反例通过。

`host_directory.c` 分开管理实际 status 墙钟时间、可见记录、cloud-online 与地址缓存。
runtime 在一个 mutex 临界区内更新目录并发布 UI 事件；IHS 与云端消费者停止/join 后才释放
目录。公布地址在 borrowed 回调结束前解析成拥有的 IP/port/标志；不保留 protobuf 指针。
前端心跳不更新实际 status 时间，因此即使 UI 有自己的短期快照失效保护，协议可见性仍由
目录的30秒边界、云端豁免和 Offline 决定。进程重启的保存地址只作为时间0/未验证 seed。
账号列表由同一目录独立持有、按 §11.2 保存；地址与 MAC 的完整持久文件不能由该账号文件替代。

发现地址列表与关注 client_id 列表不是同一种变化。原 `BAddNetworkAddress`/
`ClearInactiveAddresses` 没有写入下一发现轮次；`AddClientDiscovery` 才清零轮次时间
（§10.2）。IHS 的 `SetDiscoveryDirectory` 以原操作队列更新地址快照，关注 ID 列表相同
时保留 full/fast 截止时间和轮次；列表改变才触发新轮次。原 `SetDiscoveryTargets` 仍保留
显式刷新契约。新接口单独携带唯一非零关注 ID 列表，不从有地址的候选反推关注身份；
无已知地址的主机也可出现在禁用广域广播订阅后的 directed-client 广播中。runtime 关注
列表来自保存的 UI 主机，地址目录本身不隐式增加关注。不能让收到每个新地址或排序变化
都等价于重新关注主机，从而额外加发发现。

`host_directory_runtime.c` 经过真实 IHS 线程/报文解析/回调/应用目录和最终请求序列化，
验证22条公布文本中的20个非零候选未截断、零 IP 被拒绝、public/private 重复标志、仅源地址可达、首次 seed 清理、30秒等号、
云端豁免/断开、UDP Offline、源端口更新及已验证地址覆盖过时 UI 地址。用固定墙钟额外检查
同关注 ID 的地址更新保留轮次/截止时间，新 ID 触发轮次，以及无地址 ID 实际进入最终
directed-client 广播。网络收发、墙钟和云端 status
入口是受控 provider，不是实际 Steam、路由器、DNS、互联网可达性、Qt 或 Switch 实机证据。
这些组件用例也不代替原 manager 的 status→地址发布→当次 Update 发包的联合调用链对照，
或控制消息重试时调用者如何提供显式/隐式地址的对照。

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
有效 PIN 以 `%4.4u` 格式化，创建新的 X25519 密钥对、清零本事务的交换次数，再生成临时
32 字节 secret。`0x79f054–0x79f068` 重取整个随机块，直到 secret 的首字节非零；这不是
只排除全零块。随后调用 BCreateAuthorizationRequest，沿用 manager 当前的 request_id，
没有调用新的随机 request ID：初始值 0 仍以 present 的 field 5 发布，替换事务留下的非零
ID 也可保留。public auth_key/result 缓存不会随新 PIN、临时 secret 或新私钥重置。
SetPairingInfo 成功仅表示发布完成，授权成功仍等待主机的
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
**补充证据修订**：撤回“上游分派能否到达、真实密码校验是否接受均未作该实测”的过宽
表述。固定 shell 的 `steam-authorization-lifetime-reference` 中 `routing/foreign` 输入
执行完整 BProcess、原 header/body 解析和原密码交换，非目标 ID=456 的有效密钥材料得到
返回 1、derived=1、对 456 的保存调用、Success 后 Canceled 两次确认，manager 仍为 4。
原指令重放与该固定向量一致。网络入站、身份/熵及最终文件/发送端点是显式 provider；
它证明该受控有效材料可经原分派到达，不等于真实网络可绕过授权。
**原生边界**：路由模式的已知主机授权先交换/保存/确认，再检查当前目标；明确区分选中
事务目标、回复来源身份和密钥保存命名空间。未启用路由回调的旧 IHS API 保留原有入口
过滤契约。账号首项、文件及订阅的独立证据和实现边界见下文。
**实现修订**：撤回旧的“未知主机服务配对槽的缓存/状态仍与已知主机分开”边界。
正式 runtime 的 SetPairingInfo 现在委托同一 IHS manager 准备授权正文；云端和 UDP 的
回复都进入同一延迟授权 owner，共用 current secret 和 manager 生命周期的 key/result
缓存。服务 RPC 的 pending/deadline 仍由 remote_protocol 持有，不能据此宣称该层全部
状态 2、断线和超时策略已复刻原版。

**Evidence（入站身份的细分）**：同一 core `0x79d6c8–0x79d6cc` 的非 Success 分支
直接到 `0x79d8f4`；状态 4 的零/非目标来源在 `0x79d954–0x79d968` 转入过期分支，
该分支 `0x79d9f0–0x79da38` 只按 auth_key presence 决定是否向本次来源确认 Canceled。
因此不能将“非 Success 不交换”理解成“非目标的所有失败回复均静默丢弃”。新 key 验证
失败、缓存命中都在第一次确认后因交换 bool=false 返回；只有新的有效 key 才继续到
目标身份检查。额度耗尽由交换函数停止当前事务，取消针对当前目标，确认仍针对回复来源。
`0x79d708–0x79d7f0` 还会在 Success 且 steamid present 时先调整回复主机的身份首项并
保存 client info，早于密码交换；这项身份列表更新与成功保存 secret 是不同副作用。

`audit-steam-authorization-admission.py` 在固定 shell 执行完整 BProcess、原 protobuf
parser、原 token/PIN/交换密码运算和调用者；72 组普通/网络测试输入固定为
`steam-authorization-admission-reference.json.gz`。`check-steam-authorization-admission.py`
把同一完整入站帧交给真实 IHS UDP/RX/延迟 owner，比较 160 步状态、编号、当前 secret、
最近 key/result、派生次数、保存身份、确认/取消及请求中的密码字段；另比较保存回调和
每次发送发生时的 manager 状态、编号、缓存及已通知错误数，而非仅比较最终结果。
成功保存使用本次回复的 client ID/steamid；额度耗尽先通知当前目标错误、发取消并清除
事务，再更新公共 key/result 缓存和确认回复。普通取消同样先发取消再清除编号；原生
取消持有同一个 timer owner，任务在 visitor 返回后回收，避免中途插入重试/回复。

原版的 Qt、身份/熵、请求 RSA、时间、持久 metadata、文件系统调用及最终发送仍有显式
provider；原生端点/metadata 查找、身份/熵及保存回调也由 fixture 提供。runtime 联合
场景另以真实 X25519/AES 产生三份有效非目标材料，验证确认前的实际密钥落盘、当前目标
不变、不同账号的 profile mirror 不被覆盖，以及 key 临时文件写入失败后仍确认并更新
当前 secret。原生 profile 仅镜像其当前账号，其他身份的 key 文件与全身份列表是不同
数据；其旧版场景未覆盖冷启动。下述账号链补入真实文件重载，仍不证明真实 Steam/网络、
SDK 或 Switch。

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

**Evidence（账号顺序与订阅的完整调用者）**：固定 core 的
`HandleDeviceAuthorizationResponse @0x79d708–0x79d7f0` 在 Success 且 steamid present 时，
先读取回复主机的持久记录。如果首项不是收到的 ID，找出第一个匹配项，用末项覆盖其槽位并
缩短列表（fast-remove），然后把收到的 ID 插到首位并调用 `SavePersistentClientInfo`。
这里包括显式零值；省略 steamid 则没有此列表操作。比如 `[A,B,C,D]` 提升 B 的结果是
`[B,A,D,C]`，既不同于 status 的首项交换，也不同于稳定的 move-to-front。
该动作早于 auth_key 的缓存比较、密码校验、额度检查和当前目标检查；无效 key 或缓存命中
仍可能改变后续云端发送使用的账号，但不因此保存密钥或完成配对。

新的有效 key 依次设置当前 secret、尝试按回复 client_id/steamid 保存 key、调用
`SavePairedSteamID`、确认 Success；key 文件写入失败不会跳过保存 paired ID。
全局 paired 列表只去重追加，不随 per-client 列表首项变化重排，也不能从 UI 卡片反推。
随后 `0x79d8d0–0x79d8f0` 调用 Register，最后才检查当前事务的目标身份。
无 auth_key 的 Success 同样走 Register；缓存命中、无效新 key、额度耗尽都在其之前返回。

`OnConnected @0x79ee30` 在 session 存在且状态为 5 时，按保存的全局列表顺序逐个调用
`RegisterForStatusUpdates @0x79206c`。后者再次要求状态 5，并要求 SteamID 高 8 位 universe
等于当前 session universe；不在方法内去重。显式零值因此可以存在于文件和路由列表，却
不会在 retail universe 的 session 上产生 Register。不要把这个 universe 门槛误加到
`CRemoteClientSession::SendMessage @0x79229c–0x792414`：后者只检查 session 状态，
原指令既不拒绝账号零值，也不检查其 universe。空账号列表和首项为零是不同状态。

持久文件名由同一 core 的字符串和写入指令确认：
`<client_id 的 8 字节小端十六进制>/steamid.txt`，以及根目录 `paired_steamid.txt`。
每项写为 8 字节小端十六进制、随后换行，保留列表顺序。全局文件不是多个 UI 主机账号的
即时去重视图；重新连接时恢复其所有项，更新该内存快照本身不在在线 session 上发起订阅。

`audit-steam-account-metadata.py` 对固定 core/shell 运行 10 组列表程序（70 步）、48 组
session 状态/universe/Register/OnConnected 输入和 26 组完整授权帧。授权部分执行原
BProcess、protobuf、密码校验、metadata/key 保存调用者、client-info 文本构造和确认；
低层文件操作、Qt、身份/熵、请求 RSA、最终发送及持久记录查找为显式 provider。
独立的 `check-steam-account-metadata.py` 将同一完整帧送入实际 IHS UDP/RX/延迟 owner，
比较 identity、key-save、Confirm/Cancel、Register 和重发的事件顺序；生产列表/实际文件
读写另逐项比较原列表结果及有效文本字节，session 的原生成 protobuf 与生产 envelope
逐字节比较。固定样本和所有审计 helper 的 hash 都必须匹配。
云端 Offline 另按 `CRemoteClientSession::OnServerOffline @0x791bc8–0x791bd8` 直接转发
notification 的 client_id（包括缺失字段的零默认值），不按 SteamID 查找并批量移除 UI 主机。

**实现边界**：runtime 的目录持有 per-client 列表，独立文件持有全局 paired 列表；
UI profile 只作为单账号镜像，旧资料仅在对应新文件缺失时迁移，不能覆盖已保存的首项。
IHS 的 identity 回调在密码校验之前同步更新并尝试保存 metadata，subscribe 回调位于
确认之后、目标检查之前；当前发送、请求 key 的查找及成功响应的账号采用目录首项。
RX status 只在锁内更新拥有的列表，actor 在锁外保存快照；磁盘错误不变更协议授权结果。
key 写入失败后的 paired-ID 保存、非目标的有效 key、零首项、旧 UI 镜像、实际重启文件
加载和紧随其后的发送由 `control_route_runtime.c` 联合覆盖。
这些是受控组件/actor 证据，不证明真实 Steam、网络/SDK 或 Switch。

本地文件发布使用 tmp/bak 恢复；畸形文本整体拒绝并保留旧内存值，未宣称复刻官方
GetLine/V_hextobinary 的全部宽松解析。该账号链也不替代完整地址/MAC 持久化、显式
forget/退订操作，或 UDP status 与延迟授权的完整跨生产者
入站顺序对齐；这些边界不能从上述列表或密码向量推断。

#### 未知主机配对与共同授权 owner

`audit-steam-service-pairing.py` 以同一固定 shell 执行完整 OnPairingStarted、请求/ticket
序列化、BProcess/header/body parser、真实 X25519/SHA256/AES、key/result 缓存、持久化
调用者、StopStreaming 及 delegate 调用。48 条轨迹分别提供可用或不可用的目标 hint，
覆盖无 auth_key、缺失/零账号、零 client_id、失败后成功、重复 key、更换 PIN、四次新 key
额度耗尽、取消后迟到回复、残留 request ID、已知主机与云端配对互相替换及 result 1..8。
身份、时间、熵、持久记录查找、低层文件调用、Qt/delegate 端点、请求 RSA 和最终
SendMessage/SetPairingInfo 发送端点为显式 provider；原版 RSA 输出是边界标记。
因此它证明原始调用者和原密码校验的行为，不是原版最终路由、CM 网络或 Steam 互通证明。

生产 `IHS_ClientAuthorizationPrepareService` 返回需由调用者释放的 authorization BODY，
本身不发 discovery envelope，不生成新 request ID，也不发已知主机的周期授权请求。
RPC 层把这个 BODY 放到 SetPairingInfo.request 字段；PIN 提示在 manager 已进入状态 3
后产生。ticket 与原版逐字节核对 password、identifier、payload、timestamp、usage、
device_name/model/serial 和 device_provisioning_id 的值及 presence，后者默认 0 仍存在。
正式设备的 model 由平台提供；该字符串不是媒体能力或授权证明。

无 auth_key 的 Success 在状态 3 保存当前临时 secret、保存 paired ID、注册状态订阅，
随后通知配对完成；状态 4 的同类回复不保存 secret。新有效 key 的顺序为身份 metadata、
交换并替换 current secret、尝试保存 key 和 paired ID、Confirm Success、注册订阅、
配对完成通知、Stop。文件失败不把有效密码校验改为 Denied。相同 auth_key 的缓存命中
只重发缓存结果，不再次派生、保存或推进事务；即使新 PIN 不同，也会继续等在状态 3。

状态 3 的 Stop 并非一概不发主机消息：GetServerInfo 或命名 hint 可用时，仍尝试发送
StreamingCancelRequest(type 10)，使用停止前的目标与 request ID，ID=0 也不例外；没有
可用记录则不调用发送。通知发生在状态/ID 清除之前，额度耗尽后的 ConfirmDenied 发生
在清除之后。显式用户取消的服务 CancelPairing RPC 先于本地 Stop；成功完成配对不会
凭空增加一次 CancelPairing RPC。

`check-steam-service-pairing.py` 对实际 IHS UDP/RX/延迟 owner 投入相同完整帧，比较逐步
状态/ID、current secret、key/result 缓存、私钥/派生调用次数、保存身份/密钥、metadata
副作用、所有通知及发送/保存调用时的状态。RSA 明文 ticket 完全比较；实际 RSA 密文只
验证生产加密调用，不能与原版桩字节相等。调用者 provider 省掉的外层 IV 消耗不能被
当成差异，设备 token 和安全 PIN 另用对应 secret 验证 AES 明文。账号列表/文件使用生产
account receiver 比较原版副作用结果。固定 ELF 与全部审计 helper 的 hash 必须匹配。

`control_route_runtime.c` 另覆盖正式 runtime + RPC publication + 真实 IHS parser/crypto +
实际文件的联动：先产生已知主机缓存，再发未知主机配对正文，故意使真实 key 临时文件
写入失败，核对 Confirm 前的身份/paired 文件、完成事件、重复 key 经 CM 确认后仍等待、
服务取消先于本地清理，以及冷启动账号加载。UDP syscalls、CM 连接/服务及最终 SNS
constructor 为显式 provider，不联系 Steam、不创建真实 SDK 媒体连接。
`service_pairing_runtime.c` 使用实际产品 worker、UI 事件处理和文件保存，另在第一次 profile
保存过程中插入尚无新主机的旧 UI 快照，验证完成前排队的保存不会删掉新授权记录，随后
显式删除仍生效；正常文件与故意阻塞 key 临时文件两种输入均执行。确认调用早于第二次
快照保存，实际 CM FIFO 则允许在该保存后再刷出，不能混淆这两个观察边界。

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

### 11.5 连接 security PIN 的加密与重发

**Evidence**：`StartStreaming @0x798eb4–0x798ec0` 先加载目标主机的长期 secret，再调
`BSetStreamingPIN @0x7991a0`。后者对非空 PIN 调 SymmetricEncrypt，key 来自 manager+536、
长度来自 +556，密文存入 +856 的 buffer（`0x7991fc–0x799228`）；空 PIN 清空该 buffer。
`SendStartStreamingRequest @0x799638–0x799700` 将该已保存密文复制到请求的 pin 字段。

**Conclusion**：security PIN 使用开流开始时的长期 secret 加密一次，应用级重试复用该密文；
每轮重建的 device_token 则使用当时的 secret。Proof 更新长期 secret 后，不能因此重新加密已保存
的 PIN，或将 PIN 明文放入云端请求。此规则不改变首次 pairing authorization PIN 的用途。

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

该份 `042.bin` 还直接给出 `transport=4, port=0`，证书 app_ids 包含 353380。
**Conclusion**：不能把“有非零 UDP port”作为 SDR 材料的成功条件。AppID 必须与证书及
网络配置一致；本项目 Steam Link SDK 实例使用 353380，不能沿用开源库的默认 0。

**版本差异证据**：开源固定 `d534c19` 的 `CertStore_CheckCert` 先验证 CA 签名，成功后才
解析 outMsgCert；CA 未加载时，`InternalSetCertificate` 的后续公钥检查因此得到空证书。
这与 APK 的继续导入分支不能直接等同。本项目先获取 353380 的 SDR 网络配置并导入
certs/revoked_keys，再调用 SetCertificate，保留原有公私钥匹配、AppID 和远端证书检查。

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
`0x80044c–0x80045c`）；GetConnectionInfo 失败或 Connected 后 GetConnectionRealTimeStatus 返回0
才清空句柄并置 Failed（`0x800460–0x8004b8`、`0x800724–0x800780`），这两条分支不调用
CloseConnection。SNS 未识别状态则以 reason=2001 调 CloseConnection；其规则是保留既有 Failed，
其余变 Closed，不能自行改成所有未知状态都设 Failed。已 Connected 时仅在
`now >= last_check+1000000μs` 查询 SDK，否则直接返回 true（`0x80039c–0x8003b4`）。

**原始状态函数执行对照**：`scripts/audit-steam-sns-state.py` 直接执行以上 CheckConnection
和 SDR CloseConnection，SDK 的时钟、info、real-time status、Close 方法与诊断字符串/断言端点为
受控 provider。729 组连续程序、743 次调用记录实际返回值、transport 状态、handle、查询时钟、
SDK 调用次序及信令对象双向归属；含不一致的合成状态，不以此声称都能由线上输入产生。
生产 `sns_connection_policy.h` 共用函数由 `check-steam-sns-state.py` 与冻结原始输出逐项比较。

本地真实 SDK 无效句柄测试还执行生产 owner 的异步初始化守卫、info 失败后的队列释放/唤醒及
显式销毁：查询失败保留信令归属到销毁，无待连接时的配置获取不被误关。该测试不创建连接、
不向 Steam 请求授权或媒体。8 份独立编译反例覆盖关闭 reason、一秒等号、单位错误、Failed
保留、跳过节流、遗留无效 handle 和 Connecting 返回值及错误地只允许 OK 的分支；要求反例正常执行，再由原始输出
比较器拒绝，编译错误或 receiver 崩溃不计检出。冻结输出的 gzip SHA256 为
`d3ad810cead593063b131ba74c06b3eec525a80d1374361729044a8165267a93`。

SDK 1/2（Connecting/FindingRoute）时本函数返回 true，调用者仍须另查 transport 是否为 2；
返回 true 本身不能证明可发送媒体。SDK 4/5 的原 SDR Close 实参为 `reason=0, text=null,
linger=false`；未知状态才用 2001。0 是 SDK 方法实参，不宣称它等于最终线上 end reason。
原 SDR Close 会在 SDK Close 前解除信令对象的两个归属指针；无 handle 或查询失败分支不走
该 Close，因此不在这里解除归属。拥有者销毁时仍必须解除归属并释放其余本地资源。

时间读取来自 SDK GetLocalTimestamp，单位微秒。只有既有 Connected 才可跳过未到期的查询；
恰好 1000000 微秒须查询。原函数把 last-check 加 1000000 的64位结果按有符号数比较；测试
还覆盖倒退时刻和加法回绕，不把毫秒级近似比较当作原始边界已对齐。
**证据修订**：撤回把+128槽位称为 GetQuickConnectionStatus／bool，以及“只把 EResultOK
映射为true”的适配。该槽位 `0xc46b70` 的重定位目标实际为 GetConnectionRealTimeStatus
`0x806884`，它返回 EResult；原调用者 `0x800514–0x80051c` 却只以零为失败。SDK原函数对
不存在的handle返回3（NoConnection），原APIGetRealTimeStatus `0x8582ac` 对错误lanes返回8
（InvalidParam），有效/null-output在统计端点后返回1。源函数执行额外验证了3/8/1返回值，
handle查找/锁与SNP统计端点仍是明确provider；不是只按函数名称猜测返回类型。
相邻 GetConnectionInfo `0x8067c0` 则在 `0x806834` 用 cset 产生0/1，其bool输入域另有指令依据。

因此这里保留原调用者的原始非零判断：不能把3、8等非零结果改成 transport Failed。0分支
作为原调用者中存在的合成输入保留，不宣称固定SDK的正常API路径会返回0。新增用例和反例
显式覆盖原来的“只认OK”错误，避免0/1桩掩盖真实SDK边界。这仅核对状态分支，不把失败SDK
调用后的统计内容或诊断字符串解释为有效；生产端口将临时统计输出初始化为零。

端口的配置/证书 HTTP 是异步的，和官方先完成同步 BInit 再 BConnect 的调用边界不同。
在尚未发起 SDK 连接时不执行 CheckConnection，避免把“正在取得配置、尚无句柄”误当作
“连接句柄已失效”。状态失败后队列的本地释放/唤醒发生在 policy 之后；项目资源错误的关闭
理由和完整传输 Send/Recv 结果处理不属于本项 CheckConnection 比较范围。

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

**SNS 消息长度和所有权（原始指令复核）**：`CStreamPacket::SetSteamNetworkingMessage
@0x7f6f30` 先释放旧 SDK message（或旧的非内嵌堆缓冲区），随后把 message+0 的数据指针
存入 packet+40/+56，把 message+8 的 32 位长度同时存入 packet+48/+52，并在 packet+2336
保存 owner。这里没有 2048 或普通 UDP 的 2272 字节截断。`ResetData @0x7f6dd0` 释放 owner
一次，恢复内嵌缓冲区、容量 2272 和初始长度 13；构造函数 `0x7f6d90` 同样初始化长度为 13。
`scripts/audit-steam-sns-message.py` 对固定 Android arm64 样本执行上述三个原始函数，覆盖
inline/heap/SDK owner 以及长度 0、1、2048、2049、2272、2273、3000、65536、524288 的组合。
只替代 heap delete 和 SDK Release 两个外部调用，不替代被验证的指针/长度/所有权分支。

**结论与边界**：SNS 的消息边界由 SDK 提供，不能把 UDP 缓冲容量当作 SNS 的协议上限；
零字节 SDK 消息也应消费并交给上层长度校验，不能因此关闭连接。上述执行没有覆盖 SDK 的
线上消息准入或发送方 MTU 选择，不证明这些长度都能由真实远端发送。固定公开 GNS 的默认
`RecvMaxMessageSize` 为 512 KiB（`csteamnetworkingsockets.cpp`），这是当前替代 SDK 的限制，
不是从官方 packet 函数推出的协议常量。项目跨线程队列分别限制为 4096 条、8 MiB（含 TX 待 SDK
返回的消息预留），这些是本地资源策略。IHS 适配器以不消费消息的长度查询按需分配，避免为
每个常见小包预留 512 KiB；空消息与空队列分别表达，再走公共批量接收/更新循环。

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
stats 编码设置 bit0，空间不足会裁减 quality 字段或省略 inline stats（`0x84ff68–0x850328`）；具体顺序、严格容量
边界和内联发送登记早于 socket 的行为见 §21.23。

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
  带 ack_peer_routes_revision；本地快照未获 ACK 且到期时重发。rendezvous 填入快照后把期限设为
  当前+1秒，relay stats 登记快照后则设为当前+500ms（控制消息成功后，或数据内联封包时）；
  两条入口的到期比较见 §21.14，内联提交点见 §21.23。
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
- RelayServer 已记录连续接收失败且距最后接收至少 500001 微秒，记录 connection gap；达到
  1750001 微秒再加 100 分（`0x81c4ac–0x81c4e4`）。单纯媒体没新帧不是该条件的替代。
  **Evidence correction**：失败数来自参数 RelayServer+256（`0x81c49c`），不是该连接的
  RelaySession LinkStats+4136。此前适配器读取 session 的计数，会由另一层超时提前影响
  active 选择。原始函数使用 root/session 失败数相反的输入覆盖这两者和严格时间边界。
  换成正确所有者本身不证明故障恢复成功。
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
关闭节点缓存中停止接纳新连接期限已过的目标。有效目标可创建/取得 RelayServer，进入等待该 target 的状态
（`0x819148–0x8193c0`）。不是收到任意 IP/port 就转发媒体。

`CheckCancelMigrationRequest 0x818c7c` 在没有 active primary、primary 不再公布迁移目标、
已保存 target 与当前公布地址不符、目标 root 已进入 draining 或 alternate penalty>=8191 时
清除 migration state/target（`0x818ca4–0x818ed4`）。该状态仍属于同一个端到端连接；
不生成新的配对 PIN、开流 request_id 或 pairing secret。

**更正**：此前把迁移校验所读的缓存期限笼统写成 shutdown 时间，应撤回该等同。
`RecvDowntimeWarning 0x817db0` 分别保存真正停机时刻和随机提前 45–60 秒的避让时刻；
`0x819318` 读取后者（entry+32），`0x823590` 才使用真正停机时刻（entry+24）。
同样撤回“收到任何 shutdown warning 就取消迁移”的宽泛表述：取消函数检查 root.draining；
尚未到避让时刻的未来预警不自动满足这个条件。具体更新、等号及调度规则见 §21.7。

### 18.7 SDR 客户端复刻的范围与接口

**范围修订**：复刻目标是固定样本的 **SDR 客户端行为**，包括内嵌网络库的客户端策略，
不止 Remote Play 应用层或控制 codec。撤回可将“库内策略尚未覆盖”理解为不属于本任务、
或需要先取得 relay 服务端实现才能继续的边界表述。客户端如何选 POP/relay、建立和淘汰备用
session、记住失败地址、探测、重试、保活及接受/取消迁移，均应由客户端代码还原并核对。

§18.1–§18.4 可直接用于编写控制 codec、relay session 建立和 revision/令牌维护。
数据报中的 encrypted chunk、端到端序号窗口、stats ACK 和 SNP 消息分片/重组仍应与 SNS 的
端到端连接实现衔接，不能直接把既有 IHS 包塞在 9 字节 relay header 后。
公开 GNS 固定源码可作为 SNS 端到端加密/SNP/ICE 对照，生产 SDR 扩展需独立补齐。

**客户端策略的覆盖要求**：包括 POP 内候选的全部比较、备用 session 的创建/淘汰、
失败地址缓存期限及探测频率的全部分支。`ThinkSelectServer_SelectActiveSessions
0x81c55c–0x81ddb8` 与 P2P metrics override `0x837f2c` 表明其还比较 min/current/max、额外 penalty、
当前 primary、待确认探测、样本数与网络配置；这些函数就在固定客户端 ELF 中，不是不可见的
服务端选择器。§21 展开这些客户端决策并执行原始指令复核；§18.5 的常量表单独不足以实现它们。
§18.7 早先将 P2P override 标为 `0x837a90` 的地址有误，该处是外层 ThinkSelectServer，现予纠正。
本文不把未完整命名的对象偏移硬写为公式。使用自有简化策略时应明确为本项目策略，和 §14
已确认的 transport 选择分开；只恢复字段而自行猜这些策略不满足官方客户端行为一致的目标。

**服务端内部算法不属于复刻目标**：不需要重现 relay 如何分配容量、选择迁移目标或生成路由令牌。
客户端接收的配置、challenge、令牌、延迟/penalty、revision、shutdown/migration 通知和错误回复
是外部输入。需要恢复的是对这些输入的校验、状态变化、输出报文与定时行为：例如 NoSession
更新 challenge 后重建 session，BadRoute 失效精确匹配的令牌，迁移通知先校验目标资格再采取动作。
不能因为服务器决策算法不可见，就把这些响应处理或本地调度排除。

**行为一致的判据**：给定相同的初始客户端状态、配置、计时/RNG 输入、对端与 relay 的消息和
网络收发结果，应能解释并复现官方客户端的相应状态迁移、报文内容/目的地及调度规则。
配置和服务端结果的动态值保留为输入，不硬编码某次实验选中的 POP、token 或 penalty。
这一判据不要求自己搭建 SDR 服务或预测服务端下一步如何决策；也不等同于在所有网络上产生
逐包相同的墙钟轨迹。实际互操作仍用于检验还原的客户端契约。

## 19. 规格的适用边界

本文与认证参考、既有流协议参考一起，定义了 Android 固定样本**客户端应用层**从发现、授权、
开流、Proof、材料导入、信令桥到传输交接的主要正常/错误/取消/重试行为；§14 给出内嵌网络库
可确认的选路、迟滞和信令可靠性规则。可据此编写这些模块及具有明确契约的 backend 适配，
无需凭字段名称猜测地址选择、密钥来源、Busy 行为或把所有重试统一处理。

以下项目不在“应用层规格完整”这一判断的证明范围内，不能写成已兼容：

- PC 主机/Steam 服务内部的配对槽位寿命、风控、Proof 更新中断后的主机回滚及证书签发策略。
  客户端按实际返回结果处理，不自行伪造服务端政策。
- 不依赖官方网络库的完整 SDR **客户端**实现。§17–§18 给出 schema、challenge、签名申请、
  数据封装和 revision/错误恢复规则，§21 给出客户端选择、探测、缓存、迁移与快照契约；
  静态规格和合成对象执行仍不证明一个独立 backend 已能互操作。
  它们属于客户端复刻范围，不能用 §14 的 P2P transport 选择替代。relay 服务端内部算法则不属于
  本项目复刻或验收要求；所需的是正确处理其可见输入及返回结果。
- 不同出口 NAT/CGNAT/对称 NAT、路径变化及长时间串流的互操作实测；静态分支存在不能证明
  所有路由器/防火墙配置下都可达。
- 主机端码率/FEC 决策及全部媒体能力；由独立流协议参考和实际支持能力约束。

**接入实现的边界**：选择兼容 SNS/SDR backend 时，客户端库内的实现由 backend 提供；选择
完全自有的 Switch backend 时，这些客户端协议与策略必须一并定义、实现和核对。两种方案都
不要求重新实现 SDR 服务端；也不能因上层行为已描述，就把一个 codec 当作可工作的 SDR 客户端。
相关实现/验证任务仅在 GitHub Issues 维护。

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

## 21. SDR 客户端的选路、探测与故障策略

本节将 §18 的客户端内部分支展开为实现约束。Evidence 均来自 §17 固定 AArch64 样本；
函数名、地址和字段偏移用于定位证据，不要求新实现复制 C++ 对象布局。
时间比较使用客户端单调微秒时钟；网络配置、对端 routes、服务器响应和随机数都是输入。
初始化默认值不能从 ELF 的零填充 BSS 推断，必须读取配置注册代码。

### 21.1 三组列表与两种 ping 数量

**Evidence**：`CConnectionTransportSDRBase` 的 active 列表位于 +20/+28，数量 +36；
全部已建立 session 列表位于 +40/+56。`CP2PRouteSelector::BuildListsForServerSelection
0x83a124–0x83a8c8` 另生成两份按本地 POP 去重的候选列表：

- `selector+72`：每个本地 POP 取所有已知方向组合中的最佳路线。
- `selector+48`：每个本地 POP 只在**远端 POP 有非空 routing token**的组合中取最佳路线。

选择组合和排序使用的分数为：forward score 不是 INT_MAX、reverse score 为 INT_MAX 时取 forward；
二者都不是 INT_MAX 时取向零截断的平均数；forward 为 INT_MAX 时仍为 INT_MAX。
这里必须区分占位值 INT_MAX 和新路线尚未取得 reverse score 时写入的 `0x0fffffff`：
后者仍参与平均，会形成很大的比较值，不能把所有“大数/未知”统一改为“忽略 reverse”。
只接受 forward score < `0x0fffffff` 的结果。相同分数不另加 POP ID 排序条件。
`0x8381b4–0x8381f4` 先对 `selector+72` pursue 最多 2 个，再对 `selector+48` pursue 最多 1 个。
这是两个调用各自的配额，不是“全局只建立两个 session”。

active 列表最多两项（primary、backup），但全部 session 可以更多；退出 active 列表不立即销毁。
backup 尽量来自与 primary **不同 SharedClusterData 对象**的 POP。
基础 selector 找不到这种候选时不主动清除已有 backup，可能保留本轮 P2P metrics 不合格的旧
backup（选择扫描 `0x81d93c–0x81daf0`）。**收紧这一结论**：它要求 primary 未改变。
primary 切换路径 `0x81dc8c–0x81dc98` 先把 active count 写成 1，再保存新 primary，
然后重新运行不同 POP 的 backup 选择；旧 backup 不会仅因“本轮没有替代项”而跨此重置保留。
原先将保留规则无条件用于 primary 切换的概括应撤回；生产 C 实现与原始指令的组合差分
（`tools/steam-sdr-implementation-audit.py`）覆盖该重置边界。
**撤回将基础函数规则推广为完整 P2P 行为的解释**：P2P 外层先运行
CleanRoutesForServerSelection，已失去目标 token 的 active 项会先被移出；随后才执行基础 selector
（§21.13）。离线用例分别覆盖这两个阶段，不能把基础函数单测当成外层的最终结果。

**两种数量不可混用**：cluster 的 front tracker 只保存最近 3 次独立 ping；
session metrics 的 +16 是近期**有效时间桶数**。切路门槛 15 是有效桶数，不能用短时连收 15 包替代。
cluster+32 为最近一次 ping 接收时刻，+64 为三次样本中最老一次的接收时刻；
因此读取 +64 的 5 秒分支是在要求三次样本都足够新。
类型布局可由开源 `steamnetworking_statsutils.h` 的 PingTracker / PingTrackerForRouteSelection
交叉理解，实际常量与分支仍以固定 APK 指令为准。

### 21.2 路线分数与 active 主路切换

**Evidence**：`ThinkSelectServer_SelectActiveSessions 0x81c55c–0x81ddb8`：

1. 先将所有已建立 session 的 score 重置为 `0x0fffffff`、排序序号置 -1。
   遍历全局 RelayServer，调用 base metrics 和 P2P override。base metrics 失败且 relay 仍有
   session 时走 RemoveRelayServer；P2P override 失败只是不列入候选，不等同于销毁 session。
2. 对合格候选计算 §18.5 的 current/min/max score。排序键是
   **current score 升序、migration 标志升序、shutdown 剩余秒数降序**；
   不是按 min score 排序（原始 comparator 位于 `0x8327c0–0x834000`）。
3. 尚无合格 primary 时直接取排序第一项。已有 primary 时，依序检查排在它之前的候选，
   遇到 primary 即停止。下文 `best` 始终指排序第一项，`candidate` 指本轮正在比较的项。
4. 若没有 pending migration，而且
   `current.minScore < trunc_f32(candidate.maxScore + 10 + 0.1f*candidate.maxScore)`，
   同时 `current.shutdownSeconds >= best.shutdownSeconds`，停止比较并保留 current。
   f32 运算及最终向零截断属于该样本的规则。
5. candidate 的 `lastReceived+250000 < now` 才算 stale；恰好 250 ms 仍为 fresh。
   下列情况允许跳过常规 15 桶确认，但仍要求 fresh；stale 时只请求探测并继续保留 current：
   current 的 root 已进入避让、current alternate penalty >8190、best migration=-1、
   current migration=1。
6. current 有接收空档时，仅当 candidate 的 lastReceived 不早于 current 且 candidate fresh
   才切换；否则探测 candidate。空档使用 metrics+64，不能用“没有新视频帧”代替。
7. 若 `candidate.maxScore+50 < current.minScore` 且
   `best.otherPenalty+50 < current.otherPenalty`，也走第 5 项的强制新鲜度路径。
   两个条件都为严格小于；该分支不是“ping 好 50 ms 就无条件切换”。
8. 常规确认要求 candidate cluster 至少 3 个 front 样本，且最老一个 `received+5秒 >= now`。
   不满足则 candidate 需要补探测。满足时，best 的有效桶数 >=15 且 candidate fresh 才算
   candidate 已确认；桶数不足且尚未到 probe 时刻，即使 fresh 也不立即切换。
9. current 也须 >=15 有效桶才能正常切换。current 不足时，检查
   `min(candidateCluster.lastPingSent+200ms, candidateCluster.currentBucket.end) <= now`，
   到期则探测 current；candidate 需要补探测时也探测 candidate，保留 current。
   此处读取的是 candidate cluster 的 tracker，移植时不能擅自改读 current tracker。

上述请求探测的分支都先检查 RelayServer 是否已有 pending ping，避免重复发送。
切换可复用现有 backup；旧 primary 是否留为 backup 由随后不同 POP 的选择决定。
主路改变会重置该主路统计快照/接收计数/失联原因，并提前调度 connection 和 session thinker。
跨 POP 时用 local front+remote front+interior 为端到端 ping 提供初值。
ClientSwitchedPrimary（type 16）遥测还要求旧主路时间非零、旧主路收到至少 101 包且旧地址/POP
有效（`0x81d4b0–0x81d7dc`）；不能据缺少该遥测判定没有发生切路。

### 21.3 pursue session 的配额、准备与重试

**Evidence**：`ThinkSelectServer_PursueSessionsOnClusters 0x81df30–0x81e504`：

- 每项路线记录本轮序号；配额计算的是可继续使用或正在取得的候选，不是扫描过的项数。
  已有本连接、同 POP 的合格 session 可直接占一份配额，不重复申请。
  root 避让、alternate penalty>=8191 或不满足地址限制的旧 session 不走该复用路径。
- 本轮已消费的配额为 0 且迁移目标属于本轮 POP 时，优先追求迁移目标；否则先复用合格
  session，再由 §21.4 的共享 chooser 选 relay。这是 consumed=0，不是 remaining=0。
- 申请前要求 challenge 非零、server_time 非零；challenge 接收年龄 <=10秒；
  relay lastReceived 非零且年龄 <=20秒；cluster 至少 3 个 front 样本、最新样本年龄 <=20秒；
  relay 连续 ping 失败数为 0。challenge 超过 10 秒会先清零。
- 缺少这些条件时，没有 pending ping 才发准备探测；有 pending 则等待。
  连续 ping 失败 <2 时，这条等待/探测中的路线仍占配额；>=2 不占，可继续追求后面的路线。
- 一次 pursue 调用中，前一条路线已启动/等待取得时，后续路线不会再实际发新的 session request。
  已有 session 的直接复用本身不触发此限制。
- 满足准备条件且该 relay 没有 pending session request 时，调用派生申请函数，随后设置
  `requestDeadline=now+750000`。此期限由调用方无条件写入，不能由发送返回值擅自省略。
  deadline 超时由全局 thinker 处理，不能只在应用再次发媒体时检查。

全局 thinker 对 session request 第 1/3 次超时只清 pending 并增加计数，
第 2 次额外发 ping，第 4 次移除 relay；真正重申请由随后选路/pursue 驱动。
这一交替探测规则来自递增前的失败数奇偶判断（`0x823394–0x8233bc`、`0x8234e8–0x823508`）。

### 21.4 一个 POP 内选择具体 relay 地址

**Evidence**：共享 helper `0x81e504–0x81eb90`，同时被连接选路和全局探测使用：

1. 遍历所有 SDR clients；任何客户端已有同 POP 的 migration target 时优先返回它。
2. 再检查该 POP 已创建的 relay。排除 root 避让、alternate penalty>=8191，以及不满足
   调试地址限制的项。按其任意 session 在 owner active 列表中的最小序号选择：primary=0、
   backup=1、未激活=INT_MAX。序号相同时，优先真正停机剩余时间更长的 root；完全相同保留先遇项。
3. 没有可复用项时，先尝试 cluster last-good address；它须有 IP/port、不在最近失败缓存，
   且没有已过避让期限的停机记录，并符合地址限制。
4. last-good 不可用时，最多 **99 次**随机选地址。过滤无效 IP/port、最近失败缓存和已经
   过避让期限的停机记录；确认地址归属当前 POP，再创建/查找 RelayServer。耗尽返回 -1。
   不要写成无限重试或把 99 次改为“直到找到一个”。

`SharedClusterData::SelectRandomAddress 0x8155cc–0x815730` 在没有调试限制时从 POP 广告的
扁平地址空间均匀选 index，再由 POP::GetRelayAddressAtIndex 解出 IP/port。
有地址限制时，对属于该 POP 的 IP/port 区间按可选端口数加权抽样；没有有效限制结果才退回
普通随机选择。复现随机路径要求把随机数源也作为输入，不能期待不同随机数产生相同目的地址。

### 21.5 全局探测、初始化与路由可用判定

**Evidence**：`SteamDatagramClientThinker::Think 0x82318c–0x825370` 每轮将自己调度到
now+100ms，另由外部事件提前唤醒。固定 APK 在 `0x83410c` 的配置注册代码给出：

| 配置 | 默认值 | 使用方式 |
|---|---:|---|
| SDRClient_ConsecutitivePingTimeoutsFailInitial | 2 | 从未收到回复且无 session 的 root，达到该连续失败数即可移除 |
| SDRClient_ConsecutitivePingTimeoutsFail | 4 | 一般 relay 达到该连续失败数移除 |
| SDRClient_MinPingsBeforePingAccurate | 8 | 初始探测次数及测量准确性门槛 |
| SDRClient_LimitPingProbesToNearestN | 20 | 实际取 max(5, 配置值) |

配置名中的 `Consecutitive` 是样本本身的拼写。字段可能被配置覆盖，默认值不是硬编码协议字段。
POP 的 tier（默认 1）与 ping-only 类型由网络配置 JSON 解析（`0x898d74–0x898e0c`），
不能简单地探测列表里的前 20 个 IP。

调度先按 cluster 的 routing score 排序，未知/过大值（>=5001）用随机 5000..5100 排序值打散。
对合格 POP 构造探测优先级，较小者优先（`0x823d24–0x82445c`）：

- nearest-N 使用**排序前缀中的非失败 cluster 数**，而非已发探测数或列表下标：每项先按
  下述失败分类决定是否增加计数（`0x823f20–0x823f64`），再进行数量门槛判断。
  普通 tier=0 或 special>0 候选绕过数量门槛；其余 tier>=1 且前缀计数>N 的候选跳过
  （`0x824008–0x82409c`）。因此失败项本身不增加计数，但在计数已经>N 后仍可被跳过。
- 受本地 override 影响的 cluster 初始探测不足 8 次时使用约 -1e30 的紧急优先级。
- 无 ping 的初始候选采用上述排序值；普通 tier>=1 候选再加 10000，先为其他层的初始测量让路。
  已多次失败的候选走较低优先级的重测分支。
- 普通重测优先级为
  `20000 + (ping+50+typeAdjustment)/(max(0, secondsSinceLastPingSent)+0.5)`；
  `typeAdjustment=0` 用于普通 relay POP，其他类型为 75；ping 未知的退避分支另取排序值+2000。
  所有这些优先级都用 f32，不能直接改成整数延迟排序。
- 完成准确测量且无活动连接时不持续密集探测；有活动连接时，足量样本且最近一次 ping 接收
  不超过 120 秒仍跳过重测。不可达节点在主备齐全时还受最后探测发送+120秒约束。
- 发送前对候选优先级升序排序。尚欠其他层初始测量时将 cutoff 收紧为 10000，
  否则约 1e30；priority>=cutoff 不发。每轮最多发 10 次（缺少 primary/backup 或无活动连接），
  主备齐全且有活动连接时最多 1 次。找不到 relay 或已有 pending ping 的项不消耗发送预算。
  本路径 EProbeTOSCase=4；不能擅自对全部探测使用不同 TOS。

cutoff 的具体比较为 `initialOther > measuredTierZero`（`0x82445c–0x8244ac`）：
initialOther 统计进入无 ping 初始候选分支且未加 10000 的项；紧急 override 分支不计入。
measuredTierZero 统计普通 tier=0 且 ping>=0 的项，不额外要求该项仍可达。
二者并不是同一列表的“待测项减已测项”。本地实现须先完成整轮计数再发送，不能遇到
一个 tier=0 未测项就立即截断普通 POP，也不能在收到一个回复后无条件解除 cutoff。

**活动连接标志的语义**：`0x823b78–0x823ca8` 检查连接 wire state 1..3，保存到本轮
sp+48；它独立于 primary 是否存在。sp+40 则记录仍需补充活动 session/路线的条件。
本地曾把前者误接成 `!have_primary`；撤回该接法，准确样本的 120 秒重测条件须使用
活动连接标志。上述每轮预算为 `needRoutes || !activeConnection ? 10 : 1`。

本轮探测的失败分类另读取失败地址缓存：cluster 累计失败 >=4，或累计失败 >=2 且
失败地址缓存非空，或 reachability<0，任一满足即使用失败重测分支
（`0x823f20–0x823f68`，缓存数量为 SharedClusterData+660）。这不等于 §21.6 的
持久 reachability 置 -1 条件；不能仅因字段仍为可达就忽略已有地址失败历史。

**路由数据可用**与“已经连上某个 relay”分开保存（`0x824bbc–0x824cc8`）：
初始化已开始且已测普通 POP 数 >= `min(15, trunc(totalOrdinaryPOPs*80/100))` 时，
再满足任一条件即可允许选路：初始测量已超过 7 秒；至少一个保守 ping<30ms；
至少两个 <75ms；至少四个 <150ms。
普通 POP 的已测计数允许总接收样本数=2，延迟直方图计数则要求 >2，且 front ping 有效、
tracker 至少两次接收、cluster 已判可达（`0x823f8c–0x823ff0`）。
完成整轮初始测量也会置 good-enough，并提前唤醒各连接 thinker
（`0x82468c–0x8246dc`）。这不是要求应用等待所有 POP 或等一个固定超时才连接。

### 21.6 超时、失败缓存与恢复

**Evidence**：全局 thinker `0x8232ec–0x823a04` 和 ReceivedPacket `0x812834–0x812a28`：

- pending ping 的 deadline<=now 时清除 pending、relay 连续失败+1；root 同时增加 cluster
  连续失败计数。初始 2 次/一般 4 次的移除判定使用配置值。成功收包会清零 relay/cluster 失败。
- root 被失败策略移除时更新该 POP 的失败地址缓存；alternate 的失败另记其状态，不能把
  alternate 的地址失败一律记成 root UDP 地址失败。
- 失败缓存最多 3 项，每项为完整 IP/port 和失败时刻。同地址重记先移除旧项再追加；
  否则数量已有 3 项，或已覆盖 POP 的全部广告地址时，先丢最老一项再追加。
- 只有 cluster 失败累计>4 或此前失败地址已有至少 2 项时，才在这次失败处理把 cluster
  reachability 置 -1；不能把一次地址失败直接解释成整个 POP 不可达。
- 缓存项在 `failedTime+120秒 < now` 时过期，等号保留。
  清理后若仍覆盖 POP 全部广告地址，则另丢最老一项，使至少一个地址可以重试。
  cluster 最后发送探测超过 120 秒时，重置其累计失败状态；等号不重置。
- 任何通过上层来源/格式检查而进入 ReceivedPacket 的有效包都会刷新 relay lastReceived、
  保存 root 地址为 last-good、移除匹配的失败缓存项，并将 cluster reachability 改为 1。
  这一步不只针对带 ping 样本的 RouterPingReply。
- 全部已建立 session（包括当前不活跃的项）在 `lastReceived+60秒 < now` 时销毁；
  等号保留，按倒序删除，以免列表变动跳过元素（`0x82350c–0x82358c`）。

### 21.7 停机预警与迁移输入

**Evidence**：`RecvDowntimeWarning 0x817db0–0x817fc0` 保存两个期限：

```text
shutdownTime = now + signed_secondsUntilShutdown * 1000000
avoidTime = shutdownTime - trunc(WeakRandomFloat(45,60) * 1000000)
```

首次插入取一次随机值；已有记录仅在新 shutdownTime **严格早于旧值 3 秒以上**时更新并重取随机值。
推迟、相同、只提前 3 秒均不更新。全局 thinker 到 avoidTime（<=now）后设置 root draining 并
通知关联 session；到 shutdownTime（<=now）移除 relay，并非等 ping 超时后才避开。
同时维护 `floor((shutdownTime-now)/1秒)`，供 §18.5 的渐进惩罚使用。

chooser 和迁移校验的排除条件为匹配记录的 `avoidTime < now`；恰好相等仍可通过该局部校验，
而全局 thinker 的 draining 更新使用 <=。复现边界需保留事件处理顺序。
停机记录在 `shutdownTime+180秒 < now` 后清除；样本快速测试开关启用时为 60 秒。
因此“记录还存在”不等于“节点当前一定不可选”。

迁移请求从 state=1 开始处理时，先清除 pending 和旧 target；未知 POP、跨 POP、失败缓存命中、
已经过 avoidTime 都终止此次请求。合法且取得目标 relay 后转为 state=2、保存 target index；
创建失败保留 state=0/target=-1。目标是否成功建立 session 由随后 pursue 和 active 选择完成。
这是客户端响应服务器迁移输入的行为；服务器为什么挑中这个 IP 不属于客户端复刻目标。

### 21.8 原始指令复核的入口与替代边界

[`tools/steam-sdr-policy-audit.py`](../tools/steam-sdr-policy-audit.py) 对固定 ELF 执行上述客户端指令：

```sh
python3 tools/steam-sdr-policy-audit.py \
  --elf /absolute/path/to/libmain.so \
  --report build/steam-sdr-policy-audit.json
```

报告逐组给出用例数，不读取真实凭据、不连接网络、不改变模拟器或防火墙。
active 选择完整执行 `0x81c55c–0x81ddb8`，其排序/comparator 使用原始指令；
pursue、ReceivedPacket、BuildListsForServerSelection、具体 relay chooser、停机预警和迁移校验
同样执行完整函数。metrics provider、POP 地址查询、随机数、申请发送、锁和外部通知是明确的桩。
默认 selector 用例证明“给定这些 metrics 后如何决策”。另有 integrated_metrics_and_selection
组串接原始 base metrics、有效桶范围、P2P metrics、排序和 selector，覆盖三段 penalty、两端 front、
interior、目标 token 与迟滞；该组仍直接构造已整理的 per-POP 路线数组，不冒充 protobuf 回复到
完整选路的端到端验证。CleanRoutes 用例明确替代路线构建器，单独验证目标更新与 active 剪除。

全局 probe priority/budget/readiness、超时和缓存测试分别执行函数中的明确片段，
到指定控制点即停止；不声称执行整个全局 thinker、实际线程、socket 或跨 tick 的调度。
缓存和 schema 以外的 SDK 未建模分支不会被静默跳过。
原始指令结果与手写预期不符时应修正规格或查明 fixture 输入，不能让桩替代被核对的策略。

### 21.9 对端路线信息的生成、筛选与快照迟滞

**Evidence**：路线建立 `FindOrAddRoute 0x83988c–0x839b9c`、对端快照导入
`MarkRemoteRelaysAndRoutes 0x839b9c–0x83a124`：

- POP 先映射为网络配置中的索引。未知 POP 不生成路线；canonical POP 映射用于查 interior ping。
  本地 front 不可用、interior ping 不可用时不能新增路线；远端 front 不可用在调用方过滤。
- 新路线的 forward score 为
  `F(localFront+remoteFront)+interiorPing+localPenalty+remotePenalty+interiorPenalty`，
  `F(x)=x+trunc(x/10)`。route 另保存 interior ping/quality/penalty 和远端 token 是否非空；
  reverse score 初始为 `0x0fffffff`，不是 INT_MAX。
- interior ping 从 SharedClusterData 缓存取得；不存在或 ping<0 时返回 -1、quality=2、penalty=0。
  有有效条目时保留其 penalty；条目的测量时间非零时 quality=0，否则 quality=1。
  `EDataCenterPingType=1` 还过滤缓存中的相应禁止标志，但 P2P FindOrAddRoute 调用使用 type=0
  （`GetPingToDataCenter 0x8159dc–0x815aa0`）。
- 对端 RelayCluster 的 ping、penalty、token 更新 remote metrics。对远端有 token 的 POP，
  允许枚举所有本地 POP；另加入配置给出的最近候选及调试 POP 限制内候选，合并重复组合。
- 对端 Route 的 my_pop_id 是**它的**本地 POP，对应本端 remote；your_pop_id 对应本端 local。
  有 interior_score 时重新计算 reverse score：
  `F(localFront+remoteFront)+localPenalty+remotePenalty+peer.interior_score`。
  没有 interior_score 才使用兼容 legacy_score；缺失两个分数字段的项不能作为有效反向分数。

**Evidence**：`MarkItemsToSend 0x83b1d8–0x83c848` 与
`MessageToPeerBuilder::TruncateLists 0x83c848–0x83c920`：

1. 每条路线维护 forward/reverse 的用于公布比较的分数。原值>9999 按 `0x0fffffff` 处理；
   验证旧快照时，新出现且旧快照没有的项额外增加 `trunc(score/15)+5`，给旧内容迟滞优势。
2. 仅 controlling 一方当前 primary（active index=0）的路线被标为强制公布，临时 rank=4，
   比较分数设为 `-0x0fffffff`；backup 和非 controlling 一方不因此强制。
   角色/控制方门槛来自 `0x837190–0x8371a4`，置位来自 `0x837384`。
   其余路线执行四次排序：优先内部标志/forward/reverse、优先内部标志/reverse/forward、
   reverse/forward/内部标志、forward/reverse/内部标志；数字分数升序，内部标志 true 在前，
   最后按 local/remote POP 索引升序打破平局。该 builder 在初始化时将内部标志清零；
   强制使用标志是另一个字节，不能与之混淆。
3. 每轮排序的前两条**写为 rank=3**，包括此前临时 rank=4 的强制项；
   接下来的两条在尚无 rank 时设为 1。
   四轮的结果取并集；不能简化为“最终只发送 4 条路线”。调试 POP 限制启用时只取符合限制的前缀。
4. cluster 初始比较分数为 local front+local penalty；对端明确使用的 cluster 初始 rank=2。
   已选路线将其**本地端** cluster 的 rank 提高到路线 rank，确保必需的 token/POP 信息同批公布。
5. cluster 按比较分数、POP 索引选择，前四个提高到至少 rank=3，接下来两个在尚无 rank 时设为 1；
   不可用 front 或负 override 状态使这段选择停止。它与路线带来的必需 cluster 也是取并集。
6. TruncateLists 首先按 rank 降序，再按比较分数升序，最后用 POP 索引打破平局；
   Route 使用 forward 比较分数及 local/remote 索引，RelayCluster 使用 front+penalty 及本地索引。
   强制路线的负比较分数保证其在同 rank 中领先。最终在第一个 rank=0 处缩短列表。
   它没有再施加一个固定“最多 4 routes / 6 clusters”的总数上限。
7. RelayCluster 序列化携带所选 session 的 token、POP、ping 和 penalty；Route **同时**公布
   `interior_score=interiorPing+interiorPenalty` 与 `legacy_score=forwardScore`。
   前者不含两端 front，后者为 §21.9 的完整 forward 总分。
   真正重建后才 revision+1，清除旧的重发期限，并要求对端获知新快照
   （`0x837468–0x8378c4`）。

**Evidence correction**：此前本地构造只写 interior_score，遗漏了仍被官方同时写出的
legacy_score。`0x837688–0x8376f0` 设置四个字段的 presence bits，并将 raw route+24 的
forward 分数写入 protobuf f3、raw route+8 和 +16 的和写入 f4。不能把“支持新字段”理解为
发送方可以省掉旧字段。独立原始序列化字段投影片段验证两端 POP、两种分数与 presence，
没有把 RepeatedPtrField 分配或完整 protobuf 编码算作被执行。

**旧快照复用**：`CheckOldMessageValid 0x83aa9c–0x83b1d8` 先逐项校验旧内容，再检查它是否
覆盖仍必须公布的内容。penalty 差值达到 `5+trunc(min(old,new)/15)` 就重建（等号重建）。
ping 差值到达同一阈值时不立即重建：若旧 ping 仍在当前近期 min/max 区间内，可继续复用；
超出区间才重建。token 必须逐字节相同；旧快照有 token 而当前没有匹配 session 也不能复用。
Route 的旧 interior_score 与当前 interiorPing+interiorPenalty 按同一阈值校验。
最后以“验证旧快照”模式重新执行 MarkItemsToSend；旧快照漏掉任何 rank>=3 的必要项就失效。
在逐项迟滞前另有 primary 契约：controlling 一方有当前 primary/目标时，旧 routes 必须
非空，且首项 my/your POP 对等于该 primary 的本地/目标 POP，否则立即重建
（`0x837390–0x837400`）。不能仅比较成员集合，也不能用 rank 后按配置索引排序替代完整
TruncateLists 顺序。这些迟滞只控制 routes 快照更新，不改变 §21.2 的 active 切路阈值。

**快照前置门槛**：`CheckRebuildRoutingMessage 0x836d7c–0x836de8` 在全局 routing
good-enough 为真时才进入 InitMessageToPeer；未就绪分支不构造候选快照。它与 §21.13 中
selector 只在同一门槛后导入 peer routes 的规则一致。仅收到几个 front ping 并不能开始公布
完整路由图。原有本地“只公布已有 session”的路径间接满足了这个门槛；改为公布可测 front
时必须保留显式门槛，不能从函数级排序通过推断调用时机也正确。

连接层的调用顺序由 `CConnectionTransportSDRBase::ThinkSelectServer 0x81bf60–0x81c0e4`
约束：只有 wire state 1..3 执行；先取消无效迁移，再评估已有 active sessions，
仅在全局 good-enough 为真后才 pursue 新 session。不能把 good-enough=false 解释为停止维护
已经建立的路径。该分派、快照筛选及其原始排序器也包含在 §21.8 的离线执行入口中。

### 21.10 延迟缓存的完整/增量回复与未知 POP 的估计

**Evidence**：`RecvDataCenterLatencies 0x812f40–0x8134d8` 的输入是已完成来源与数组长度检查的
RouterPingReply；容器操作与 canonical POP 查询不改变以下字段语义：

- 没有 FLAG_MAYBE_MORE_DATA_CENTERS（bit 0）时，先将旧条目的直接测量时刻置 0，
  保留旧 ping/penalty/flags，记录本轮完整回复时刻。它不是清空缓存；旧值变为估计质量。
  有该标志时保留旧测量时刻，按增量更新。
- 普通 latency_datacenter_ids/ping_ms 写 ping、测量时刻=now，清 penalty 和 flags。
  随后的 P2P 数组写相同数据并设置 flags=0x20000000。重复 canonical POP 后项覆盖前项；
  同包同时出现在两类数组中时，P2P 数组后写。
- 存在反向 cluster 缓存时，允许把 ping 复制为反向估计，但不能覆盖反向已有非零直接测量时刻的条目。
  反向估计不伪造一个“now 已实测”的时间。
- route_exceptions 只修改找到的条目：flags 按位 OR，penalty 替换；未知条目不凭 exception 新增。
  本函数在两个延迟数组都为空时不走 exception 循环：完整回复仍降级旧测量并要求重算，
  增量空回复直接返回。不能仅凭字段存在就假定任何分支都会应用它。
- 有更新时要求路线缓存重算；bit 0 不是“稍后一定再收到一包”的保证。
- 独立的 `RecvClusterScoringPenalty 0x812cb4–0x812dd4` 将输入钳到 0..5000；负数或 >=5000
  先诊断再继续钳位。钳后值等于旧值时不要求重算；改变时先通知 dirty 再保存值。
  不要把这条校验自动套给 route_exceptions 的 penalty 字段。

**Evidence**：`EnsureDataCenterRoutesValidLocked 0x810e70–0x8113c4` 生成未直接探测 POP 的
route estimate，供 §21.5 排序使用，同时维护各 POP 最近的实际 relay 候选：

1. 可达且 front ping>=0 的 cluster 以自身 ping 初始化 direct front 和 route estimate；
   其余为 direct=-1、estimate=0x0fffffff。已知节点取 cluster penalty（负 override 额外+1000），
   未直接测量的初值 penalty 为 10。
2. 按配置中的 cluster 顺序，最多做 **3 轮原位松弛**，一轮没有改进就结束。
   只从 route estimate<=2000 的 source 扩展非负 interior ping：
   `rawCandidate=source.estimate+interiorPing`，
   `selectionScore=F(source.estimate)+interiorPing+interiorPenalty+sourcePenalty`。
   前者收紧未知目标的 estimate 上界，后者用于挑选入口 relay。
3. 第一轮中，source 有直接 front 且边有非零直接测量时刻时，可更新目标的实际最近候选：
   普通 datacenter 候选排除 0x20000000 标志的 P2P-only 边，P2P 候选保留最好的 3 个。
   估计边不冒充这些实际候选。
4. 对未直接测量目标，直接 source 还贡献非负下界 `max(0, source.estimate-interiorPing)`。
   最后同时有上下界时，estimate 改为两者之和右移 1；没有下界就保留最小 rawCandidate。
   直接 front 的 estimate 不被路径推断覆盖。

“3 轮”不是完整最短路算法，也不是严格最多 3 跳：原位更新允许本轮后面的 source 继续传播。
离线输入中，正序的五节点链可一次传到末端；逆序链在第三轮后仍有一个节点未知。
因此不能换成任意 Dijkstra/无限循环收敛并宣称与原客户端相同。
source 的 2000 边界包含等号，2001 不扩展；负 interior ping 不参与。该估计也供全局
探测排序使用（`0x823d4c–0x823d88`）：估计 >=5001 才换成 5000..5100 的随机排序值，
不能对所有尚无直接 front ping 的 POP 一律使用随机高分。

### 21.11 alternate 地址的公布、探测与淘汰

**Evidence**：`RecvAltTransports 0x8134d8–0x813bd0` 仅处理 root relay 的公布：

- 无 FLAG_MAYBE_MORE_ALT_ADDRESSES（bit 1）时，先给旧项标记删除候选；增量回复保留未提及项。
- 按完整 IP/port 查找项。未带 ipv4 时继承 root IPv4；port 为本包给值。更新 id 字符串和 protocol。
  新项和重新公布项的内部 penalty 都设为 **8191**；AltAddress.penalty 不在此函数中直接成为可用
  线路评分。不能把未测的 alternate 当作零惩罚的正式路径。
- protocol 改变时移除旧探测 relay；非 DefaultProtocol（0）的项在该固定样本的清理阶段被移除。
  完整回复未再公布的 DefaultProtocol 项也被移除；必要时销毁其关联 relay。
  vector 压缩后会修复仍存活 child relay 的 AltTransport 指针，避免引用旧槽位。

`CheckCreatedAltTransportByIndex 0x810d38–0x810e70`：已有 probe relay 直接返回；
没有时须 `lastFailure+120秒 < now` 才尝试 New。创建失败记 lastFailure=now；
等号仍受冷却限制，不能每次 thinker 都重建失败 socket。

全局 thinker 完成初始测量后，按 root front ping 升序检查最多 5 个合格 root，创建其
DefaultProtocol alternate 探测（`0x8247d0–0x824b34`、`0x824f94–0x825104`）。
`RecvPingReply 0x812afc–0x812b78` 在测量足够准确时保存 alternate 的实际 ping 并清除失败时间；
这里的门槛仍使用 MinPingsBeforePingAccurate 配置，和 active 切路的 15 桶不是一个量。

**探测调度 Evidence**：`0x824d38–0x824ea8`：

- alternate 连续失败达到一般阈值时，该片段跳过它，移除由前面的全局失败处理负责。
- 收到至少 8 个 ping（可配置）且保存的测量有效时，移除临时探测 relay，保留测量槽位。
  不能把 probe 对象删除误解成服务端撤销了 alternate 广告。
- 任一未完成的 alternate 最近发送尚未满 90ms，该轮结束，不发送此前选中的其他 probe。
  否则从无 pending ping 且最后发送至少 500ms 的项中取最久未探测的一个，每轮最多发送 1 次；
  恰好 500ms 可发送。同一发送时刻的平局取后遍历项。
- 若该 alternate 的 root 已有失败，优先探测 root，仍检查 root 的 pending 和发送年龄。
  这些是探测辅助路径的节流，不替代 §21.5 的普通 POP 探测预算。

### 21.12 错误响应、session 成立与 ACK 的精确状态变化

**NoSession Evidence**：`ProcessMessage_NoSession 0x81a290–0x81a358` 先应用存在的停机预警，
再调用 SaveChallenge，随后持锁销毁对应 session，最后重新选路。SaveChallenge 仅在 challenge
字段 presence 存在时更新 challenge/server_time/本地接收时间和非零公网映射；没有该字段时保留旧值。
不能因为收到 NoSession 就先清全部凭据，也不能等重建 session 后才保存 challenge。

**P2PSessionEstablished Evidence**：`0x83dac8–0x83e034` 要求非空 token；空 token 诊断后返回，
甚至不清 pending session request。非空 token 先清 relay.pendingRequest，处理存在的停机预警。
内部连接状态 -2/1/2/3 可复用本连接已有 session，或创建一个新 session，再保存 token、刷新
session 的最后接收/计数并清 relay 的申请失败次数；随后立即重新选路。
内部状态 -1/4/5 调用 `SendConnectionClosedToServer`，不把迟到成立消息变成新的活动 session。
**撤回此前把该分支写成 wire NoConnection 的说法**：原审计事件 `no_connection` 只是桩名称，
继续执行真实 sender `0x81b554–0x81b6a4` 后确认发送 type **20 / ConnectionClosed**，
不是 type 21。Sender 设置本地 from_connection_id、存在时设置远端 to_connection_id，
再调用派生 population，最后发给 relay；新增 `connection_closed_sender` 原始指令用例直接
检查其消息类型和 ID。不得根据桩的文字标签推断实际 wire 类型。
这些是内部状态域，不可直接当成应用/CM 状态值使用。
`next_r2c_packet_number !=0` 才将该 relay 序号窗口初始化到 next-1，扩展 next 并登记此次接收；
0 跳过这段，不是无条件重置。connection_id 的匹配还依赖上层分派的定位与前置条件。

**BadRoute Evidence**：`0x83cd68–0x83cf94` 按 token 字节匹配，清除**第一个**相同 peer cluster 的
token 和其 presence bit，然后设置重算原因。重复 token 不会一包清掉所有副本；该函数没有额外
排除空 token 的判断。没找到时不改其他 cluster。BadRoute 中的 ack_forward_target_revision
不能仅因 schema 含有该字段就假定本函数应用了它。

**补充 §18.4 的 revision 边界**：

- `RecvRoutes 0x834df0` 在 parse 前设置待 ACK 标志，因此解析失败也会留下该标志。
  解析成功且 revision 严格大于已保存值才替换快照、要求重算；比较是普通 uint32 大小比较，
  不是环绕序列号比较，已到 UINT32_MAX 不会把 0 当成新版本。
- `RecvStats 0x83d860` 中 forward ACK 等于当前 revision 时置已确认；不等于且此前已确认时，
  **清除已确认标志**。不能把旧 ACK 一律当作无副作用忽略。
- peer ACK 大于本地最新 revision 时忽略；<=最新时写入 lastAckedPeerRevision，
  因而迟到旧 ACK 可以让该值倒退。等于最新才清重发期限；旧 ACK 不主动写新的期限。
  后续 thinker 仍按“是否等于最新”决定重发，不能自行改成 monotonic max。
- stats 的 routes、revision ACK、通用 stats 依次处理。要求 end-to-end ACK 或携带 E2E quality
  时，当前主 transport 可交给普通 ACK 调度；非主 transport 或要求 immediate 时立即发 stats。
  relay ACK 与 end-to-end ACK 是两个独立队列/回调。

`RecvStatsCommon 0x83e034–0x83e624` 只对当前 primary relay 收到的非零 migrate_request_ip/port
接受新目标；地址发生变化才写入 relay 并将迁移 state/target 改为 1/-1。
没有字段、零 IP/port、backup 的通知以及重复的同地址通知不会清除或重启已有迁移。
port 先按 uint32 检查非零，再截到 16 位组成地址；超范围值不可擅自假定已通过有效端口校验。
§18.6 的“primary 不再有目标”指内部保存的地址不再有效，**不是某一包 stats 没带迁移字段**。

通用 stats 维护最多 5 项 relay 待 ACK 记录（uint16 sequence +48 位接收微秒）：
只与队尾去重，不与整个队列去重；满队列时普通新增 ACK 丢弃，immediate 请求覆盖队尾再登记，
不会自动丢队首。immediate 同时设置强制回复标志。E2E ACK 根据 E2E 序号和请求/quality 条件
单独排队。具体发送 deadline 仍由 LinkStatsTracker 和 session thinker 收紧；不能把该待 ACK
队列误写成 CM/SNS reliable 信令的累计 ACK 队列。

本节及 §21.10–§21.11 的函数/片段已加入 §21.8 的原始指令执行工具。
protobuf 对象构造/解析、hash 容器插入、socket/RelaySession 构造、部分统计转换及实际发包使用
明确桩，不能据此宣称消息 parser 或完整网络互操作已通过。接收入口用例替代序号窗口提供者；
§21.16 另对 relay/E2E 窗口的原始函数执行合成输入，不把两种证明范围混为一谈。


### 21.13 重算后的目标 token、active 清理与发送 revision

**Evidence**：P2P 的 `ThinkSelectServer_SelectActiveSessions 0x836a60–0x836ae4` 先运行
`CleanRoutesForServerSelection 0x83627c–0x836980`，再调用基础 active selector，最后检查是否
需要重建 routing message。它在 +288 标志为 0 且没有 active session 时调用
P2PTransportEndToEndConnectivityNotConfirmed；**撤回根据函数名直接推定该调用会置位标志
的解释**。固定 APK 的被调函数在标志为 0 时直接返回，实际组合行为见 §21.15。

CleanRoutes 的前置条件为全局存在 cluster、wire state 在 1..3；仅在本地有重算原因或全局 route
revision 已改变时重建。它记录新 revision、清原因、标记本地 routing message 需要检查；
初始化 route selector，global good-enough 时才导入 peer routes，随后建立两组 per-POP 候选表。
对每个已建立 session，以其本地 POP 对应的最佳有 token 路线选择**对端 POP**的 token 和 POP ID。
缺少有效目标时清 desired token 并将 desired POP 置 0，然后从 active 列表移出 desired token
为空的项。移除保持余项顺序，原 backup 可以临时成为 slot 0；全部 session 列表不因此缩短。
未触发重算或不在上述 wire state 时不执行这次剪除。

**Conclusion**：BadRoute 清掉 token 后先要求重算，重算再使受影响路径失去 active 资格；
它不是收到 BadRoute 立即销毁所有该 POP session。§21.1 的基础 backup 保留行为只适用于
已经通过这层清理的输入。路由候选不可用、active 角色消失和底层 session 销毁是三个不同事件。

`BSetSessionForwardTargetToken 0x83505c–0x835290` 区分 desired 与用于构造报文的已登记目标
（字段简称 sent）。**撤回将 sent 理解为“最后成功发出的目标”的描述**：本函数在 Populate
阶段更新它，随后 socket 发送失败也不回滚 token、POP 或 revision（§21.22）。其字段规则为：

- desired token 为空时返回 false，保留旧 sent token、sent POP、revision 和 ACKed。
- desired token 非空、字节与 sent token 相同时返回 true，以上状态均保持；即使 desired POP
  与 sent POP 不同也不单独增 revision。
- 非空 token 的字节确实改变才复制 token 和 POP，revision 按 uint32 加一并清 ACKed。
  UINT32_MAX 加一得到 0；这里和 §21.12 的 peer routes 普通大小比较是不同的规则。

因此清 desired token 不能顺手清掉发送历史；目标随后恢复为相同 token 时可能复用旧 revision
和 ACK 状态。该行为与收到旧 forward ACK 会清 ACKed 的接收规则共同约束重发。
这些分支以及原始 metrics→selector 组合已纳入离线审计；它们不证明服务器接受任意 token，
token 的签发和目标选择仍作为外部输入。


### 21.14 routes/目标确认的发送条件与两种重发时钟

**Evidence**：`PopulateSendPacketContext 0x835400–0x8355f8` 先执行 §21.13 的目标 token 更新。
无 desired token 时本次不填 forward token，也不经该入口填 peer routes/ACK；仍继续填通用 stats。
有目标且尚未确认 forward revision 时，每次都带 sent token 和 revision，不另设“一秒才带一次”。

peer routes/ACK 仅在该 session 是 active primary，或调用者显式 force end-to-end 时加入：

- 有待 ACK 标志，或 +288 的 need-confirm 标志为真时，带当前 peer routes revision 的 ACK。
- 本地 routes 最新 revision 与 last ACK 不同时，`resendDeadline < now` 才填本地快照；
  need-confirm 为真可绕过期限。这里**等于 deadline 时不发送**。
- force end-to-end 要求携带 E2E stats/请求；普通 backup 可只携带 relay 级信息。
  是否为 active primary、是否为当前 transport 分别生成非主 session/非主 transport 标志，
  不能把这两个主路概念合并。
- Populate 仅构造待发送内容，不清待 ACK、不推进 routes 重发时钟。
  `TrackSentStatsToSession 0x835f00–0x835fbc` 清已登记的 peer ACK 标志，
  登记 routes 时将期限设为 `now+500000` 微秒。该函数在控制消息成功后调用，数据内联则
  在封包阶段调用，早于实际 socket 结果；不能把前一种调用时机推广到后一种（§21.23）。

**rendezvous Evidence**：`PopulateRendezvousMsg 0x834bc0–0x834d04` 总填 peer routes ACK 并清
待 ACK 标志，包含 connection_closed 时也执行这一步，但不继续附加本地 routes。
正常消息检查并刷新本地 routing message；当本地最新 revision 未获 ACK 且 `deadline <= now`，
填本地 routes 并将 deadline 设为 `now+1000000` 微秒。因此它与 stats 入口共享一份 deadline，
但发送间隔和等号不同。`BNeedToSendRoutesNow 0x834dd4–0x834df0` 的到期判断也是 `<=`。

**Conclusion**：撤回“一律每秒重发 routes”的概括。实现须保留“构造上下文”和“成功发送后登记”
两个阶段；rendezvous 在填消息时就推进一秒期限，stats 在 TrackSent 登记时推进半秒期限
（控制消息成功后，或内联数据封包时）。旧 peer ACK
导致 lastAcked 倒退、forward ACK 不匹配会撤销确认等接收行为按 §21.12 保留，不能自行规范化。

### 21.15 P2P stats 的双序号、短暂乱序等待与可达性标志

**Evidence**：`ProcessMessage_P2PStats 0x83cf94–0x83d3ac` 先按内部连接状态分派：

- -2/2/3 可处理；1 在特定握手上下文仍存在时诊断并返回，否则可处理，带 E2E sequence 时先通知
  收到连接阶段的 E2E 流量。-1/4/5 回复 connection closed；其余状态诊断后返回。
- relay wire sequence 独立扩展、查重；有 E2E sequence 时再独立扩展 E2E 序号。
  两者都返回正扩展序号才更新 E2E 收包统计、登记 relay 序号并进入 RecvStats。
  仅 relay 序号有效不能绕过 E2E 重复/无效检查；没有 E2E 序号时只要求 relay 序号有效。
- 在扩展前，用 E2E wire sequence 相对最后接收值的 signed-16 gap 检查小缺口：
  gap 为 2 或 3 且与 relay 的 uint16 gap 相同，或已经存在待判乱序包时，先调用乱序处理器。
  gap 不相同、gap>=4 且无待判包时不执行这段短等待。
  返回 0 时此包暂不进入 stats，1/2 才继续；不能把 0 当作永久网络丢弃。

`HandleOutOfOrderPacket 0x86a844–0x86ab88` 的客户端动作：

| 已有待判包 | 当前包已经延迟后重投 | 结果 |
|---|---|---|
| 无 | 是 | 立即继续，不再次延迟 |
| 无 | 否 | 配置窗口<1 时继续；否则复制包，安排到接收时间+窗口，记录 owner，返回暂缓 |
| 有，signed16(待判序号−当前序号)>=2 | 任意 | 保留待判包，当前包继续 |
| 有，差值<2 | 任意 | 先从旧队列移除、解除 owner，将旧包放回近队首；然后按下两行处理当前包 |
| 差值<2 | 是 | 当前包继续，避免无限重复延迟 |
| 差值=1 | 否 | 确认发生一次乱序，当前包继续，返回 2 |
| 其他差值<2 | 否 | 将当前包也复制并放到近队首，返回暂缓 |

这里的复制、owner 与重投调度属于 packet lagger；离线用例执行原始决策，显式替代分配/队列调用。
延迟窗口是全局配置输入，不能凭“公网”标签额外加一个自创的重排时长。

**固定版本可达性标志 Evidence**：P2P base 构造 `0x8780d8` 将 need-confirm 置 1；该对象作为
SDR base 的 +264 子对象，因此其 +24 对应 SDR +288。Confirmed `0x87877c–0x8788b0` 在可发送
且标志为 1 时清标志并通知选路；不可发送时只诊断。与此同时，固定 APK 的 NotConfirmed
`0x878698–0x87877c` 在标志为 **0** 时直接返回；为 1 时才写 1 并通知。
所固定 GNS 源码同名函数也有相同提前返回；这不是已证明的 APK 特有差异，不能推广到其他
版本。原始指令的 8 个输入及外层组合的 4 个输入覆盖该行为。超时调用方另有直接通知，见 §21.20。

**Conclusion**：§21.13 的“无 active 且标志为 0”调用在该固定版本中不会把标志恢复为 1。
不可仅凭日志 “Will re-confirm” 或函数名称宣称已经发生状态改变。若实现决定修正这一行为，
应明确记录为与固定官方版本的差异，不能伪称二进制本来就这么做。


### 21.16 LinkStats 的上报、ACK、序号窗口和回复期限

**Evidence**：`GetStatsSendNeed 0x8b3580–0x8b36c4` 与
`InternalGetSendStatsReasonOrUpdateNextThinkTime 0x8b36c4–0x8b38bc` 使用独立的 LinkStats 状态，
不复用 peer routes / forward target revision：

| 项目 | 可顺带发送 | 到期主动发送 |
|---|---|---|
| instantaneous stats | 上次确认后 >=20 秒，返回 Ready=2 | >=30 秒，返回 Due=1 |
| lifetime stats | 上次确认后 >=120 秒，返回 Ready=8 | GetStatsSendNeed 按**上次 instantaneous 确认**后 >=140 秒返回 Due=4；主动调度器按 lifetime 确认后 >=140 秒 |

仅 Active=0 且没有统计包 in-flight 时生成上述需求；Idle=1 可维护 ACK/保活，Disconnected=2
不据此产生新的统计上报。期限比较为 >=，不是严格超过。主动调度器先将已有 reply deadline
纳入最早唤醒时刻，再分别检查 30/140 秒；没有立即发送理由时收紧下一次检查时刻。
GetStatsSendNeed 与主动调度器的 lifetime 参考时钟确实不同，固定开源 GNS 也有同样的区分；
不得把两个函数合并成一个“上次发送后 140 秒”的计时器。

上报还要求有足够新流量。`BCheckHaveDataToSendInstantaneous 0x8b33e8–0x8b34f0` 取
`threshold=floor((now-lastInstantAck)/3000000)`；自上次确认以来，sequenced 收包增量或发包
增量**严格大于** threshold 才有内容。否则更新 instantaneous 的确认时刻和计数基准，等同于
空闲期间无需发送。lifetime 要求对应任一增量严格大于 100；不足时只更新时间，不清累计计数
基准。这里的 sequenced 计数包含扩展/检查时的登记，不能用成功解码的视频帧数替代。

**回复期限 Evidence**：`TrackSentMessageExpectingReply 0x8b4108–0x8b420c`：

- 没有 pending deadline 时，尚无 smoothed ping 使用 1250000µs；有 ping 时取
  `min(worstRecentPingMs*2000, 1000000)+250000`。recent 为最近最多 3 个样本；没有有效样本
  时回用 smoothed 值。允许 delayed reply 再加 200000µs。
- 已有 deadline 时不因新请求继续延后；要求 immediate reply 仍更新 lastImmediateRequest，
  允许延迟的请求不改该时刻。
- relay tracker thinker `0x83235c–0x8324e0` 在 `deadline>0 && deadline<=now` 时清 deadline，
  首次失败保存 firstTimeout，失败次数加一。一个 thinker 即使晚到也只记一次，不能补算每个
  错过周期一次失败；没有新请求就不会再凭空增加失败数。Active 的统计 interval 每 >=5 秒更新。

**relay ACK Evidence**：`RelayBaseGetSendReasonOrUpdateNextThinkTime 0x822c9c–0x822e84` 优先
处理到期统计，reply request=2。否则有待 ACK 且 force、最老年龄 >=250000µs、或队列至少 5 项
时发 ACK，reply request=1；其余将下一次唤醒收紧到最老记录接收+250000µs。
这不把 Idle 升成 Active；它也不取代外层的 10/45/60 秒保活和 200ms aggressive probe。

`PutAcksIntoRepeatedField 0x840fd8` 将每项编码为
`(uint16(sequence)<<16) | floor((now-received)/64)`；延迟部分超过 65535 时饱和为 65535，
负延迟经诊断也走饱和分支。构造 ACK 字段不消费 pending 队列；由后续 TrackSentAck/
TrackSentStatsToSessionCommon 清理相应项。控制消息成功后触发，数据内联在封包时触发，
不能把 Populate、inline 封包和 socket 成功混成同一个阶段（§21.23）。

`RecvPackedAckInternal 0x84f1f0–0x84f424` 先将 wire ACK 的高 16 位扩展为发送序号：
匹配统计 in-flight 时先更新已确认的 instantaneous/lifetime 基准并清 in-flight 标志，然后查
期待 ACK 的发送时刻、计算 RTT。`GetTimeSentAndRemoveAck 0x84f424–0x84f5cc` 只移除
精确匹配的一项，保留更早未确认项，不是累计 ACK；16 位相对距离超出 ±16384 的异常查找返回
错误，范围内未找到返回 0。未登记的 ACK 不形成 ping 样本；有时刻才减低 16 位×64µs 的
远端延迟，向零截断到毫秒，允许 -1..3000ms（-1 作为 0 使用），超界拒绝样本。
因此无效 RTT 不会回滚已经完成的统计确认；不能把 RTT 有效性当作前面确认状态的前置门槛。
有效 RTT 再交给 relay/front tracker 和本 session tracker，进入随后选路的测量输入。

**序号窗口 Evidence**：relay `ExpandWirePacketNumberAndCheck 0x819e08–0x819f9c` 与 E2E
`0x83d3ac–0x83d540` 都用
`expanded=latest+int16(wire16-uint16(latest))`，以 latest 对齐 64 的当前块和前一块维护位图；
早于前一块的旧包拒绝，已登记重复返回 0，不伪造新的有效收包。跨 path 的重复另登记该 path
位图/计数，仍不再次交付。扩展函数本身不推进 latest；后续 TrackProcessSequencedPacket 才登记。
半圈差值 32768 按 -32768 处理，不按“更大的 uint16 就是新包”处理。

上述提供者均有原始指令输入覆盖。接收入口与提供者各自的断言不代表实际 socket、线程时序、
protobuf 解析或跨设备的网络互操作。

### 21.17 stats 的承载选择、发送失败与 sequence 消耗

**Evidence**：`BSendStatsMsgToRelayLocked 0x835c64–0x835f00` 构造上下文后，若 wire state=3
且带 E2E 请求/quality 或调用者 force，先尝试 SNP_SendPacket，以便统计可与端到端数据同发。
普通 relay-only stats 也可在当前 transport 的 primary session 上、SNP 确实有待发数据时走这条
入口。非当前 transport、backup、没有待发数据时不因此强造业务包。

SNP 成功即结束本次发送；SNP 失败，或不满足该路径条件时，退回 type 26 的控制消息。
非 state=3 不尝试 SNP，但仍可发送控制 stats。退回路径分配 relay sequence 并递增计数；本次
需要 E2E 时也分配独立 E2E sequence、递增对应计数，再调用 RelayServer::SendMsg。
socket 返回失败也**不回滚**已分配的 sequence；成功才登记 TrackSentStats、消费已发送 ACK，
以及 §21.14 的半秒 routes 期限。成功发送的 E2E 非数据包还通知 SNP 的统计状态。

**Conclusion**：一次控制 stats 不等于一条永远独立于数据包的固定心跳。实现需要允许与 SNP
同发及控制消息回退；“发送失败后重试”必须分清原来构造的内容、已消耗的序号和成功后才提交
的确认/重发状态。**该成功后登记规则仅指独立 type 26 控制消息，撤回将它推广到所有 stats
承载的解释**；数据包内联 stats 在 UDP 发送前已登记，见 §21.23。本节的原始函数用例明确替代
上下文生产、SNP 与 socket 返回值，以验证承载
选择和失败状态；§21.14/§21.16 分别核对其生产者和发送登记，不能据此声称整个 SNP 已互操作。


### 21.18 通用 stats 生产器的探测与隐式 ACK

**Evidence**：`PopulateSDRSendPacketContextGeneric 0x8355f8–0x835c64` 同时使用 relay tracker 和
connection 的 E2E tracker；§21.14 传入 E2E mode=0/1/2，分别为不加入、可顺带加入、要求加入。
reply request=3 在 relay 侧置 ACK_RELAY|IMMEDIATE（1|4）；mode=2 再要求 ACK_E2E（2）。
reply request=2 请求 ACK_RELAY，mode=2 再请求 ACK_E2E。它们和反方向收到的 ACK 不是一回事。

在没有显式要求立即回复时，Active tracker 已经发生至少一次回复超时，且
`lastImmediateRequest+200000 <= now` 仍会生成 aggressive 请求；relay 侧要求 1|4，E2E
mode>=1 且该侧超时时要求 1|2|4。Idle 不按此方式 aggressive 探测。
保活分支保留独立判断：已有在途 reply timeout、最近收包至少 10 秒时 Active 要求回复；Idle
需达到 60 秒。没有 pending 时的外层保活由 §18.6 处理，不能删除任一层并假定完全等价。

普通 Active tracer 使用最近 ping 接收/请求发送两者较晚时刻：严格超过 5 秒为可顺带探测，
严格超过 7 秒为需要探测。恰好 5/7 秒不晋级。仅“可顺带”且没有其他 flags、待 ACK、统计需求时
不独立造请求；已有其他内容时可以一起请求 relay/E2E 回复。E2E 仅在 mode>=1 时参与这一计算。
这就是正常收流也会测量 RTT、而非等整段连接失败才开始探测的客户端策略。

生产器先取得 §21.16 的需求，将 Due 部分填入 quality，再处理 pending ACK 和回复 flags；
后面允许把 Ready 部分作为附加统计加入。**存在 relay/E2E quality 本身就隐含对应 ACK 请求**。
如果没有额外 flags 需要表达，可省略 flags 字段；解析端不能把 flags 缺失解释为不必 ACK。
上下文中显式要求的 flags、protobuf 实际序列化的 flags，以及 quality 所隐含的 ACK 是三个值，
不要求它们逐位相同。额外非主路径 flags 和 immediate 仍需显式表达。

离线组合用例执行该原始生产器及原始 GetStatsSendNeed/BCheckHaveDataToSendInstantaneous，
另以明确桩提供 quality 字段构造、protobuf ByteSize 与 ACK 数组写入；覆盖 5/7 秒、200ms、
10/60 秒边界、E2E mode 和隐式 ACK。它证明请求/选择分支，不以固定 ByteSize 桩证明编码长度
或完整 SNP 的 MTU 处理。


### 21.19 实现时必须分开的状态与事件接口

下表是以上指令契约的状态划分，不要求复制官方 C++ 内存布局。把状态合并会改变前面已经核对的
行为，例如清 desired token 不等于清 sent token、移出 active 不等于销毁 session。

| 状态所有者 | 必须独立保存的内容 | 主要契约 |
|---|---|---|
| 全局网络 | 配置/POP canonical 映射、路由修订号、good-enough、失败地址缓存和全局探测预算 | §15、§21.5–§21.6 |
| SharedCluster/POP | front 的最近三样本及有效桶、direct/estimate、interior cache 的 ping/penalty/flags/测量时刻、最近候选 | §21.1、§21.4、§21.10 |
| RelayServer | 地址、root/alternate 关系、cookie、challenge/server_time/本地收到时刻、公网映射、ping/申请 pending 及各自失败计数、shutdownTime/avoidTime | §18.2–§18.3、§21.3、§21.7、§21.11 |
| 连接的 SDR transport | 全部 session、active primary/backup、两组 per-POP 路线、peer routes 快照及 revision、本地快照及 latest/ACK/retry、重算原因和全局 revision、migration state/target、need-confirm | §21.1–§21.2、§21.7、§21.9、§21.12–§21.15 |
| 每个 RelaySession | relay 签发的本端 token、desired 对端 token/POP、构造阶段登记的 sent token/POP/revision/ACKed、relay 序号及 LinkStats/待 ACK/期待 ACK | §18.4、§21.12–§21.18、§21.22 |
| P2P transport 子对象 | 自己的 end-to-end ping tracker、pending reply、失败次数、继续采样额度和独立 thinker；与连接 LinkStats 分离 | §21.20 |
| SNS 端到端连接 | E2E 序号/统计/加密/SNP、当前 transport；与 relay/session 的生命周期分离 | §12–§15、§18.1、§21.15–§21.18 |

外部输入与调度入口也应明确区分：

| 输入/到期事件 | 客户端入口的约束 |
|---|---|
| 配置/POP 或统计材料变化 | 标记重算；按全局 revision 和本地原因决定重建，不在每个 Tick 无条件重置快照 |
| RouterPingReply / NoSession / Established / BadRoute | 按各自的来源、presence、连接状态和字段校验进入处理；不能统一成“连接失败后全清重连” |
| peer routes / stats revision ACK | 区分两个 revision、last ACK、待回复标志和发送后 retry clock；按 §21.12 的旧 ACK 副作用处理 |
| shutdown / migration | 保存服务器给定目标与预警，再执行客户端资格校验、avoid/真正关闭/取消规则；不预测服务器算法 |
| 全局约 100ms thinker 或提前唤醒 | 更新超时/失败缓存/探测预算/readiness；再按连接的 good-enough 条件 pursue |
| 连接选路 | CleanRoutes → 基础 active selector → 本地 routing message 检查；端到端确认标志保留固定版本的实际行为 |
| session thinker / stats ACK / RTT 样本 | 收紧最早 deadline，处理 LinkStats 失败/统计/ACK/保活；relay 与 E2E 两侧分别维护 |
| 构造待发包 | Populate 上下文、rendezvous 填充和 inline 封包是三个阶段；后两者分别可以推进 routes 期限或触发 TrackSent 登记，不能一律视作无副作用（§21.14、§21.23） |
| SNP 或控制 socket 的发送结果 | 按承载区分登记点：独立控制消息成功后登记；数据内联 stats 在 gather 前已登记，失败不回滚。两者都不回滚已分配的 wire sequence（§21.23） |

**实现一致性约束**：不同层使用同一单调时钟来源，但不能统一它们的期限、严格/非严格比较、
失败额度或 revision 比较方式。随机避让、配置、对端 token 和服务器目标作为明确输入；公网与
局域网是这些输入和测量结果的差异，以上路径中没有据“公网”另换一套选路/ACK 协议的分支。
不同 transport、活动级别、network test 与普通播放器的分派仍分别按 §9–§16 执行。


### 21.20 P2P transport 的独立确认、采样额度与后台探测

**Evidence**：`CConnectionTransportP2PBase` 构造 `0x87806c–0x8780fc` 的 +536/+540 初始化
为 0/5，+528 deadline 清零，+24 need-confirm=1。这里的 transport 探测状态与 §21.16 的
connection/session LinkStats 分开；不能把相同的“end-to-end”名字理解成同一组 deadline/counter。

`P2PTransportTrackSentEndToEndPingRequest 0x8782a0–0x878404` 总更新本 transport 的最后请求
时刻；没有 pending 时才递减非零采样额度、用自己的近期 RTT 建立期限（未知 RTT 1250000µs，
允许延迟再加 200000µs）并调度 thinker。已有 pending 则不递减、不延长期限。
构造时的 5 不是连接总共只能探测五次：连接的
`TransportEndToEndConnectivityChanged 0x874c2c–0x874d80` 会把该额度提高到至少 5。

**thinker Evidence**：`P2PTransportThink 0x878404–0x878698`：

1. 仅内部连接状态 -2/2/3 处理；其他状态直接返回。基础复查时间为 now+2秒，再按以下 deadline
   收紧，不等同于全局 100ms thinker 或 §14 的路径评估间隔。
2. pending 非零且 `<=now` 时清零、失败次数加一；第三次起、need-confirm=0 时调用
   NotConfirmed，随后**直接**通知 TransportEndToEndConnectivityChanged。因此 §21.15 的提前
   返回仍不置 flag，但这条调用方会清/收紧选路状态并补采样额度，不能推广为“超时完全没副作用”。
3. 没有 pending 且 BCanSendEndToEndData=true 时，采样额度>0 就发 immediate（request=3）。
4. 额度耗尽后，当前选中自己、尚无当前路径或当前路径 need-confirm 时，只要自己 need-confirm、
   有失败、smoothed ping<0、最近样本不足 3 或**累计 ping 接收量<10**，仍发 immediate。
   这项 10 是 tracker 的累计样本量（子对象+516），不是 §14/§21.2 的 15 个有效时间桶。
   都满足健康条件时由普通 E2E 保活维护，不额外造此层探测。
5. 当前已有另一条确认可用的路径时，本 transport 改为每 `lastRequest+10秒 <=now` 才发
   delayed-OK（request=2）；未到期则收紧下次唤醒。不能因为它是备用 transport 就完全停止测量。
6. 发送回调可能建立新的 pending；thinker 在回调后重新读取，下一次取 pending 与 now+2秒的
   较早者。发送失败且未建立 pending 时保留两秒复查，不自行制造一个“已发探测”的期限。

`TransportEndToEndConnectivityChanged` 总提高额度至至少 5、立即唤醒 connection。
need-confirm 与“是否当前选中”相等时清 sticky 并把下一次评估置 ASAP：包括当前路径需确认、
或另一条路径刚确认可用。状态活跃且已确认时，还按相应 transport 首次记录协商可用耗时，
已有记录不重写。这是客户端响应状态变化的策略，不是 SDR 服务器的资源分配。

**有效 E2E 收包 Evidence**：`RecvValidEndToEndPacket 0x83f314–0x83f748` 先清本 transport 的
pending 和连续失败。need-confirm=1 时先要求重选已有 session，再在有 active 路径且可发送时
确认；无 active 时不会只凭一个迟到包清 need-confirm。首次 smoothed ping<0 时可用选中路线的
front+interior+remote 作为初值，应用本地 override（-1 禁止、>=0 替代）并登记一个桶内样本。
连接的路径评估已到期时再运行 ThinkSelectTransport。清 pending 不表示重新初始化采样额度，
也不是清掉所有 session 的序号/ACK 窗口。

这些入口均有原始指令输入断言；thinker 的发送返回/调度服务、首次样本 PingTracker 回调及连接
路径选择提供者在对应组中明确替代。不能把已有单个保活间隔当作这层完整策略。

### 21.21 本地 routes/ACK 在 relay stats 与 CM 信令之间的回退

**Evidence**：P2P SDR 外层 `ThinkSelectServer 0x837a90–0x837f2c` 在内部状态 -2/2/3 运行
基础选路，并取得当前 primary 的已登记目标。定义：

- `routesDue = lastAckedLocalRevision != latestLocalRevision && retryDeadline<=now`。
- `ackPending` 为待回复 peer routes 的标志。
- `probeWanted` 要求 primary/目标可用、need-confirm=1，且 connection E2E 没有 pending reply，
  或 `lastImmediateRequest+200000<=now`。

原始 `0x837b38–0x837b44` 在这些判断前调用 BSetSessionForwardTargetToken，
因此本轮不发送时仍可登记 sent token/POP/revision，不只是无副作用地读取旧值。
三者都为 false 就返回。只有 probeWanted、没有 routesDue/ackPending 时直接对 primary 发
request=3、force E2E 的 stats；这条专用分支不先发 CM。发送后期望 connection E2E pending
已建立；发送失败且没有 pending 时走诊断，不能凭空假设转为 CM。

需要 routes 或 ACK 时先设置待 ACK；有 primary 且 wire state=3 才先尝试 relay stats。
probeWanted 时 request=3；否则 routesDue 时 request=2，只有 ACK 时 request=1；均 force E2E。
成功后还要同时满足以下条件才省略 CM：待 ACK 已清、local routes 已确认或 retry 尚未到期、
need-confirm=0、relay 没有失败且最后收包严格在 10 秒内、connection E2E 也没有失败且最后收包
严格在 10 秒内。恰好 10 秒会回退；仅 socket 返回成功不充分。

没有 primary、不在 wire state=3、stats 失败，或上述健康条件任一不满足时，经
SetRendezvousCommonFieldsAndSendSignal 发送 CM/rendezvous。若本轮开始时 routesDue，还先将
共享 retry deadline 清 0，使 PopulateRendezvousMsg 能立即附加快照；这也可能发生在前一次
stats 成功、已经写过半秒期限之后。CM 填消息的后续一秒规则仍按 §21.14。
特别是 deadline==now、need-confirm=0 时，外层视为 routesDue，但实际 stats 构造器的严格
小于检查不带 routes；即使该 stats 成功，仍经 CM 附加快照，最终期限变为一秒。
`native_outer_stats_signal_chain` 已串接实际 stats 与 rendezvous 填充核对该等号，不能用会
无条件写半秒期限的发送桩替代这一组合结论。

若同轮还需要探测而第一次 stats 未成功，CM 分派之后可再次请求 immediate stats：一次外层调用
最多因此出现“stats → signal → stats”，不能自行去掉后一次并声称与官方相同。
外层完整函数用例明确替代基础选路、实际 stats/socket 和信令发送，覆盖单独探测、十秒/200ms
等号、ACK-only、缺少目标、健康状态以及失败回退；§21.14/§21.22 另核对实际 stats 生产/提交。

### 21.22 同一对象图上的接收与发送组合约束

**接收 Evidence**：输入为已由外层定位 session、解析后的 stats；离线
`native_receive_sequence_chain` 连续调用原始 ProcessMessage_P2PStats，
串接 relay/E2E Expand、两侧 TrackProcess、RecvNonDataSequencedPacket、RecvStats/Common、
待 ACK/ACK 调度、有效 E2E 处理；仅替代 SNP 交接、E2E ACK 服务、socket/线程调度和连接层
ThinkSelectTransport。初始化及跨包状态都保留在同一合成对象图，不每包重置窗口。

一侧新序号、另一侧重复时，扩展/诊断计数可以变化，但两个接收高水位都不提前提交。
例如 `(relay=101,e2e=201) → (102,201) → (102,202)` 中第二包拒绝，第三包仍能接受；把 relay
的 TrackProcess 放到 E2E 校验前会错误吞掉第三包。反向混合也如此。已经拒绝的重复 stats 不
重复进入 pending ACK 队列；quality 的隐式 ACK 仍对有效包生效。

TrackProcess 的小缺口先按 gap-1 记暂定丢失，迟到的未重复包可减少该计数并增加乱序计数，
不倒退最高序号或最高序号对应时刻。gap>=100 则记 lurch 并 InitMaxRecvPktNum，重建窗口，
不是将整个 gap-1 计作普通丢包。初始化将新高水位之前的相应位图标为已登记，因此大跳后的
旧缺口包可能被拒绝；不能只移一个空窗口再允许它们逐个补入。

**发送 Evidence**：`native_stats_send_chain` 串接原始 BSendStats、Populate、BSet target、通用
生产器、GetStatsSendNeed、ACK 编码、TrackSentStats/Common、期待 ACK 登记、relay 与 transport
的探测登记。quality 对象构造/ByteSize、序列化容器、SNP/socket 和 thinker 服务是明确提供者。
发送失败时仍已消耗 wire sequence，且 BSet 阶段登记的新 sent token/POP/revision 保留；这不是
最后成功发送快照。成功后才消费待 ACK、启动对应 reply/期待 ACK 记录、清已发 routes ACK 并
推进 routes 的半秒期限。这里指独立控制消息；内联数据包的另一提交点见 §21.23。
一次“提交或回滚整个发送事务”会同时违反这两类状态的规则。

两组组合输入覆盖重复/迟到/双序号不一致/环绕/大跳及发包失败、空目标、隐式统计 ACK；它们
加强函数间顺序的证据，仍不声称执行了真实网络、整个 SNP 或不同进程/线程的所有交错。


### 21.23 内联 stats 的空间裁减与发送前登记

**Evidence**：`SerializeSDRInlineStatsGeneric 0x84ff68–0x850374` 读取上下文缓存的 body 长度和
包含 varint 前缀的长度。长度为 0 时不附加；包含前缀的长度必须**严格小于**剩余空间才附加，
恰好相等也进入裁减。裁减策略不区分公网/局域网，也不按字段名称任意挑最不重要者：

1. 只要有 relay quality，优先处理它。该 quality 同时有 instantaneous 和 lifetime 时先移除
   instantaneous；只有其中一种或为空时清整个 relay quality。
2. relay quality 已不存在后，才用同样规则处理 E2E quality。因此可以先丢掉 relay lifetime，
   而仍保留 E2E instantaneous，不是“先删所有 instantaneous，再删所有 lifetime”。
3. 每次裁减后重新计算 quality 所隐含的 ACK 与显式 flags、protobuf ByteSize 和 varint 长度，
   再判断是否放得下。若原显式请求需要保持 ACK，即使删除 quality 也会补显式 flags；
   仅由被删除 quality 隐含的请求则可以随它消失。新增 flags 自身占空间，不能只减旧字段长度。
4. 两类 quality 都移除仍放不下时，整个 inline stats 省略；这里不继续删路由 token、routes 或
   ACK 数组来强塞，也不在该函数中另发控制消息。省略不设置数据头的 stats bit，不推进写指针，
   不调用本次 TrackSentStats。
5. 放得下时先写 `varint(body_length)` 和 body，检查写入长度，设置数据头 bit0、推进写指针，
   随即调用 TrackSentStatsToSession。

**提交顺序 Evidence**：`SendEncryptedDataChunkGeneric 0x83ed9c–0x83f0a8` 先分配 relay/E2E
序号、调用上述 serializer，最后才调用 BSendPacketGather（`0x83f068`）。因此包含 inline stats
时，TrackSentStats 已经消费待 ACK、清已发送的 peer routes ACK、推进 routes 半秒期限及登记
reply/期待 ACK；即使随后 gather 返回 false，这些状态也保留，返回值只是 0。
这与 §21.17 的独立 type 26 控制消息不同。发送字节/包计数也在 gather 前增加，不能直接当作
物理网卡成功交付数量，更不能当作对端确认数量。

`native_inline_stats_send_chain` 在实际发送回调入口读取对象状态，确认这些变更确实已经发生，
覆盖 gather 成功/失败；它串接原始数据头、inline serializer、ACK/探测/路由登记函数。
`inline_stats_budget` 另执行原始裁减与 varint 前缀指令，覆盖恰好放满、两类 quality 的优先级和
127/128 字节边界；ByteSize、quality 容器清理和 body 序列化由明确提供者返回，不能据此宣称
原始 protobuf 编码器或 SNP 加密已验证。数据发送测试的输入为已加密 chunk，不重做端到端握手。

### 21.24 关闭通知、确认与迟到成立消息

**Evidence**：`TransportConnectionStateChanged 0x81ba8c–0x81bbdc` 的分派使用真实
connection state：-2/1/2/3 提前唤醒 thinker；-1/4/5 遍历本连接全部 relay sessions，
跳过已由对端关闭的项，并发送 `ConnectionClosed`；-3/0 不发。仅在 SDR 是当前 transport
或当前 transport 为空、同时该 session 是 primary 或尚无 primary 时，给此发送设置
end-to-end 参数。backup 同样收到关闭通知，但不能一律带 end-to-end 参数。
这个状态域与 `ThinkSelectServer` 仅维护 wire state 1..3 的条件应分别保留。

`SendConnectionClosedToServer 0x81b554–0x81b6a4` 发送 type 20，设置本地
from_connection_id、非零时设置对端 to_connection_id，然后执行派生 population。
base population `0x81b6a4–0x81b878` 写入 connection reason/debug：wire state=4 时
relay_mode=ClosedByPeer(2)，否则只在 end-to-end 参数为真时设置 EndToEnd(1)。携带
session 时写 relay lifetime；end-to-end 参数为真时写 E2E lifetime。
P2P population `0x83e9a4–0x83ebe8` 继续处理 desired/sent token 与 revision，填写
not_primary_transport 及 routing summary。routing summary 是另一个明确的统计生产器，
不能把“已有 routes 消息”当成它已经生成。

**关闭确认与上面的 type 20 发送不同**：
`ProcessMessage_ConnectionClosed 0x819f9c–0x81a160` 导入 quality，标记该 session 已由
对端关闭，调用 `ConnectionState_ClosedByPeer(reason, debug)`，随后执行
`RelayServer::SendNoConnection 0x817bb4–0x817db0`。后者发送 type **21**，交换刚收到
消息的 to/from IDs；收到的 relay_mode=EndToEnd 时设置 end_to_end=true。存在 session
时，base/P2P population 与 relay lifetime 也被写入；base 的 E2E lifetime 并不要求
end_to_end=true（`0x81b9ec–0x81ba8c`）。
`ProcessMessage_NoConnection 0x81a160–0x81a290` 则导入 quality、标记 session 已关闭，
以固定 reason **5010** 结束连接，不再次发送关闭确认。

本节的 sender 和 state-change 原始指令用例在 `tools/steam-sdr-policy-audit.py`；
消息构造/派生 population 的显式桩范围由用例标明。对端统计/summary 的完整生成不能
仅由这些 stub 通过推断。迟到 `P2PSessionEstablished` 的状态分支见 §21.12；空 token
不得清 pending，非空 token 即使在关闭状态也先清 pending，再处理关闭通知。

### 21.25 POP 别名的方向与 canonical 查询

**Evidence**：`SetupFromJSON 0x898754–0x89a508` 以 `pops` 对象的 key 构造 POP 的
主 ID（`0x898cbc–0x898cfc`），从该对象的 `aliases` 数组读取额外 ID
（`0x8992d4–0x8994d4`）；仅接纳 3 或 4 字节别名，长度无效时忽略该别名。
`BuildLookupTables 0x8981e4–0x898754` 把主 ID 与别名共同映射到这个 POP 的索引；
已有 key 冲突进入错误路径（主 ID `0x898708`、别名 `0x898644`），不能以最后写入覆盖。

`MapToCanonicalPOPID 0x897e70–0x897ed0` 先把返回值初始化为输入 ID，再查表；命中后
取 POP record 的主 ID。未知 ID 原样返回，**不返回 0，也不选择相似 POP**。
原始指令用例包含空表、主 ID、多个别名、别名映射到另一主 ID、低/中/高未知 ID 与
UINT32_MAX，容器节点是显式构造的输入，不把 JSON parser 也算成已被离线执行。

**Conclusion**：若配置为 `"eat":{"aliases":["mwh"]}`，映射方向是 **mwh → eat**。
别名不会创建新的 POP、relay 地址或独立 session。延迟数组和 route exception 的 ID
须在写入缓存前 canonical 化；同包多个名字映射到一个 POP 时，仍按 §21.10 的数组
顺序后写覆盖。未知 ID 可以作为缓存 key 保留，但不能因此成为已知 POP 或获得建路资格。
对端路线的 POP 按同一 lookup 映射到配置索引，目标 token 与对应 POP 必须保持绑定。

### 21.26 RouterPingReply 的接收门槛与后续回复

**Evidence**：外层 `ProcessMessage_RouterPingReply 0x812178–0x812794` 先核对 root
cookie，失败时还遍历该 relay 的 sessions，接受本地 connection_id；随后核对普通延迟
数组数量并计算低 32 位时间差。它**没有**将 client_timestamp 与最近发送时间逐字比较，
也**没有**要求 ping deadline 非零。其 RTT 分支为：

- 有符号低 32 位差值 0..10000000µs：整除 1000 得毫秒；10000001 拒绝。
- 负差值：只有 timestamp 偶数且差值 >=-2000µs 才按 0ms 接纳；其他拒绝。
- 通过后依次 ReceivedPacket、RecvPingReply、可选 downtime、cluster penalty、
  SaveChallenge、latency 更新、alternate 更新；cluster penalty 在此入口无 presence 条件。

**Evidence correction**：撤回实现中“测量必须匹配最新在途 ping，且只处理一次”的注释
和门槛。这会漏掉时间范围内、cookie 正确的后续回复，也可能丢掉 §21.10 允许的增量信息；
不能因为首包已清 deadline 就跳过后续 metadata。是否在某次真实测试中实际分包，仍需抓包证明。
实现额外检查 P2P 延迟数组的等长边界是本地解析防御，不能据此声称原版外层也有同一检查。

原始入口审计显式替代 ReceivedPacket、PingTracker、challenge/latency/alternate 处理器，
验证上述分派次序与 cookie/RTT/普通数组门槛。分别在有/无 pending 的输入执行同一组时间边界，
另测 session cookie、错误 cookie、普通数组不等长、downtime presence 与低 32 位回绕。
下游处理器自己的策略由其他用例验证，不能由这些调用桩推断。
完整延迟回复时刻还控制 §18.2 的短 ping：`lastFull+5000000 > now` 发 100 字节，等号
发 1300 字节；不能虽然正确记了 full/incremental 状态，发送时仍无条件用长包。
独立的原始 `0x8178ec–0x81793c` 片段用例核对了送入 BSendPacketGather 的长度与 0x82 标志，
没有把其他 sender 分支或 socket 发送结果算作已验证。

### 21.27 POP 用途、front 资格与 session 加密公钥

**Evidence**：`SetupFromJSON 0x898da0–0x898e0c` 分别读取 `ping_only` 与
`relay_ping_only`，任一解释为 true 时将 POP type 设为 2，否则为 1。
它调用 `vjson::Value::TryInterpret(bool&) 0x8dc880–0x8dca4c`，不是直接检查 JSON
类型：布尔值、非零数字、大小写不敏感的字符串 `true` 和字符串 `1` 可得到 true。
null、无法解释的字符串、object/array 保留调用方初始化的 false。C 字符串消费在嵌入 NUL
处停止。离线配置分支用例执行原始 TryInterpret，vjson key 查询使用显式输入桩；并未把
整个官方 JSON parser 也计作被执行。

`0x89924c–0x8992d0` 在 POP 无 relay 地址或其显式 `relay_public_key` 解析失败时将
type 置 0；后者还清空该 POP 的 relay 地址向量。主 ID 和 aliases 仍可查询，不能把禁用
POP 的别名指向其他 POP。全局公钥在 `0x899940–0x899988` 单独解析，失败走整个配置错误
路径。本地配置接受至少一个可用 endpoint；拒绝更新时保留原配置，属于本地可用性边界。

**Evidence correction**：撤回实现曾将空/缺失全局公钥视为有效配置的接法。全局字段缺失或
类型不符时传入空串，`SetFromHexEncodedString 0x757208–0x7572f8` 解码后仍经
`CEC25519KeyBase::SetRawData 0x746508–0x74651c` 的严格 32 字节门槛；空串失败。
POP 未给该字段则跳过本地公钥解析、使用全局；显式空串则使该 POP 禁用。
`HexDecode 0x74c78c–0x74c990` 会跳过非十六进制字符并丢弃末尾孤立半字节，故不能用
“字符串必须恰好 64 个 hex 字符”替代解码后的 32 字节检查。该解码与 32 字节门槛也执行
原始指令对照；raw buffer 的实际存储为显式桩，不宣称重测了密码 provider。

**P2P front 资格**：`CP2PRouteSelector::Init 0x839750–0x839790` 要求 ping>=0，且
满足 `(reachability>=1 && type==1) || special>=1`。因此 type=2 仍可参与全局探测和延迟
估计，不能因为回复了 ping 就作为普通本地 P2P 入口。正 override 是单独例外，不能覆盖
负 front ping。该规则有包含 type=0/1/2、负/零/正 ping、未知/可达/不可达与 override 的
原始分支输入；项目未提供 override UI 时应传 0。

资格失败时 `0x8396ec` 从常量 `0x3d2c68` 同时写入 `front=-1`、
`penalty=0x10000000`，不是只把 front 设成 -1 并留下普通 penalty。
后续 builder 比较 `front+penalty` 时，此组合映射到 unknown score 并排在有效项之后，
防止负 front 以低分排到 cluster 选择前缀并提前截断有效候选。

**session 申请用钥**：`0x8384a4–0x8384dc` 先检查 canonical POP 的公钥是否有效，
仅在无效时检查全局公钥；两者均不可用才进入 §18.3 的明文 peer identity 分支。选定的
同一公钥须用于 X25519 和 `encryption_your_public_key_lead_byte`，不能一个用 POP key、
另一个仍用 global key。离线 key 选择用例显式提供 IsValid 结果，验证指针选择/分支，不
借此宣称验证了密码 provider。实际 crypto 答案与认证失败用例另行验证。

### 21.28 官方运行时的主路中断对照与观测边界

**Evidence**：同版 x86_64 `libshell_x86_64.so` 的 SHA-256 为
`195025601c2b17194a4d8b3debd674aca3377290fe3851986656c49bc973f907`。
`tools/steam-sdr-runtime-audit.py` 在已 root 的指定模拟器上先核对该文件及进程架构，再挂钩
主备选择和 RecvValidEndToEndPacket。播放器库另核对 §0 的 x86_64 `libmain.so` 哈希，
通过 module observer 在实际加载后、调用前安装对应挂钩；不能仅观察启动器库就宣称覆盖实际媒体。
两份库的独立 stats 原因常量分别为 `0x4b2ed5` / `0x3b11eb`。它只采集地址、POP、角色、计数和时间元数据；不采集
凭据、protobuf 业务缓冲或编码帧。主路/备用字段和两组 failure count 使用该固定库的布局，
不能拿这些偏移直接挂到其他版本。

只阻断已知 IPv4 直连地址仍可能走 IPv6 ICE，SDR 初始化或 primary session 存在并不能证明
业务选中了 SDR。运行时对照在 ConnectP2PCustomSignaling 真正收到的配置数组中，将 Int32
配置 104（ICE Enable）改为 0，同时记录原值与实际值；还要核对 SDK 的实际 Connected SDR
日志。此前只挂小型 getter 的尝试没有命中该调用，不能据挂钩安装成功宣称已禁用 ICE。
导出函数可能在内部调用点被内联，其他入口的回调缺席同样不是“原版没做这个动作”的证据。

**应用层窗口**：§8.6 的 HandleNetworkTest `0xcff6b6–0xcff6c9` 比较 `this+0x150`
与 GetStreamTimestamp，使用 `0x30000` 的帧等待窗口。实际纯 SDR 网络测试在主路中断后
约 3 秒就进入 NetworkTestDone 并销毁 transport；这早于后续 SDK 主备切换，不能把应用
提前结束解释为 SDK 已尝试并耗尽所有路线。

为了单独观测 SDK，可显式使用 `--hold-test-timeout 45`：只在注入后暂时更新上述
CNetworkTest 的帧时钟，本例 45 秒（工具上限 60 秒）；不改 SDR 的评分、角色、失败数或
探测 deadline。
这是**测试外壳覆盖**，不是官方产品原本的等待策略，相关网络测试质量数字不用于性能结论。
默认不覆盖此时钟。`--force-sdr` 是另一项明确的连接配置覆盖，也不隐瞒为原厂默认配置。

**一次受控样例**：`build/anywhere-research/official-recovery-20261017-022617/`
的 events 与 app 日志记录了以下事实：

- 实际 ICE 配置由 `0x7fffffff` 改成 0；SDK 选择 SDR，香港 primary 与东京 backup 均存在，
  首先有经香港的有效 E2E 收包。该客户端的 controlling 字节为 0。
- 仅在模拟器内部双向丢弃该香港 UDP endpoint。OUTPUT 另以 Steam Link UID 限定；INPUT
  以来源 IP/port 限定。计数记录确认两向 DROP 都命中；开发机防火墙没有改动。
- 注入后约 6.4 秒，官方 selector 将东京提升为 primary。此前 RelayServer failure 已为 1，
  RelaySession failure 仍为 0；这直接支持 §18.5 的所有者区分。
- 在保持测试外壳存活的这次窗口中，没有观察到经新 primary 的有效 E2E 恢复；SDK/IHS
  日志随后出现 peer Destroyed 和约 15 秒 inactivity。不能把 primary 指针改变当作恢复。

**Evidence correction**：整理后的工具在 `build/anywhere-research/official-runtime-fault/`
再次运行同一覆盖，捕捉到东京成为 primary 后的一个有效 E2E 样本；随后仍因 IHS inactivity
结束。撤回将前一份“没有采到新 E2E”推广为“官方 SDK 完全不会恢复 E2E”的判断。不同
样例或采样缺席都不能证明零包。后续 `official-runtime-packet-category-v2/` 用 §21.29 的同线程入口分类，
记录换路后的一个 `data` 样本；这仍可能只是 SNP ACK/控制，不能据此证明编码帧或持续收流恢复。
新的本地 fixture 被动跟踪 E2E 计数，要求五秒角色保持的末尾一秒内仍有新计数增长，不
用单包把整个保持窗口判为成功。SDK/relay/业务帧的失败与超时仍按各自所有者解释。

**关闭元数据的布局证据**：播放器 x86_64 `ProcessMessage_ConnectionClosed 0x85bfd0`
在 `0x85bfe7/0x85c12a` 分别读 protobuf+0x5c 的 relay_mode 和 +0x60 的 reason；
启动器 `0xd55a20` 使用相同字段偏移。`ConnectionState_ClosedByPeer 0x89f5a0`
读 connection+0x1ac0 的 SDK state、在 `0x89f613` 写 +0x1458 的 end reason；
启动器对应 `0xd99550` 的 state 位于 +0x1ad8，end reason 仍为 +0x1458。
两份 `ConnectionState_FinWait` 的读点分别为 `0x89eabe` / `0xd98ace`，再次支持该
state 差异，不能沿用一个偏移观察两库。运行时工具在这些固定哈希的入口记录 type20
reason/mode、type21、API close 及 peer/local_problem/FinWait 的 state 前后值，关闭类
最多每库 32 项；另在 SetState 入口记录最多 64 项 before/next/reason。
播放器 `APICloseConnection 0x89e710` 在 `0x89e843–0x89e84b` 直接令 SetState(-1)，
没有经过具名 FinWait 入口；因此后者的挂钩缺席不能解释为应用没有请求关闭。
不读取 SDK debug 字符串、peer identity 或 protobuf 业务缓冲；FinWait 的 reason 读已保存
字段，其余两种终态另记录调用参数。以上仍只适用于 §0 的固定 x86_64 样本。
session 的目标也只采数值 POP/revision/ACK：两份 x86_64 的
`BSetSessionForwardTargetToken` 在 player `0x87798f–0x877998` / shell
`0xd7294f–0xd72958` 将 +0x40 的 desired POP 复制到 +0x60 的 sent POP，再更新
+0x64 revision、清 +0x68 ACK；与 §21.13 的 ARM 输入对象一致。不读取 token 字节。

**Conclusion**：这份证据说明“只换 POP 并保持 Connected”不足以验收恢复；也不能仅因本地
适配器的同类样例失败就把根因归给新增快照代码。它没有证明正常游戏串流也有同样结果，
没有证明服务器内部的回程选择规则，更不能由两个失败样例推定客户端实现已经全等。
Frida 与应用帧时钟覆盖的影响须保留在结论范围内。

复现时先用 `android-network-sandbox.py` 在模拟器内阻断新鲜的 peer 地址，再冷启动应用，
自动定位 Computer Settings 的 Network Test 按钮；避免沿用已缓存的内网直连。下列坐标仅
适用于本次已核对的 2340×1080 界面，工具本身不猜测当前页面：

```sh
python3 tools/steam-sdr-runtime-audit.py \
  --serial emulator-5554 --remote 127.0.0.1:27043 \
  --output build/official-sdr-runtime \
  --peer-file /private/current-peer-addresses.json \
  --force-sdr --fault --hold-test-timeout 45 \
  --tap 480 945 --seconds 60 --stop-app
```

前置条件是已运行的 frida-server 和 adb forward。工具核验实际配置覆盖成功后，才在首次有效
E2E 后至少 3 秒、有 primary/backup 时注入丢包；有布局读取错误则停止。有效 E2E 最多每
250ms 采样一次，并保留每个 session/包类别的首个样本，注入时重新登记首样本。结果只记录是否
注入、是否见到新 primary 的 E2E 样本与清理错误，不自行输出恢复 PASS。采样不能替代逐包
统计；`--stop-app` 是实验清理，也不是 SDK 析构/loader 生命周期通过的证据。

实际媒体是另一项显式实验：应用必须在 Home，使用 `--media --tap 480 450 --stop-app`。
该模式禁止 `--hold-test-timeout`，启动 Start Playing 并在限定窗口结束时停止应用；未观察到
真正 ICE 配置覆盖或未完成故障注入均记失败。只挂 shell 的首次媒体尝试没有命中播放器入口，
日志实际选择 ICE，工具报告 `force_sdr_not_observed` / `fault_not_reached`；这份样例不参与
SDR 故障比较。播放器挂钩还按每秒上限记录 `CStreamDecoderVideo::DecodeFrame` 的调用累计数，
不读取帧缓冲。它证明视频进入该函数的次数，不能直接等同成功解码帧数或已显示帧数。

**实际媒体 Evidence**：`build/anywhere-research/official-actual-media-fault-v2/` 核验两份
ELF 并命中 `libmain.so` 的实际 ICE 配置，应用日志为 `Streaming`、业务选择 SDR。
未覆盖帧时钟；故障在 elapsed=9.611s 注入，6.662s 后主路由香港换到东京。新主路在故障后
6.789s 与 14.525s 分别采到 `data` E2E；切换后没有新的解码器输入采样，IHS 因 15 秒无活动
从 Streaming 退出。注入前有持续的 decoder input，最后一个每秒采样累计值为 62；这个值
不是完整帧计数。两向 DROP 命中、工具与规则清理无错误。

**Conclusion**：在该主机/模拟器/强制 SDR/单 endpoint 中断的具体条件下，官方媒体同样没有
完成持续恢复。它将“官方网络测试外壳提前结束”的边界扩展到一次未改时钟的实际串流观察，
但仍不证明其他拓扑必然失败，也不证明适配器和官方 SDK 的所有请求、时序或断流原因相同。
E2E 数据包可在 IHS inactivity 之前或附近到达，故仍不能用少量 E2E 代替视频帧验收。

### 21.29 Session ACK 对 RelayServer 探测时钟和 front 测量的副作用

**Evidence**：`TrackSentStatsToSessionCommon 0x83e624` 在 relay ACK 请求或隐式 relay quality
需求下调用 `TrackSentMessageExpectingSeqNumAckInternal 0x84f8b4–0x84fb9c`。该函数不只更新
session LinkStats：`0x84f98c–0x84f998` 还调用 `RelayServer::TrackSentPingRequest
0x817304–0x817330`，更新 root 最后请求时刻、cluster 最后请求时刻及累计请求数；root
没有 pending 时才建立期限，已有 pending 不被后续包延后。

- session 原来没有 pending 时，root 使用刚建立的 session deadline 与 now 之差。
- session 原来已有 pending 时，重新计算该 session tracker 的 conservative timeout，允许
  delayed reply 再加 200000µs，再交给 root 的“不延长已有 pending”规则。
- root 与 session 的失败计数、pending 和超时 thinker 始终独立；这里登记请求不直接增加失败。
- 控制消息成功后登记；数据的 inline stats 在 gather 之前登记，gather 失败仍保留这些副作用。
  没有附带 inline stats 时不凭数据头登记这一请求，见 §21.23。

**接收 Evidence**：有效 packed relay ACK 的 RTT 经 `RecvPackedAckInternal 0x84f1f0`
调用 `RelayServer::RecvPingReply 0x812a28–0x812cb4`，更新 relay 与 SharedCluster/front 的
测量，并在 `0x812c90` 清 root pending；随后再交给 session tracker。缺少对应发送记录或
RTT 不在允许范围内时，不产生这些测量/清 pending 的副作用。单纯 ReceivedPacket 清 root
连续失败、记录 lastReceived，与 RTT 成功后清 pending 是两个动作，不能合并。

**Conclusion / evidence correction**：§18.5 的 root/session 失败状态归属修正还必须与上述
生产者/消费者相连。适配器此前只在显式 RouterPing 时建立 root pending，session ACK 请求
没有登记；有效 ACK RTT 也只更新 session tracker，未反馈 front 或清 root pending。
这会使已完成初始测量的 relay 在中断后缺少 root 失联输入，旧前台测量也得不到正常流量刷新。
原始发送链核对现在同时断言 root 时钟/累计探测数；独立 root/session pending、延迟回复及
ACK→root/front 回调使用完整原始指令组合覆盖。函数级 selector 对照不替代这些接线证据。

**观测边界**：官方 `RecvValidEndToEndPacket` 的原因字符串 `Stats` 也可能来自数据包内联
stats。运行时工具用同线程内 `RecvValidDataPacket` 的调用范围区分 `data` 与独立 `stats`，
不读取 payload；固定 x86_64 的独立 stats 原因常量位于 `0x4b2ed5`。`data` 只说明加密数据
承载被接收，仍可能只含 SNP ACK/控制，不证明交付了 IHS 视频帧。媒体故障 fixture 因此独立
使用 `--sdr-fault-desktop`：首次至少收到 30 帧再注入；新角色的恢复观察窗口内再收到至少
30 个编码帧，且窗口末尾一秒仍有新帧，同时满足五秒 E2E 验收。网络专用 NRO 不接受该模式。

§21.18 的生产接线同样不能省略：`populate` 将两组 tracker 的活动级别、连续失败、最近收包、
lastImmediateRequest、最近 RTT/请求时刻和 pending 状态分别交给
`sl_sdr_stats_request_flags`，保留 5/7 秒严格边界、200ms 的包含等号、10/60 秒及 mode=0/1/2。
此前只处理调用者显式 request 和 quality，不能实现这些自动探测分支。该 C 函数与原始通用
生产器在相同输入下比较，包含非对称 relay/E2E 活动及 pending；并不因此扩大到 protobuf
实际长度、MTU 裁剪及完整 SDK 策略全等的声明。

后端诊断分别保存 SDK state/end reason 和首个本地 terminal source/detail；发送/接收可能早于
一秒状态轮询发现关闭，销毁 SDK handle 前还要读取并锁存原始 SDK state/end reason。适配器
Failed 不等于 SDK ProblemDetectedLocally：SDK 已 ClosedByPeer 时，Send 同样可以先返回
NoConnection，再由适配器记为 send/Failed。数值来源分别为
signal、certificate/start/config、connection info/status/state、signal queue、send/receive、
datagram bounds/queue、allocation；不把来源枚举当作线上协议错误码，不打印 SDK 调试文本。

### 21.30 primary 历史、切换报告与连接 RTT 初值

**Evidence**：`ThinkSelectServer_SelectActiveSessions 0x81cddc–0x81ce18` 检查旧 primary 的
开始时刻非零、数据接收数 >=101、地址有 IP/非零 port/非零 POP，才构造 type 16
`CMsgSteamDatagramClientSwitchedPrimary`。`0x819854–0x819874` 的计数属于 active primary
的数据包入口，不是所有 E2E 事件、独立 stats 或 IHS 视频帧数；数据内联 stats 不重复计数。

消息由**新 primary relay** 发出（`0x81d678–0x81d688`），带 connection_id、旧地址/POP、
旧 primary 活动秒数与数据接收数。gap 优先用已记录的失联起点，否则使用旧 current metrics
的非零 gap。`from_quality_now` 使用旧地址本轮测量，`to_quality_now` 使用新 session 测量；
`*_quality_then` 来自上次 primary 生效时保存的候选快照。RouterQuality 的 back_ping 是
interior ping（session+4584），不是 remote front 与 interior 的和；score 包含两端 front、
10% internet 项和各 penalty，seconds_until_down 为 INT_MAX 时省略。

新节点的旧快照先在相同 POP 中找精确地址；找不到时按 score 升序、迁移标记升序、shutdown
剩余时间降序选备用记录。**Evidence correction**：旧文将 `0x81d524` 的记录+96 误标为
alternate penalty；它对应保存的 SessionSelectQualityMetrics+72 迁移标记。
原单地址模型不再适用；多地址快照和所选 session 的接线见 §21.33。报告的 dropped_reason 取旧 primary 被
移除时缓存的原因。原适配器没有保存这条字符串；该缺口由 §21.32 的移除事件接线补齐，
不能用普通换路时当前候选的失败原因临时替代。

`0x81d694–0x81d718` 在新 primary 生效时重置该历史计数并保存地址/POP/时刻/候选快照。
跨 POP 时，`0x81d724–0x81d74c` 将**连接** RTT tracker 的最近样本数清零，再以
local front+remote front+interior 生成样本；不是重置 P2P transport 独立确认状态或全部 session
ACK 窗口。随后提前调度 connection 与 session thinker。

**Conclusion**：这条客户端报告应按条件产生；把它称为遥测并不能据此断言服务端忽略它。
它的服务端影响仍须单独验证，报告已发出也不代表媒体已恢复。原始发送组合覆盖 100/101 边界、
缺少地址字段和首次 primary，并检查消息发送到新 relay 及 current quality 字段。

媒体故障 fixture 另提供 `--sdr-warm-fault-desktop`：在 SNS 连接至少 15 秒且已有 30 帧后才
注入。15 秒只是用于比较建立初期和持续收流的实验条件，不是选路阈值；它与普通故障模式
使用相同的切换后新帧、五秒保持及末尾收包新鲜度要求，不能用其中一组替代另一组。

故障 fixture 的 `SDR_LOSS_SAMPLE/FEEDBACK/ROUTING` 是每秒最多一组的只读诊断：在 SDK
锁内复制主备 POP、root/session 失败与时钟年龄、目标/peer 首路 POP、revision/ACK 和 E2E
探测状态；时间单位毫秒，UINT32_MAX 表示没有对应时刻。它不读身份/地址/载荷，不产生新
网络请求，也不改变选路。stdout 仅从 fixture owner 在一秒采样点输出；Switch 使用已有的
非阻塞 64KiB transcript，生产 release 不编译此诊断 API。单纯 root ACK 持续正常与 E2E
保持为零必须分开解释，不能把前者记作后者恢复。

`SDR_ROUTE_EVIDENCE` 同时复制控制方、local revision 的 ACK、本地首路、当前 primary POP
是否已有本地 token/双向 Route，以及 routes/关闭消息的计数。`cm_populated` 只计信令填充，
`stats_committed` 只计 stats 的提交，不等于成功发送或对端接收；inline stats 在 UDP send
之前提交（§21.22）。开始故障观测后，首个 terminal 在 CloseConnection 前保存最后一份
快照，供句柄失效后的 final 读取；不继续访问已销毁 SDK 对象。关闭来源分别计已通过解析和
connection ID 校验的 relay type 20、type 21 与 CM connection_closed；type 20 另保存原始
relay_mode 和来源 POP。4001 是 SDK 的 Remote_Timeout 分类，不能仅据该数字断言是 Steam
主机主动超时；relay_mode=0 也不能写成已经观测到 EndToEnd(1) 关闭。诊断不输出 debug 文本。

### 21.31 外层 routes 交付的实现接线

**Evidence**：§21.21 的 `ThinkSelectServer 0x837a90–0x837f2c` 与 20 项原始指令用例覆盖
单独探测、ACK-only request=1、200ms/10 秒等号、健康门槛及 stats→signal→stats 次序。
适配器原来只在 routesDue/ackPending 时发送 stats，再按这两个标志是否剩余决定 CM，遗漏
单独 probeWanted 和发送成功后的 E2E/root 健康判断；ACK-only 也错误地统一请求 delayed。

**Conclusion**：`deliver_routes` 在基础选路及快照维护后准备 primary target，再按该独立
交付契约执行。`send_stats` 返回实际承载发送结果；成功不代表健康、ACK/revision 已满足。
需要 CM 且本轮 routesDue 时先清共享重试期限，随后由信令填充沿用一秒规则。生产 C helper
分别判断 probeWanted 和 relay 是否足够，使用同一输入与原始函数的网络动作序列核对；
原始诊断回调不当作网络动作。此处修正依据既有静态证据，不预先认定它是某次断流的根因。

### 21.32 已移除 primary 的原因与断流时刻

**Evidence**：`DestroySessionLocked 0x8188f4–0x818c78` 从所有 session 列表及对应 relay
列表移除对象。若它是 active 列表首项，`0x818b98–0x818bac` 将原因以 64 字节有界字符串
保存在 transport+124，并把移除时刻保存在 +112，active 数量置零。移除 backup 只截去该
角色；移除非 active session 不改这段历史。P2P 的 token 清理 `0x8367b4–0x8368a0` 仅剪掉
角色，不销毁 session，也不登记该原因/时刻，不能将两种事件合并。

下一个 primary 的报告在 `0x81d2ec–0x81d334` 附上非空原因；存在移除时刻时优先用
`(now-removedAt)/1000` 作为 gap_ms，即使结果为 0 仍设置字段。没有移除时刻才考虑旧
current metrics 的正 gap；小于一毫秒的正值也保留一个存在的零字段。`0x81d694–0x81d6cc`
在新 primary 生效时清空原因/断流时刻，即使 101 包报告门槛没有满足也会清空。

原因生产者：NoSession `0x81a2f8` 的 `0x374190` 为 `received_nosession`；全局 thinker
`0x8233f4` / `0x8233c4` / `0x8234bc` 分别使用 `consecutive_ping_timeout` /
`session_request_timeout` / `initial_ping_timeout`；停机期限 `0x823594` 使用
`downtime_warning_reached`；session 60 秒无活动 `0x823574` 使用 `0x383ea7` 的
`session_inactivity_timeout`。这些是固定样本字符串，不从远端 debug 文本推测。

**Conclusion / evidence correction**：撤回“只保存旧地址、开始时刻和包计数即可覆盖 primary
历史”的概括。适配器在 NoSession、root 超时/停机和 session 无活动移除前通知 transport，
先保存主路历史并清 active 角色，再清 session 状态或轮换地址；下次正常选择消费历史。
这避免同一模型对象换了地址后失去旧路径原因。普通选路淘汰和 token 剪枝不伪造移除事件。

原始指令新增 24 个 primary/backup/非 active 删除输入及 30 个报告输入（含空原因、63 字节
截断、既有历史、0/999/1000 微秒及 metrics 回退）。C 状态函数对照使用相同原始对象输入；
容器内存与有界字符串复制仍是显式提供者，不把它们计为 SDK 析构/网络验证。该修正不覆盖
单 POP 多地址/alternate 的完整对象模型，也不证明持续媒体恢复。

同一生产链还区分 session 和 root 的接收活动：`0x823540` 读取 session+2512，按严格
`lastReceived+60秒 < now` 销毁 session；它没有读取 root+248。SessionEstablished
`0x83dc14–0x83dc44` 即使没有非零初始序号，也会刷新 session 接收时刻/包数/字节数、清
pending 与连续失败。原始现有建连用例已经断言这些副作用。原适配器用 root lastReceived
判定 session 过期，并漏掉 SessionEstablished 的 LinkStats 收包登记；现改为分别接线。
RouterPingReply 因而不能独自保持一个已无 session 流量的旧 session。

NoSession 的 session 销毁、60 秒 session 销毁及 root 移除都清 session 的 forward/ACK/
序号和 LinkStats；NoSession 保留 root challenge/front，后续新 session 重新登记。这对应
`0x818bb0–0x818c20` 的销毁及 `0x83dbe4–0x83dbfc` 的重新创建，不将 transport 或 root
整体重置。另加 12 个原始 thinker 输入覆盖 session 时钟的 60 秒两侧/等号、root 新鲜而
session 过期、root 过期而 session 新鲜及倒序多项移除；显式锁/销毁回调不证明真实线程时序。

### 21.33 多 relay 对象、迁移与 alternate 的生产接线

**Evidence**：§21.3/21.4/21.7/21.11 的原始入口以及 `RecvPingReply 0x812a28–0x812c90`
分别使用 RelayServer 的 own ping 和 SharedCluster 的 front ping。只有 root 的 RTT 更新
POP front；alternate probe 的 RTT 更新它自己的测量槽位。有效收包把 root 地址保存为 POP
last-good，但从失败缓存移除的是实际收包地址。§21.9 的 nearest 输入由
`EnsureDataCenterRoutesValidLocked 0x810e70–0x8113c4` 的 SharedCluster+806/+812/+818
生成；仅直接测量的 interior edge、有效 direct front<=2000 参与，按
`front+front/10+clusterPenalty+interiorPing+interiorPenalty` 维护三个严格更小的 score。
32767 是未填充的 short score；平局保留原遍历项。估计 edge 不填这些槽位。

`MarkRemoteRelaysAndRoutes 0x839dc8–0x839e78` 先加入 nearest 三项；远端 token 非空时
枚举全部本地 POP，另加入显式 POP 限制。对端明确公布的 Route 也尝试建立对应组合。
这不是“本地必须已有 session 才能公布 Route”；session token 仍只从实际 session 取得。
`CheckRebuildRoutingMessage 0x836f90–0x83718c` 对已有 session 按 active index、base score、
迁移标记、shutdown 剩余时间排序，在每个 POP 取首个 session 的 token。排序的原始 helper
`0x84c848` 和 `0x84e430` 与旧历史 fallback 的迁移标记字段交叉核对。

**Conclusion / evidence correction**：撤回单 POP 单 relay 和原地覆盖地址的实现假设。
`ProbeCluster` 保存共享 front、失败地址、interior、penalty、last-good；`ProbeRelay` 保存
独立 IP/port、cookie/challenge、own ping、请求/pending、session ACK/序号/token。多个 relay
可共用 POP，迁移目标与旧 primary 可以同时存活。移除前通知 transport 并剪除角色，随后
清 session；回收前剪除 pursue 引用，root 移除同时移除 children，POP 缓存和按地址保存的
停机记录继续存活。备用仍按不同 POP 选，不因同 POP 多对象就改为同 POP backup。

迁移通知只由当前 primary 的非零 IP/port 触发，重复地址不重新启动事务；uint32 port
仍截断到 uint16，截断为零由随后请求资格校验拒绝。state=1 经过同 POP、失败缓存及严格
avoidTime 校验后创建/查找目标，state=2 在目标消失、root 避让、alternate penalty>=8191、
主路/请求消失或不再匹配时取消。目标优先进入 chooser/pursue，并以 -1/1 迁移标记参与
active 选择。全局维护后再处理迁移、active 和本轮 pursue，2/1 配额不消费重复 POP。

alternate 地址按完整 IP/port 保留稳定槽位，遵守 bit 1 增量/完整回复、protocol 变化和撤销；
公布的 wire penalty 不取代 8191 未测内部状态。仅合格 root 的前五个按 front 排序者创建
DefaultProtocol 探测；失败冷却严格 120 秒，own RTT 达 8 次后保存测量。临时 probe 完成时
只释放 child，保留测量和槽位；失败时才清测量、记录冷却。每轮 90ms/500ms/最多一次及
失败 root 优先规则由独立 C planner 执行，不并入普通 POP 探测预算。

本实现每个 SNS owner 只有一条活动媒体连接，图在该 owner 内维护；最多 512 个地址对象、
每 root 128 个 alternate 是本地内存上限，耗尽返回创建失败，不覆盖活动对象。没有启用
官方调试地址/POP override UI。函数级对照保留容器/provider/调度边界，不声称完整 SDK、
所有容器平局顺序或多 owner 共享实例行为全等。

`nsl-sdr-topology` 以合成 localhost 地址测试实际 C++ 对象图：共享/独立时钟、迁移重复与
无效目标、增量/完整公布、probe 回收与稳定 child 引用、last-good 重建、停机缓存存活和
nearest/token/显式 Route 门槛。它仅绑定一个 ephemeral UDP socket，不发送网络包；SDK
使用 manual poll 并显式 Kill。此 fixture 及其 API 均不进入 release。

独立 `--sdr-migrate-desktop` fixture 在收至少 30 编码帧后，将同 POP 的另一个配置地址
作为合成迁移通知交给生产 consumer；跳过了通知的接收 parser，不伪称真实服务端发过该
通知。后续 challenge、签名 session、routing 和媒体收发来自真实服务。只有指定目标主路
已收到有效 E2E 才在进程内屏蔽旧 endpoint；屏蔽后要求目标的新 E2E、至少 30 个新编码帧、
五秒保持及末尾一秒内的新 E2E/视频。它验证先建后拆，与直接断主路的 fault fixture 分开。
