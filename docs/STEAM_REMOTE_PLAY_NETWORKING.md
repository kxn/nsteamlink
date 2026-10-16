# Steam Link 公网发现、信令与 NAT 穿透参考

证据复核日期：2026-10-16。本文是协议参考，不记录任务进度。

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

**待验证边界**：实测已收到主机返回的证书字段并建立官方网络库连接，但没有独立实现
证书签发/验证或 SDR 服务访问。STUN 地址选择、重连与路径切换状态机和 CGNAT/对称 NAT
仍未逐项验证。旧独立 WebRTC transport 在本仓 proto 中已标
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

**待验证**：其他播放器入口的 key 生命周期、证书签发身份与有效期、SDR 私有线路协议、
无官方网络库时的服务接入兼容性。开源 GNS 的 ICE 示例可供参考，不能替代这些验证。

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
