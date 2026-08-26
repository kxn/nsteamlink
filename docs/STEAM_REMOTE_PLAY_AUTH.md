# Steam Remote Play 认证流程证据整理

日期：2026-08-24

本文只记录当前有证据支撑的理解。没有抓包或源码证据的内容必须标为“待验证”，不能写成结论。

## 证据等级

- 强证据：本仓 `third_party/ihslib` 源码与 proto；SteamDatabase/Protobufs 当前
  `steammessages_remoteclient_discovery.proto`；上游 plume 的 README 和源码。
- 真机证据：Switch 已经能发现 Steam 主机；用户在 Switch 输入 Steam 端已设置的 PIN 后，Steam host
  继续要求“设备上的四位数授权代码”；IHSlib 回调最终给出 `result=6`。
- 旁证：Steam 社区讨论、ValveSoftware/steam-for-linux issue 中的 Remote Play
  “Authorize Device”/authorization code UI 现象。旁证只能辅助解释 UI 名词，不能单独决定协议实现。

## 必须分开的两个码

### 1. Pairing PIN / authorization code

结论：首次授权配对时，最有证据支撑的流程是客户端生成并显示四位码，用户把这个码输入到 Steam host
的 Remote Play 配对窗口。

证据：

- 上游 plume README 写明 `./build/plume --pair` 的首次流程是输入“shown PIN”到 Steam host；首次从
  launcher 启动时也会显示 pairing screen，并让用户在 host 的
  `Settings -> Remote Play -> Pair Steam Link app` 中输入该码。
- 上游 plume `src/main.c:40-44`：生成 PIN 后打印 `Enter this PIN in Steam on the host to approve`，
  再调用 `PlumePairStart(&p, host, pin)`。
- 上游 plume `src/ui.c:582-614`：`PairScreen()` 调用 `PlumeMakePin(pin)`，启动 `PlumePairStart()`，
  然后在客户端 UI 上绘制 `Enter this PIN in Steam on the host:` 和该 PIN。
- 上游 plume `src/ihs.h:49-55`：注释说明 pairing 被拆成 start/poll/finish，因为调用方必须在 host
  等待期间显示 PIN；并写明这是用户输入到 Steam host 的四位码。
- 上游 plume `src/ihs.c:229-237`：`PlumeMakePin()` 用随机数生成 `%04u` 四位码。
- 上游 plume `src/ihs.c:247-256`：`PlumePairStart()` 调用
  `IHS_ClientStartDiscovery(..., 0)` 后，把这个 PIN 传给 `IHS_ClientAuthorizationRequest()`。

### 2. Connect PIN / security code

结论：协议和 Steam UI 证据显示还存在另一类连接/安全码，语义不是首次 pairing PIN。
它与串流请求阶段有关这一点有字段和返回码支撑；它在所有 Steam UI 场景中的精确触发条件仍需真机日志或抓包验证。

证据：

- 本仓 IHSlib `include/ihslib/client.h:52-65` 定义了 `IHS_StreamingPINRequired = 11`。
- 本仓 IHSlib `include/ihslib/client.h:78-80` 的 `IHS_StreamingRequest` 独立带 `char pin[16]`。
- 本仓 IHSlib `src/client/streaming.c:176-178` 会把 `IHS_StreamingRequest.pin` 写入
  `CMsgRemoteDeviceStreamingRequest.pin`。
- SteamTracking proto 中 `ERemoteDeviceStreamingResult` 有
  `k_ERemoteDeviceStreamingPINRequired = 11`，`CMsgRemoteDeviceStreamingRequest` 也有
  `optional bytes pin = 8`。
- Steam 社区讨论里有人把它称为 host 端设置的 `connect code` / `security code`，并说明 pairing
  code 只需要一次。该来源不是协议规范，只能作为现有 Steam UI 术语的旁证。

待验证：

- host 设置了 security code 时，首次 pairing 与后续 streaming 分别会出现哪些返回码。
- `IHS_StreamingPINRequired` 是否只在 streaming 阶段出现，还是现代 Steam UI 会在首次 pairing 期间
  也触发同名/相似提示。

## 协议消息层事实

### AuthorizationRequest

本仓 `third_party/ihslib/protobuf/discovery.proto:154-176` 定义
`CMsgRemoteDeviceAuthorizationRequest`：

- encrypted ticket 里有 `password`、`identifier`、`payload`、`usage`、`device_name`。
- 外层有 `device_token`、`device_name`、`encrypted_request`，以及可选 `auth_key`、`request_id`。

本仓 `third_party/ihslib/src/client/authorization.c:139-168` 每 1 秒发送一次
`k_ERemoteDeviceAuthorizationRequest`。

本仓 `third_party/ihslib/src/client/authorization.c:171-188` 配置 encrypted ticket：

- `password = state->pin`
- `identifier = client->base.deviceId`
- `payload = client->base.secretKey`
- `usage = k_EKeyEscrowUsageStreamingDevice`
- `device_name = client->base.deviceName`

本仓 `third_party/ihslib/src/base.c:59-68` 说明 `deviceToken` 由 `deviceId` 和 `secretKey` 派生。

因此可以确定：`IHS_ClientAuthorizationRequest(..., pin)` 的 `pin` 进入 pairing authorization ticket
的 `password` 字段，并和客户端身份材料一起发给 host。

### AuthorizationResponse

本仓 `third_party/ihslib/protobuf/discovery.proto:181-186` 定义 response：

- required `result`
- optional `steamid`
- optional `auth_key`
- optional `device_token`

本仓 `third_party/ihslib/src/client/authorization.c` 当前处理 `AuthorizationResponse`：

- `InProgress` 调 progress 回调并继续等待。
- `Success` 调 success 回调并停止任务。
- 其他结果调 failed 回调并停止任务。
- 当前代码会把 response 中的 `result`、`steamid`、`auth_key` 长度和 `device_token` 长度写入日志，
  用于下一次真机回归取证。
- 当前代码没有持久化 response 中的 `auth_key` / `device_token`。

真机日志里的 `authorization failed result=6` 可以确定映射到
`IHS_AuthorizationTimedOut`，因为本仓 `include/ihslib/client.h:40-49` 和 proto
`ERemoteDeviceAuthorizationResult` 都把 `6` 定义为 timed out。

### AuthorizationConfirmed / PairingState

SteamTracking proto 和本仓 proto 都定义：

- `k_ERemoteDeviceAuthorizationConfirmed = 14`
- `k_ERemoteClientBroadcastMsgPairingState = 15`
- `k_ERemoteClientBroadcastMsgPairingExclusivity = 16`

本仓在 D-017 之前的 `MessageDescriptors` 只覆盖到 `k_ERemoteDeviceStreamingProgress = 13`；
当时 `client.c` 会检查范围，超出范围的类型不解码，默认分支不处理。

当前 D-017 实现已经把 `MessageDescriptors` 扩到
`k_ERemoteClientBroadcastMsgPairingExclusivity = 16`：

- `AuthorizationConfirmed` 会进入 authorization callback，并记录 `result`。
- `PairingState` / `PairingExclusivity` 会解码并记录 msg type 与 payload size。
- 当前没有把这些消息赋予 success/failed 语义；真正授权成功仍以 `AuthorizationResponse result=Success`
  为准。

待验证：现代 Steam 是否要求客户端进一步处理 `AuthorizationConfirmed`、response `auth_key` 或 response
`device_token` 才能完成/持久化 pairing。现在只能把它列为协议缺口，不能直接说它就是超时根因。

## D-016 前 Switch 实现的错位（已修正）

D-016 之前 `tools/switch-discover/main.c` 的 M2 UI 是：

- 主机页按 `A` 后进入 `APP_PIN_ENTRY`，状态写成 `Enter the Steam pairing PIN`。
- PIN 页让用户输入数字，`PLUS` 提交。
- `submit_current_pin()` 把用户输入的字符串传给 `IHS_ClientAuthorizationRequest()`。

和证据链对照后，这个 UI 语义是错的：

- 如果这里做的是首次 pairing，就应该由 Switch 生成并显示 pairing code，然后让用户把它输入到 Steam
  host；不应该要求用户先在 Switch 输入一个“Steam 端 PIN”。
- 如果用户输入的是 host 上设置的 security/connect PIN，那么它不应该进入
  `IHS_ClientAuthorizationRequest()`；协议字段显示 streaming request 另有 `pin` 字段，具体触发条件待验证。

当前最有证据支撑的解释是：2026-08-24 真机测试里，用户输入的是 Steam host 上设置的
security/connect PIN，而 host 随后要求的是 Switch 应该显示的 pairing authorization code；Switch
没有显示这个 code，所以流程卡到 timeout。这个解释由上游 plume 行为和真机现象共同支持，但仍应在当前
D-017 日志中继续验证。

## D-017 后当前 M2 实现

当前 `tools/switch-discover/main.c` 已按证据链调整：

- 发现页按 `A` 或 PC 端 debug `pair` 命令会生成四位 pairing code。
- Switch 屏幕显示 `Enter this code in Steam on the host` 和该 code。
- `IHS_ClientAuthorizationRequest(client, host, code)` 使用 Switch 生成的 code，不使用用户输入的
  host security/connect PIN。
- debug `state` / `code` 输出包含 `code=xxxx`，方便 PC 端确认 Switch 屏幕上的 code。
- debug `pair` 不接收参数；旧 `pin` / `submit` 返回 deprecated 错误。
- pairing 前保持 discovery worker/socket 服务，调用 `IHS_ClientStartDiscovery(client, 0)` 与上游
  plume 的流程对齐。
- 授权成功后继续保存 `auth.bin` 中的 `deviceId`、`secretKey`、`steamId` 和最近 host 信息。
- 2026-08-24 真机回归已验证该主路径：Steam authorization response 返回
  `result=0 steamid=76561198217069647`，debug state 返回 `mode=done paired=1`。

## 当前可执行的正确流程

### 首次配对

1. 读取或生成稳定客户端身份：`deviceId`、`secretKey`、`deviceName`。
2. 发现 Steam host。
3. Switch 生成四位 pairing PIN。
4. Switch UI 显示该 PIN，英文/数字为主，避免 console 字库乱码。
5. Switch 调用 `IHS_ClientStartDiscovery(client, 0)` 保持 IHS worker/socket 被服务。
6. Switch 调用 `IHS_ClientAuthorizationRequest(client, host, generated_pairing_pin)`。
7. 用户在 Steam host 的 Remote Play 配对窗口输入 Switch 显示的四位码。
8. Switch 等待 `AuthorizationResponse`：
   - `InProgress`：继续显示等待。
   - `Success`：保存 `auth.bin` 中的身份材料和 `steamId`/最近 host 信息。
   - `TimedOut`/`Failed`：显示结果码，保留日志。

### 后续串流

1. 复用 `auth.bin` 中的 `deviceId` 与 `secretKey`。
2. 发现 host，发起 `IHS_ClientStreamingRequest()`。
3. 如果返回 `IHS_StreamingUnauthorized`，回到首次配对流程。
4. 如果返回 `IHS_StreamingPINRequired`，再让用户输入 host security/connect PIN，并把它放到
   `IHS_StreamingRequest.pin` 后重试。
5. 如果 streaming 成功，进入 session 连接、session authentication 和 audio/video/input negotiation。
   SSTIC 2023 论文对 session 阶段有逆向概述：Remote Play 的 streaming session 在握手后，客户端会发
   authentication request，然后进行音视频/输入能力协商，最终进入 Streaming 状态。

## 当前实现状态与后续要求

- 已完成：M2 pairing UI 已改成“生成并显示四位码”，文字使用 ASCII：
  `Enter this code in Steam on the host`。
- 已完成：pairing 中不停止 discovery worker；对齐 plume，在 authorization request 前保持
  `IHS_ClientStartDiscovery(client, 0)`。
- 已完成：auth response 调试日志包含 `result`、`auth_key.len`、`device_token.len`。
- 已完成：收到 message type 14/15/16 时打日志。只有在真机日志或抓包证明它们影响 pairing 后，
  才能写“必须实现”。
- 继续保存 `auth.bin` 的 `deviceId`/`secretKey`。不要把 pairing PIN 保存为认证材料。
- 后续 M3/M4 再做数字输入 UI，语义必须是 streaming/security PIN；只在 streaming 阶段需要时使用，
  不再用于 `IHS_ClientAuthorizationRequest()`。
- 如果后续 security/connect PIN 需要保存，必须在 UI 上单独标为 host security PIN，并和 pairing
  code 分开命名。

## 禁止再犯的结论规则

- 不能把 `IHS_ClientAuthorizationRequest()` 的参数名 `pin` 直接解释成“Steam 端固定 PIN”。
- 不能把 Steam UI 上出现的所有 “PIN/code” 当成同一个码。
- 不能把社区讨论当协议规范；社区讨论只能作为旁证，必须回到 proto/source/log 验证。
- 真机观测优先于 PC 端工具推断。用户看到 Steam host 要设备授权码，而 D-016 前 Switch 没显示，
  这就是旧 UI 缺失的强证据。

## 外部资料

- SteamTracking proto：
  https://raw.githubusercontent.com/SteamDatabase/Protobufs/master/steam/steammessages_remoteclient_discovery.proto
- plume README：
  https://raw.githubusercontent.com/beudbeud/plume/main/README.md
- plume pairing source：
  https://raw.githubusercontent.com/beudbeud/plume/main/src/main.c
  https://raw.githubusercontent.com/beudbeud/plume/main/src/ihs.h
  https://raw.githubusercontent.com/beudbeud/plume/main/src/ihs.c
  https://raw.githubusercontent.com/beudbeud/plume/main/src/ui.c
- SSTIC 2023 Remote Play reverse engineering paper：
  https://www.sstic.org/media/SSTIC2023/SSTIC-actes/bug_hunting_in_steam_remote_play/SSTIC2023-Article-bug_hunting_in_steam_remote_play-ricotta.pdf
- Steam Remote Play authorization code UI issue：
  https://github.com/ValveSoftware/steam-for-linux/issues/11495
- Steam community discussion, only as UI terminology corroboration：
  https://steamcommunity.com/groups/homestream/discussions/0/3827541651930464867/
