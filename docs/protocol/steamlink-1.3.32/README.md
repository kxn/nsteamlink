# Steam Link Android 1.3.32 的协议定义

这些 proto2 文件从官方 arm64 `libmain.so` 内嵌的 FileDescriptorProto 重建，用于协议互操作研究。
样本 SHA256：`50e1d3147d5d47b71ef1970e1867a2fe4f3e1ecf2ea6153f927fac88b88ea38e`。
消息名、字段号、类型、默认值和枚举来自固定样本，不随外部协议仓库的 master 更新。
8 个文件共包含 264 个消息（含嵌套消息），依赖均在本目录内。

| 文件 | 覆盖范围 |
|---|---|
| steammessages_remoteclient_discovery.proto | LAN/云端复用的设备发现、授权、Proof、开流、transport signal |
| steammessages_remoteclient_service_messages.proto | Remote Client 云端 session、配对撮合、订阅、RemotePacket |
| steammessages_remoteplay.proto | 流协议控制、媒体、输入、反馈与能力协商 |
| steamdatagram_messages_sdr.proto | relay session、路由令牌、revision、统计和消息编号 |
| steamdatagram_messages_auth.proto | relay 授权与票据结构 |
| steamnetworkingsockets_messages.proto | SNS 加密握手材料、rendezvous、ICE reliable signaling、统计 |
| steamnetworkingsockets_messages_certs.proto | 证书、签名证书、身份类型 |
| steamnetworkingsockets_messages_udp.proto | SNS UDP 建链、关闭、统计 |

行为与调用证据见 [公网协议参考](../../STEAM_REMOTE_PLAY_NETWORKING.md)。schema 中存在某个字段
不代表官方在全部路径使用它；例如该样本 P2P stats 收发都使用 message ID 26，接收方向没有按
枚举名直接选 27。presence、请求 ID 校验、重试与取消规则必须结合行为规格。

## 重现提取

需要 Python 3、google.protobuf 和自行取得的上述固定 ELF，不需要运行或登录 Steam Link。
输出目录必须不存在：

```sh
python3 tools/steam-remote-descriptors.py \
  --elf /absolute/path/to/libmain.so \
  --output build/steamlink-descriptors

protoc -I docs/protocol/steamlink-1.3.32 \
  --include_imports \
  --descriptor_set_out=build/steamlink-schemas.protoset \
  docs/protocol/steamlink-1.3.32/*.proto
```

工具校验 ELF hash、架构和布局，读取 descriptor_table 符号及 ELF 相对重定位，递归选取依赖。
输出每个原始 `.proto.desc`、依赖完整的 `steamlink.protoset`、可读 `.proto` 和 `manifest.json`。
仓内 manifest 的 hash 针对**原始描述字节**；protoc 重新编译可能增加 json_name 等信息，不能把
重新编译的二进制 hash 不同当成字段定义不同。语义校验须仅规范化 json_name、源码位置信息和
隐式/显式 proto2 表示，再比较全部描述字段；本组 8/8 通过该校验。

本目录只含静态协议事实与来源清单，不含 APK/ELF、会话凭据或抓包。SignedCertificate 的
private_key_data 字段可能带私钥；运行时数据不能因为消息名带 Certificate 就公开记录。
