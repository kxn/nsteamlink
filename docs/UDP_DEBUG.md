# UDP 调试

本页仅适用于 `-DNSL_DIAGNOSTICS=ON` 构建；默认 Release 不包含这些入口或日志。
诊断应用和 `switch-stream-selftest.nro` 的诊断端口为 UDP `28772`。
调试 Switch 地址为 `10.10.10.17`；命令由 `app/platforms/common/runtime.c` 实现。

```bash
tools/switch-debugctl.py 10.10.10.17 state
tools/switch-debugctl.py 10.10.10.17 stats
tools/switch-debugctl.py 10.10.10.17 audio
tools/switch-debugctl.py 10.10.10.17 hid
tools/switch-debugctl.py 10.10.10.17 hidlog
tools/switch-debugctl.py 10.10.10.17 diag current
tools/switch-debugctl.py 10.10.10.17 diag prev
```

| 命令 | 内容 |
|---|---|
| `ping` / `state` / `stats` / `perf` | 会话是否存在、实际呈现帧数、fps、HID 队列、最大 ACK 等待 |
| `audio` | 实际采样率／声道、队列字节数、解码帧数、丢弃及错误计数 |
| `hid` | 提交／发送／确认计数、待发与在途数、重试次数、最大 ACK 等待 |
| `hidlog` / `hid-history` | 有界的 SDL／原始输入及已提交报告历史 |
| `diag current` | 当前诊断日志的内存尾部，最多 3500 字节 |
| `diag prev` | 上次启动日志的缓存尾部，最多 3500 字节 |

该产品入口的 UDP 接口只读。连接、配对、安全码、停流和退出通过同一套屏幕／手柄操作完成。
手动地址位于选项 → 设置 → 手动地址。图形、IHS 初始化及发现不再由调试命令分步驱动。
独立 `switch-discover` 工具的 `hosts/select/pair/code/exit` 等命令属于其工具接口，
不适用于正式应用。

## 屏幕诊断

串流中同时长按 **− 和 + 0.8 秒**打开本地游玩菜单；菜单内单独长按 **X 一秒**切换只读 Debug 浮层，
随后自动返回游戏。再次进入菜单长按 X 关闭。默认关闭，断开后复位。

浮层的“本机视频”从客户端提交完整帧计时到 present 返回，不是网络延迟或物理屏幕扫描完成时间。
最大 ACK 等待是会话累计传输确认最大值，不证明游戏已应用输入。重复绘制同一视频纹理不增加视频帧率。
没有样本显示“—”；超过三秒没有更新标记数据已过期。

## 日志与清理

独立 joinable 日志线程接收有界队列；生产者 trylock，队列满时丢弃日志，不阻塞渲染或输入。
每秒记录实际媒体与可靠传输摘要。文件位于 `sdmc:/switch/nsteamlink/stream_diag.log`，
每次运行最大 4 MiB；启动时轮转至 `stream_diag_prev.log`、`stream_diag_older.log`。
UDP 读取内存快照，不在渲染线程读文件。配对码、安全码及密钥不进入该日志接口。

清理日志包括 HID worker、session interrupt/join/destroy、IHS client、IHS_Quit、SDL_Quit。
退出后 nxlink 结束仅是 PC 侧证据，Switch 返回 hbmenu 及再次启动结果仍以屏幕观察为准。
