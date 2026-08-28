# UDP 调试命令参考

> 面向真机联调的操作手册：`nsteamlink.nro` / `switch-stream-selftest.nro` 运行中，
> 通过 `tools/switch-debugctl.py <ip> <命令>` 经 UDP 端口 `28772` 查询与驱动。
> 该通道不依赖 `nxlink -s`，是复现故障后回收证据的主要手段。
> 字段语义随版本演进，以 `client/main.c` 的命令处理与 help 文本为权威。

## 约定

- 调试单元 IP 固定 `10.10.10.77`，UDP 端口 `28772`；经 nxlink 启动时优先只接受 nxlink host 的命令。
- `nsteamlink.nro` 与 `switch-stream-selftest.nro` 使用同一端口、同一命令集
  （selftest 保留自动 3600 帧长跑行为；audio 保持 off 作为对照）。
- `switch-discover`（M2 配对工具）是独立命令集，见文末。

## 命令总表

```
ping            存活探测
state           会话/媒体状态摘要（含 lastFrameAgeMs、STATUS 等）
stats | perf    帧统计（fps、gaps、transferAvgUs、vicTransfers、transferFallback、
                frameLat/frameWait/hidSend/hidEvAge 延迟分段等）
audio           音频状态：active、codec/frequency/channels、解码帧数、
                SDL queued bytes、queue drop、decode/queue 错误计数
hid             HID/输入可靠通道计数（字段见下）
hidlog [n]      进程内最近 n 秒（默认 16，上限 60）HID 每秒摘要环形历史
diag [what]     SD 卡持久诊断：current|prev|older 读 stream_diag(_prev/_older).log 尾部；
                status 返回诊断线程状态；marker current|prev|older 只读 `-` marker 记录
diag-chunk <which> <offset> [length]
                分页读取诊断文件全文，避免尾部采样掩盖较早的故障窗口
hosts / select <n>
                发现结果列表 / 选择 host
press <button>  注入一次按键（复用 app 输入逻辑）：
                A|B|X|Y|MINUS|PLUS|MINUS+B|MINUS+PLUS|UP|DOWN|LEFT|RIGHT
ihs-init | discover-once | media-init | media-shutdown
                分步驱动 IHS/发现/媒体层（排障用）
stream [desktop|game] [short|long|frames=N|seconds=N|hold] [pin]
                启动串流；selftest 默认 3600 帧自动 stop
stream-pin <pin>  串流阶段 host PIN 提交（注意：这是 streaming PIN，
                  不是 M2 pairing authorization code，两者语义不同）
stop / exit     停流 / 退出程序
```

## `hid` / `hidlog` 字段释义

| 字段 | 含义 |
|---|---|
| `e` / `ok` / `f` | 当秒 SDL HID 事件数 / input report 发送成功 / 发送失败 |
| `h` / `p` | 100ms 全量心跳（stateFull）发送数 / pump 调用数 |
| `raw=x/y` | libnx `PadState` 原始摇杆/按钮变化计数（绕过 SDL 直读共享内存的对照探针） |
| `sty=flips:style/attrs` | style/attribute 抖动计（验证 SWITCH_JoystickUpdate 早退风暴用） |
| `sticks=lx/ly/rx/ry`、`b=0x...` | 当秒结束时的 SDL 摇杆轴值与按钮 mask |
| `minus=sdlHeld/sdlSamples/rawHeld/rawSamples` | `-` 故障 marker 统计（被动记录，不吞键） |
| `rel=tracked/acked/superseded retry/fail/out/oldest/maxAck` | 可靠发送状态机直接计数：在途登记/精确 ACK/被新快照取代退休/重试/失败/在途/最老在途年龄/最大 ACK 延迟 |
| `hidSM=submitted/coalesced/sent/acked/superseded/pending/inFlight` | HID 状态机：提交/被合并/已发送/已确认/已取代/待发/在途 |
| `vicTransfers` / `transferFallback` | VIC 256B 对齐传输命中 / 回退 FFmpeg 自动 transfer（stats 输出） |
| `frameLatAvgUs/MaxUs` | 单帧客户端总延迟：完整帧提交（ihslib 组帧完成）→ 上屏完成，仅统计实际显示帧 |
| `frameWaitAvgUs/MaxUs` | 跨线程排队：解码线程 latch 帧 → 主线程取帧 |
| `hidSendAvgUs/MaxUs` | 含输入事件处理的 pump → HID 发送完成的本地耗时（仅计有事件的 pump） |
| `hidEvAgeAvgMs/MaxMs` | 事件捕获延迟：SDL 事件时间戳 → 被 poll 处理的年龄（ms） |
| `diag-lat` 行 | stream_diag.log 每秒一行上述延迟分段（avg/max/样本数），供离线分析 |

## `diag` 体系

- 正式 app 启动后开启后台 joinable 诊断线程，每秒把 `state/hid/audio` 摘要
  append+flush 到 `sdmc:/switch/nsteamlink/stream_diag.log`；下次启动把上一轮
  轮转为 `stream_diag_prev.log`（再上一轮为 `_older`）。退出后不可达 UDP 时，
  靠下一轮启动的历史文件复盘。
- marker 日志另写 `stream_diag_markers.log`：`markMinus` 是输入同窗记录，
  `markNet` 是同一 seq 的视频/音频/control 同窗摘要（`frames/displayed/audio` 增量、
  `lastFrameAgeMs`、`mainAgeMs`、`gaps/maxGap`、`ctrlRetrans/ctrlWarn` 增量），
  用于判断是否整条 Wi-Fi/stream 同步断流。
- 约定：streaming 中 `-` / `MINUS` 只作为被动故障 marker（不吞键、不停流）；
  本地退出/停流是 `L3+R3+VOL+` / `L3+R3+VOL-`。

## `switch-discover`（M2 配对工具）独立命令集

`ping`、`state`、`hosts`、`select <n>`、`press <button>`、`pair`、`code`、
`delete-auth`、`exit`。`pair` 不接收 PIN——Switch 生成并显示 pairing code，
把它输入 Steam host；`auth.bin` 持久化身份。旧 `pin/submit` 已废弃。

## 排障用法速查

- 复现输入故障后：`diag marker prev` 看 marker 同窗 → `markNet` 判断是否 Wi-Fi 整体断流
  → `hidlog` 对照 `rel/hidSM` 判断可靠通道是否健康（当前 BUG-M4-HID-001 已证明
  ACK 正常仍可复现，嫌疑在 host 侧 apply）。
- `openOk=0`：host 没 open 我们的 HID 设备；`openOk>0 && start=0`：open 了但没启动
  input reports；`start>0 && hidSendOk>0 && ctrlRetrans/ctrlWarn>0`：查控制通道；
  `ctrlRetrans=0`：查 report 内容/映射/caps。
- nxlink 日志 fd 非阻塞、热路径限速；日志风暴本身不应再卡渲染与本地退出
  （2026-08-25 修正）。若疑似日志背压，先查 `mainAgeMs`。
