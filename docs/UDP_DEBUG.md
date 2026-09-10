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

## 视频直显性能统计

诊断构建每秒由 runtime worker 输出 `vp1` 至 `vp5`，同一 `id` 表示一份一致快照。
Switch 继续使用现有非阻塞日志发送；不重试阻塞发送，不逐帧写日志。渲染线程仅进行固定大小
计数/快照、额外三个单调时钟读取和短锁内复制，无格式化、文件 I/O 或新增线程。
新增采样以 `NSL_DIAGNOSTICS` 编译开关隔离；关闭诊断时不执行这些渲染采样。
实际设备上的诊断开销仍应通过 ON/OFF 同场景对照确认，不能宣称为零。

- `vp1`：session/epoch、后端、硬件解码标志、尺寸、解码/呈现/替换/拒绝累计数。
- `vp2`：新呈现帧的样本数 `n`；CPU 视频准备 `prep`；解码准入至 present 返回 `age`；
  解码输出至准备开始 `wait`；全部解码输出的驻留累计 `decode`。时间单位均为微秒。
  解码驻留包含重排/缓冲，不能直接视为 NVDEC 硬件执行时间；`age` 不包含此前网络接收，
  也不是输入至屏幕发光延迟。`prep` 不包含 UI、acquire、present 或 GPU fence 等待。
- `vp3`：包括旧帧重画的绘制次数 `draws`、重画次数 `redraw`，及 begin（可能包含 acquire 等待）、
  视频调用结束至 present 前的 UI/记账阶段、present API 的累计墙钟耗时。
  两个后端等待垂直同步的位置可以不同，不能只比较 present 耗时。
- `vp4`：仅视频调用造成的上传次数/有效像素字节数、硬件帧下载次数，以及 renderer 生命周期累计导入次数。
  UI 字形上传不混入视频上传统计。旧帧缓存重画不增加新帧准备样本或实际上传数。
- `vp5`：renderer 管理的图像/导入字节数、map/pool 数量和在途 batch 数。
  它不覆盖 decoder 全部内部内存或进程总内存，也不能将 mapped+image 直接当成唯一物理内存占用。

分析一份日志，默认按每个 session/epoch/尺寸组合排除前 5 秒：

```sh
python3 scripts/analyze-video-perf.py deko.log --output deko-perf.json
python3 scripts/analyze-video-perf.py deko.log --baseline sdl.log --output comparison.json
```

脚本只使用完整的五行组，并对累计量取差、按对应帧数加权；丢失中间日志仍可跨采样计算。
计数倒退、epoch 切换不会产生负耗时；活跃期间无新帧的窗口仍计入 FPS 分母。
比较输出每个新帧节省的 CPU 准备微秒和百分比。基准必须采用相同游戏场景、分辨率、码率、
刷新率、设备模式、频率策略与诊断配置；脚本仅能检查其中的后端/解码/尺寸元数据。
旧版只有 `stats` 且耗时为 `—` 的日志无法反推出这些指标。每秒快照不能推导逐帧 p95。

deko 诊断构建另外每秒输出 `vq1/vq2`，采用同一快照 `id`，不影响旧的五行分析器：

- `vq1`：`attempts` 是 begin 尝试次数（不是完整主循环次数）；`nobatch` 是没有空闲
  GPU batch 的返回次数；`acquire` 和 `acquire_us` 是输出缓冲 acquire 的次数和 CPU
  累计耗时。均为 renderer 生命周期累计量，应取差分析。
- `vq2`：`polls/timeout` 是现有非阻塞完成 fence 查询次数/超时次数；一次 batch
  可以被查询多次，不能将超时次数当作丢帧数。`done` 是观察到完成的 batch 数，
  `residence_us/done` 的差分比值是提交命令前至 CPU 观察完成的平均驻留时间。
  它包括 GPU 队列等待、输出图像 release fence 等待及 CPU 回收采样延迟，**不是 GPU
  绘制耗时或物理屏幕延迟**。阶段边界的在途 batch 会混入后一段，应排除过渡窗口。

`vp3.draws` 只记录成功的视频绘制，不包含 BUSY 返回；`vp3.begin` 同样只覆盖成功路径。
即使持续 BUSY，主线程仍至多每秒复制一次资源/队列计数，避免诊断数据随成功绘制一起停更。
新增计数复用现有 fence 查询，仅在 acquire 和提交/回收边界读取 ARM 计数器，不增加 GPU
等待、逐帧日志或新线程；关闭诊断时不执行新增队列计数和计时。

扩展节奏诊断：

- `vq3`：每 16 个 batch 采一次 GPU 时间戳。三个位置为输出 fence 等待之前、之后、
  绘制末尾；前两项使用 pipeline-top，末项使用 timestamp report。`wait_ns` 是前两点
  的累计差，`work_ns` 是后两点的累计差，`n/bad` 是有效/无效组数，`wmax/xmax` 是
  renderer 生命周期最大值。工作区间包含屏障、清屏、视频和 UI，不是纯 shader 时间；
  不包含第一个时间戳之前的队列等待。报告格式/时钟换算遵循 deko3d 0.5.0 `Primer.md`
  Counters 和 `dk_variable.cpp`。报告可能扰动管线，稀疏采样不能保证捕获所有尖峰。
  每个 batch 额外 4 KiB CPU/GPU uncached 报告内存，仅原完成 fence 成功后读，退出在
  queue idle 后销毁。不开启诊断时不分配、不记录。无额外 waitIdle 或 CPU 等待。
- `vq4`：同一 epoch 的解码发布间隔 `<8 ms` / `>25 ms` 次数和最大间隔；两次 take
  之间发布数量为零/一/多次的次数，以及最大 take 间隔（微秒）。在现有 mailbox 锁内
  更新，不逐帧输出。固定阈值用于当前 60 fps 实验，不是通用掉帧判据。
- `vq5`：进入 decoder 后、send_packet 前的提交次数、压缩字节数、间隔 `>25 ms`
  次数及最大间隔。这不是网卡到包时间，包含上游组帧和 decoder 串行化影响，不能独立
  区分主机、网络和解码锁。`vp2.decode` 提供提交到解码输出的驻留时间作为交叉证据。
- `vq6`：主循环次数和 control/media/tail/sleep 累计墙钟微秒。control 包括 UI 状态、
  输入和 runtime 事件；media 包括 present 调用；collect 是 media 内部事件处理/资源
  回收的子区间，不应再次加进总耗时。main 每秒发布，和视频快照的采样边界不完全一致。
- `vq7`：主线程 CPU 执行 ticks、采样墙钟 ticks 和 svcGetInfo 返回码。仅 `rc=0` 且
  两次计数单调时，`Δcpu/Δwall` 可表达主线程占用一个 CPU 核的比例；不是全进程 CPU
  使用率，更不覆盖 NVDEC/GPU。接口失败保留错误码，不用墙钟耗时冒充 CPU 使用率。

### 产品自适应选帧诊断

Deko 产品调度由 `NSL_ADAPTIVE_PACING` 控制，默认 ON；算法输入在 diagnostics OFF 中也保留。
诊断版 `--no-adaptive-pacing` 可关闭本次运行的调度，供基线比较。
`vq8` 的 `a/p` 是同 epoch 累计发布/首次成功提交数，`ca/cp` 是已关闭 cohort 的计数，
`unknown` 非零表示元数据观测缺失，此时不把累计 cohort 当完整样本；`defer` 为主动延后重复绘制次数，
`tv/ts` 是在线估计的输入/输出周期，`active` 表示已启用且满足预测条件。重复绘制不增加 p。
不要把任意时间窗的 p 增量除以 a 增量当作严格 cohort 利用率，也不要以 fence 等待是否缩短判断收益。
这些日志由既有诊断 worker 输出，release 编译排除。

`vq9` 的 `ready_us` 是控制器具备预测条件的累计时间，`wait_us` 是主动等待的累计时间，
`start_us` 是首次发布至首次具备预测条件的间隔，`hold` 为输入观测中断时保留时钟的次数。
时间跨度过长的主循环暂停不计入状态占比；首次具备条件不等于利用率已经收敛。
该行由诊断 worker 输出，release 排除；控制器不使用这些计数决策。
