# UDP 调试

本页仅适用于 `-DNSL_DIAGNOSTICS=ON` 构建；默认 Release 不包含这些入口或日志。
诊断应用和 `switch-stream-selftest.nro` 的诊断端口为 UDP `28772`。
调试 Switch 地址为 `10.10.10.17`；命令由 `app/platforms/common/runtime.c` 实现。

```bash
tools/switch-debugctl.py 10.10.10.17 state
tools/switch-debugctl.py 10.10.10.17 cloud
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
| `cloud` | 云端目录/TLS/Upgrade/WebSocket 阶段、会话是否就绪、候选位置、重试等待、可订阅及在线主机数 |
| `audio` | 实际采样率／声道、队列字节数、解码帧数、丢弃及错误计数 |
| `hid` | 提交／发送／确认计数、待发与在途数、重试次数、最大 ACK 等待 |
| `hidlog` / `hid-history` | 有界的 SDL／原始输入及已提交报告历史 |
| `diag current` | 当前诊断日志的内存尾部，最多 3500 字节 |
| `diag prev` | 上次启动日志的缓存尾部，最多 3500 字节 |

该产品入口的 UDP 接口只读。连接、配对、安全码、停流和退出通过同一套屏幕／手柄操作完成。
手动地址位于选项 → 设置 → 手动地址。图形、IHS 初始化及发现不再由调试命令分步驱动。
独立 `switch-discover` 工具的 `hosts/select/pair/code/exit` 等命令属于其工具接口，
不适用于正式应用。

## 自包含真实主机会话测试

诊断构建单独生成 `nsl-live-media-probe.nro`；普通发布构建不包含此测试入口。
测试包直接读取 Switch 现有 `profile.bin`、按主机密钥和串流设置，不需复制 SD 文件。
它只选择与指定地址的实际发现回复匹配、且已保存为配对的主机；身份缺失、损坏、
需要授权码/安全码或连接失败时记录失败并退出，不猜测 PIN，也不新建测试身份。
正常串流过程中的密钥轮换、配置和测网统计保存仍由生产 runtime 执行。

测试执行一次被动播放，不发送用户控制输入。若普通开流先进入正式测网，工具使用
生产结果确认命令执行“继续但不接受推荐”，保留已有设置，再进入播放。
测网 session 的流量不纳入普通媒体计数。此自动确认只属于独立测试程序；
正式应用的推荐确认、FEC 保存/初始请求策略仍见协议参考 §32、§116。

```sh
# 先完成 clean 提交及对应诊断构建；默认仅归档，不启动设备。
python3 tools/live-media-probe.py --steam 10.10.10.166 --switch 10.10.10.25 \
  --seconds 30 --output build/live-media-ready
# 用户准备好 netloader 后，另选一个新归档目录，明确 --run，只部署一次。
python3 tools/live-media-probe.py --steam 10.10.10.166 --switch 10.10.10.25 \
  --seconds 30 --output build/live-media-run --run
```

工具归档实际 NRO/SHA256、提交身份、graphics manifest、命令、nxlink 原始日志与
机器结果；不探测 netloader TCP，也不自动重复启动。示例地址只是明确的测试参数，
设备或主机变化时应使用实际确认地址。离线复核可用 `--analyze-log`、
`--expected-build`、相同 `--steam/--seconds` 和一个输出 JSON 路径。

`LIVE_WIRE` 是通过连接入口的普通 type3/4、type11 包数；`parity_enabled` 仅表示
包头声明 m>0，`parity_shards` 表示到达的校验片，`fec_complete` 是生产 FEC 接收器
实际交付次数。收到 type11（可为 m=0）或 FEC 交付，都不单独证明发生了 RS 修复。
`LIVE_FLOW` 的 complete 是完整媒体回调次数，recovery 是 DataLost 入口调用次数；
feedback_sent/failed 是普通会话实际 Socket 发送 type10 的结果，不把每份反馈都当作
请求缺片，更不等于主机收到/执行了请求。计数覆盖普通会话的所有媒体 channel，
不是只覆盖视频。观察器原样转发生产调用，只做有界原子记账，不逐包输出或等待。
读取元数据前先检查数据指针和长度；空/短 FEC 包仍交给原接收器拒绝，
不会为诊断提前请求空缓冲的指针。空/短出站缓冲也保留原发送结果，不读取其包头。

观察器格式 2 在 `LIVE_BEGIN` 中声明 `observer=2`，另按实际 Video channel 类型识别
视频角色，不预设 channel ID=4。每个计数周期与最终计数组还包含：

| 记录 | 直接观察的边界 |
|---|---|
| `VCHANNEL` | 当前视频 channel 的普通/type11 入站计数；retry 仅计普通包重发字节非零，不等于唯一丢片或主机已处理反馈 |
| `VRECV` | 送往视频完整媒体回调的次数；key/finish 是其中明文视频头的原始标志，在 FIFO 准入/退休之前 |
| `VWORK` | decoder worker 取得完整媒体的次数；key/finish 在消费者偏移缓冲之前读取，不表示关键帧已完成组装/解码 |
| `VSUBMIT` | 应用视频提交入口、返回、关键帧参数、致命返回计数；不把入口/返回当作产生图像 |
| `VDECODE` | 解码反馈调用与实际布尔返回；reset/lost/disable 是提供的有效标志，accepted 不证明异步重建已完成 |
| `VREQUEST` | 实际 Video 类型 endpoint 的 DataLost 入口，以及普通会话同 channel 的 DataLost datagram Socket 成功/失败；不证明主机收到或响应 |

`VRECV/VWORK.last` 是一次原始头观察的打包值：bit40 为存在位、低16位为媒体
frame ID、bit16–31 为视频片段 sequence、bit32–39 为原始 flags；工具在 JSON 中展开。
`VSUBMIT.last` 的 bit48 为存在位、低16位为提交 frame ID、bit16–47 为应用提交 flags。
这些 ID/flags 与原子计数不是跨字段事务快照，也不是完整帧像素身份；关键帧标志依据
协议参考 §24/59，不能直接当作成功恢复。入站在角色确定前也按 channel 记账，未保留
跨线程的 channel 指针；不同视频 epoch/channel 的计数不能误作同一连续帧序列。
网络/decoder 观察器只做固定上限的原子操作，不逐包输出；主线程每秒采样，单行保持
在平台 240B 日志上限内。丢失/截断记录按原规则拒绝通过。

格式 2 的最终六组视频计数均为验收必需项，并要求提交已返回；播放失败原因与
清理结果分别保留，不能因为 `result=FAIL` 就把已记录的 join/destroy 称作失败。
旧格式归档仍保留其原提交工具生成的报告，不补造缺失的视频计数；新工具拒绝把
旧格式当作本版本验收。

`LIVE_RESULT` 保留实际解码/首次呈现/音频解码计数、硬解事实、首帧后的播放时间、
主循环观察的最大呈现计数推进间隔 gap_ms 和结束前无推进时间 tail_ms。它不是逐帧
GPU 时间戳；epoch 内计数在两次采样间多次增加时，只能观察到最后一次主循环采样。
测试至少要求两次实际呈现，且结束前两秒仍有推进，拒绝“首帧后冻结仍通过”；
两秒仅是 smoke 验收阈值，不进入生产重发、丢帧或重连决策。历史 gap_ms 仍单独保留。
PASS 只表示已有配对身份完成真实主机视频播放 smoke 与应用资源清理；音频计数
需单独判断，未注入丢包，不证明异常网络恢复、长期同步或全部线程交错。
GPU/显示 API 的呈现计数也不证明物理扫描完成；FINAL 在关闭日志 socket 之前输出，
不证明 socketExit、返回 hbmenu 或第二次启动。缺少当前 BEGIN/完整终态、
计数或清理记录、播放时间不足、超时及 nxlink 非零退出均不能通过。

## 屏幕诊断

串流中同时长按 **− 和 + 0.8 秒**打开本地游玩菜单；菜单内单独长按 **X 一秒**切换只读 Debug 浮层，
随后自动返回游戏。再次进入菜单长按 X 关闭。默认关闭，断开后复位。

浮层的“本机视频”从客户端提交完整帧计时到 present 返回，不是网络延迟或物理屏幕扫描完成时间。
最大 ACK 等待是会话累计传输确认最大值，不证明游戏已应用输入。重复绘制同一视频纹理不增加视频帧率。
没有样本显示“—”；超过三秒没有更新标记数据已过期。

## 日志与清理

独立 joinable 日志线程接收有界队列；生产者 trylock，队列满时丢弃日志，不阻塞渲染或输入。
每秒记录实际媒体与可靠传输摘要。每次启动在 `sdmc:/switch/nsteamlink/logs/`
创建独立的 `session-<时间>-<纳秒>-<分卷>.log`；单卷达到 4 MiB 后续写新卷，
不会因总写入超过 4 MiB 停止，也不自动覆盖或删除历史文件。磁盘写入失败由下载索引的
`storage_errno` 报告。升级前的三份 `stream_diag*.log` 原样保留，也可通过下载接口读取。
UDP 的 `diag` 仍只是兼容用的内存尾部，完整历史应从 HTTP 接口下载。
配对码、安全码及密钥不进入该日志接口。

调试版运行期间，原日志线程提供 TCP `28773` 的只读 HTTP 接口；停流返回首页后仍可使用。
无需重进 hbmenu 或部署回收 NRO。切回可达的局域网后，在电脑运行：

```bash
python3 tools/pull-switch-logs.py --address 10.10.10.17 --output build/device-logs
```

`GET /logs` 返回版本、commit、存储错误、诊断队列丢弃数及日志索引；超过一页可按
`next_after` 查询。`GET /logs/<文件名>` 支持有界 HTTP Range。工具以 32 KiB 分段下载，
超时重试并保留 `.part` 以续传，核对响应范围和长度，在 `capture.json` 保存本地 SHA-256。
当前文件按索引时的大小取快照，下次拉取补齐其后追加部分。工具不修改远端文件，
也不读取配对资料。退出应用后 HTTP 服务随日志线程关闭；重新启动调试版即可读取保留下来的历史。
文件与网络操作均由后台日志线程承担，协议收包、渲染和输入线程不执行下载文件 I/O。

日志首行包含应用版本、完整 commit 和设备 Unix 时间，回收后须先核对是否属于目标会话。
`connection_event` 记录实际选用 LAN UDP 或云端 SNS、请求响应及 IHS 配置/连接/断开阶段；
每秒 `connection` 的 `route` 区分 `lan_udp`、`sns_direct`、`sns_relay` 和未就绪/已关闭，
同时记录 SDK state、relay 标志、终态来源和 SNS datagram 累计数。它不把云端发现等同中继。
`control_tx` 每秒记录握手state、完整地址查找/空地址查找、CM本机入队、被拒、交给WebSocket
发送队列、交付失败、队列清理/旧会话丢弃及当前待发送数量。reason为最近入队拒绝原因：1云端未就绪、
2没有目的账号记录、3本地队列/大小上限、4分配失败。forwarded仅证明CM发送队列接收，
不证明Steam服务器或主机收到；direct_lookup也只证明有完整缓存地址，不证明UDP送达。
`control_rx`记录云端控制回调累计数、最后的消息type、开流request_id和结果码；它位于
IHS准入之前，收到不等于请求编号匹配或票据被接受。结果不可读取时为-1，received=0时
最后字段无含义。计数从进程启动累计，包含发现产生的控制发送，按请求阶段比较增量。
`control_identity`只记录目的账号是否存在/为零、是否匹配已配对卡片、key文件加载结果
（0读到、1不存在、负值错误），不记录账号ID、密钥或token；不得仅凭这些布尔值判定授权成功。
`pipeline` 即使尚未显示第一帧也输出提交、解码、显示、音频及帧停滞时间；`reliable` 输出
ACK/NACK/重试/失败、待确认数量与最老项年龄。退出前及 IHS join 后再保存一次阶段快照。
`log_drop` 是有界队列或 trylock 丢弃的诊断记录数，不能把它当作网络丢包数。
这些记录只在诊断包启用，不包含 packet payload、配对材料或 SDK 原始身份文本。

`cloud_net` 在目录请求、候选连接、失败/重试时记录具体阶段、libcurl result、HTTP 状态、
系统网络错误和证书校验结果；`cloud_time` 的 DNS/TCP/TLS 数值是 curl 的阶段完成时间，
均以请求开始为起点，不能将它们相加。`curl=-1` 表示该事件没有对应的 curl result，
不是成功；`curl=0` 只说明那次 curl 操作完成，HTTP、Upgrade、protobuf 仍可能失败。
常见 result：6=DNS、7=连接、28=超时、35=TLS、60=证书校验。`cloud_addr` 记录连接实际
本地/远端 IP；`cloud_update stall_ms` 记录 owner 内一次云端更新超过 250 ms（最多每秒一条），
用于核对是否阻塞了同线程的其他工作，不能仅凭使用 multi 就断言所有 DNS 路径均不阻塞。
`cloud_try` 从 curl 的连接前事件记录每个尝试的数字 IP/端口，即使 TCP 超时、
`cloud_addr` 尚无值也能留证。每个请求最多 16 条；该地址不是 DNS 响应全集，也不代表连接成功。
只接受 `Trying` 文本中经数字地址校验的 IP/端口；其他文本、头部及数据全部忽略。
当前Switch统一解析策略用`dns_query event=begin`记录主机名和当前本机/DNS数字地址，
`event=ready|failed|cancelled`记录有界查询结果与耗时。ready只代表取得DNS地址，不代表
HTTPS成功。旧4e810d5的cloud_dns仅覆盖目录，不能据此判断SDR配置或SDK解析已恢复；
该单点补丁已被D-A075统一策略替代。`sns_config`另外记录GetSDRConfig HTTP/curl结果、
信任导入、证书安装与P2P创建。须继续对应后续SDK状态、IHS和媒体进度，不把发现成功当作
传输成功。清理时DNS scope/socket结果在日志关闭前保存。
`sns_start failed_stage=... detail=...` 在SDK尚未返回有效连接句柄时记录拒绝类别：
`option` 的detail是配置项ID；`udp_socket/nonblock/send_buffer/recv_buffer/bind/local_address`
的detail是底层socket错误码；`crypto` 的detail=1表示尚无可用签名证书。
同时保留SDK认证可用性和本地证书剩余秒数（无证书为INT_MIN）。只有同步创建连接期间
临时启用SDK错误回调，最多接纳8条并转换成固定分类/数字，不保存SDK原文或身份；
回调内不输出日志，调用返回后恢复禁用，正常收流不增加SDK日志。
`cloud_watch` 记录保存主机中有多少具备配对/账户/设备信息；`cloud_subscription queued`
仅代表订阅进入发送队列，`cloud_host event=online` 才代表收到并接纳主机状态。

调试主应用另外每秒记录 `udp_rx` 与 `media_rx`。前者按本次会话的 IPv4 主机地址/端口
统计 native UDP 返回的 datagram；后者按 channel 分开记录原始媒体报文头、通过 IHS
校验后到达媒体通道入口的报文及已排队的恢复请求。入口计数不代表窗口接纳或完整组帧。
原始计数尚未通过 CRC/连接身份检查，
不能视为有效媒体；计数差也不能直接当作无线丢包率。协议线程只更新固定原子计数，
不逐包输出、分配、复制 payload 或重新校验 CRC。SNS 的底层收发仍看既有 `connection`
计数；测试驱动有自己的观察器，不能把其 `observer=0` 误读为没有收到包。

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

### 正式客户端云端媒体自包含测试

`nsl-runtime-probe` 复用正式桌面应用，通过现有 UI 自动启动、显示视频、核对音频队列、
合成 SDL 手柄的报告内容及 ACK，再从菜单断开并退出。需 `NSL_BUILD_SNS=ON`、
`NSL_BUILD_TOOLS=ON` 和 `NSL_DIAGNOSTICS=ON`；外部服务验收不加入普通 CTest。
传入独立的已配对 profile 目录和 Steam 主机 LAN IPv4：

```sh
build/gns-mbed/app/nsl-runtime-probe /absolute/private-profile 10.10.10.166 --sdr-only
```

省略 `--sdr-only` 则保留自动 ICE/SDR。两种模式都仅在 fixture 进程内过滤指定主机
及广播 UDP，使正式 runtime 通过云端发现请求 SNS；不会修改电脑/路由器的防火墙。
指定 IP 必须是实际 Steam 主机，不能把该隔离称为不同出口 NAT 验收。

Switch 对应入口复用私有 RomFS 交付和加密回读，用户只准备 hbmenu Netloader：

```sh
python3 tools/switch-sns-runtime-probe.py --address 10.10.10.25 \
  --lan-host 10.10.10.166 --profile /absolute/private-profile --mode sdr --prepare-only
python3 tools/switch-sns-runtime-probe.py --address 10.10.10.25 \
  --lan-host 10.10.10.166 --profile /absolute/private-profile --mode sdr --run-only
```

`--mode auto` 保留自动选路。私有 NRO、profile 与诊断只保留在 ignored build 目录，
不要分发为发布包；同一身份不能同时运行于 PC 和 Switch。结果保存在私有 build
目录的 `runtime-result.json`，日志含阶段、错误、身份回读 ACK 与临时文件清理结果。
按下/释放均要求新的报告序号和按钮位、发送/ACK 进展以及空待确认队列；初始化全量
报告不能代替输入验收。合成事件不证明物理按键，音频队列不证明实际扬声器声音，
`nxlink` 正常退出也不证明 LCD 已返回 hbmenu。契约见 D-A071。

桌面 runner 另有 `--cloud-reconnect`（替代 `--sdr-only`）：保留首页并注入一次 CM
读取错误，将该 provider 保持停止更新 20 秒，核对 UI 离线、新匿名连接和重订阅后
恢复在线，再正常退出。不启动媒体；其余网络继续正常工作。这是客户端进程故障环境，
不代表真实服务器 Offline、退订或不同 NAT 出口的验收。

`nsl-remote-lifecycle-live` 是不启动媒体、不创建 LAN discovery socket 的桌面云端
生命周期验收工具。手动运行，不能放进无人值守 CTest：

```sh
build/desktop/app/nsl-remote-lifecycle-live --pair-cycles
build/desktop/app/nsl-remote-lifecycle-live --subscriptions /absolute/private-profile
build/desktop/app/nsl-remote-lifecycle-live --offline /absolute/private-profile
```

`--pair-cycles` 使用临时随机安装身份，申请的 PIN 不输出、不要求主机输入，随后自动取消。
它在接收入口暂存真实 StartPairing 回复，核对取消后迟到 PIN 的清理、发布后取消，以及
丢弃一次回复后真实等待 RPC 超时、重建 session、重新申请和取消；不修改产品协议。
`--subscriptions` 使用两个只读发现会话，以其中一个为持续订阅对照，另一个退订后排空
两秒再观察 30 秒；同时要求原始接收层的退订侧 status 为零、对照侧收到 status，随后
重订阅恢复。若对照期没有通知，只能报告 INCONCLUSIVE，不能以本地不再分发 callback
代替服务端退订证明。`--offline` 打印 READY 后各等待最多三分钟，需先让主机完整退出
Steam，再重新打开；要求真实服务 Offline、匹配目标的回调和在线恢复，期间 CM 没有断线。
后两种模式独占私有 profile，不得同时启动其他使用此身份的测试或客户端。

`nsl-remote-tests` 的密钥中断测试采用合成主机输入、真实密码算法和生产 profile 存储：
在保存新 secret 后、Proof 入队前，以及入队后直接退出子进程；父进程重新加载身份，
验证请求 token 和后续 session key 使用正确密钥。保存失败另验证不发送 Proof、旧身份
可读。这证明本地持久化与重启契约，不证明主机端回滚规则或设备断电时文件系统耐久性。

`--cloud-initial-failure` 保留首页，将真实目录首轮 CM 候选的 TLS 完成结果替换为
连接失败，检查逐个轮换、耗尽后的 10–30 秒退避，以及下一轮真实匿名连接/主机发现。
`--cloud-initial-bridge` 对同一 provider 显式设置 bridge_mode，核对耗尽后立即重试的
配置分支；不启动串流，也不代替完整媒体 bridge 重连验收。两个模式总期限为 180 秒，
均只作用于当前桌面测试进程，日志只输出计数、数值错误和延迟。

`--sdr-loss-soak` 使用正式 SDR 客户端，输入内容与 ACK 验收后，对测试进程的公网
IPv4 UDP 双向注入约 1% 固定种子伪随机丢包，持续 180 秒，核对显示帧进展和新鲜度，
再经菜单正常断开/退出；总期限为 240 秒。此模式会启动桌面串流。每五秒记录收发/丢弃
计数与媒体计数，不输出地址或 payload，不改全局网络。它不覆盖突发断路、jitter、
跨 NAT 回切或数小时稳定性。详细验收门槛见 D-A071。

`--sdr-abrupt` 在正式客户端完成显示与输入内容/ACK 验收后，仅在进程内双向屏蔽当时
primary 的一个 UDP endpoint，保留其他地址；不追随新 primary 改写屏蔽目标。要求不同
POP 的有效 E2E 与至少 30 个新显示帧，保持五秒且末尾一秒仍有 E2E/新帧，再正常菜单
断开；等待恢复最多 35 秒。记录 SDK 终态及 type20/type21/CM 关闭元数据，失败走正式
清理路径。这是媒体故障实验，会启动桌面串流；与独立 CLI 的编码帧 fixture 分开记录。
