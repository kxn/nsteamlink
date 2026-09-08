# third_party — 第三方依赖目录

所有外部库以 git submodule 或 vendored 源码形式放在这里，**禁止就地修改**。
对一般第三方库的改动以 patch 文件放 `patches/<库名>/` 并在 `docs/decisions.md` 登记；
**例外：IHSlib 使用本项目的 GitHub fork（D-037），改动直接提交到 fork 分支并推送**。

## 已引入

| 库 | 版本 | 说明 |
|---|---|---|
| IHSlib | `kxn/ihslib` `nsteamlink` 分支，基线 `8c5a17c`（fork 自 `beudbeud/ihslib` plume） | 协议层依赖；改动直接进 fork 分支（D-037） |

## IHSlib fork（kxn/ihslib，分支 nsteamlink）

基线为上游 `beudbeud/ihslib` plume 分支 pin `8c5a17c`。基线之上的全部项目改动
（历史补丁 0001–0013 的内容 + 后续工作）已固化为 fork 上的单提交 `263fd5d`，
其内容与当时通过双目标构建和 ihslib 27/27（host / ASan+UBSan / TSan）测试的
submodule 工作区逐字节一致。旧 patch 文件已删除，需要查阅时从本仓库 git 历史取回
`third_party/patches/ihslib/`（0001–0013 为按主题分层的历史记录，0020 为当时的
权威累计快照；分层补丁单独/顺序重放已不可靠）。

改动内容按主题（协议依据见 `docs/STEAMLINK_PROTOCOL_RE.md` §14、decisions D-042）：

- Switch/libnx 构建、socket 和 SDL2 兼容适配；认证字符串 NUL 终止和消息诊断。
- HID：报告长度跟随 StartInputReports；状态变化采用 delta/full 自适应，显式重置用 full；
  收集与发送统一排序，active_input 按实际活动计算，相同状态不额外发送定期快照。
- 可靠传输：初发前登记，累计 ACK 与选择 NACK 正确释放已确认包，缺失包持续重传；
  接收窗口保留空洞并扩容，ACK echo 驱动 RTT 与时钟偏移估计。
- 视频/统计：等待 StartVideoData 后创建或替换解码器；帧事件首项加时钟偏移、后续 delta；
  媒体可靠模式尚未实现，协商 reliable_data=false。
- 生命周期与诊断：有界 socket 唤醒，stop/join 后释放依赖，设备快照延迟释放；
  日志队列显式记录截断/掉条，诊断输出先检查容量。
- 回归入口：host CTest、`scripts/audit-ihslib-control.sh` 协议反例探针；
  Switch 运行行为必须以真机证据验证。

## 后续改 ihslib 的流程（取代 patch 流程，D-037）

1. 在 `third_party/ihslib` 内（`nsteamlink` 分支）正常提交；
2. `git push fork nsteamlink`（remote `fork` = `https://github.com/kxn/ihslib.git`）；
3. 父仓库随之更新 submodule pin 并提交；
4. 若日后上游恢复活动，评估把 `nsteamlink` 分支的独立主题以 PR 反哺上游
   （控制可靠状态机是现成素材）；反哺被吸收前，fork 为权威源。

## 待引入（按里程碑）

| 库 | 引入时机 | 说明 |
|---|---|---|
| plume | M1 | 参考实现，仅作对照学习，不链接进本项目；克隆必须 `--recursive` |
| protobuf-c | M2 | devkitPro 无现成 Switch 包，用 `$DEVKITPRO/cmake/Switch.cmake` 交叉编译装入 portlibs |
| FFmpeg / SDL2 | M3 | 使用 devkitPro `switch-ffmpeg` / `switch-sdl2` portlibs；FFmpeg 已启用 `--enable-nvtegra` |

## 注意

- 克隆/拉取后务必 `git submodule update --init --recursive`，
  否则会静默回退上游版本且行为不对（kickoff §7.2 的坑）。
- 复用的任何第三方代码保留原版权与许可声明，并更新 `DEVELOPMENT.md` §7 的依赖表。

## jsmn：游戏封面元数据解析

`third_party/jsmn/jsmn.h` 与 `LICENSE` 来自 [zserge/jsmn](https://github.com/zserge/jsmn)，
固定提交 `25647e692c7906b96ffd2b05ca54c097948e879c`，MIT，未修改上游内容。
使用 strict 模式、固定 token 数、64 KiB 响应上限，只提取匹配 AppID 的图片资源。
新增链接依赖 libcurl（curl license）和 libjpeg-turbo（BSD/IJG）由系统/devkitPro portlibs 提供；
Switch curl 使用 libnx SSL，不引入应用自己的根证书文件或关闭 TLS 校验。
