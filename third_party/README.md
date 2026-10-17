# third_party — 第三方依赖目录

Git submodule与vendored源码放在这里；Opus的未修改归档由CMake核验并展开到
构建目录，来源与许可见下文。第三方源码**禁止就地修改**。
对一般第三方库的改动以 patch 文件放 `patches/<库名>/` 并在 `docs/decisions.md` 登记；
**例外：IHSlib 使用本项目的 GitHub fork（D-037），改动直接提交到 fork 分支并推送**。

## 已引入

| 库 | 版本 | 说明 |
|---|---|---|
| IHSlib | `kxn/ihslib` `master` 分支，基线 `8c5a17c`（fork 自 `beudbeud/ihslib` plume） | 协议层依赖；改动进入 fork 主分支（D-037/D-055） |
| Opus | 1.5.2，SHA256 `65c1d2f78b9f2fb20082c38cbe47c951ad5839345876e46941612ee87f9a7ce1` | CMake核验官方归档，定点构建、保留float API；桌面/Switch共用，见协议参考§72 |

## IHSlib fork（kxn/ihslib，分支 master）

基线为上游 `beudbeud/ihslib` plume 分支 pin `8c5a17c`。当时基线之上的全部项目改动
（历史补丁 0001–0013 的内容 + 后续工作）固化为 fork 上的单提交 `263fd5d`，
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

官方 `mariotaku/ihslib` master 的 `1881b9a` 已纳入 fork 历史。平台和解码器能力由
应用通过 `IHS_SessionSetClientCapabilities()` 在连接前提供；通用层省略未知字段，
不会默认上报 Switch/Marvell/TV。此接口拷贝字符串，不扩展既有 `IHS_SessionConfig`。
应用与 fork 须同步源码重编译；配对 secret 的按主机保存/选择、tracked ticket 所有权
和显式 HID flush 契约继续有效。详见 fork README 和 D-057。

## 后续改 ihslib 的流程（取代 patch 流程，D-037）

1. `git submodule update --init --recursive` 后子模块默认处于 detached HEAD；先在
   `third_party/ihslib` 中执行 `git switch master`，不存在时执行
   `git switch --track origin/master`，再 `git pull --ff-only origin master`。
   本地 `origin`（或既有的 `fork`）必须指向 `https://github.com/kxn/ihslib.git`；
2. 在 fork 的 `master` 正常提交并 `git push origin master`（使用 `fork` remote 时
   相应改为 `git push fork master`）；风险主题可先开短期分支，合入 `master` 后删除；
3. 父仓库随之更新 submodule pin 并提交；
4. 官方更新吸收到 fork 的 `master`，先核对协议定义和接口差异，再合并、验证、
   推送并更新父仓 pin；本项目独立维护 fork，不要求向官方提交 PR（D-057）。

## 待引入（按里程碑）

| 库 | 引入时机 | 说明 |
|---|---|---|
| plume | M1 | 参考实现，仅作对照学习，不链接进本项目；克隆必须 `--recursive` |
| protobuf-c | M2 | devkitPro 无现成 Switch 包，用 `$DEVKITPRO/cmake/Switch.cmake` 交叉编译装入 portlibs |
| FFmpeg / SDL2 | M3 | 使用 devkitPro `switch-ffmpeg` / `switch-sdl2` portlibs；FFmpeg 已启用 `--enable-nvtegra` |

## 注意

- 克隆/拉取后务必 `git submodule update --init --recursive`，
  这会检出父仓库记录的确切提交；`branch = master` 仅供显式
  `git submodule update --remote` 使用，不能代替审核和提交 submodule pin。
- 复用的任何第三方代码保留原版权与许可声明，并更新 `DEVELOPMENT.md` §7 的依赖表。

## Opus：音频解码

`cmake/Opus.cmake`从[Xiph官方归档](https://downloads.xiph.org/releases/opus/opus-1.5.2.tar.gz)
下载未修改源码并核验SHA256，静态链接fixed-point decoder，调用multistream float API。
官方客户端的实际恢复分支和定点输出证据见`docs/STEAMLINK_PROTOCOL_RE.md`§72。
源码在构建目录中，无需全局安装；已有源码缓存可用CMake的
`FETCHCONTENT_SOURCE_DIR_NSL_OPUS`指定，使用者负责其与固定归档一致。
BSD许可原文保存为`third_party/opus-LICENSE.txt`，随发布NRO收集到同一输出目录。
1.5.2是本项目的可复现依赖版本，不将官方库的`unknown-fixed`误称为已识别版本。

## jsmn：游戏封面元数据解析

`third_party/jsmn/jsmn.h` 与 `LICENSE` 来自 [zserge/jsmn](https://github.com/zserge/jsmn)，
固定提交 `25647e692c7906b96ffd2b05ca54c097948e879c`，MIT，未修改上游内容。
使用 strict 模式、固定 token 数、64 KiB 响应上限，只提取匹配 AppID 的图片资源。
新增链接依赖 libcurl（curl license）和 libjpeg-turbo（BSD/IJG）由系统/devkitPro portlibs 提供；
Switch curl 使用 libnx SSL，不引入应用自己的根证书文件或关闭 TLS 校验。

## nx-hbloader：HOME 入口加载器

`third_party/nx-hbloader/` 来自 [switchbrew/nx-hbloader](https://github.com/switchbrew/nx-hbloader)，
固定提交 `82b95122c5ae8dc059bf23893ba7623c72c86773`，ISC。仅保留构建所需的
Makefile、hbl.json、source/main.c、source/trampoline.s 和 LICENSE.md，均未修改。
`scripts/build-shortcut.py` 在 build 副本应用固定路径和返回 HOME 调整，见 decisions D-049。
不使用 Nintendo/Steam 原生图标，不提交机器密钥、生成的 NCA 或模板二进制。

IHSlib 的 `src/session/outgoing_sort.c` 参考
[LLVM libc++19 sort.h](https://github.com/llvm/llvm-project/blob/llvmorg-19.1.0/libcxx/include/__algorithm/sort.h)
实现至多32个通道的排序，单文件使用 Apache-2.0 WITH LLVM-exception；完整许可位于
`third_party/ihslib/src/session/LLVM-LICENSE.txt`。排序策略与同优先级结果以固定官方
Steam Link 客户端原指令对照为准，开源实现只用于算法实现参考。
