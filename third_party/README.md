# third_party — 第三方依赖目录

所有外部库以 git submodule 或 vendored 源码形式放在这里，**禁止就地修改**；
需要的改动以 patch 文件放 `patches/<库名>/`，并在 `docs/decisions.md` 登记。

## 待引入（按里程碑）

| 库 | 引入时机 | 说明 |
|---|---|---|
| IHSlib | M1 | 上游 `mariotaku/IHSlib` 还是 `beudbeud/ihslib`(plume 分支) —— 开工时先 diff 补丁差异再定（决策 D-002，见 kickoff §3.1） |
| plume | M1 | 参考实现，仅作对照学习，不链接进本项目；克隆必须 `--recursive` |
| protobuf-c | M2 | devkitPro 无现成 Switch 包，用 `$DEVKITPRO/cmake/Switch.cmake` 交叉编译装入 portlibs |
| FFmpeg (averne NVDEC fork) | M3 | 先直接复用 Moonlight-Switch 仓库 `lib/switch/` 内的预编译静态库 |

## 注意

- 克隆/拉取后务必 `git submodule update --init --recursive`，
  否则会静默回退上游版本且行为不对（kickoff §7.2 的坑）。
- 复用的任何第三方代码保留原版权与许可声明，并更新 `DEVELOPMENT.md` §7 的依赖表。
