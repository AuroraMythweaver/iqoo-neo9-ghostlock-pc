# NOTICE —— 文件来源与许可

本仓库只包含**驱动脚本与文档**，以及两个上游二进制产物。清单如下。

| 内容 | 来源 | 许可 / 说明 |
|---|---|---|
| `ghostlock.bin` 内的 `libghostlock.so`、`vrpatch.ko` | 酷安原作者《vivo iQOO Neo9 (PD2338) Root 研究》<https://www.coolapk.com/U/43561117>；GhostLock 上游 <https://github.com/YuKongA/ghostlock-app> | 原样分发，未修改 |
| Release 资产 `android13-5.15_kernelsu.ko` | SukiSU-Ultra `v4.2.0` 的 LKM 构建（模块内 `version=g904c60d18f02`）<https://github.com/SukiSU-Ultra/SukiSU-Ultra> | **GPL-3.0**；对应源码见该 tag 的 `kernel/` 目录 |
| `reroot.sh` / `reroot-mac.sh` / `install-ksu.sh` / `clean.sh` / `docs/` | 本项目 | 随仓库分发 |

## 关于 GPL-3.0 的 `kernelsu.ko`

- 它是 SukiSU-Ultra 的内核模块构建产物，按 GPL-3.0 分发；
- 对应源码：<https://github.com/SukiSU-Ultra/SukiSU-Ultra/tree/v4.2.0>（`kernel/`，模块版本串 `g904c60d18f02`）；
- 需要自行编译时，按该仓库的 LKM 构建流程（`just` / CI）产出 `{kmi}_kernelsu.ko` 即可。

## 关于 `libghostlock.so` / `vrpatch.ko`

- 它们是原作者发布的 exploit 产物，本项目只做驱动封装，未修改二进制；
- 版权归原作者；仅供自有设备学习研究。
