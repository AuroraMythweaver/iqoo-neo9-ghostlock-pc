# iQOO Neo9 一键临时 root（PC 版）

**中文** · [English](README.en.md)

把原本要在手机上运行的 root App，改成电脑上用 `adb` 驱动的一个脚本：
**手机插上电脑 → 跑脚本 → 拿到临时 root**。

- 不解 BL 锁、不刷机、不写系统分区（系统分区保持 erofs + dm-verity green）
- root 只在内存里：**重启就没了**，要用就再跑一次
- 原理：CVE-2026-43499（GhostLock / futex-PI 竞态），把提权时点卡在手机刚开机的那十几秒

> **只支持这一种机型/系统**（脚本会自检 `uname -r`，不匹配直接拒绝）：
> vivo **iQOO Neo9（PD2338）** · **OriginOS 6（橘子 6）16.2.13.2** · 内核 **`5.15.197-g708015331567-dirty`**

---

## 一、手机侧准备（4 项）

1. USB 数据线连电脑，**USB 调试**打开
2. 开发者选项 → **停止限制子进程** 关掉
3. **锁屏密码 / 所有锁屏方式去掉**
4. 默认 USB 配置 = **文件传输**

## 二、电脑侧

需要 `adb`。Linux / WSL / macOS 都行（macOS 用 `reroot-mac.sh`，不用装 coreutils）。

```bash
unzip ghostlock-pc-iqoo-neo9-v1.0.0-linux.zip && cd ghostlock-pc-v1.0.0
chmod +x *.sh
./reroot.sh                 # macOS: ./reroot-mac.sh
```

脚本会一轮一轮地跑，命中就打印结果：

```
[+] 成功：root 已在（KernelSU late-load）
  su      : uid=0(root) gid=0(root) context=u:r:ksu:s0
```

之后：

```bash
adb shell su -c 'id'
```

## 三、它做了什么（通俗版）

1. 从 `ghostlock.bin` 里解出 exploit，等手机**刚开机那十几秒**（实测 30–45 秒命中率最高）
2. 打 futex-PI 竞态，把当前 shell 提成 root —— **SELinux 仍然是 Enforcing**
3. 先加载 `vrpatch.ko` 中和 vivo 自己的 `vr.ko`，再用管理器的 `ksud` 把 KSU 模块 load 进内存
4. `su` 可用，管理器显示「**工作中 · 越狱模式**」

没中时内核会 panic → 手机会自己重启 → 脚本等它回来继续。**多跑几轮是正常的**，这是概率问题。

## 四、三个脚本

| 脚本 | 用途 |
|---|---|
| `reroot.sh` / `reroot-mac.sh` | 主脚本：抢开机窗口拿 root（**不会主动重启手机**） |
| `install-ksu.sh` | 提权之后：加载**你自己的 `.ko`**、装任意 KSU 管理器 |
| `clean.sh` | 清理 / 卸载（默认只列清单） |

常用参数（`reroot.sh`）：

```bash
./reroot.sh --check          # 只看当前有没有 root
./reroot.sh --inspect        # 看 payload 包里有什么
./reroot.sh --deploy         # 只把 payload 部署到手机，不打
./reroot.sh 20               # 最多 20 轮
```

**一条龙**（列 ko → 你选 → 提权 → 成功后清理 → 退出）：

```bash
./reroot.sh --ko 1 --clean-after
```

- 启动时先列出本目录的 `.ko` 供你选（不加 `--ko` 就交互选，回车 = 用管理器自带的）
- 选 ko 只是本地文件操作，**不影响开机窗口**（push 发生在等窗口之前）
- 成功后自动清掉本次残留，但保留 `user.ko` 与 `ksud` wrapper，下次仍会用你的 ko

## 五、换 / 装 KSU 管理器

管理器必须和**内核里那个 KSU 模块的 uapi 一致**，否则首页只提示「需要更新内核」。

把你的 `xxx_kernelsu.ko` 和管理器 APK 放到脚本同级目录：

```bash
./install-ksu.sh                     # 预览：列出本目录的 ko / apk 和当前内核状态
./install-ksu.sh --ko 1              # 提权后加载第 1 个 ko
./install-ksu.sh --ko 1 --install 1  # 加载 + 装管理器
./install-ksu.sh --persist --ko 1    # 以后每次 reroot.sh 都用这个 ko（需重启生效）
```

已实测组合：**SukiSU-Ultra v4.2.1（uapi 5）+ `android13-5.15_kernelsu.ko`** → 首页「工作中 · 越狱模式」。

## 六、清理

```bash
./clean.sh                          # 看清单（默认不动手）
./clean.sh --yes                    # 删 payload / 日志 / 测试目录
./clean.sh --yes --all --reboot     # 全清 + 重启，回到干净系统
```

内存里的东西（KSU 模块、vrpatch 补丁、SELinux 状态）**重启就没了**；
磁盘上的 payload、日志、KSU 用户态用 `clean.sh` 删。

## 七、常见问题

- **一直不成功？** 概率问题，让它多跑几轮；卡死了手机会自己重启，脚本会等。
- **重启后没 root 了？** 正常。late-load 只在内存里，重跑 `./reroot.sh`。
- **管理器提示"需要更新内核"？** 管理器 uapi 比内核高，换与 ko 同版本的管理器。
- **多刷几次会伤手机吗？** 不写系统分区；失败是内核 panic 重启，不丢数据。
- **macOS 上跑不动？** 用 `reroot-mac.sh`（`reroot.sh` 依赖 GNU 工具）。

## 八、来源与免责

原作者（酷安）：<https://www.coolapk.com/U/43561117> ·《vivo iQOO Neo9 (PD2338) Root 研究》
GhostLock 原项目：[YuKongA/ghostlock-app](https://github.com/YuKongA/ghostlock-app)

`ghostlock.bin` 里的 `libghostlock.so` / `vrpatch.ko` 是上游原二进制，未修改；脚本与文档是本项目重写。
仅供自有设备学习研究，风险自担。

## 详细文档（面向过程，不在正文里展开）

| 文件 | 内容 |
|---|---|
| [`docs/FIELD-NOTES.md`](docs/FIELD-NOTES.md) | 实测数据、踩坑记录、macOS 兼容问题、管理器 uapi 门槛 |
| [`docs/PORTING.md`](docs/PORTING.md) | PC 化全过程：协议/格式的字节级证据、与作者帖子核对 |
| [`docs/ANALYSIS.md`](docs/ANALYSIS.md) | GhostLock APK 静态分析：漏洞链、`vrpatch.ko` 反汇编 |
| [`scripts/`](scripts/) | 调参 / 取证用的 python 工具（日常不需要） |
