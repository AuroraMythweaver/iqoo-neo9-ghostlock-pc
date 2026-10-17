# GhostLock PC 化 · iQOO Neo9 (PD2338) 一键临时 root

把手机上的 root App 壳搬到 PC：**一个脚本 + 一个二进制**，用 `adb` 驱动设备上那个原生 exploit，
抢开机窗口拿临时 root（KernelSU late-load）。不需要解 BL 锁，不刷机，不写系统分区。

> **状态**：已在真机（iQOO Neo9 / PD2338 / 内核 `5.15.197-g708015331567-dirty`）**提权成功**。
> `su -c id` → `uid=0(root) context=u:r:ksu:s0`；`/proc/modules` 有 `kernelsu`；SELinux 保持
> **Enforcing**。原始日志见 [`evidence/`](evidence/)。

```
$ ./reroot.sh
================ 第 2/10 轮 ================
[*] adb reboot
[i] 拿到 shell：uptime=32.5 秒
---- 第 2 轮 / 第 1 次（uptime=32.7s）----
[+] KSU late-load 成功
[+] 成功：root 已在（KernelSU late-load）
  su      : uid=0(root) gid=0(root) groups=0(root) context=u:r:ksu:s0
```

---

## 1. 这是什么 / 不是什么

| 是 | 不是 |
|---|---|
| 对 **GhostLock v1.2 (CVE-2026-43499)** 这套现成 exploit 的 **PC 侧驱动器** | 不是自己写的漏洞利用代码 |
| 把 App + Shizuku 那一层换成 `adb shell`（同样的 uid 2000 / `Seccomp: 0`） | 不是把漏洞"搬到电脑上跑"（竞态只能打手机内核） |
| 一个 bash 脚本 + 一个 payload 包，零 python 依赖就能跑 | 不是通用 root 工具（**只对匹配的内核 release 有效**） |
| 开机窗口内的自动重试（失败 panic 重启 → 自动等回来继续） | 不是持久 root（`late-load` 只在内存里，硬重启即失效） |

**为什么值得这么干**：在原 App 里跑，进程挂在应用 cgroup / app-freeze / LMK 下面，跑到一半就被系统
回收；而这个漏洞要的是"抢在开机后 12~45 秒内命中几个内核对象"。换成 `adb shell` 之后进程落在 shell
session 里（`setsid` 脱离，PC 断开也不影响），可以无成本地一直刷。

## 2. 快速开始

前提：手机开 USB 调试、插在电脑上、`adb devices` 能看到（`device` 状态）；固件/内核与 payload 匹配
（脚本会自己比对 `uname -r`，不一致直接拒绝）。

```bash
git clone <this-repo> && cd <repo>

./reroot.sh                  # 最多 10 轮：每轮 adb reboot → 抢窗口 → 命中即停
./reroot.sh 20               # 想多刷几轮
./reroot.sh --no-reboot      # 设备刚重启过 / 你手动重启完：直接抢窗口
./reroot.sh --check          # 只看当前有没有 root（不会重启）
./reroot.sh --inspect        # 看 payload 包里有什么
./reroot.sh --deploy         # 只布署 payload，不打
./reroot.sh --check-payload  # 看设备上的 payload 是否就绪（不会重推）
```

成功后：

```bash
adb shell su -c id           # uid=0(root) ... context=u:r:ksu:s0
```

**关键：别重启。** `vrpatch.ko` 的 insmod 和 `ksud late-load` 都只存在于内存里；一旦硬重启就没了，
下次开机重跑 `./reroot.sh` 即可（作者实测 `vrpatch` 的文本补丁能扛**软重启**）。

## 3. 两个文件

```
reroot.sh        10 KB   脚本：纯 bash + adb（od/dd 拆包、比大小、抢窗口、盯日志）
ghostlock.bin   736 KB   payload 包：libghostlock.so + vrpatch.ko + profile.bin + release
```

`ghostlock.bin` 的容器格式（little-endian，bash 用 `od`/`dd` 就能解析，不需要 python）：

```
0x00  8B   magic "GLPACK01"
0x08  u64  data_start
0x10  u32  n_entries
0x14  u32  format_version (=1)
0x18  n×32B 条目 { u64 off; u64 size; char name[16] }
data_start: payload 依次排列
```

实测校验：脚本把三个文件拆出来推到设备后，`md5sum` 与原件完全一致
（`eef05feb…` / `07d6eb23…` / `647fba3d…`）。

## 4. 脚本干了什么

1. 已 root 直接退出（幂等，**不会把到手的 root 重启掉**）；
2. 拆包 → 与设备上的文件逐个比大小，不一致才推（`--redeploy` 强制重推）；
3. 比对包内 `release` 与设备 `uname -r`，不一致**拒绝执行**（`--force` 才硬打）；
4. `adb reboot` → 死等 `adb shell` 真的可用 → **立刻发射**；
5. 盯 root 脚本日志，出现 `KernelSU module loaded` 即成功并**立即停手**；
6. 没中 / panic 重启 → 自动等回来继续；窗口内（`WINDOW` 秒）连刷 `PER_BOOT` 次。

可调环境变量：`TIMEOUT=180`（单次盯多久）、`PER_BOOT=6`、`WINDOW=90`、`GL_DIR=...`（换设备端目录）。

## 5. 实测结论：这是个开机窗口竞争

历史日志里 `boot_ms` 和结果的相关性非常干净（`boot_ms` = native 启动时距开机毫秒数）：

| boot_ms | 结果 |
|---|---|
| 14.4 s | **W1 过** → 进 W2 |
| 38.6 s / 40.6 s / 61.5 s | 进 W2，其中 **40.6 s 那次直接拿到 root** |
| 84 s / 106 s / 178 s / 12 min / 2.9 h / 22 h | 全部 `Write 1 failed` |

所以本项目的核心不是"改参数"，而是"**抢时间**"：重启、一有 shell 立刻发射、窗口内连刷。
作者帖子（见致谢）写的"单轮约 43 秒稳定提权"与实测完全吻合。

另外两条踩坑记录（都写在 [`docs/PORTING.md`](docs/PORTING.md)）：

- **`execution.consumer.max_calls = 0` 是致命的**：直接用 APK 里那份 `.conf` 生成的 blob 里这项是 0，
  真机日志是 `attempts=128 calls=0 success=0` —— consumer 线程一次都没触发，路由空转。
  能打通的 blob 是 `1/1`。
- **`route.multicast_waiter.compact_waiter` 在 APK 的 route 对象里会被丢弃**（只有 `kernel` 组和
  `route.select_stack` 组认这个 key）；能打通的 blob 里它是 `kernel.compact_waiter = 1`。

## 6. 适配其它固件 / 机型

payload 里的 offset 是**按内核 release 精确匹配**的，不匹配会 panic 重启（设备能自行恢复，
但别拿错 profile 去刷）。换固件时：

```bash
# 1) 用你自己解包出来的 APK 产物重建 pack
#    （本仓库不分发 APK 与解包结果，见 NOTICE）
python3 scripts/mkpack.py -o ghostlock.bin \
    --lib  <your>/lib/arm64-v8a/libghostlock.so \
    --ko   <your>/assets/modules/vrpatch.ko \
    --blob evidence/profile.bin          # 或你自己按目标内核生成的 blob

# 2) 看包
python3 scripts/mkpack.py --list ghostlock.bin
```

`scripts/ghostlock_profile.py` 能把 APK 里的 HOCON 内核配置（`assets/kernel_profiles/<uname -r>.conf`）
转成 native 要的二进制 blob，带 native 侧组名/键名白名单校验：

```bash
python3 scripts/ghostlock_profile.py build -c <uname -r>.conf -o profile.bin
python3 scripts/ghostlock_profile.py dump profile.bin
```

> ⚠ 用 `.conf` 现场生成时，multicast 路由会得到 `consumer.max_calls = 0`（上面那条坑）。
> 生成后请确认 `execution.consumer.max_calls >= 1`。

## 7. 已知限制

- **只对匹配的内核 release 有效**：本仓库的 `ghostlock.bin` 对应
  `5.15.197-g708015331567-dirty`（iQOO Neo9 / OriginOS 16.2.13.2）。脚本会校验。
- **概率事件**：不是每次都能中；失败表现为内核 panic → 自动重启恢复（数据不丢），
  所以脚本是"多轮 + 窗口内连刷"。作者经验：连续很多次不中时，恢复出厂设置能恢复命中率。
- **临时 root**：`late-load` 只在内存里，硬重启失效；软重启后 vrpatch 的补丁仍在。
- **不改系统分区**：全程只有内核内存写 + `cred` 替换 + `ksud insmod/late-load`，
  以及 `$HOME`（`/data/local/tmp/ghostlock-app`）和 `/sys/fs/selinux/*` 的读写；
  `safe_mode=0` 所以也不动 `/data/adb/modules`。
- **SELinux 最后是 Enforcing**（不是 permissive）：靠 policy fixup + `ksu` 域拿的 root。

## 8. 目录

```
reroot.sh                          主脚本（脚本 + 一个二进制）
ghostlock.bin                      payload 包
QUICKSTART.md                      最短用法
docs/PORTING.md                    PC 化全过程：协议/格式的字节级证据、实战记录、与作者帖子核对
docs/ANALYSIS.md                   GhostLock v1.2 APK 的静态分析（漏洞链、vrpatch.ko 反汇编）
docs/root-script.sh.tmpl           从 libghostlock.so 里整段抽出的 root 脚本模板（7349 B）
scripts/mkpack.py                  打/看 payload 包
scripts/ghostlock_profile.py       .conf → native 二进制 profile blob（白名单校验）
scripts/ghostlock_pc.py            完整 python 驱动（调参/取证用，含 check/run/status 等）
scripts/README.md                  脚本层说明
evidence/profile.bin               真机打通过的那份 2058 B blob
evidence/ksu-*.log                 成功那轮的 root 脚本日志（policy fixup → vrpatch → late-load）
evidence/native-*.log              成功那轮的 native 日志（boot_ms=40663 起）
```

## 9. 安全与授权

- 仅用于**你自己持有并授权的设备**；它做的是内核提权，等同于本机最高权限，风险自负。
- 不修改系统分区、不刷机、不写 boot；失败时依赖设备自身的 panic→重启恢复。
- 本仓库**不分发** GhostLock APK 或其解包结果（`classes.dex`、`assets/`、`libextract.so` 等），
  只分发我写的脚本/文档，以及为方便复现而打包的必需二进制（见 NOTICE）。
- 上游项目/作者已在公开渠道发布过这套 exploit 与工具链；这里的工作是**工程化的 PC 侧驱动 +
  可复现的记录**，不包含新的漏洞细节。

## 10. 致谢

- **@图灵和冯诺依曼老祖保佑我** — 酷安《vivo iQOO Neo9 (PD2338) Root 研究》，本项目的窗口、
  `vrpatch` 处理方式、KSU late-load 路线都以其结论为准，并逐条与实测对齐。
- **YuKongA/ghostlock-app** — GhostLock 上游（本 APK 是 linux-tools 的 iQOO Neo9 定制 fork）。
- **x-spy / CVE-2026-43499-popsicle** — futex-PI 竞态原语。
- **NebuSec / CyberMeowfia** — 相关工具与方法。
- **KernelSU / ReSukiSU** — 内核模块与管理器（本机管理器为 `com.resukisu.resukisu`）。

## 11. NOTICE

`ghostlock.bin` 内嵌的 `libghostlock.so` 与 `vrpatch.ko` 来自上述上游项目（随 GhostLock v1.2
APK 分发），版权归原作者；本仓库仅为在同一设备上复现而原样打包，未做修改。本仓库自身写的脚本与
文档（`reroot.sh`、`scripts/*`、`docs/*`、`README.md`）可按 MIT 使用。

如果你要把它推成 public，请自行确认上游许可证与当地法规；默认建议保持 private。
