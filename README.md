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

## 原作者与来源（先看这个）

| 项目 | 内容 |
|---|---|
| **原作者（酷安主页）** | <https://www.coolapk.com/U/43561117> |
| **原文** | 《vivo iQOO Neo9 (PD2338) Root 研究》 <https://www.coolapk.com/feed/74180094> |
| **GhostLock 原项目** | [YuKongA/ghostlock-app](https://github.com/YuKongA/ghostlock-app)（本 APK 为其 iQOO Neo9 定制 fork：`GhostLock-v1.2-IQOO-Neo9(545)-arm64.apk`） |
| **原语 / 工具致谢** | x-spy / [CVE-2026-43499-popsicle](https://github.com/x-spy/CVE-2026-43499-popsicle)、NebuSec / CyberMeowfia；管理器 KernelSU / ReSukiSU |
| **本仓库做了什么** | 只做 **PC 侧驱动器 + 打包 + 可复现记录**；漏洞利用本体、内核偏移、`vr.ko` 处理方案**全部来自原作者与原项目** |

> 本项目的窗口判定、`vrpatch` 用法、KSU late-load 路线均以原作者文章为准，并逐条与真机实测对齐
> （见 [`docs/PORTING.md`](docs/PORTING.md) §9 的对照表）。**请先去原作者主页看原文。**

## 适用机型：iQOO Neo9 · OriginOS 6（橘子 6）**特化版**

本仓库的 `ghostlock.bin` 是**专用于**下面这套组合的特化版，不是通用包：

| 项 | 值 |
|---|---|
| 机型 | vivo iQOO Neo9（PD2338 / V2338A，骁龙 8 Gen 2 / SM8550） |
| 系统 | **OriginOS 6（"橘子 6"）**，16.2.13.2 |
| 内核 | **`5.15.197-g708015331567-dirty`** |
| APK 依据 | `GhostLock-v1.2-IQOO-Neo9(545)-arm64.apk`（linux-tools 定制 fork） |
| 利用漏洞 | CVE-2026-43499（rtmutex / futex-PI 竞态，即 GhostLock） |

profile 里的 `task_struct` / `cred` / 内核符号偏移 / 路由几何 / 时序，都是按**这颗内核**实测标定的。
换机型、换 OriginOS 版本（哪怕同样是 5.15）**都不要直接套用** —— offset 不匹配会 panic
（设备一般能自行重启恢复，但别拿它去试别的机器）。脚本运行前会自动比对 `uname -r`，不一致直接拒绝。

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

### 相比原 APK（走 Shizuku）的优势

| 维度 | 原 APK（App + Shizuku UserService） | 本项目（adb 驱动） |
|---|---|---|
| 执行进程归属 | 应用相关进程/会话，受 app-freeze、LMK、省电策略影响 | `adb shell`（uid 2000 / `Seccomp: 0` / `u:r:shell:s0`）+ `setsid` 脱离，**不在应用 cgroup** |
| 进程被回收 | 跑到一半被系统杀掉是常态——这正是"成功率低"的主因之一 | PC 断开也不影响；只要设备不重启就一直跑 |
| 进入窗口的时间 | 要等系统起完 → 手动开 App → Shizuku 服务就绪，通常更晚 | `adb shell` 实测 **11.8 s** 就能用（窗口 12~45 s，越早越好） |
| 重试 | 每次失败要人再点一次；panic 重启后还得重新开 App | 自动：重启 → 等 adb → 立刻发射 → 窗口内连刷 6 次 → 多轮循环 |
| 依赖 | 装 APK + 装 Shizuku + 逐次授权 | 只要 `adb` + `bash`（**零 python 依赖**） |
| 参数与复现 | 参数在 App 的 SharedPreferences / assets 里，改靠 UI | profile 是文件，可 diff / 校验 / 打包；`GHOSTLOCK_*` env 可调绑核等 |
| 日志与取证 | UI 里滚动，事后难取 | 每轮 `native-<id>.log` + `ksu-<id>.log` 落盘，可 `adb pull` 回传 |
| 对设备的影响 | 安装 App、产生应用数据 | 不装任何 App；payload 只在 `/data/local/tmp/ghostlock-app`，删目录即清 |
| 可审计 | 原生库 + dex 黑盒 | 驱动脚本 100 行 bash 可读；只有 exploit 本体是二进制 |

**一句话**：同一个 exploit，换了个"不会被杀、能抢更早、能自动重试、还能留下证据"的宿主。

> 也不是全赢：**APK 更"傻瓜"**（一键、不需要电脑）。只用一次的话 APK 更省事；
> 要成功率、要反复刷、要事后对日志，这套更合适。

## 前置条件（手机侧，先做这一步）

实测能稳定进窗口的配置。这些开关不是"可选优化"，在 vivo/OriginOS 上基本是必要的：

| 步骤 | 怎么设 | 为什么需要 |
|---|---|---|
| **USB 数据线连电脑** | 用能传数据的线（别用"仅充电"线）；`adb devices` 能看到 `device` | 整套方案靠 `adb shell` 执行；无线调试在开机早期通常还没就绪 |
| **开发者选项 → USB 调试** | 打开，弹窗勾"始终允许这台电脑" | `adb shell` 是执行载体（uid 2000、无 seccomp 过滤） |
| **开发者选项 → 停止限制子进程**（后台进程限制设"标准"） | 打开 | 防止系统在窗口期回收/冻结我们的 shell 子进程 |
| **去掉锁屏密码** | 设置 → 安全 → 关闭锁屏密码 | 开机后 `/data` 立即解密，`/data/local/tmp` 才能早早可用 |
| **去掉所有锁屏**（含"卡屏即进入系统"／直接进桌面） | 设置 → 锁屏与密码 → 关闭全部锁屏 | 少一层等待，抢到更早的窗口 |
| **USB 默认用途 = 文件传输（MTP）** | 开发者选项 → 默认 USB 配置 → 文件传输 | 避免早期 adb 传输不稳 / 反复重新授权 |
| （建议）屏幕常亮、关省电模式 | 开发者选项 → 不锁定屏幕；或手动亮屏 | 息屏会降频，竞态更难中 |

补充：

- **不需要**装 GhostLock App、**不需要** Shizuku、**不需要**先有 root（本来就是在拿 root）。
- 如果之前装过 GhostLock App，**先别打开**：两套驱动同时跑会互相抢同一批内核对象。
- 电脑侧：Linux / macOS / WSL 均可，只要有 `adb` 与 `bash`（脚本不依赖 python）。
- 成功之后**别重启**（见 §7 已知限制）。

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

## 9. 安全边界

- 只做**内核内存写 + cred 替换 + `ksud insmod` / `late-load`**；不刷机、不改 boot、不写系统分区
  （系统分区保持 erofs + dm-verity green）。
- 文件系统层面只碰 `$HOME`（`/data/local/tmp/ghostlock-app`）、`/sys/fs/selinux/*`；
  `safe_mode=0`，所以也不动 `/data/adb/modules`。
- 失败表现为内核 panic → 设备自行重启恢复（数据不丢），脚本会等它回来继续。
- **临时 root**：`late-load` 只在内存里，硬重启即失效；软重启后 `vrpatch` 的文本补丁仍在。
- 收尾 SELinux 仍是 **Enforcing**（靠 policy fixup + `ksu` 域），不是关掉 SELinux。

## 10. 免责声明（Disclaimer）

1. **用途限定**：本项目仅供**个人学习、移动安全研究、自有设备维护**使用。使用者须确保对操作设备
   拥有完全所有权与明确授权。
2. **风险自担**：本工具执行**内核级提权**，可能导致设备重启/临时不稳定、数据丢失、保修失效、
   OTA 更新异常，以及被银行/支付/游戏等应用的完整性检测识别。请自行评估风险，操作前**备份重要数据**。
3. **无担保（AS-IS）**：本仓库按"现状"提供，不附带任何明示或暗示的担保，包括但不限于适销性、
   特定用途适用性、不侵权担保。作者与贡献者**不对**因使用或无法使用本项目导致的任何直接、间接、
   附带、特殊或后果性损害承担责任。
4. **禁止滥用**：严禁用于**未经授权的设备、他人设备、批量控制、绕过安全机制实施违法行为、
   游戏作弊/外挂、商业化分发**，或任何违反当地法律法规与中国大陆相关规定的用途。
   因滥用产生的一切法律责任与后果由使用者自行承担。
5. **第三方组件**：本仓库**不分发** GhostLock APK 及其解包产物；`ghostlock.bin` 内嵌的
   `libghostlock.so`、`vrpatch.ko` 版权归原作者/上游项目所有，此处仅为在同一设备上复现而**原样打包、
   未做修改**。本仓库自写的脚本与文档（`reroot.sh`、`scripts/*`、`docs/*`、`README.md`）可按 MIT 使用。
   若相关权利人认为不妥，请联系删除，会立即处理。
6. **接受条款**：使用、克隆、分发或以任何方式使用本项目，即视为你已阅读、理解并同意上述全部条款；
   若不同意，请立即停止使用并删除本仓库内容。

## 11. 致谢

- **@图灵和冯诺依曼老祖保佑我**（酷安 <https://www.coolapk.com/U/43561117>）—— 原文
  《vivo iQOO Neo9 (PD2338) Root 研究》是整个工作的基础。
- **YuKongA/ghostlock-app** —— GhostLock 上游（本 APK 是 linux-tools 的 iQOO Neo9 定制 fork）。
- **x-spy / CVE-2026-43499-popsicle** —— futex-PI 竞态原语。
- **NebuSec / CyberMeowfia** —— 相关工具与方法。
- **KernelSU / ReSukiSU** —— 内核模块与管理器（本机管理器为 `com.resukisu.resukisu`）。
