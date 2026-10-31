# iQOO Neo9 一键临时 root（PC 版 · Go 单文件）

把原本要在手机上跑的 root App，改成电脑上用 `adb` 驱动的**一个可执行文件**：
**手机插上电脑 → 跑它 → 拿到临时 root**。

- 不解 BL 锁、不刷机、不写系统分区（系统分区保持 erofs + dm-verity green）
- root 只在内存里：**重启就没了**，要用就再跑一次
- 原理：CVE-2026-43499（GhostLock / futex-PI 竞态），把提权时点卡在手机刚开机的那几十秒
- payload 与 71 份内核 profile 全部内嵌在二进制里，目标机器只需要 `adb`

> **只支持这一种机型/系统**（会自检 `uname -r`，不匹配直接拒绝）：
> vivo **iQOO Neo9（PD2338）** · OriginOS 6 · 内核 **`5.15.197-g708015331567-dirty`**

---

## 一、手机侧准备

1. USB 数据线连电脑，**USB 调试**打开并授权这台电脑
2. 开发者选项 → **停止限制子进程** 关掉
3. **去掉锁屏**（指纹/密码/图案）
4. 默认 USB 配置 = **文件传输**

## 二、电脑侧

从 release 下载对应平台的二进制，或自己 `make` 编译。只需要 `adb` 在 PATH 里。

```bash
chmod +x ghostlock
./ghostlock
```

无参数就是菜单：

```
  1) 一键 root（循环重试，脱手）      <- 推荐
  2) 打一次（调试，失败会重启）
  3) 体检（只读）
  4) 选 ko / 装管理器
  5) 清理设备残留
  0) 退出
```

按 `1` 再一路回车即可。成功时：

```
[+] 成功：root 已在（KernelSU late-load）
    用法: adb shell su -c id
```

之后 `adb shell su -c 'id'` → `uid=0(root) context=u:r:ksu:s0`。

## 三、命令行（不用菜单时）

```bash
ghostlock doctor                      # 只读体检：设备/内核/profile/SELinux/管理器
ghostlock run --loop                  # 脱手循环
ghostlock run --loop --clean-after    # 成功即清理设备痕迹
ghostlock run --dry-run               # 只打印将要执行的命令，不碰设备

ghostlock manager install [apk]       # 安装/升级 KSU 管理器（路径可省略）
ghostlock manager list                # 已装的管理器及版本
ghostlock manager remove <pkg>        # 清掉残留的旧管理器

ghostlock ko add|list|check|pick      # 管理本地 ko
ghostlock profile list|show|compile   # 内核 profile
```

常用参数：`--rounds`（轮数，默认 10）、`--window`（uptime 上沿，默认 90s）、
`--per-boot`（同一开机窗口内连发次数，默认 6）、`--reboot-first`（先重启抢窗口）、
`--ko <file>`（用指定的 ko）、`--conf <file>`（用自定义 profile）。

## 四、它做了什么

一次运行分三段，**只有第一段和机型/系统有关**：

1. **提权**：把内嵌的 exploit（`libghostlock.so` 改名成 `ghostlock`）推上去，
   按内核 profile 里的偏移/路由去打 futex-PI 竞态，先把当前进程的 cred 换成 root
2. **落地 root**：拿到临时 root 后，一段 root 脚本改 SELinux policy → 载入 `vrpatch.ko`
   （中和 vivo 的 vr 守卫）→ 用管理器自带的 `ksud` 做 `late-load`，把内核模块装进内存
3. **交棒**：之后的 `su` 由你装的 KSU 管理器接管

全程不碰磁盘上的系统分区。

## 五、实现要点

### 三层解耦

| 层 | 来自 | 什么时候换 |
|---|---|---|
| exploit payload | GhostLock APK 里的 `libghostlock.so` / `vrpatch.ko` | 上游出修复/新版本时 |
| kernel profile | 71 份 `.conf`（内核偏移、路由、调优） | **只有 `uname -r` 变了才换** |
| KSU 管理器 | 你自己装的 APK | 想升级 KSU 时 |

换 KSU 版本不影响提权成功率——内核模块是提权**成功之后**才加载的。

### profile blob

原生程序不读文本 conf，只吃一个二进制 blob（`--load-prebuilt-profile`）。格式：

```
u32 magic 0x0D000721 | u16 version=2 | u16 frontend | u16 backend | u16 route
u16 releaseLen | u16 0 | release bytes | u16 sectionCount
  每段: u8 nameLen + name + u32 entryCount
    每项: u8 keyLen + key + i64 value
```

段名固定 12 组（`meta` / `task_struct` / `cred` / `offset` / `kernel` /
`execution.*` / `route.<路由>`）。编码器逐字段对齐原 App 的实现，并有单测锁住
每个字段值；`profile compile/show` 可以自己看。

### 成功判据是问内核，不是看日志

exploit 的 root 脚本是它 fork 出去的后台进程，日志往往晚于进程退出几秒才写完。
所以判定用 `/proc/modules` 里有没有 `kernelsu`、或者 `su -c id` 通不通，
重启前还会再复核一次——不会把已经拿到的 root 重启掉。

### 循环节奏

- 只在开机后的一个窗口内发射（uptime 越小越容易中，超过窗口就等下次）
- 一次失败通常会让内核 panic 并自动重启，**这时等它自己起来**，不要手动重启
  （手动重启后 adb 恢复太快，容易打在还没稳定的时刻）
- 干净失败（没 panic）才需要主动重启一次

### 管理器识别不靠包名

官方 SukiSU 的 spoofed 构建**每次换随机包名**（如 `rqglxo.qzizju.uholjr`），
而且会把 `libksud.so` 改名成随机库名。所以工具：

- 直接解析 APK 的 binary `AndroidManifest.xml` 读包名，记住并写进设备的 `.gl_ksu_pkg`
- 按**内容**找 ksud（哪个 aarch64 PIE 里带 `<kmi>_kernelsu.ko` 表），推到 `/data/local/tmp/ksud`

## 六、KSU 管理器与 ko

```bash
ghostlock manager install            # 自动在 二进制同目录 / 当前目录 / ~/Downloads 里找 APK
ghostlock manager install /path/x.apk
ghostlock manager list               # 看有几个、各自版本、哪个在用
```

升级只做这一件事。~late-load~ 用的内核模块来自 **ksud 内嵌的 asset**，
而 ksud 来自你装的那个 APK，所以换 APK 就等于换内核模块。

**ko 文件能自己指定吗？** 可以选（`ghostlock ko pick` + `--ko`），但要说清：

- `ksud insmod` 走内核模块加载器，GKI 会**严格校验 vermagic**，版本不一致直接拒
- `late-load` 是手动重定位，绕过该校验，但它只吃 ksud 内嵌的 asset，不吃路径
- 所以自己下载的 `lkm-*.ko` 实际生效的场合有限，工具会如实报告成功与否

## 七、清理

```bash
ghostlock run --loop --clean-after     # 成功即清
ghostlock manager remove <pkg>         # 清残留的旧管理器
```

清掉的是设备上的 staging 目录（payload、profile、日志、脚本）和 `/data/local/tmp/ksud`。
KSU 已经在内核内存里，清理不影响 root 本身。

## 八、风险

- **失败会让手机 panic 重启**，这是该漏洞的正常失败形态；重启后可继续重试
- **命中率不是 100%**：实测几轮内会中，也可能连续多轮不中；连续失败很多次后
  建议冷启动一次再跑
- **root 只在内存**，硬重启即失效，需要重新跑
- 会临时把 SELinux 置 permissive 并加载两个内核模块（`kernelsu` / `vrpatch`）
- 设备上会留下 `/data/local/tmp/ghostlock` 与 `/data/local/tmp/ksud`，可用上面的清理命令删掉
- 第三方管理器 APK 请自行确认来源；本项目不附带 APK

### Windows 上双击闪一下就没了？

多半是**没装 adb**（或 adb 没进 PATH）。旧版会直接打印错误然后退出，双击的窗口
来不及看见就关了。现在不会：

- 菜单顶部会写「**没找到 adb —— 按 6 指定 platform-tools 路径**」
- 按 `6` 填 platform-tools 目录（如 `C:\platform-tools`），会自动记住
- 也可以命令行直接给：`ghostlock doctor --adb "C:\platform-tools"`
- 出错时窗口会停住并提示「按回车退出」，不会再一闪而过

adb 的查找顺序：`--adb` → 环境变量 `GHOSTLOCK_ADB` → 记住的路径 → PATH。

## 九、偏移值是怎么算出来的

profile 里的数字不是猜的，全部来自**内核镜像本身**（工具 `ghostlock-extract` 就干这个）：

| 字段 | 来源 | 算法 |
|---|---|---|
| offset.init_task / init_cred / selinux_enforcing / security_hook_heads / slide_* | **kallsyms** | 符号虚拟地址 − `_text` 基址 |
| task_struct.* / cred.* | **BTF**（内核自带类型信息） | 结构体成员偏移 |
| cred.caps_value / usage_value / ref*_image | init_cred 的实际内容 | 读镜像里 init_cred 的字段值 |
| kernel_phys_load | 内核映像加载地址 | SM8550 = 0xA8000000（或由 `_text` 反推） |
| kernel_phys_offset | `/proc/iomem` 的 System RAM 起始 | 0x80000000 |
| route.*.waiter_shift | **BTF + 反汇编** | 从 `pselect` / `futex` 的 `add x, sp, #imm` 提取栈上 waiter 位移 |
| route.*.task_offset / lock_offset | BTF | `rt_mutex_waiter` 的成员偏移 |

自检对得上：conf 里 `init_task = 49493248`（0x2F33500），加上 KASLR 后的
`_text`（0xffffff8028000000）正是运行日志里的 `init_task=ffffff802af33500`。

换内核时用 `ghostlock-extract boot.img --format conf --out new.conf` 重新生成，
再用 `ghostlock run --conf new.conf` 试。

## 十、两种 payload（26.1 / v1.2）

| 模式 | 用哪个 | 是否 insmod `vrpatch.ko` | 特点 |
|---|---|---|---|
| `native` | 26.1 的 `libghostlock.so`（685 KB） | 否 | vr 守卫在 exploit 内部处理，少一个环节 |
| `vrpatch` | v1.2 的（474 KB） | 是 | 旧流程：fixup → `ksud insmod vrpatch.ko` → late-load |
| `auto`（默认） | 交替 | 交替 | 同一次开机内奇数次 native、偶数次 vrpatch |

两种 payload 的**失败形态不同**，同一个 uptime 窗口内交替能覆盖更多情况。
这也解释了外部二改版为什么"2~3 轮就中"：它每次开机最多打 6 次，而不是 1 次。

## 十一、常见问题

| 现象 | 原因 | 处理 |
|---|---|---|
| `profile release mismatch` | conf 与设备 `uname -r` 不一致 | 换对应 profile，或用 `profile show` 核对 |
| `credential copy profile is incomplete` | profile 的 cred 段没解出来 | `profile show` 看 `cred.copy_size` 是否为 0 |
| `multicast geometry incomplete` | 5.15 路由缺 `waiter_off` | 检查 conf 的 `route` 段 |
| 一直 `native exit=1`（干净退出） | 写原语没生效，通常是 profile 不对 | 用内置已验证 profile，或核对 `--conf` |
| 一轮都打不中 | 命中率问题 | 多跑几轮；冷启动后再试 |
| 管理器显示"未安装/需要更新管理器" | 管理器与内核模块版本不匹配 | `manager list` 看版本，`manager install` 换匹配的 APK |
| `su` 不存在 | late-load 没成功 | 看 `/data/local/tmp/ghostlock/ksu-*.log` |
| Windows 双击窗口秒关 | 没好 adb，或旧版直接退出 | 见上面「双击闪一下就没了」 |
| `--adb 指定的路径无效` | 路径既不是 adb 也不是 platform-tools 目录 | 填目录或 adb.exe 完整路径 |

## 十二、来源与免责

- exploit 来自 GhostLock（CVE-2026-43499）作者发布的 APK，本项目只做 PC 侧驱动与 profile 编解码
- KSU 内核模块与管理器来自 SukiSU Ultra 上游
- 仅在你自己的设备上使用；刷机/提权有变砖与数据丢失风险，自负

## 目录

```
cmd/ghostlock/      CLI 入口、菜单、子命令
internal/profile/   HOCON 解析 + profile blob 编解码（对齐 App 的 ea1.java / native 的 sub_67DBC）
internal/stage/     设备探测、payload 下发、ksud wrapper、清理
internal/run/       单次执行与脱手循环
internal/manager/   APK 解析（包名/内嵌 ko/改名 ksud）、安装
internal/ko/        ko 校验（vermagic / KMI）
internal/assets/    内嵌 payload 与 71 份 profile
```

构建：`make`（linux/amd64）、`make win`、`make mac`、`make arm64`、`make test`
