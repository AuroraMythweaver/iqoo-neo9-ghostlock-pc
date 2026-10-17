# GhostLock v1.2 (iQOO Neo9 定制版) 静态分析报告

> 注：本文是 APK 静态分析记录，`apkout/`、`java/`、`x/` 等本地解包目录未随仓库分发。
> 原作者（酷安）：<https://www.coolapk.com/U/43561117> ·《vivo iQOO Neo9 (PD2338) Root 研究》
> 上游项目：YuKongA/ghostlock-app · 本文只做静态分析记录，专用于 iQOO Neo9 + OriginOS 6 特化版。

分析对象：`GhostLock-v1.2-IQOO-Neo9(545)-arm64.apk`
sha256 = 9c85bd85cfe08db4891548574684256dbc33f751f392b4cfb2691d2226600a56
包名 / 版本：com.ghostlock.app，versionName 1.2-IQOO-Neo9，versionCode 545，minSdk 31 / targetSdk 37
初版为纯静态分析；**2026-10-18 已在本机（PD2338 / 5.15.197-g708015331567-dirty）真机执行并提权成功**，
动态结果与复现方式见 [`ghostlock-pc-port.md`](ghostlock-pc-port.md) §8–§9。

## 结论

一个"一键内核提权（root）"App，围绕 **CVE-2026-43499（"GhostLock"，rtmutex / futex-PI 栈上 waiter 释放后使用）** 实现：

1. 用内核竞态在原进程内拿到**临时 root**（uid 0 + 全 capability，SELinux 关掉，seccomp 清掉）；
2. 加载 `vrpatch.ko`，把厂商 root 检测内核模块 **vr.ko** 的检测函数改成"永远返回 0"；
3. 借用设备上已安装的 KernelSU 系管理器自带的 `ksud`，`late-load` 内核模块，得到**持久 root**。

App 本身是一个 GUI 外壳（Jetpack Compose / miuix），真正的攻击逻辑在 native 里。

## 组成

| 成员 | 大小 | 作用 |
|---|---|---|
| classes.dex | 2.9 MB | Compose UI、profile 解析/校验、Shizuku UserService、OTA/boot.img 解析入口 |
| lib/arm64-v8a/libghostlock.so | 485 KB | 漏洞利用主程序（CLI），链条编排 |
| lib/arm64-v8a/libextract.so | 2.2 MB | Rust 离线提取器：boot.img / payload.bin / OTA → 解 LZ4/gzip/zstd → 恢复 kallsyms + BTF → 生成 kernel profile，并判断漏洞原语是否存在 |
| assets/modules/vrpatch.ko | 249 KB | 反 root 检测内核模块（带 debug_info，未 strip） |
| assets/kernel_profiles/*.conf | 60+ | 按内核 release 精确匹配的 HOCON 配置：task_struct/cred 偏移、内核符号偏移、KASLR 锚点、路由几何、竞速调参 |

## 漏洞利用链路（来自 libghostlock.so 的日志字符串）

```
usage: ghostlock [--ghostlock-app-call | --load-prebuilt-profile <bin>]
                 [--dump-kernel-log <dir>] [--force-attack] [--enable-status-record]
```

1. **环境探测**：uid/euid、`/proc/self/status` 的 Seccomp、`/proc/self/attr/current`、SELinux enforce、CLOCK_BOOTTIME。
2. **KernelSnitch**：futex 哈希碰撞扫描 + heap spray（memfd）+ `perf_event_open` mmap 泄漏，得到 `mm_struct` 与内核地址，绕过 KASLR（`slide_nfulnl_logger` / `slide_boot_id` 作锚点），并据 `/proc/iomem` 缓存 direct-map 几何与 `kernel_phys_load`。
3. **竞速路由（三选一 + 回退）**：`pselect`（select_stack，waiter 在栈上，shift 可为负）、`tcp_zerocopy`、`multicast_waiter`。伪造 `rt_mutex_waiter`（`fake_lock` / `fake_w0` / `fake_task`），用 `FUTEX_CMP_REQUEUE_PI` 触发 UAF 的 waiter 被重用 → **任意地址写**；日志里是 `[route] CMP_REQUEUE_PI ret=... step=... success=...`。
4. **W1**：写 `selinux_state.enforcing = 0`（W1 编号在日志里写作 `W1: SELinux`）。
5. **W2**：把当前 task 的 `cred`/`real_cred` 换成 `init_cred` 的拷贝（5.x copy_size=176 / 6.x=136，caps 偏移 48，caps 值 -1 或 0x1ffffffffff），并修补引用计数与 PI 现场（`W2: cred`、`child is root!`、`child uid = 0`）。
6. **W3**：清 `TIF_SECCOMP`（`W3: TIF_SECCOMP`），fork 出无 seccomp 过滤器的子进程，否则 `finit_module` 被拦（`child seccomp fully bypassed`）。
7. **交接**：写 root 脚本并在 root 子进程里 `exec` 之（`handoff: root script path=...`）。

## 提权后 root 脚本做了什么（从字符串还原）

`/data/local/tmp/ghostlock-app/.ghostlock_root.sh`：

- 记录 `id -u`、seccomp、`uname -r`、`/proc/modules`、dmesg、pstore 等（可选 dump 到用户选定的目录）；
- `echo 0 > /sys/fs/selinux/checkreqprot`；
- **SELinux policy 修补**：读 `/sys/fs/selinux/policy`，校验 header，把 offset 23 的 config 字节 `|= 0xC0` 后 `load_policy`，最多重试 10 次，用 `/sys/fs/selinux/status` 的 policycap 计数确认生效；
- **调试终端**：轮询 `$HOME/.gl_cmd`，用 `echo -n u:r:shell:s0 > /proc/self/attr/exec` 切到 shell 域再执行，输出写 `.gl_out`；
- 缓存一次 `/proc/iomem` 到 `.ghostlock_iomem` 供下次用；
- **safe mode**（可选）：给 `/data/adb/modules/*/` 放 `disable` 文件，禁用所有 Magisk/KSU 模块；
- **先 vrpatch**：`ksud insmod vrpatch.ko`；`KSU_ENFORCE=9` 时到此为止（只保留临时 root）；
- **再激活 KernelSU**：`ksud late-load --allow-shell --package-name <管理器包名> --kmi <kmi>`，轮询 `/proc/modules` 50×100ms 确认 `kernelsu` 出现；失败则报 `KernelSU module not loaded`；
- `KSU_ENFORCE=0` 时最后 `echo 0 > /sys/fs/selinux/enforce`（转 permissive）。

管理器包名候选写死在脚本里：me.weishu.kernelsu(.pr)、com.rifsxd.ksunext、com.suki.sukisu、com.resukisu.resukisu、com.kowx712.supermanager、com.sevenk.core(.pr)；找不到就退回 `/data/local/tmp/ksud`、`/data/adb/ksu/bin/ksud`。

## vrpatch.ko 反汇编（实证）

```
init_module:
  find_module("vr")                      ; 找不到 -> printk, 返回 -ENOENT
  x19 = mod->mem[0].base   (offset 0x180) ; MOD_TEXT
  w2  = mod->mem[0].size   (offset 0x188)
  base==0 || size==0 -> printk "layout invalid", 返回 -EINVAL
  target = base + 0x2ecc
  set_memory_rw(target, 1 page)
  *(u64*)target = 0xd65f03c052800000     ; = mov w0, #0 ; ret
  caches_clean_inval_pou(target, target+8)
  kick_all_cpus_sync()
  set_memory_ro(target, 1 page)
  printk "vr base=0x%lx size=%zu detect=0x%lx" / "vr.ko root-detect neutralized (0x%lx)"
```

- 语义：把 vr.ko 里位于 text+0x2ecc 的检测函数**首条指令改成 `mov w0,#0; ret`**，即"恒返回 false / 未检测到 root"，然后刷 icache 并让所有 CPU 同步。
- modinfo：`license=GPL`、`description=neutralize vr.ko root detection (soft-reboot compat)`、`vermagic=5.15.202-android13 ... aarch64`。
- DWARF 里源码路径：`/home/dengxiang/VIVO-IQOO-Neo9-Root-Tools/ksu-root/test-modules/vrpatch-kmi/vrpatch.c`，comp_dir `/home/dengxiang/ddk/kdir/android13-5.15`。模块只做一次 patch，`cleanup_module` 仅打印 "exit (leave vr.ko neutralized)"，即卸载后不回滚。
- offset 0x2ecc 是写死的，只对特定 vr.ko 二进制有效；不是按符号解析。

native 侧还有第二层针对 vr.ko 的处理：

- `VR: flags+tagA` / `VR: tagB`（`GHOSTLOCK_VR_TAG_B` 可覆盖 offset）/ `VR.ko per-task tags cleared`：直接清掉 vr.ko 给 task 打的标记位，避免已 root 的子进程在 W2 校验阶段被杀；
- `vr guard: neutralizing __tracepoint_sys_exit.funcs image=... target=... width=u`：用同一任意写原语改 `__tracepoint_sys_exit` 的 funcs（回调数组），让 vr.ko 挂在 sys_exit 上的钩子对所有任务失效（全局中和，而不是单任务）。

## 权限与网络

- 权限：仅 `INTERNET` + Shizuku API（`moe.shizuku.manager.permission.API_V23`）+ 一个 signature 级动态广播权限；queries 里列的全是 root 管理器包名。
- 网络用途：用户在"解析 OTA 链接"里粘贴 zip URL 时，按 `Range: bytes=` 分段下载镜像再本地解析（libextract）。native 里没有 getaddrinfo/域名，没有把设备信息上传的证据。
- 关键点不是网络，而是它在本机做的事：任意内核写、替换 cred、关 SELinux、清 seccomp、insmod 任意 .ko、加载 KernelSU。

## 风险与判断

- **能力等价于本地提权恶意软件**：同样的链路由恶意作者使用即为"零交互 root"；此处只在用户主动点 Run + 授权 Shizuku 后执行。
- **只对匹配的内核 release 有效**：`kernel_profiles/index.conf` 里每个 release 一份精确 offset；不匹配会失败（或按错误 offset 写内核 → panic / 自动重启，模块描述里的 "soft-reboot compat" 与脚本里的 pstore/dmesg dump 都指向这一点）。
- **vrpatch 依赖精确二进制布局**：vr.ko 版本不符时是 -EINVAL 而不是崩溃（有 layout 校验），但 patch 点写死意味着一份 .ko 只对应一类设备。
- **持久化**：最终落地的是 KernelSU 内核模块 + 可能的 `/data/adb` 改动；safe mode 会动 `/data/adb/modules/*`。
- 来源：credits 页与字符串指向开源项目 YuKongA/ghostlock-app（本包为 linux-tools 的 iQOO Neo9 定制 fork），并致谢 x-spy/CVE-2026-43499-popsicle、NebuSec/CyberMeowfia。APK 仅有 v2/v3 签名块，无 v1 JAR 签名。

## 未确定项

- vr.ko 的厂商归属：静态推断 + 作者帖子（`vr 45056 [permanent] Live`，查 `euid==0` 且不在
  `u:r:vrp:s0` 即 SIGABRT）互相印证，**已可确证为 vivo 反 root 模块**。
- 漏洞机理（rtmutex/futex-PI 栈上 waiter UAF）来自项目 credits 与外部公开资料，未在本机做动态验证；本报告只对 APK 内证据负责。
- ~~未执行任何 exploit，未验证某台设备是否实际可利用~~ → **已执行并成功**：`su -c id` 返回
  `uid=0(root) context=u:r:ksu:s0`，`/proc/modules` 含 `kernelsu`，SELinux 保持 Enforcing；
  W1/W1b、W2（含 `W2b: firing prebuilt init_cred+8 repair`）、handoff 均在日志中实证。
  见 `evidence/ksu-1792264567-6-1.log`、`evidence/native-1792264567-6-1.log`。

---

## 补充（PC 化复现，见 `ghostlock-pc-port.md`）

- `libghostlock.so` 已验证是 PIE 可执行文件（`INTERP=/system/bin/linker64`，entry `0x2bb30`），
  App 只是调用方；`adb shell`（uid 2000 + 无 seccomp）可原样替代 Shizuku UserService 那层。
- profile blob 格式已在 native `0x67dbc` 处逐指令确认：magic `0x0D000721` @0、
  version 2 @4、flag_a/flag_b @6/@8、route_id @0xa、release_len @0xc（native 限 ≤255）、
  保留 u16 @0xe、release @0x10，其后 u16 组数 + `u8 name/u32 count/u8 key/i64 value` 记录。
- native 只接受 15 个固定组名（表在 `0x76608`，含每组 key 白名单）加上当前 route 对应的
  `route.*` 组；`route.multicast_waiter` 组**没有** `compact_waiter` 键（只有 `kernel` 组和
  `route.select_stack` 组有），所以 `5.15.197-...conf` 里 route 块内写的 `compact_waiter = 1`
  在 App 路径里不会传给 native。
- **真机实测补充**：multicast 路由下 `execution.consumer.max_calls = 0` 会让 consumer 一次
  都不触发（日志 `calls=0 success=0`，路由 128 次空转）——这份 conf 单独拿去用必须要
  `≥1`；实战用的是设备上那份 2058 B blob（`1/1` + `compact_waiter=1` + `vr_sys_exit_tp`）。
- **命中是开机窗口竞争**：历史日志 `boot_ms` 与结果强相关（14 s / 41 s 能过 W1；>60 s 全部
  `Write 1 failed`；12 min~22 h 必挂），失败表现为 panic 自动重启。
- 产物：`reroot.sh` + `ghostlock.bin`（**两个文件带走**：重启→抢窗口→盯 ksu 日志→命中即停）、
  `scripts/ghostlock_profile.py`（.conf → blob，带 native 白名单校验）、
  `scripts/ghostlock_pc.py`（adb 驱动：check/setup/run/status/exec/pull-log）、
  `evidence/`（成功那轮的 native/root 脚本日志 + 那份 2058 B blob）。
