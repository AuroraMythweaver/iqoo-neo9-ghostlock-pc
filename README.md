# ghostlock-cli

vivo iQOO Neo9（PD2338 / 5.15.41 GKI / 未解 BL）的**电脑端命令行**提权工具。
一条命令跑完全流程，不需要 GUI、不需要装 App、不需要每次叫 AI 盯着。

```bash
make                     # 生成 ./bin/ghostlock（单一静态二进制，内嵌 payload）
./bin/ghostlock doctor   # 体检：设备 / 内核 profile / SELinux / KSU 管理器
./bin/ghostlock run      # 提权
```

---

## 0. 先说明：到底哪部分跑在手机上

| 部分 | 运行位置 | 说明 |
| --- | --- | --- |
| `ghostlock` 这个 CLI | **电脑** | 编排、profile 编译、adb 下发、日志解读 |
| `payload/ghostlock`（来自 APK 的 `libghostlock.so`） | 手机 `/data/local/tmp` | 内核漏洞利用本体。内核漏洞只能在内核所在的那台机器上执行，这一块没法搬到 PC |
| `payload/vrpatch.ko` | 手机（由 ksud insmod） | 中和 vivo 的 vr 守卫 |
| KSU 模块（kernelsu.ko / sukisu 的 ko） | 手机 | **不由本工具提供**，由你装的管理器 App 里的 ksud 自己取 |

也就是说：**没有任何东西常驻手机**，不装 App、不建服务、不写 `/data/adb`。
跑完以后接管 root 的是你自己装的 KSU 管理器，和以前一样。

---

## 1. 这个工具做了什么（逆向结论）

原版 GhostLock v1.2 的 APK 只有三样东西有用：一个原生利用程序、一个 ko、一堆内核 profile。
把 APK 拆开（`unzip` + `jadx`），真实结构是：

```
lib/arm64-v8a/libghostlock.so   484 KB  arm64 PIE，无 JNI 符号 —— 就是一个命令行程序
lib/arm64-v8a/libextract.so     2.2 MB  Rust 写的内核镜像 → profile 生成器（另一个命令行程序）
assets/modules/vrpatch.ko       249 KB  内核模块，中和 vivo vr 守卫
assets/kernel_profiles/*.conf    71 个  每个内核 build 一份的偏移/几何表（HOCON 文本）
classes.dex                     3 MB   Compose 壳 + Shizuku 客户端 + profile 编译器（Java）
```

**关键结论：GUI 只是壳。** 真正干活的 `libghostlock.so` 自带命令行接口，本来就能从 adb shell 直接跑，
而且 shell（uid 2000）没有 app 的 seccomp 过滤器，原生程序里明确有一条
`no app seccomp filter (adb/shell flow); skipping W3` 的分支 —— 也就是说
**从 adb 跑比从 App 跑还少一个失败点**。App 的 Shizuku UserService 做的唯一事情，
就是用 shell 身份把编译好的 profile 写进这个程序的 stdin。

### 1.1 原生程序的命令行契约（逆向自 `sub_5FBE8` = main）

```
ghostlock [--ghostlock-app-call | --load-prebuilt-profile <bin>]
          [--dump-kernel-log <dir>] [--force-attack] [--enable-status-record]
```

* `--ghostlock-app-call`：App 用。stdin 读 4 字节大端长度 + profile blob，配 `--enable-status-record`。
* `--load-prebuilt-profile <bin>`：**本工具用**。从文件读同一个 blob。
* `--dump-kernel-log <dir>`：结束时把 uname / /proc/modules / dmesg / /proc/iomem 落盘，失败排查用。
* `--force-attack`：如果 /proc/modules 里已经有 kernelsu，原生默认会跳过（"already has root"），这个开关强跑。

环境变量（逆向自原生字符串 + `m7.java` 的 `ProcessBuilder`）：

| 变量 | 含义 |
| --- | --- |
| `GHOSTLOCK_HOME` | 工作目录，root 脚本的 `HOME_DIR`，也会读 `.gl_ksu_pkg` / `.gl_kmi` |
| `TMPDIR` / `HOME` | 都指到同一个目录 |
| `GHOSTLOCK_KSU_LOG` | root 脚本日志（默认 `/data/local/tmp/.ghostlock_ksu.log`） |
| `GHOSTLOCK_VRPATCH_KO` | vrpatch.ko 路径，缺省则跳过 |
| `GHOSTLOCK_KSU_ENFORCE` | `0` = 完整流程（late-load + 最后置 permissive）；`9` = 只临时 root，不碰 KSU |
| `GHOSTLOCK_MAIN_CPU` / `GHOSTLOCK_CONSUMER_CPU` | 覆盖主/消费线程绑核 |
| `GHOSTLOCK_VR_TAG_B` / `GHOSTLOCK_KSU_APK` | 遗留字段，v1.2 里 root 脚本已不读 |

退出码：0 正常，1 致命，2 = 组件选择被拒。中途失败会走 `FatalError` 直接 `abort()`。

### 1.2 profile blob 格式（原版完全没文档，这里是唯一一份）

App 把 `.conf`（HOCON）编译成二进制塞给原生程序。编码器逆向自 `ea1.java`，
解析器逆向自原生的 `sub_67DBC`，两边完全对得上：

```
u32 magic       = 0x0D000721
u16 version     = 2
u16 frontend    = 1     (1 = root_child, 2 = umh_forward)
u16 backend     = 1     (1 = cve_2026_43499, 2 = cve_2026_64560)
u16 route       = 1..3  (1 tcp_zerocopy / 2 select_stack / 3 multicast_waiter)
u16 releaseLen
u16 reserved
bytes[releaseLen]       release 字符串（= uname -r，必须完全一致）
u16 sectionCount
  per section:  u8 nameLen, name, u32 entryCount
    per entry:  u8 keyLen, key, i64 value
```

段名固定为：`meta`、`task_struct`、`cred`、`offset`、`kernel`（可缺省）、
`execution.recommended_cpus`、`execution.heap`、`execution.race`、`execution.stages`、
`execution.handoff`、`execution.consumer`、`route.<route名>`。
原生会在加载后立刻做一串自检（`credential copy profile is incomplete`、
`multicast geometry incomplete`、`profile release mismatch` …），所以**错误 profile 会在真正下手前被挡下来**。

`ghostlock profile compile` 就是这套格式的实现，另有单测锁死每个字段值（见 `internal/profile/profile_test.go`）。

### 1.3 提权之后到底发生了什么（逆向自原生里的 root 脚本）

原生拿到临时 root 后会 fork 一个 root shell 跑一段内嵌脚本，顺序是：

1. 读 `/sys/fs/selinux/policy`，把第 24 字节（config）**按位或 0xC0**，再 `load_policy` —— 借权限位把策略撑开；
2. `ksud insmod vrpatch.ko` —— 中和 vivo 的 vr 守卫（它会 hook `__tracepoint_sys_exit`，专杀 ksud 起的一次性 shell）；
3. `ksud late-load --allow-shell --package-name <管理器包名> --kmi <kmi>` —— 由管理器的 ksud 把**它自带的、和 KMI 匹配的 ko** 用 `finit_module` 晚加载；
4. 轮询 `/proc/modules` 确认 `kernelsu` 出现；
5. `GHOSTLOCK_KSU_ENFORCE=0` 时最后再 `echo 0 > /sys/fs/selinux/enforce`。

ksud 从哪来：脚本自己在 `/data/app/*/<管理器包>/lib/arm64/libksud.so` 里找。
支持的管理器：KernelSU 官方 / KSU-Next / **SukiSU Ultra** / ReSukiSU / KowSU(SuperManager) / 7kimisu / 自定义包名。

---

## 2. 你提的两个问题，在这个设计里怎么解决

### 问题 1：以前每次都要 AI 陪着跑

现在是一条命令。三步：体检 → 跑 → 看结论。

```bash
./bin/ghostlock doctor          # 只读，看 profile 对不对、管理器在不在、kmi 对不对
./bin/ghostlock run --dry-run   # 只把要执行的命令和 profile 打出来，不碰设备
./bin/ghostlock run             # 真跑
```

跑完会直接给结论表（临时 root / KSU 模块 / SELinux）+ 诊断记号 + root 脚本日志，不需要人再解读一长串 `[0m...`。

### 问题 2：sukisu-ultra 更新就得手动改东西

**根因：根本就不该往里面塞 ko。** 原版从来没有"加载你放进去的 ko"这条路：
`ksud late-load` 加载的是**管理器 APK 里自带的那一份** ko（ksud 负责按 KMI 选、按它的方式 insmod）。
手动把一个 ko 丢进目录不但没被使用，还会因为 KMI/签名/版本不匹配让整条链路更不稳。

所以本工具的做法是：

* 不内置任何 KSU 的 ko，也不提供 `--ko` 这种坑；
* 自动发现管理器包名（`pm list packages` 里匹配 6 种已知包名）→ 取它的 `libksud.so` 路径；
* 自动从 `uname -r` 推 KMI（`5.15→android13-5.15`、`6.1→android14-6.1`、`6.6→android15-6.6`、`6.12→android16-6.12`）；
* 包名和 KMI 通过 `.gl_ksu_pkg` / `.gl_kmi` 交给 root 脚本（这就是原版 App 里那套机制）。

**上游更新时你只要做一件事：把新版管理器 APK 装上。** 别的都不用动。

（同理，GhostLock 自己更新：`ghostlock assets import 新版.apk ~/.local/share/ghostlock/assets`，
立刻换用新 payload + 新 profile 集，不用重新编译。）

### 关于 v1.0 稳、v1.1 变磕巴

差异几乎肯定不在利用思路，而在**执行调优**：多核竞态需要主线程/消费线程钉在两个不同核上，
而绑核值来自 profile 里的 `execution.selected_cpus`（Neo9 这份是 3/4，`recommended_cpus` 是 0/1），
以及 W1/W2/W3 三段的 settle/attempts 参数。自己重写时如果把这些"照抄 profile"的步骤省掉、
或写死成 0/1，成功率就会掉。本工具的做法是：

* **一个字段都不自己编**，全部来自 `.conf`，编码进 blob 由原生自己读；
* 需要覆盖时用 `--main-cpu` / `--consumer-cpu` 显式指定，也仍然走 profile 的其余参数。

---

---

## 2.5 自己下载 ko / APK 的最新版本（v4.2.1-r2 那种）

先说结论，这一条决定了所有用法：

> **`ksud late-load` 不接受 ko 路径。** 它按 `format!("{kmi}_kernelsu.ko")` 去
> **ksud 二进制自己内嵌的 asset 表**（rust_embed）里取模块。
> 所以 release 里那个 `lkm-aarch64-android13-5.15_kernelsu.ko` 是**构建输入**
> （打包进 ksud / 给 boot patch 用），不是运行时能塞进去的文件。

也就是说「换 ko」真正等价于「换那个 APK」。能手动指定 ko 的只有另一条路：
`ksud insmod <路径>` —— 而内嵌 root 脚本里**只有一个 insmod 槽**，默认装的是 `vrpatch.ko`。

于是工具给你三条可用工作流：

### A. 用官方最新版（推荐，成功率最高）

```bash
ghostlock manager inspect ~/Downloads/SukiSU_v4.2.1-r2_41068-release-spoofed.apk
#   -> 列出这个 APK 的 libksud.so 里内嵌了哪些 <kmi>_kernelsu.ko
#      确认里面有 android13-5.15（Neo9 需要的那个）再装
ghostlock manager install ~/Downloads/SukiSU_v4.2.1-r2_41068-release-spoofed.apk
ghostlock run
```

`manager inspect` 是在**电脑上**直接读 APK（解 zip + 扒 libksud.so 里的内嵌 asset 名），
不需要设备、不会安装任何东西。这是最快判断「这个 release 到底能不能用在我这台机器上」的办法。
`lkm-…_kernelsu.ko` 这个文件在这种情况下**用不上**，留着当备份即可。

### B. 就要用自己挑的那颗 ko

```bash
ghostlock ko add ~/Downloads          # 把目录/单个 .ko 收进库存 ~/.local/share/ghostlock/ko
ghostlock ko list                     # 列出：KMI / vermagic / 大小
ghostlock ko pick                     # 交互式编号选择（* 标记与设备内核匹配的）
ghostlock run --ko <选中的 ko>
```

`--ko` 的语义（很重要）：

* 你的 ko 会占用 root 脚本里**唯一的 insmod 槽**，也就是**这一次不加载 `vrpatch.ko`**；
* 自动切到 `GHOSTLOCK_KSU_ENFORCE=9`（临时 root + 装你这颗 ko，不跑 late-load）；
* 跑之前会用 vermagic / 文件名里的 KMI 与设备 `uname -r` 比对，**不匹配就直接拒绝**，不冒险上机。

想恢复原流程（vrpatch + 管理器内嵌 ko）就去掉 `--ko`。

### C. 已经有 root，只想换/验证一颗 ko

```bash
ghostlock ko load ~/Downloads/lkm-aarch64-android13-5.15_kernelsu.ko
ghostlock ko load vrpatch          # 补装工具内置的 vrpatch.ko（run --ko 之后想补回守卫中和时用）
```

依次尝试 `su -c 'ksud insmod …'` → `/data/adb/ksud insmod …` → `insmod …`，
然后查 `/proc/modules` 确认 `kernelsu` 真的进去了。

### 关于 KMI 与 vermagic 的两个坑

* 文件名里的 `android13-5.15` **就是 KMI**，工具会自动解析并和 `uname -r` 推出的 KMI 对比；
* ko 的 vermagic 必须和运行内核的 major.minor 一致（例如 `5.15.x-…`）。
  顺带一提：APK 里那颗 `vrpatch.ko` 的 vermagic 是
  `5.15.202-android13-5.15.202_r00-dirty`，如果你的 `uname -r` 不是 5.15 系列，
  说明 APK 版本和机器对不上，先别急着跑。

---

## 2.6 交互菜单与脱手循环（v1.3）

### 无参数就是菜单

```
$ ./ghostlock
  ╔══════════════════════════════════════════════╗
  ║   ghostlock-cli · iQOO Neo9 (PD2338) root    ║
  ╚══════════════════════════════════════════════╝
     设备: V2338A · 5.15.197-g708015331567-dirty
     1) 一键 root（循环重试，脱手）      <- 推荐
     2) 打一次（调试，失败会重启）
     3) 体检（只读）
     4) 选 ko / 装管理器
     5) 清理设备残留
     0) 退出
     选择>
```

带参数时行为不变（`run` / `doctor` / `ko` / `profile` …），所以脚本化照旧可用。

### 一键 root 的循环逻辑（对齐 v1.0 的"脱手"）

```bash
ghostlock run --loop --rounds 10 --per-boot 6 --window 90 --reboot-first
```

* **uptime 窗口**：只在开机后 `--window` 秒内发射，过了就等下一次重启；
* **每窗口多次**：窗口内连发 `--per-boot` 次，任何一次 panic 掉线就转入等待；
* **掉线判定**：`adb shell echo up` 失败 = panic/重启，属于正常失败路径，自动等它回来；
* **成败判据**：轮询 `ksu-<ts>.log` 出现 `KernelSU module loaded` 即成功；
* **root 脚本启动后不再发射**：检测到 `root script start` 就把等待延长到 120s，让 policy/vrpatch/late-load 做完。

### 成功即清理

```bash
ghostlock run --loop --clean-after
```

清掉 `/data/local/tmp/ghostlock/*`（payload、profile、ko、日志、glrun.sh、root 脚本）、
`/data/local/tmp/ksud`、`.ghostlock_*` 残留，并 `pkill` 遗留的 native 进程。
KSU 已在内存里，清理不影响 root 本身。菜单 5 是同一套逻辑。

### 这一轮实测发现的三件事

1. **新 APK 把 ksud 改名了**：`libksud.so` 不存在，真正的 ksud 是 `lib/arm64-v8a/libscibhqvpso.so`（5.7 MiB，
   内含 8 个 KMI 的 `*_kernelsu.ko`）。所以 v1.0/v1.2 里 `find /data/app -name libksud.so` 的做法在新版上必然落空。
   `ghostlock manager inspect/install` 现在按**内容**认：找带 `<kmi>_kernelsu.ko` 表的那个 PIE，并把它推到
   `/data/local/tmp/ksud`，late-load 就用这个 APK 里的最新 ko。
2. **profile 缺 `vr_guard` 组**：App 的 writer 不产出它，但 native 白名单接受 `meta.vr_guard`、
   `offset.vr_sys_exit_tp`、`[vr_guard] tracepoint_funcs`。缺了它，native 不会中和 vivo 的
   `__tracepoint_sys_exit` 探针。已补进 `5.15.197-g708015331567-dirty.conf`。
3. **写原语在 SELinux Enforcing 下失败**：日志 `multicast route ... sockopt=-1 errno=99`、`calls=0 success=0`；
   作者的证据日志里是 `selinux: Permissive` + `sockopt=-1 errno=0` + `calls=1 success=1`。
   `errno=99 (EADDRNOTAVAIL)` 说明 `ip_mc_msfilter` 在 `ip_mc_find_dev` 就返回了，fake waiter 没进内核，
   PI 链建立不起来（`calls=0`），W1 写 `selinux_enforcing` 必然失败。

---

## 2.7 v1.3 实测结论（vivo iQOO Neo9 / 5.15.197-g708015331567-dirty）

### 决定性对比：同一个 native，两套 profile

把 v1.1 release 里的 `ghostlock.bin`（GLPACK01 容器）解出来，和 APK v1.2 里的东西逐项比：

| 文件 | v1.1 release | APK v1.2 | md5 |
|---|---|---|---|
| `libghostlock.so` | 484840 B | 484840 B | **相同** |
| `vrpatch.ko` | 249224 B | 249224 B | **相同** |
| `profile.bin` | 2058 B | （由 conf 现场生成） | **不同** |

也就是说：**exploit 本体一模一样，能不能成功只取决于那份 2058 字节的 profile**。

v1.1 的 profile 与 APK v1.2 conf 生成的 blob 有 4 处实质差异：

| 字段 | v1.1（打过 8 轮成功） | APK v1.2 conf |
|---|---|---|
| `cred.ref0..3_image` | −274695699576 / … | −274695699824 / …（差 248） |
| `offset.security_hook_heads` | 37151352 | 37149664（差 1688） |
| `execution.heap.prepare_max_attempts` | 4 | 6 |
| `execution.stages.w1_attempts` | 15 | 24 |

v1.2 的 conf 是"更激进"的调参 + 两处偏移改动，**没有被现场验证过**（作者自己也没跑通 v1.2.1）。
现场表现：用 v1.2 conf 生成的 blob → `native exit=1` 干净退出（写原语没生效）；
用 v1.1 的 blob → panic 掉线（写进去了，是正常的失败形态）。

### 所以工具改成"内嵌已验证 profile"

```bash
ghostlock run --loop       # 默认就用内嵌的、现场验证过的 blob
ghostlock run --conf x.conf   # 想用自己生成的，显式指定
ghostlock run --blob y.bin    # 想用别的现成 blob
```

优先级：`--blob` > `--conf` > 内嵌 `payload/profile-verified.bin`（且 release 必须与设备 `uname -r` 一致，否则自动退回 conf 生成）。

这就把"上游一更新就抓瞎"变成了：**payload 从 APK 拿，profile 用验证过的，两者解耦**。

### 现场观测（2026-10-25）

* v1.1 的 `reroot.sh` 在 **SELinux Enforcing** 下第 8 轮成功：`kernelsu` + `vrpatch` 都在 `/proc/modules`，
  `su -c id` → `u:r:ksu:s0`，`getenforce` 仍是 Enforcing。
  → 之前"Enforcing 下写不进去"的判断是错的，真正的变量是**轮数**。
* 每轮典型形态：发射 → 内核 panic → adb 掉线 → 设备自动重启 → 等回来 → 下一轮。
  掉线**不是**异常，是失败路径的正常表现。
* uptime 窗口按 v1.1 的明文来：\`WINDOW=90\` 只是"超过就收手"的上沿，
  脚本自己的提示写的是 **"12~45 秒才容易中"**、**"越早越好"**。
  所以拿到 shell 就在窗口内立刻发射，不做任何"等到某个 uptime 再打"的等待——
  竞态窗口是越早越好，人为加下沿只会白白丢掉最好的那几秒。


### 现场实测（2026-10-25，去掉了自造的窗口下沿之后）

```
$ ghostlock run --loop --rounds 20 --per-boot 1 --window 90 --reboot-first
[*] 先重启，抢开机窗口…
================ 第 1/20 轮 ================
[i] uptime=12s（窗口内）
---- 第 1 轮 / 第 1 次（uptime=12s）----
[!] 设备掉线（panic/重启）—— 正常失败路径
[i] 等设备回来…
================ 第 2/20 轮 ================
[i] uptime=32s（窗口内）
---- 第 2 轮 / 第 1 次（uptime=32s）----
[+] 成功：root 已在（KernelSU late-load）
```

```
$ adb shell 'su -c "id; grep -c kernelsu /proc/modules; getenforce"'
uid=0(root) gid=0(root) groups=0(root) context=u:r:ksu:s0
1
Enforcing
```

随后菜单 5 清理：27 个文件的 staging 目录、`/data/local/tmp/ksud`、`.ghostlock_*` 全部清掉，
`su -c id` 依然是 root —— 清理不动内核里已经生效的 late-load。

---

## 2.8 无人值守实测（2026-10-25 晚，全程无人工介入）

### 最终形态的循环：每轮主动重启

读 v1.1 明文后按它的节奏重写，唯一改动是"不赌设备会不会自己重启"：

```
================ 第 3/10 轮 ================
[*] 重启设备…
[i] uptime=31s
[i] .gl_ksu_pkg -> com.sukisu.ultra
---- 第 3 轮 / 第 1 次（uptime=31s）----
[!] 设备掉线（panic）—— 下一轮重启
[i] 本轮没中
```

* 每轮 `adb reboot` → 等 shell → 读 uptime → **刷新 .gl_ksu_pkg** → 发射；
* 干净失败（`native exit=1`）和 panic 掉线一视同仁，下一轮重启；
* 每步都有日志，任何一步挂住立刻能看出来（之前一版就因为 adb 调用没超时，设备重启时整轮静默挂死 7 分钟——已给所有 adb 调用加 25s 硬超时）。

### 三次成功、两次失败的现场统计

| 轮次 | uptime | 形态 | 结果 |
|---|---|---|---|
| 第 1 轮 | 12s | panic | 失败 |
| 第 2 轮 | 32s | — | **成功** |
| 第 4 轮 | 43s | — | **成功**（带 `--ko`） |
| 1~10 轮 | 11~35s | 8 panic / 2 干净退出 | 未中 |

结论：**命中率就是几轮一次**，和 v1.1 的 8 轮一致；单轮成败没有稳定规律，别从单次样本推因果。

### 关于"自己下载的 ko"

```
• ko      lkm-aarch64-android13-5.15_kernelsu.ko
          （vermagic 是 5.15.202-android13-5.15.202_r00-dirty，设备是 5.15.197-g708015331567-dirty
            —— 只能靠 late-load 手动重定位加载；走 insmod 会被 GKI 的 vermagic 检查拒绝）
```

实测：`ksud insmod user.ko` 在 vermagic 不一致时被内核直接拒（模块大小仍是管理器内嵌那份的 241664，
不是用户 ko 的 532480），随后 `late-load` 正常接管。wrapper 会把 insmod 的 rc 写进 `ksud.log`。

所以：

* **"随手丢一颗 release 里的 ko 进去"是走不通的**——GKI 要求 vermagic 完全一致；
* late-load 只吃**管理器 ksud 内嵌**的 ko（rust_embed），不吃路径；
* 真正可控的旋钮是 **换管理器 APK**，不是换 ko 文件；
* `--ko` 保留，但它的语义是"尽力试 + 如实报告"，不再假装能装。

### 管理器 uid：这才是"新管理器显示未安装"的真因

```
$ su -c dmesg | grep -i "manager uid"
KernelSU: update_uid: uid parse err
KernelSU: manager uid unchanged, skip search!
```

内核拿到的管理器包名是空的 → `manager uid` 留 0 → 新版管理器判"未安装"。
原因是重启后 `uptime` 只有几秒就探测，PackageManager 还没起来。
修法：发射前用 `pm list packages <pkg>`（单包过滤，比全量列表早可用）刷新，
再把包名写进 `.gl_ksu_pkg` 交给 root 脚本 → `ksud late-load --package-name`：

```
[i] .gl_ksu_pkg -> com.sukisu.ultra
```

**自由选择管理器**：`ghostlock manager install 任意.apk`（菜单 4 → 4），
工具会按内容认出改名后的 ksud 并推到 `/data/local/tmp/ksud`，late-load 用的就是那个 APK 里内嵌的 ko。
换管理器 = 换 APK，不需要动别的。


### 命中率与参数（数据，不是推测）

| 配置 | 轮数 | 结果 |
|---|---|---|
| per-boot 1，无下沿 | 10 | 2 中（uptime 32s / 43s） |
| per-boot 3，无下沿 | 20 | 0 中 |
| per-boot 1，无下沿（设备已反复重启 40+ 次） | 20 | 0 中 |
| per-boot 1，`GHOSTLOCK_MIN_UPTIME=30` | 8 | 0 中 |

* 干净失败后的第二发几乎必然 panic，`--per-boot` 保持 1 更省时间；
* 连续重启几十次后命中率明显下降 —— 作者原话是"恢复出厂可以恢复命中率"，实测吻合；
* 窗口下沿做成环境变量 `GHOSTLOCK_MIN_UPTIME`（默认 0 = 不等待，尊重"越早越好"），
  想看数据就 `GHOSTLOCK_MIN_UPTIME=30 ghostlock run --loop`。

---

## 2.9 两个真 bug（不是命中率问题）

### bug 1：成功判据只看日志，把已经拿到的 root 重启掉了

现场证据（修之前）：

    ---- 第 6 轮 / 第 1 次（uptime=63s）----
        === native exit=255
    [i] 本轮没中（干净退出），主动重启进下一轮      <- 把 root 灭了

而当时管理器已经跳出来显示超级用户和模块 —— **其实成功了**。
原因：root 脚本是被 native fork 出去的后台进程，它写 ksu-*.log 晚于 native 退出，
而我只认日志里那行 "KernelSU module loaded"。native exit=255 一出现就被判"没中"。

修法：**问内核，不看日志**。

    func rooted(a *device.ADB) bool {
        if a.HasModule("kernelsu") { return true }   // /proc/modules
        return a.IsRoot()                            // su -c id
    }

* fire() 在 native 退出后发现 rooted() -> 直接判成功；
* 每轮"干净退出"要重启之前，再 rooted() 复核一次，命中就停，绝不重启；
* 修完后实测：第 2 轮成功，su -c id -> u:r:ksu:s0，设备保持 root。

### bug 2：把"换 KSU"当成了命中率变量

换 ko / 换管理器都发生在**提权成功之后**的 root 脚本阶段，不可能影响 exploit 本身。
之前为了"脱手"加的两处改动才是真凶，已撤销：

| 改动 | 影响 | 现在 |
|---|---|---|
| 每轮主动 adb reboot | 手动重启后 adb 恢复太快，11~13s 就发射（全灭）；panic 自然重启能到 30~60s | 只在首轮和"确认没中"时重启，panic 后等设备自己回来 |
| 每轮发射前 RefreshManager | 6 个包 x 重试，最多拖 15s，把发射点推离"刚回来"的时机 | 移到 staging 阶段只做一次 |

### 关于 manager uid

    KernelSU: packages.list detected: 128
    KernelSU: update_uid: uid parse err

.gl_ksu_pkg 里确实是 com.sukisu.ultra，但内核只从 packages.list 解析到 128 条
（本机装了 538 个包），没匹配上 -> manager uid 留 0。这是 **KSU 内核模块自己的解析问题**，
不影响 su：--allow-shell 已经给了 shell 授权，su -c id 正常。
管理器端如果想显示"已激活"，在管理器里手动点一次授权即可。

---

## 2.10 升级到任意版本 KSU（随机包名）

### 官方 spoofed 构建用的是随机包名

    $ aapt dump badging SukiSU_v4.2.1-r2_41068-release-spoofed.apk | head -1
    package: name='rqglxo.qzizju.uholjr' versionCode='41068' versionName='v4.2.1-r2'

官方稳定版是 com.sukisu.ultra，而 spoofed 构建每次换随机包名。任何写死的包名列表
都找不到新版本——这正是"明明装了 r2 却还是 40994"的原因。

### 现在从 APK 里读包名

internal/manager/axml.go 直接解析 AndroidManifest.xml 的 binary AXML
（不需要 aapt / apktool，纯 Go）：string pool + start element 的 package 属性。
实测：

    rqglxo.qzizju.uholjr     (SukiSU v4.2.1-r2 spoofed)
    com.ghostlock.app        (GhostLock APK)

\`ghostlock manager install <apk>\` 会：

1. 读出版名 + 内嵌 <kmi>_kernelsu.ko 列表；
2. 安装；
3. 把包名记到 ~/.local/share/ghostlock/manager；
4. 把 ksud（不论叫什么名字）推到 /data/local/tmp/ksud。

之后 \`run\` 的 \`.gl_ksu_pkg\` 就用这个包名，内核的 manager uid 才会指向新管理器。

### 实测结果（2026-10-25 23:03）

    $ ghostlock manager install ~/Downloads/SukiSU_v4.2.1-r2_41068-release-spoofed.apk
         包名   : rqglxo.qzizju.uholjr
         已记住管理器包名 rqglxo.qzizju.uholjr（.gl_ksu_pkg 会用它）
         ksud 已就位: /data/local/tmp/ksud

    $ ghostlock run --loop        # 第 3 轮成功
    $ adb shell su -c id
    uid=0(root) ... context=u:r:ksu:s0
    $ adb shell grep kernelsu /proc/modules
    kernelsu 532480 1 - Live        # r2 的 ko（旧版是 241664）
    $ su -c dmesg | grep "manager uid"
    KernelSU: manager uid=10203 still installed (signature fallback)

管理器截图：**工作中 / 版本 41068-6 / 管理器版本 v4.2.1-r2 (41068-6)**。

### 日常升级

    ghostlock manager install 新的SukiSU-xxx.apk     # 唯一要做的
    ghostlock run --loop --clean-after

payload（exploit）与 profile 无需改动：exploit 只跟内核版本有关，KSU 版本只影响
提权成功之后谁来接管 root。

---

## 2.11 三个问题的答案

### Q1：之前明明成功了，为什么工具说没中？

判据错了。修之前的证据：

    ---- 第 6 轮 / 第 1 次（uptime=63s）----
        === native exit=255
    [i] 本轮没中（干净退出），主动重启进下一轮     <- root 被这一行重启掉

root 脚本是 native fork 出去的后台进程，它写 ksu-*.log 比 native 退出晚几秒。
旧判据只认日志里 "KernelSU module loaded" 那行文本，所以 native exit=255 一律判失败。

现在改成**问内核**：

    func rooted(a) bool { return a.HasModule("kernelsu") || a.IsRoot() }

* native 退出后先 rooted()，命中直接判成功；
* 每轮"干净退出"要重启之前再复核一次，有 root 就停，绝不重启有 root 的设备。

### Q2：为什么重装一次管理器，它就认内核了？

不是"重装"起作用，是**换了 ksud，从而换了内核里的 ko 版本**。

root 脚本找 ksud 的顺序：

    KSUD="$HOME_DIR/ksud"                          # 1) 我们放的 wrapper
    [ -x "$KSUD" ] || find .../lib/arm64/libksud.so # 2) 管理器 App 的 native lib
    [ -x "$KSUD" ] || KSUD=/data/local/tmp/ksud     # 3) 我们推上去的 ksud
    [ -x "$KSUD" ] || KSUD=/data/adb/ksu/bin/ksud   # 4) App 自己解压的

而 ksud late-load 是**从 ksud 自己内嵌的 asset** 里取 <kmi>_kernelsu.ko，
所以 **ksud 的版本 = 内核里 ko 的版本**。

现场证据（/proc/modules 的模块大小就是版本指纹）：

| 阶段 | ksud 来源 | 内核模块 | 结果 |
|---|---|---|---|
| 之前 | /data/adb/ksud（旧 App 解压，40994） | kernelsu 241664 | r2 管理器看到内核 40994 -> 版本不匹配 -> 未安装/需要更新管理器 |
| 现在 | /data/local/tmp/ksud（r2，5932624，ksud 4.2.1-r2 uapi 6） | kernelsu 532480 | 内核 41068 -> r2 管理器 工作中 / 41068-6 |

dmesg 里能直接看到版本号：

    KernelSU: welcome to KernelSU version 41068, package name com.sukisu.ultra

顺带一个细节：

    kernelsu: version magic '5.15.202-android13-5.15.202_r00-dirty ...'
              should be '5.15.197-g708015331567-dirty ... vivo'

ko 的 vermagic 和内核本来就不一致，late-load 是**手动重定位**加载，绕过内核的
vermagic 检查（只打警告）。所以版本号对得上才重要，vermagic 不是门槛。

### Q3：官方又更新了，怎么升级？

    ghostlock manager install 新的SukiSU-xxx.apk      # 唯一一步
    ghostlock run --loop --clean-after

manager install 会自动做四件事：

1. 解析 APK 的 binary AndroidManifest，读出**新包名**（官方 spoofed 构建每次随机，
   例如 rqglxo.qzizju.uholjr；不能用写死的包名）；
2. 装 APK；
3. 把包名记到 ~/.local/share/ghostlock/manager，之后 .gl_ksu_pkg 用它；
4. 找出 APK 里那个改名的 ksud（libscibhqvpso.so 之类），推到 /data/local/tmp/ksud。

于是 late-load 用的就是**这个 APK 内嵌的 ko**。

注意事项：

* late-load 只在内存，**硬重启就没了**，重启后重跑；
* 旧管理器会显示"需要更新管理器"——它只是版本对不上，用
  ghostlock manager list 看有没有残留、ghostlock manager remove <旧包> 清掉；
* 只有**内核 release 变了**（uname -r 不是 5.15.197-g708015331567-dirty）才需要换 profile；
  KSU 版本变化不碰 payload 和 profile。

---

## 2.12 便携分发（拷一个文件就能用）

### 路径审计结果

代码里唯一的绝对路径是**设备端**的 /data/local/tmp/ghostlock（Android 标准可写目录，
本来就该固定）。你机器上的东西全部动态：

| 东西 | 位置 |
|---|---|
| payload + 71 份 profile | 内嵌在二进制里（go:embed） |
| 可执行文件 | 任意目录，无外部依赖 |
| ko 库存 | $HOME/.local/share/ghostlock/ko（自动创建） |
| 管理器包名记录 | $HOME/.local/share/ghostlock/manager（自动创建） |
| 覆盖项 | GHOSTLOCK_ASSETS / GHOSTLOCK_KO / GHOSTLOCK_MIN_UPTIME |

### 对方机器怎么跑

    make dist                       # 生成 dist/（二进制 + README）
    cp dist/ghostlock 目标:/any/dir/
    cp SukiSU_xxx.apk 目标:/any/dir/
    cd /any/dir && ./ghostlock       # 无参数进菜单

装/升级管理器时**不用给路径**：

    ./ghostlock manager install     # 自动在 1) 可执行文件同目录 2) 当前目录
                                    # 3) ~/Downloads ~/Download ~/下载 里找
                                    # "带 <kmi>_kernelsu.ko 表的 APK"，多个取最新
    ./ghostlock manager install /path/to/SukiSU.apk   # 也可以直接给
    ./ghostlock manager inspect     # 同样支持省略路径

识别**不靠包名**（官方 spoofed 构建是随机包名），而是看 APK 里有没有那 8 个
<kmi>_kernelsu.ko 的内嵌表。

### 实测（模拟另一台机器）

    $ mkdir /tmp/dist && cp bin/ghostlock /tmp/dist/ && cp SukiSU_v4.2.1-r2_...apk /tmp/dist/
    $ cd /tmp && HOME=/tmp/fakehome /tmp/dist/ghostlock manager install
    安装 /tmp/dist/SukiSU_v4.2.1-r2_41068-release-spoofed.apk ...
         包名   : rqglxo.qzizju.uholjr
         ksud 已就位: /data/local/tmp/ksud

从任意 cwd、任意 HOME 都能定位到同目录的 APK（唯一要求是 HOME 存在，adb 自己要用）。

### 交叉编译

    make build    # linux/amd64
    make win      # windows/amd64 -> bin/ghostlock.exe
    make mac      # darwin/arm64
    make arm64    # linux/arm64

对方机器只需要 adb 在 PATH 里。

## 3. 构建与安装

```bash
make            # 本机二进制 -> bin/ghostlock
make test       # 单测（profile 解析/编码/71 个内置 profile 全部回归）
make arm64      # 交叉编译到 arm64 Linux（例如想在手机端 termux 里跑编排）
make install    # 安装到 ~/.local/bin
```

依赖：Go ≥ 1.22（只用标准库，无第三方依赖）、`adb` 在 PATH。

payload 与 profile 通过 `embed` 编进二进制，装完是**单文件**。

---

## 4. 用法

### 4.1 体检

```bash
ghostlock doctor [-s SERIAL]
```

会打印：设备型号/内核/SELinux/Seccomp/管理器/ksud/KMI，以及匹配到的 profile 的关键字段
（route、init_task、init_cred、selinux_enforcing、绑核）。**这一步全是只读命令**，可以随便跑。

### 4.2 提权

```bash
ghostlock run                     # 完整：临时 root → vrpatch → KSU late-load
ghostlock run --temp-root         # 只要临时 root，不加载 KSU（= 原版"调试终端"模式）
ghostlock run --safe-mode         # root 后自动禁用 /data/adb/modules/*（模块自救用）
ghostlock run --main-cpu 3 --consumer-cpu 4
ghostlock run --debug-dir /data/local/tmp/ghostlock/dbg   # 失败后留 dmesg/iomem
ghostlock run --ko <自己挑的 ko>                          # 用指定 ko 代替 vrpatch
```

想核对它到底会执行什么：

```bash
ghostlock run --dry-run
```

### 4.2.1 ko 与管理器

```bash
ghostlock ko list / add / check / pick / load    # 库存、导入、按设备校验、交互选择、装到内核
ghostlock manager inspect <apk>                  # 看 APK 内嵌哪些 <kmi>_kernelsu.ko
ghostlock manager install <apk>                  # 安装 / 升级 KSU 管理器
```

### 4.3 profile

```bash
ghostlock profile list                                  # 内置 71 个 profile
ghostlock profile show 5.15.41-android13-8-g8dc4c75ab7d8-ab1673212412
ghostlock profile compile my.conf -o profile.bin        # 手写/改过的 conf 编译成 blob
```

`--conf my.conf` 可以直接跑非内置 profile。

### 4.4 换 payload / 换机器

```bash
ghostlock assets import ./GhostLock-v1.3-xxx.apk ~/.local/share/ghostlock/assets
export GHOSTLOCK_ASSETS=~/.local/share/ghostlock/assets   # 或每命令 --assets <dir>
```

新内核（没内置 profile）→ 用 `ghostlock-extract`（就是 APK 里的 `libextract.so`）：

```bash
adb push ~/.local/share/ghostlock/assets/payload/ghostlock-extract /data/local/tmp/
adb push boot.img /data/local/tmp/
adb shell /data/local/tmp/ghostlock-extract /data/local/tmp/boot.img --format conf --out /data/local/tmp/new.conf
ghostlock run --conf new.conf
```

---

## 5. 风险与边界（务必先看）

* 该利用改了 cred / SELinux 状态，**失败时设备会重启**。重启后先 `ghostlock doctor` 再重试。
* 工具不会写系统分区（不解 BL 也做不到），不会常驻，不会清数据。
* 连续失败不要硬刷，先抓 `--debug-dir` 的 dmesg 看是哪一段（KernelSnitch / route / cred 自检）。
* 每次能成功的窗口跟开机时间、内存布局有关：**冷启动后第一次跑成功率最高**。

---

## 6. 排错

| 现象 | 判断 | 处理 |
| --- | --- | --- |
| `no bundled profile for kernel ...` | 内核 build 不在内置 71 份里 | 用 ghostlock-extract 生成 conf，`--conf` 传入 |
| `profile release mismatch` | conf 的 release 与 uname -r 不一致 | 改 conf 第一行，注意大小写和后缀 |
| `credential copy profile is incomplete` | cred 段没解出来（conf 缺字段） | `profile show` 看 cred.copy_size 是否为 0 |
| `multicast geometry incomplete` | 5.15 路由缺 `route.multicast_waiter.waiter_off` | 检查 conf 的 route 段 |
| `cores %d/%d not in allowed cpuset` | 绑核被 cpuset 限制 | `--main-cpu/--consumer-cpu` 换核 |
| `KernelSnitch mm_struct leak failed` | 堆喷没撞上 | 冷启动重试；`--safe-mode` 降低干扰 |
| `vr guard: all N attempts failed` | vrpatch 没生效，ksud 一次性 shell 被杀 | 确认 `--no-vrpatch` 没开、ko 推上去了 |
| `temporary root ready; KernelSU module not loaded` | 有临时 root，late-load 没成 | 看 ksud.log：多半是管理器没装 / KMI 不对 |
| `ko 与设备内核不匹配` | vermagic / KMI 与 uname -r 不符 | `ghostlock ko check` 看哪颗能用；换对应 KMI 的文件 |
| `manager inspect` 显示内嵌 ko 为空 | 该 APK 的 ksud 不带 late-load 表 | 换官方 release 的 APK |
| `KernelSU module load failed` | ksud 拿到但模块加载被拒 | 管理器与 KMI 必须匹配；不要手塞 ko |
| `KernelSU already has root; skipping exploit` | 上一次已经成功过 | 冷启动，或 `--force-attack` |

---

## 7. 代码结构

```
cmd/ghostlock/main.go     子命令与参数
cmd/ghostlock/ko.go       ko list/add/check/pick/load
cmd/ghostlock/manager.go  manager inspect/install
internal/profile/          HOCON 子集解析 → 语义解析（对齐原版 c9.java）→ blob 编解码（对齐 ea1.java / sub_67DBC）
internal/device/           adb 封装（devices / shell / push / 流式输出）
internal/stage/            设备探测、KMI 推断、管理器与 ksud 发现、payload 下发
internal/ko/               .ko 头/vermagic/KMI 解析、库存管理、兼容性判定
internal/manager/          APK 内嵌 <kmi>_kernelsu.ko 探测（纯电脑端，不需设备）
internal/run/              一次完整流程的编排与结果解读
internal/assets/           embed 的 payload + profile，支持外部目录覆盖与从 APK 导入
internal/assets/payload/   ghostlock（原 libghostlock.so）、vrpatch.ko、ghostlock-extract（原 libextract.so）
internal/assets/profiles/  原 APK 的 71 个 .conf，一字未改
```

维护原则：**payload 一律从 APK 里拿，不自己写；参数一律来自 profile，不自己编。**
本工具只负责"把正确的 blob 用正确的环境变量喂给正确的程序"。

---

## 8. 已验证 / 未验证

* 已验证（本机）：HOCON 解析、71 个内置 profile 全部 resolve + validate + encode、
  设备 profile 每个字段值与 conf 逐项比对、blob 编码/解码自洽、APK 导入、CLI 构建与单测。
* 未验证（本机没有手机）：真机执行链路（adb push → 运行 → late-load）。
  首次在真机上跑请先 `ghostlock doctor` 和 `ghostlock run --dry-run`，再实跑；
  建议先 `--temp-root` 验证利用阶段，成功了再上完整流程。
