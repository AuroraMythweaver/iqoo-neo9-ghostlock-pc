# 实测记录与踩坑（工程向）

> 这份文件专门放"过程"：时间窗口的实测数据、踩过的坑、每个结论的证据。
> 面向使用者的说明在 [`../README.md`](../README.md)；协议/格式的字节级分析在
> [`PORTING.md`](PORTING.md)，APK 静态分析在 [`ANALYSIS.md`](ANALYSIS.md)。

---

## 1. 时间窗口的实测分布

判据取自 root 脚本日志：`Write 1 failed` = W1（SELinux 写）没中；`KernelSU module loaded` = 成功。

| 发射时 uptime | 结果 |
|---|---|
| 12.0 / 12.2 / 13.3 / 14.2 s | 部分直接 panic 重启，部分 `Write 1 failed` |
| **32.4 / 33.3 / 37.4 / 39.5 / 40.0 s** | **W1 通过，走到 W2 并成功** |
| 52.9 / 61.5 s | 多数 `Write 1 failed` |
| 84 s / 106 s / 178 s / 12 min / 2.9 h / 22 h | `Write 1 failed` |

结论：**越靠近开机越容易中，但不是越早越好**（太早 12 秒左右反而常 panic）；
经验窗口 **~30–45 秒** 命中率最高。`WINDOW` 默认 90 秒，只是"超过就不再浪费子弹"的粗略上限。

单轮成功率不高（作者的 App 也一样），所以脚本默认最多 10 轮、每轮窗口内最多 6 发。

---

## 2. 一个代价很大的教训：root 脚本启动后必须停火

早期版本在"native 进程退出"时就认为该发下一发。但 native 退出 ≠ 结束：
它 handoff 之后 root 脚本还在跑 policy fixup / vrpatch / late-load。

实测：某一轮已经打中（日志出现 `root script start uid=0`），脚本紧接着在 66 秒补了第二发，
**第二个 exploit 直接把内核打崩，刚拿到的 root 一起没了**。

现在的规则（`reroot.sh` 里 `handoff=0/1`）：

- 一旦日志里出现 `root script start` → 立即停止发射，把等待延长到 120 秒；
- 只等 `KernelSU module loaded` / 失败标记 / 设备掉线，三者之一。

---

## 3. macOS 上为什么必须单独一个脚本

| 现象 | 原因 | 处理 |
|---|---|---|
| `[!] 包里没有 libghostlock.so` | 解包用了 `dd … iflag=skip_bytes,count_bytes`，这是 **GNU dd** 扩展；macOS 的 BSD dd 直接报 unknown operand | 改 `tail -c +N \| head -c M`，并校验解出字节数 |
| `--check` 的 id/kernelsu/selinux/su 全空 | macOS 没有 `timeout`（GNU coreutils；Homebrew 给的是 `gtimeout`），命令没执行且错误被 `2>/dev/null` 吞掉 | `to()` 包装：`timeout` → `gtimeout` → 无超时直跑 |
| 诊断行残留 `[0m` | BSD `sed` 不认 `\x1b` | 用 `printf '\033'` 生成真实 ESC |
| `adb` 找不到 | macOS 常用 Android Studio 的路径 | 自动探测 `~/Library/Android/sdk/platform-tools`、`/opt/homebrew/bin`、`/usr/local/bin` |

`reroot-mac.sh` 同时去掉了 `seq` 依赖（改 bash 算术 for），兼容系统自带 bash 3.2。

---

## 4. 管理器为什么老提示「需要更新内核」

管理器源码里的门槛（SukiSU-Ultra `HomeViewModel.kt`）：

```kotlin
requiresNewKernel  = isManager && Natives.managerUAPIVersion > Natives.kernelUAPIVersion
requiresNewManager = isManager && Natives.managerUAPIVersion < Natives.kernelUAPIVersion
```

即 **管理器 uapi 必须等于内核模块 uapi**，否则首页只提示"更新内核/管理器"，不算全功能。

实测过的组合：

| 内核模块 | 管理器 | 结果 |
|---|---|---|
| BakaSU rc3（uapi 4） | ReSukiSU rc3 /  35171 (uapi 4) | 工作中 |
| BakaSU rc3（uapi 4） | SukiSU-Ultra 4.2.1 (uapi 5) | "需要更新内核" |
| **SukiSU-Ultra 自带的 android13-5.15 ko（uapi 5）** | **SukiSU-Ultra v4.2.1 (40994-5)** | **工作中 · 越狱模式** |

另外 `isManager` 是签名门槛：自己从源码编的管理器（自签名）永远过不了，只能是官方签名的 APK。

---

## 5. ko 的来源：内嵌 vs 外部文件

原 APK 的实现（`userspace/ksud/src/late_load.rs`）：

```rust
if ksuinit::has_kernelsu() { skip }
let ko = assets::get_asset_data(&format!("{kmi}_kernelsu.ko"))?;   // include_bytes! 内嵌
ksuinit::load_module(&ko, params)                                   // 手动重定位 + vermagic 适配
```

所以 ko 跟着 APK 版本走。想用外部 ko，走的是**同一个加载器**（`debug.rs` 的 `insmod`）：

```rust
ksuinit::load_module(&module_data, &cparams)
```

流程：`ksud insmod <你的.ko> allow_shell=1` → 模块进内核 → 再跑 `ksud late-load`
（此时 `has_kernelsu()` 为真 → 跳过 ko，只做用户态 bootstrap：装 ksud、模块、sepolicy、features）。

vermagic 不匹配不用怕：`ksuinit` 会从第一次失败的内核日志里取出内核要求的值，
改写模块头里的 `vermagic=` 再重试一次（`ksuinit/src/lib.rs`）。

---

## 6. 清理顺序为什么是"先删文件、再重启"

- 磁盘上有些文件是 root 属主（`ksu-*.log`、`.ghostlock_iomem`、`.gl_out`），
  root 一旦重启就没了，shell 删不掉 → **先删**。
- 内存态（KSU 模块、vrpatch 的 8 字节补丁、SELinux 状态与 policy、临时 cred）
  只能靠 **reboot** 清，删文件没用。
- `clean.sh` 因此默认 dry-run，`--yes --all --reboot` 是"一步回到干净系统"。

---

## 7. `/data/local/tmp` 看起来"消失"了

`/data` 是 `0771 system:system`、`/data/local` 是 `0711 root:root` —— **others 只有 `x`（能穿过、不能列）**。
普通文件管理器（含系统自带的）根本列不出来，看起来就像"没这个目录"。

`/data/local/tmp` 属主恰好是 `shell:shell`（`0771`），所以：

- `adb shell`（uid 2000 = shell）能列，PC 脚本一切正常；
- 手机上非 shell 身份的应用列不出来。

另外这个权限位正是 **adbd 创建 `/data/local/tmp` 时的默认值**：真被 ROM/清理类 App 删掉时，
adbd 重新建立会话会自动 `mkdir` 回来，所以"一 adb 就有了"在真删的场景下也成立。

---

## 8. 其它零散记录

- 设备有两个用户（`0` 机主 / `666` XSpace）。shell 若挂在 666 上，`pm list packages` 会被限制（看不到 user 0 的包）。
- `ADB_SERVER_SOCKET` 被设成 `tcp:127.0.0.1:5037` 时，WSL 里的 adb 会拒绝自己起 server
  （`cannot start server on remote host`）；要么 `env -u ADB_SERVER_SOCKET adb …`，
  要么重启 Windows 侧的 adb。
- 打包/签名本地管理器：`platforms;android-37.0`（不是 `platforms;android-37`）、
  build-tools `36.1.0`、NDK `30.0.16248370`、JDK 21；`resources.arsc` 必须 STORED 且 4 字节对齐，
  否则安装报 `requires the resources.arsc … stored uncompressed`。
