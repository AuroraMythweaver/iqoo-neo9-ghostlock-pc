# 脚本层说明

> 仓库根目录的 `reroot.sh` + `ghostlock.bin` 是日常入口；本目录放的是可复现/可调参的工具。
> 文中 `apkout/`、`evidence/` 等路径以本仓库结构为准（`evidence/` 已在仓库里）。

## 一、最简形态：一个脚本 + 一个二进制（下次只用这两个）

```
ghostlock/
├── reroot.sh        脚本：纯 bash + adb，自己从包里拆 payload、抢启动窗口
└── ghostlock.bin    payload 包（736 303 B）：libghostlock.so + vrpatch.ko + profile.bin + release
```

```bash
cd /home/qinghuan/SomeIDEA/app/ghostlock

./reroot.sh                  # 最多 10 轮；每轮自动重启，命中即停
./reroot.sh 20               # 想多刷几轮
./reroot.sh --no-reboot      # 设备刚重启过（或你手动重启完）：直接抢窗口
./reroot.sh --check          # 只看当前有没有 root（不会重启）
./reroot.sh --inspect        # 看包里有什么
./reroot.sh --deploy         # 只布署 payload，不打
./reroot.sh --check-payload  # 看设备上的 payload 是否已就绪（不会重推）
```

它做的事（每一步都有实测依据）：

1. 已 root 就直接退出，不碰设备（幂等，不会把到手的 root 重启掉）；
2. 从 `ghostlock.bin` 拆出 `libghostlock.so` / `vrpatch.ko` / `profile.bin`，
   与设备上的文件逐个比大小，不一致才推（`--redeploy` 强制重推）；
3. 比对包里的 `release` 与设备 `uname -r`，不一致**直接拒绝**（`--force` 才硬打）；
4. 死等 `adb shell` 可用 → **立刻发射**（窗口约 boot 后 12~45 秒）；**脚本不主动重启**，
   打崩/卡死时手机自己重启，脚本等它回来；
5. 盯 root 脚本日志，出现 `KernelSU module loaded` 即成功并**立即停手**；
6. 没中/panic 重启 → 自动等回来继续；窗口内还会连刷（`PER_BOOT` 次）。

可调环境变量：`TIMEOUT=180`（单次盯多久）、`PER_BOOT=6`、`WINDOW=90`（uptime 超过就不打了）、
`GL_DIR=/data/local/tmp/...`（换设备端目录，测试用）。

> adb 偶发 `offline` / `unauthorized`（USB 重新授权，几秒自愈）不是设备重启，脚本会等；
> 真掉线（panic 重启）时 uptime 会归零，脚本会自动等回来继续。

## 二、包格式与重新打包

容器（全部 little-endian，bash 用 `od`/`dd` 就能拆）：

```
0x00  8B   "GLPACK01"
0x08  u64  data_start
0x10  u32  n_entries
0x14  u32  format_version (=1)
0x18  n × 32B 条目 { u64 off; u64 size; char name[16] }
data_start: payload
```

```bash
# 重新打包（改了 profile / 换设备时）
python3 scripts/mkpack.py -o ghostlock.bin \
    --lib  apkout/lib/arm64-v8a/libghostlock.so \
    --ko   apkout/assets/modules/vrpatch.ko \
    --blob evidence/profile.bin

# 看包
python3 scripts/mkpack.py --list ghostlock.bin
```

实测校验：拆出来的三个文件在设备上 `md5sum` 与原件完全一致
（`eef05feb…` / `07d6eb23…` / `647fba3d…`）。

## 三、scripts/ 里剩下的（调参 / 取证用，日常不需要）

两个 python 工具，只依赖标准库 + `adb`。协议与字段映射是照 APK 里的
`GhostlockUserService` / `defpackage.ea1` / `defpackage.c9` 一对一复刻，并用
`libghostlock.so` 反汇编出来的组/key 白名单校验过。

### ghostlock_profile.py —— `.conf` → native 的二进制 profile blob

```bash
python3 scripts/ghostlock_profile.py build \
    -c apkout/assets/kernel_profiles/5.15.197-g708015331567-dirty.conf -o /tmp/p.bin [--verbose]
python3 scripts/ghostlock_profile.py dump /tmp/p.bin     # 回读 + 白名单校验
```

- 组名/键名严格按 native 白名单（`dump` 会指出 native 不认的项）。
- `execution.selected_cpus.*` 覆盖 `execution.recommended_cpus.*`（与 App 的 `k3` 一致）。
- `compact_waiter` 只取**顶层** key（route 块里的写法会被丢弃，见报告 §5 第 2 条）。
- ⚠ **陷阱**：`-c <.conf>` 现场生成时 multicast 路由会得到 `execution.consumer.max_calls = 0`，
  真机上 consumer 一次都不触发（日志 `calls=0 success=0`，128 次空转）。
  **实战请用 `evidence/profile.bin` 那份（`1/1`）**。

### ghostlock_pc.py —— 完整驱动（想调参 / 看细节时用）

```bash
python3 scripts/ghostlock_pc.py check                            # 体检 + release 一致性
python3 scripts/ghostlock_pc.py setup --from-blob evidence/profile.bin --force-attack
python3 scripts/ghostlock_pc.py run --on-boot --reboot --reboots 8 \
        --per-boot 8 --window 150 --timeout 120 --poll 0.4
python3 scripts/ghostlock_pc.py status
python3 scripts/ghostlock_pc.py pull-log                         # 取回设备日志
```

常用开关：

| 开关 | 作用 |
|---|---|
| `--from-blob <bin>`（setup） | 直接推已有 blob（推荐）；不给就按 `--conf` 现场生成 |
| `--app-call`（setup） | 改用与 App 一致的 stdin 帧入口（默认走已验证的 `--load-prebuilt-profile`） |
| `--force-attack` | 传给 native，跳过前置检查 |
| `--dump-kernel-log <dir>` | 传给 native，panic 前把 dmesg/pstore 落到指定目录 |
| `--ksu-pkg <包名>` `--kmi <kmi>` | 写 `.gl_ksu_pkg` / `.gl_kmi`，root 脚本用它定位管理器 `libksud.so` |
| `--main-cpu N --consumer-cpu M` | 绑核（等价 native 的 `GHOSTLOCK_MAIN_CPU/CONSUMER_CPU`） |
| `--ksu-enforce 9` | 只做临时 root（vrpatch 后停），不 late-load |
| `-b overlay.conf`（setup） | 叠加基线配置，便于参数 A/B |

### 设备端目录

`/data/local/tmp/ghostlock-app/`（与 App 完全一致）：
`libghostlock.so` `vrpatch.ko` `profile.bin` `glrun.sh`
运行时产出：`native-<runid>.log` `native-<runid>.rc` `ksu-<ts>.log`

### 成功怎么判

日志出现 `child is root!` / `handoff: root script path=` 说明 W1/W2 打通；
root 脚本日志出现 `KernelSU module loaded` 才是真成功；`su -c id` 出 `uid=0`、
`/proc/modules` 有 `kernelsu` 则为持久（本次重启前有效）。

`scripts/reroot.sh` 只是兼容 shim，转调根目录的 `reroot.sh`。
