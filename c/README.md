# ghostlock C CLI — 无 UI 的 PC 驱动（C11）

> **分支定位（重要）**：这是开发中的备用实现，只存在于 `feat/c-cli` 子分支。
> 还没有在真机验证，审计加固后的版本也还没重跑离线测试；
> **成熟、验证通过、并经仓库所有者明确同意后**才考虑合并进 `main`。
> `main` 目前仍然是 v1.1 的 bash 驱动（`reroot.sh` 等）。

把 v1.1 的 bash 驱动（`reroot.sh` / `install-ksu.sh` / `clean.sh`）和
`scripts/ghostlock_pc.py` 的能力，重写成**一个不依赖 Python 的单二进制**：
`adb` 驱动、抢开机窗口、部署 payload、盯 root 脚本日志、命中即停。

```
c/
├── Makefile
├── include/gl.h          公共声明
├── src/
│   ├── main.c            参数解析 + 子命令分发（兼容 v1.1 的 flag 写法）
│   ├── util.c            字符串缓冲、日志、文件/目录、base64
│   ├── adb.c             带硬超时的子进程执行 + adb 包装
│   ├── pack.c            GLPACK01 容器解析/解包（越界即失败）
│   ├── profile.c         profile blob 解析 + native 组/键白名单校验
│   ├── script.c          生成设备端 glrun.sh 与 ksud wrapper
│   ├── deploy.c          release 闸门、按大小幂等推送、user.ko 布置
│   ├── cmd_run.c         启动窗口竞速主循环
│   ├── cmd_basic.c       check / status / inspect / pull-log
│   ├── cmd_deploy.c      deploy
│   ├── cmd_clean.c       clean（默认 dry-run）
│   ├── cmd_install.c     提权后加载 ko / 装管理器
│   ├── cmd_exec.c        root 调试终端（.gl_cmd → .gl_out）
│   └── cmd_blob.c        blob dump / check（离线）
└── tests/
    ├── mock-adb.py       离线 adb 替身（模拟命中链路）
    └── run-tests.sh      67 项离线验收
```

## 构建

```bash
cd c
make                 # -> ./ghostlock
make test            # 离线验收（不需要手机；用仓库里的真包/真 blob）
make static          # 静态链接（musl/glibc 静态库可用时）
sudo make install    # PREFIX=/usr/local
```

要求：C11 编译器 + libc + `adb`。没有第三方库，没有 Python，没有 shell 脚本生成依赖
（设备端脚本由程序按字节生成后 `adb push`）。

## 用法

```bash
# 一条龙（和 v1.1 的 ./reroot.sh --ko 1 --clean-after 等价）
./ghostlock run --ko 1 --clean-after

# 只看设备 / profile 是否对得上
./ghostlock check

# 看包里有什么
./ghostlock inspect

# 只部署
./ghostlock deploy

# 提权后：加载自己的 ko / 装管理器
./ghostlock install --ko 1 --install 1

# 核验
./ghostlock status

# 取日志 / 清残留
./ghostlock pull-log --out ./logs
./ghostlock clean --yes --all --reboot

# 通过 root 调试终端执行（root 脚本的 .gl_cmd/.gl_out）
./ghostlock exec -- id

# 离线看一份 profile blob（等价 ghostlock_profile.py dump）
./ghostlock blob dump ../evidence/profile.bin
./ghostlock blob check ../evidence/profile.bin 5.15.197-g708015331567-dirty
```

v1.1 的肌肉记忆也认：`./ghostlock --check`、`--inspect`、`--deploy`、`--force`、
`--redeploy`、`--clean-after`、`--ko N`、`ghostlock 20`。

## 与 v1.1 的行为对齐

| v1.1 脚本行为 | C 版 |
|---|---|
| `GLPACK01` 解包三件套 + release.txt | `pack.c`，全字段越界检查后解包 |
| 设备上按大小比对、不一致才推 | `gl_need_deploy()`，`--redeploy` 强制 |
| `uname -r` 与 release 逐字符比对，不一致拒绝 | 以 blob 头里的 release 为准（更贴近 native 的检查），`--force` 才硬打 |
| 死等 `adb shell` 可用后立刻发射 | `gl_wait_shell()` + `uptime` 窗口判断 |
| 窗口内每轮最多 6 发，uptime > 90 s 停 | `--per-boot` / `--window` |
| **root 脚本一启动就停火**，等 120 s | `observe()` 里 `root script start` → handoff，延长 deadline；`run` 见 `handoff/soft` 即结束本 boot，**绝不再发第二发**（有回归测试锁住：launches==1） |
| 成功 = ksu 日志 `KernelSU module loaded` | 同左，随后 `status` 核验 |
| 不主动重启；panic 后等设备回来继续 | `wait_cycle()`，不调用 `adb reboot` |
| 已 root 直接退出（幂等） | `gl_is_root()` 早退，不碰设备 |
| `--ko` 选本目录 ko → `user.ko` + ksud wrapper | `gl_select_ko()` / `gl_install_ko_wrapper()` |
| `install-ksu.sh` 的 ksud 定位、insmod、late-load | `cmd_install.c`（含 `--persist`） |
| `clean.sh` 默认 dry-run，`--yes` 才删 | `cmd_clean.c`，删除只发生在 `--yes`；且**只允许清 `/data/local/tmp/<dir>`**（`--dir /data` 会被拒绝） |
| macOS 的 `timeout`/`dd`/`sed` 兼容问题 | 不存在：没有 shell 拼装，超时在 `poll()` 里实现 |

底层语义来自 `docs/PORTING.md`（字节级）与 v1.1 的实测结论；C 版没有改变任何一条
「提权正确性」规则，只换了实现语言。

## 验证状态（重要）

**离线验收：67/67 通过**（`make test`），用的是仓库里的**真** payload 包与**真**成功 blob：

- `inspect`：736 303 B / 4 条目，`release.txt` 正确读出；
- `blob dump`：2058 B、13 组、82 个键，与 `scripts/ghostlock_profile.py dump` **逐键一致**
  （82/82，无缺失、无值差异）；`unknown = 0`（native 白名单全通过）；
- `deploy`（mock 设备）：推上去的 `libghostlock.so` / `vrpatch.ko` / `profile.bin`
  与包内字节**完全相同**；`profile.len` 为 4 B 大端长度；生成的 `glrun.sh` 过 `sh -n`；
- release 闸门：不匹配拒绝、`--force` 放行；
- 完整 `run`：mock 设备模拟 `root script start` → `KernelSU module loaded`，
  驱动识别成功、`status` 变 `root: YES`，第二次运行识别「已经是 root」；
- **停火回归**：模拟「root 脚本启动但 KSU 没加载」，一次 boot 内只发射 **1** 次
  （mock 统计 launches==1），不会出现 FIELD-NOTES §2 那种第二发打崩 root；
- `exec` / `pull-log` / `install --dry-run` / `clean`（dry-run 与 `--yes`）全部走通；
- ASAN + UBSAN 跑同一套验收，无内存错误、无未定义行为；
- 测试用的 `adb` 替身记录了所有命令，验收要求「没有未实现的命令」。

> **加固后未重跑测试。** 上面 67/67 是在加固前的版本上跑出来的；之后按评审意见改了
> 掉线判定、release 复检、clean 路径守卫、`gl_exec` 回收、参数校验等，
> 按要求**停在验证前**，没有重跑。第一次上真机前建议先 `make test` 再 `check`。

**未在真机上跑过这一版二进制**（本次开发环境没有连手机）。风险点：
adb 版本差异、设备端 `tail -c +N` / `setenforce` 行为、KSU 授权弹窗等，
v1.1 已实测，C 版只是同一命令序列的另一种发送方式。第一次上真机建议：

```bash
./ghostlock check                 # 只读，确认 release/uid/seccomp
./ghostlock deploy --redeploy     # 只推，不发射
./ghostlock run --rounds 2        # 小步试
```

## 已知边界

- **不生成 profile**：`.conf`（HOCON）→ blob 的生成器仍在
  `scripts/ghostlock_profile.py`（C 版只解析/校验/推送）。要用 `--profile` 指定现成 blob。
- `--app-call`（App 的 stdin 帧入口）已实现但和 Python 版一样**未在真机验证**，
  默认走已验证的 `--load-prebuilt-profile`。
- 没有交互式 `shell` 子命令；用 `ghostlock exec -- <命令>`（每次一条）。
- 只支持 POSIX（Linux/WSL/macOS）；Windows 原生没有做。
- 删除类操作只发生在 `clean --yes`，且只删本工具自己的 payload/日志（与 `clean.sh` 同清单）；
  工作目录必须在 `/data/local/tmp/` 下，否则直接拒绝。
- 设备端会执行的值（`--profile-file` / `--ksu-pkg` / `--kmi` / 绑核 / 各超时）都做了字符集或
  整数校验；`--profile-file` 等不再有 shell 注入面。
- install 专属参数（`--install` / `--ksud` / `--persist` / `--dry-run`）不会静默落到 `run`，
  会自动选择 `install` 子命令。

## 退出码

| 码 | 含义 |
|---|---|
| 0 | 成功 / 已 root / dry-run 正常结束 |
| 1 | 没打中（`run`），或 `status` 无 root，或 blob 校验有未知项 |
| 2 | 用法错误、包损坏、部署失败 |
| 3 | `check` 发现 release 不匹配 |
| 4–10 | `install` 的前置/执行失败（无 root、无 ksud、选不中 ko 等） |
