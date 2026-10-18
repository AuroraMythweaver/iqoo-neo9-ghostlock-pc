# C 版无 UI 驱动：工程记录

> 面向过程：为什么用 C 重写、怎么保证和 v1.1 脚本同一套语义、离线怎么验证、
> 哪些还没验证。使用说明在 [`../c/README.md`](../c/README.md)，协议字节级证据在
> [`PORTING.md`](PORTING.md)，实测踩坑在 [`FIELD-NOTES.md`](FIELD-NOTES.md)。

## 1. 目标与边界

目标：把 PC 侧驱动做成**单二进制、无 UI、无 Python 依赖**的 C 程序，功能对齐
v1.1 release 里的 `reroot.sh` / `install-ksu.sh` / `clean.sh`，并吸收
`scripts/ghostlock_pc.py` 里那些只在调参时才用到的能力（`check` / `status` /
`exec` / `pull-log`）。

明确不做：

- 不重写漏洞利用（`libghostlock.so` 是上游原二进制，原样部署）；
- 不重写 `.conf` → blob 生成器（HOCON 解析在 `scripts/ghostlock_profile.py`，
  C 版只解析/校验/推送现成 blob）；
- 不改变任何一条提权正确性规则（窗口、停火、成功判据、release 闸门）。

## 2. 为什么不是「把 bash 翻译成 C」

bash 版的价值不在语法，而在几条**用真机事故换来的规则**（见
[`FIELD-NOTES.md`](FIELD-NOTES.md) §2、[`PORTING.md`](PORTING.md) §8.3）：

1. `root script start` 出现后必须停火，否则第二发 exploit 会把刚拿到的 root 打崩；
2. 成功判据是 root 脚本自己的 `KernelSU module loaded`，不是 native 退出；
3. 失败是内核 panic 自重启，驱动只能等，不能主动 reboot；
4. release 不一致要拒绝，因为偏移错了就是 panic。

C 版把这几条变成显式状态：`attempt_res { win, soft, dropped, handoff }`，
外加外层 `progressed`：只要本次 boot 出现过 `handoff` 或 `soft`（root 脚本启动、
`child is root!` 等），`run` 就结束本次 boot 的发射循环，只等设备重启或退出。
`observe()` 里只有 `win` 才提前结束。这样「停火」不依赖某一行 shell 的 `if` 顺序，
代码评审时能直接看到；测试里用 launches==1 锁住。

开发过程中这里确实犯过一次：第一版只把 `handoff` 记到外层、内层 `per_boot`
循环仍会继续发射。补了回归测试（`MOCK_NO_KSU=1`，断言只发射一次）后才算修好。

## 3. 结构

```
main.c      flag/subcommand 解析；v1.1 的 --check/--deploy/--ko 写法与
            run/check/... 子命令共用同一份 gl_opt
adb.c       gl_exec(): pipe + fork + poll + 硬超时 + SIGKILL；所有 adb 调用
            都带超时，避免「设备重启时 adb 卡死」把整个循环拖住
pack.c      GLPACK01：magic/data_start/条目表全部对文件大小做边界检查
profile.c   blob 解析（magic 0x0D000721 / version 2 / release<=255 / 组与键）
            + native 白名单（15 组固定 + 当前 route 组）
script.c    生成 glrun.sh（诊断头、GL_RUN_ID、HOME/TMPDIR/GHOSTLOCK_HOME、
            GHOSTLOCK_KSU_LOG）与 ksud wrapper
deploy.c    release 闸门（优先 blob 头的 release）、按大小幂等推送、
            profile.len（4 B 大端）、user.ko/ksud wrapper
cmd_run.c   启动窗口主循环 + 单次观察 + 阶段诊断 + 等待自重启
cmd_*.c     其余子命令
```

依赖只有 libc/POSIX；没有 `system()`、没有把设备命令拼进本地 shell。
设备端脚本按字节写好后 `adb push`，与 v1.1 的 `gen_glrun()` 输出同义。

## 4. 与旧实现的命令/行为映射

| 旧实现 | C 版 | 备注 |
|---|---|---|
| `reroot.sh` | `ghostlock run`（默认） | 同样不主动重启 |
| `reroot.sh --inspect` | `ghostlock inspect` | 额外打印 format |
| `reroot.sh --deploy` | `ghostlock deploy` | 总是推送 |
| `reroot.sh --check-payload` | `ghostlock check-payload` | 只读 |
| `reroot.sh --check` | `ghostlock check` | 多了 seccomp 告警 |
| `install-ksu.sh` | `ghostlock install` | `--ko/--install/--ksud/--pkg/--persist/--dry-run/--yes` |
| `clean.sh` | `ghostlock clean` | 默认 dry-run；`--ksu/--uninstall/--all/--reboot` |
| `ghostlock_pc.py status` | `ghostlock status` | 同五项 + ksu 日志尾巴 |
| `ghostlock_pc.py exec/shell` | `ghostlock exec -- <cmd>` | 没有交互循环 |
| `ghostlock_pc.py pull-log` | `ghostlock pull-log --out DIR` | 同 `*.log/*.rc` |
| `ghostlock_pc.py --from-blob` | `ghostlock run --profile <blob>` | |
| `ghostlock_profile.py dump` | `ghostlock blob dump/check` | 含白名单校验 |

`glrun.sh` 的调用与 v1.1 一致：`--load-prebuilt-profile <blob>`，默认带
`--force-attack`（v1.1 的 `gen_glrun` 就是固定带的），`--no-force-attack` 可关。

## 5. 离线验证方法（没有真机时）

### 5.1 用真 fixture，不用自造数据

`make test` 直接用仓库里的：

- `ghostlock.bin`（736 303 B，4 条目，真 payload）；
- `evidence/profile.bin`（2058 B，真机打通过的那份 blob）。

解析器的正确性因此是对着真实字节验证的，不是对着自己写出来的样本。

### 5.2 mock adb：把整条链路跑起来

`tests/mock-adb.py` 是一个 `adb` 替身：

- 设备文件系统映射到 `$MOCK_STATE/fs`；
- 实现驱动实际发送的命令形状（`wc -c` / `tail -c +N` / `test -f` / `dd|od`、
  `su -c`、`getprop`、`pm list packages`、`push/pull`、`.gl_cmd`/`.gl_out` 等）；
- 收到 launch 命令后写 native/ksu 日志，第 2 次 size 探测补 policy/vrpatch 行，
  第 3 次补 `[+] KernelSU module loaded` 并把 root 置 1，第 4 次写 `.rc`；
- **未实现的命令写进 `unmatched.log`，验收要求该文件为空**——防止测试因为
  「命令其实没被执行」而假通过。

这样 `run` 走的是真正的状态机：部署 → 等 shell → 读 uptime → 发射 → 增量读日志 →
识别 handoff → 识别成功 → `status` 核验 → 退出码 0。

### 5.3 交叉验证

- C 的 `blob dump` 与 `scripts/ghostlock_profile.py dump` 逐键比对：
  **82/82 键一致，无缺失、无值差异**；
- 部署到 mock 设备上的三个文件与包内条目**逐字节相同**（Python 辅助脚本比对）；
- 生成的 `glrun.sh` 过 `sh -n`，并检查关键导出/入口行；
- release 闸门两条路径（拒绝 / `--force` 放行）都验；
- **停火回归**：`MOCK_NO_KSU=1` 时 mock 的 launches 必须是 1——第一次写错的地方
  由这条测试兜住；
- ASAN + UBSAN 构建跑同一套 67 项验收：无内存错误、无 UB；
- 结果：**67/67 通过**（加固前那版），`unmatched.log` 为空；加固改动未重跑。

## 6.1 独立审计后的加固（未重跑测试）

初版完成后做了一次独立代码审计，修了以下问题（属于「正确性/安全」而非新功能）：

| # | 问题 | 修法 |
|---|---|---|
| 1 | `clean --yes --dir /data` 会以 root `rm -rf /data` | clean 只接受 `/data/local/tmp/<非空子目录>`，其余直接拒绝 |
| 2 | 单次 4 s `echo ping` 超时被当成重启；且先判 dropped 后判 handoff，可能丢掉已看到的 handoff 并二次发射 | 连续 3 次失败才判掉线；handoff/soft 优先于 dropped；掉线恢复后要求 uptime 归零才继续 |
| 3 | 推不出 release 时静默跳过闸门；已部署的 payload 只比大小，OTA 后不复检 | 推不出 release = 拒绝（`--force` 才放行）；`run` 在发射前总是复检 release |
| 4 | `.rc` 出现后的最后一段日志不再判成功标记 | 最后一段 native 日志 + 一次补读 ksu 日志后重新判 win/fail/handoff |
| 5 | `gl_exec` 超时后 `waitpid` 可能永久阻塞；`read()` 的 EINTR 被当成 EOF | SIGKILL 后 WNOHANG 有界回收（5 s）；EINTR 不再置 EOF |
| 6 | `/tmp/glrel.<pid>` 可预测临时文件 | 改成直接 `fread` 包内 release.txt，不再写临时文件 |
| 7 | 只给 install 参数时默认落到 `run` | 检测到 install 专属参数即选 `install` |
| 8 | `--profile-file` 等值进入设备 shell 前未校验 | 字符集/整数校验；`--dump-kernel-log` 限定绝对路径字符集 |
| 9 | `--kmi` 没有消费者，`.gl_kmi` / `.gl_ksu_pkg` 从不写 | deploy 时写入这两个提示文件；`--window/--cycle-wait/--handoff-wait` 下限 1 |
| 10 | `--clean-after` 硬编码 `profile.bin`，漏 `profile.len` 等 | 按 `--profile-file` 生成清单，补 `profile.len/incoming.ko/.last_ts` |

**这些改动按要求没有重跑测试套件**：`make test` 的 67 项结果属于加固前那版；上真机前
应先跑一遍。改动本身都很局部，但「没跑 = 没验证」这条不例外。

## 6. 未验证项与风险

1. **没有在 PD2338 真机上跑过这一版二进制。** 本次开发环境无设备。C 版发送的是
   v1.1 已经实测过的同一组命令（同一 `glrun.sh` 语义、同一 payload、同一 profile），
   但「同一命令序列」不等于「同样打过真机」。
2. **`--app-call` 路径**：与 Python 版一样只有 App 侧证据，未在真机验证；
   默认入口仍是 `--load-prebuilt-profile`。
3. **`install` 的 insmod/late-load** 只做了 dry-run 与命令生成检查；真机加载
   依赖设备的 ksud 与 KMI，mock 不模拟内核模块。
4. **adb 版本差异**：`adb shell` 的引号/换行行为在旧版本上可能不同；C 版对
   stdout 统一去 `\r`，与脚本的 `tr -d '\r'` 一致。
5. **macOS**：代码是 POSIX，未在 macOS 上编译/运行；v1.1 的 macOS 兼容问题
   （GNU `timeout`/`dd`/`sed`）在 C 版结构上不存在，但仍属未测。
6. **profile 生成**不在 C 版范围内，`consumer.max_calls=0` 的坑仍然只由
   `ghostlock_profile.py` 的告警覆盖；C 版 `blob check` 能看出值，但不会替你修。

## 7. 建议的下一步

- 真机小步验证：`check` → `deploy --redeploy` → `run --rounds 2`；
- 给 `run` 加机器可读输出（`--json`），便于和其他驱动做 A/B；
- 若要彻底去掉 Python：把 `ghostlock_profile.py` 的 `.conf` → blob 也用 C 实现，
  需要一个小型 HOCON 子集解析器（这份 conf 只用到 `key = value`、嵌套块与注释）；
- 增加 `shell` 交互子命令（复用 `cmd_exec` 的 `.gl_cmd` 轮询）；
- 在 CI 里跑 `make test`（mock 不需要设备，成本很低）。

## 8. 文件清单

| 路径 | 作用 |
|---|---|
| `c/Makefile` | `all` / `test` / `static` / `install` / `clean` |
| `c/include/gl.h` | 公共类型与声明 |
| `c/src/*.c` | 见 [`../c/README.md`](../c/README.md) 的目录树 |
| `c/tests/mock-adb.py` | 离线 adb 替身 |
| `c/tests/run-tests.sh` | 64 项验收 |
| `docs/C-PORT.md` | 本文 |
