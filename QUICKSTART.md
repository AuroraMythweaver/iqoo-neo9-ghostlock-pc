# 怎么用（iQOO Neo9 / PD2338 重新 root）

本仓库根目录下只有两个文件要用：

```
reroot.sh        脚本（纯 bash + adb）
ghostlock.bin    payload 包（libghostlock.so + vrpatch.ko + profile.bin）
```

```bash
git clone <this-repo> && cd <repo>

./reroot.sh                  # 最多 10 轮：重启 → 抢开机窗口 → 命中即停
./reroot.sh 20               # 多刷几轮
./reroot.sh --no-reboot      # 设备刚重启过 / 手动重启完：直接抢窗口
./reroot.sh --check          # 只看当前有没有 root（不会重启）
./reroot.sh --inspect        # 看包里有什么
./reroot.sh --deploy         # 只布署 payload，不打
./reroot.sh --check-payload  # 看设备上 payload 是否已就绪
```

成功后：

```bash
adb shell su -c 'id'        # uid=0(root) context=u:r:ksu:s0
```

注意：`late-load` 只在内存里，**重启就没了**，重启后再跑一次 `./reroot.sh` 即可；
`vrpatch.ko` 的补丁在软重启后存活。

细节见 `ghostlock-pc-port.md`（§8 实战、§9 与作者帖子核对）和 `scripts/README.md`。
