# 怎么用（iQOO Neo9 / PD2338 · OriginOS 6「橘子 6」特化版）

> 原作者（酷安）：<https://www.coolapk.com/U/43561117>
> 原文：《vivo iQOO Neo9 (PD2338) Root 研究》<https://www.coolapk.com/feed/74180094>
> GhostLock 原项目：[YuKongA/ghostlock-app](https://github.com/YuKongA/ghostlock-app)
>
> 本仓库的 `ghostlock.bin` **只适用于** iQOO Neo9（PD2338）+ OriginOS 6 16.2.13.2 +
> 内核 `5.15.197-g708015331567-dirty`。换机型/固件请勿直接使用（会 panic）。
> 仅供自有设备学习研究，**风险自担**，完整条款见 README 的《免责声明》。

## 先用 30 秒做完手机侧准备

1. **USB 数据线连电脑**（数据线，不是仅充电线），`adb devices` 能看到 `device`；
2. 开发者选项 → **USB 调试**打开，弹窗勾"始终允许这台电脑"；
3. 开发者选项 → **停止限制子进程**（后台进程限制设"标准"）；
4. **去掉锁屏密码** + **去掉所有锁屏**（含"卡屏即进入系统"）；
5. 开发者选项 → **默认 USB 配置 = 文件传输（MTP）**；建议屏幕常亮、关省电。

不需要装 GhostLock App / Shizuku（装过的话先别打开）。成功之后**别重启**。

本仓库根目录下只有两个文件要用：

```
reroot.sh        脚本（纯 bash + adb）
ghostlock.bin    payload 包（libghostlock.so + vrpatch.ko + profile.bin）
```

```bash
git clone <this-repo> && cd <repo>

./reroot.sh                  # 最多 10 轮：等开机窗口 → 发射 → 命中即停（脚本不主动重启）
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

细节见 `README.md`、`docs/PORTING.md`（§8 实战、§9 与作者帖子核对）、`scripts/README.md`。
