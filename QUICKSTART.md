# 怎么用（iQOO Neo9 / PD2338 · OriginOS 6「橘子 6」特化版）

> 原作者（酷安）：<https://www.coolapk.com/U/43561117>
> 原文：《vivo iQOO Neo9 (PD2338) Root 研究》<https://www.coolapk.com/feed/74180094>
> GhostLock 原项目：[YuKongA/ghostlock-app](https://github.com/YuKongA/ghostlock-app)
>
> `ghostlock.bin` **只适用于** iQOO Neo9（PD2338）+ OriginOS 6 16.2.13.2 +
> 内核 `5.15.197-g708015331567-dirty`。换机型/固件请勿直接使用（会 panic）。
> 仅供自有设备学习研究，风险自担。

## 30 秒手机侧准备

1. **USB 数据线连电脑**（数据线，不是仅充电线），`adb devices` 能看到 `device`
2. 开发者选项 → **USB 调试**打开，弹窗勾"始终允许这台电脑"
3. 开发者选项 → **停止限制子进程**（后台进程限制设"标准"）
4. **去掉锁屏密码** + **去掉所有锁屏**
5. 开发者选项 → **默认 USB 配置 = 文件传输（MTP）**；建议屏幕常亮、关省电

不需要装 GhostLock App / Shizuku。

## 解压后有什么

```
ghostlock-pc-v1.2/
├── reroot.sh         主脚本（Linux/WSL）
├── reroot-mac.sh     主脚本（macOS 专用，只依赖系统自带工具）
├── install-ksu.sh    提权后：加载你自己的 .ko、装任意 KSU 管理器
├── clean.sh          清理 / 卸载（默认 dry-run）
├── ghostlock.bin     payload（libghostlock.so + vrpatch.ko + profile.bin）
├── README.md / QUICKSTART.md
└── SHA256SUMS.txt
```

> 包里**不含** KSU 管理器 APK 和 `.ko`：管理器装在手机上，`.ko` 由你自己提供
> （官方 LKM 资产或自己编），详见 README §五。

## 跑

```bash
chmod +x *.sh

./reroot.sh                          # 最多 10 轮：等开机窗口 → 发射 → 命中即停
./reroot.sh --check                  # 只看当前有没有 root（不发射）
./reroot.sh --inspect                # 看 payload 包里有什么
./reroot.sh --deploy                 # 只部署 payload，不打
./reroot.sh --ko 1 --clean-after     # 一条龙：列 ko → 选 → 提权 → 成功后清理 → 退出

# 还没装管理器？把上游 APK 放进来，一条命令装好再跑：
./reroot.sh --install-apk SukiSU_v4.2.1-r1_41049-release.apk --ko 1 --clean-after

# macOS 全程把 reroot.sh 换成 reroot-mac.sh
```

成功后：

```bash
adb shell su -c 'id'                 # uid=0(root) context=u:r:ksu:s0
```

## 之后

```bash
./install-ksu.sh                     # 提权后：列本目录的 ko / 管理器 apk
./install-ksu.sh --ko 1 --install 1  # 加载你的 ko + 装管理器
./clean.sh                           # 清理清单（--yes 才删）
./clean.sh --yes --all --reboot      # 全清 + 重启，回到干净系统
```

`late-load` 只在内存里，**重启就没了**，重启后重跑 `./reroot.sh` 即可。

细节见 `README.md`；实测数据与踩坑记录见 `docs/FIELD-NOTES.md`。
