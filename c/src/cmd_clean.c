/*
 * cmd_clean.c -- clean our own residue on the device (parity with clean.sh).
 *
 * Dry-run by default. This deletes OUR deployed files and logs, which is the
 * documented cleanup path; it refuses to touch the system and requires --yes.
 */
#include "internal.h"

#include <stdlib.h>
#include <string.h>

static bool dev_exists(const gl_adb *a, const char *path)
{
    char *cmd = xasprintf("test -e '%s' && echo y", path);
    char *out = gl_adb_sh_out(a, cmd, 8000);
    free(cmd);
    bool yes = out && strstr(out, "y") != NULL;
    free(out);
    return yes;
}

static char *dev_human(const gl_adb *a, const char *path)
{
    char *cmd = xasprintf("du -sh '%s' 2>/dev/null | cut -f1", path);
    char *out = gl_adb_sh_out(a, cmd, 10000);
    free(cmd);
    return out;
}

static char *dev_as_root(const gl_adb *a, bool is_root, const char *cmd)
{
    if (!is_root) return gl_adb_sh_out(a, cmd, 20000);
    char *wrapped = xasprintf("su -c '%s'", cmd);
    char *out = gl_adb_sh_out(a, wrapped, 20000);
    free(wrapped);
    return out;
}

int cmd_clean(void)
{
    char *serial = gl_env_serial();
    gl_adb a2 = {g_opt.adb_bin, serial};

    bool is_root = gl_is_root(&a2);
    char *ksu_cnt = gl_adb_sh_out(&a2, "grep -c kernelsu /proc/modules", 10000);
    char *vr_cnt = gl_adb_sh_out(&a2, "grep -c '^vr ' /proc/modules", 10000);
    char *selinux = gl_adb_sh_out(&a2, "getenforce", 10000);
    char *procs = gl_adb_sh_out(&a2, "ps -A 2>/dev/null | grep -c libghostlock.so", 10000);

    say("==============================================================");
    say(" 清理清单（%s）", g_opt.yes ? "执行模式 --yes" : "DRY-RUN，只列不动手");
    say("==============================================================");
    blank();
    say("[内存态] reboot 即消失，不删文件：");
    say("  kernelsu 模块      : %s （1=仍在）", ksu_cnt ? ksu_cnt : "?");
    say("  vr 模块            : %s （1=仍在）", vr_cnt ? vr_cnt : "?");
    say("  SELinux            : %s", selinux ? selinux : "?");
    blank();
    say("[磁盘态] 要删的：");

    const char *targets[8];
    const char *labels[8];
    int n = 0;
    targets[n] = g_opt.dev_dir;
    labels[n++] = "payload+日志+root脚本";
    const char *test_dirs[] = {
        "/data/local/tmp/gl-selftest",
        "/data/local/tmp/gl-pack-test",
        "/data/local/tmp/gl-mac-test",
        NULL,
    };
    for (int i = 0; test_dirs[i]; i++) {
        targets[n] = test_dirs[i];
        labels[n++] = "测试残留";
    }
    if (g_opt.clean_ksu) {
        targets[n] = "/data/adb/ksud";
        labels[n++] = "KSU 用户态";
        targets[n] = "/data/adb/ksu";
        labels[n++] = "KSU 用户态目录";
    } else {
        say("  (KSU 用户态 /data/adb/ksud + /data/adb/ksu 未选：加 --ksu 才删，约 91 MB)");
    }
    if (g_opt.clean_uninstall) say("  * 卸载管理器：com.resukisu.resukisu");

    char **plan = xcalloc((size_t)n, sizeof *plan);
    for (int i = 0; i < n; i++) {
        bool ex = dev_exists(&a2, targets[i]);
        if (ex) {
            char *h = dev_human(&a2, targets[i]);
            say("  %d) %s   (%s) 体积=%s", i + 1, targets[i], labels[i],
                h ? h : "?");
            free(h);
            plan[i] = xstrdup(targets[i]);
        } else {
            say("  %d) %s   (不存在，跳过)", i + 1, targets[i]);
        }
    }
    blank();
    say("[残留进程] %s 个 libghostlock.so", procs ? procs : "?");
    if (g_opt.clean_reboot) say("[收尾] 删除后执行 reboot（清内核态，root 同时消失）");

    if (!g_opt.yes) {
        blank();
        say("以上只是清单。确认无误后执行：");
        say("  %s clean --yes%s%s%s", "ghostlock", g_opt.clean_ksu ? " --ksu" : "",
            g_opt.clean_uninstall ? " --uninstall" : "",
            g_opt.clean_reboot ? " --reboot" : "");
        for (int i = 0; i < n; i++) free(plan[i]);
        free(plan);
        free(serial);
        free(ksu_cnt);
        free(vr_cnt);
        free(selinux);
        free(procs);
        return 0;
    }

    say("==============================================================");
    say(" 开始执行（root=%s）", is_root ? "有" : "无");
    say("==============================================================");

    msg_step("停止残留的 exploit 进程");
    dev_as_root(&a2, is_root, "pkill -f libghostlock.so");
    dev_as_root(&a2, is_root, "pkill -f ghostlock_root.sh");
    msleep(1000);

    for (int i = 0; i < n; i++) {
        if (!plan[i]) continue;
        if (!dev_exists(&a2, plan[i])) continue;
        msg_step("删除 %s", plan[i]);
        char *cmd = xasprintf("rm -rf '%s'", plan[i]);
        char *out = dev_as_root(&a2, is_root, cmd);
        free(cmd);
        free(out);
        if (dev_exists(&a2, plan[i])) {
            say("    [!] 删不掉（多半是 root 属主而当前没有 root）；先确保 root 还在再跑一次");
        } else {
            say("    ok");
        }
    }

    if (g_opt.clean_uninstall) {
        msg_step("卸载 com.resukisu.resukisu");
        gl_adb_uninstall(&a2, "com.resukisu.resukisu", 120000);
    }

    blank();
    say("==============================================================");
    say(" 清理结果");
    say("==============================================================");
    say("  工作目录存在? %s", dev_exists(&a2, g_opt.dev_dir) ? "是" : "否");
    say("  KSU 用户态?   %s", dev_exists(&a2, "/data/adb/ksu") ? "是" : "否");
    char *chk = xasprintf(
        "pm list packages 2>/dev/null | grep -q com.resukisu.resukisu && echo 是 || echo 否");
    char *inst = gl_adb_sh_out(&a2, chk, 10000);
    free(chk);
    say("  管理器安装?   %s", inst ? inst : "?");
    free(inst);
    char *kc = gl_adb_sh_out(&a2, "grep -c kernelsu /proc/modules", 10000);
    char *se = gl_adb_sh_out(&a2, "getenforce", 10000);
    say("  kernelsu 模块: %s （1=仍在内存里）", kc ? kc : "?");
    say("  SELinux      : %s", se ? se : "?");
    free(kc);
    free(se);

    if (g_opt.clean_reboot) {
        blank();
        msg_step("reboot（内核态随之清空，root 消失）");
        gl_adb_reboot(&a2);
        say("done");
    } else {
        blank();
        say("内核态还在内存里。要彻底回到干净系统：");
        say("  adb reboot     （或 ghostlock clean --yes --all --reboot）");
    }

    for (int i = 0; i < n; i++) free(plan[i]);
    free(plan);
    free(serial);
    free(ksu_cnt);
    free(vr_cnt);
    free(selinux);
    free(procs);
    return 0;
}
