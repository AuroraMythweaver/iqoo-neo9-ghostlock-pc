/*
 * cmd_install.c -- post-root: load a user-supplied .ko through the manager's
 * own ksud, then bootstrap KernelSU userspace (parity with install-ksu.sh).
 *
 * This never extracts a ko out of an APK: the module is a plain file the user
 * provides, matching the upstream late-load contract.
 */
#include "internal.h"

#include <stdlib.h>
#include <string.h>

static char *list_dir_pretty(const char *dir, const char *suffix, char ***out,
                             int *n)
{
    *out = NULL;
    *n = 0;
    list_files(dir, suffix, out, n);
    gl_buf b;
    gl_buf_init(&b);
    for (int i = 0; i < *n; i++) {
        int64_t sz = 0;
        file_size((*out)[i], &sz);
        gl_buf_addf(&b, "  %d) %s  %lld B\n", i + 1, base_name((*out)[i]),
                    (long long)sz);
    }
    return gl_buf_steal(&b);
}

static int pick_from(int n, char **list, const char *sel, char **out)
{
    *out = NULL;
    if (!sel || !*sel) return -1;
    /* explicit path */
    int64_t sz;
    if (file_size(sel, &sz) == 0) {
        *out = xstrdup(sel);
        return 0;
    }
    bool numeric = true;
    for (const char *q = sel; *q; q++)
        if (*q < '0' || *q > '9') {
            numeric = false;
            break;
        }
    if (numeric) {
        long v = strtol(sel, NULL, 10);
        if (v >= 1 && v <= n) {
            *out = xstrdup(list[v - 1]);
            return 0;
        }
        return -1;
    }
    for (int i = 0; i < n; i++)
        if (str_eq(base_name(list[i]), sel)) {
            *out = xstrdup(list[i]);
            return 0;
        }
    for (int i = 0; i < n; i++)
        if (strstr(list[i], sel)) {
            *out = xstrdup(list[i]);
            return 0;
        }
    return -1;
}

static char *managers(const gl_adb *a)
{
    char *out = gl_adb_sh_out(
        a,
        "pm list packages 2>/dev/null | sed -n 's/^package://p' | "
        "grep -iE 'sukisu|resukisu|bakasu|kernelsu|ksunext|supermanager'",
        20000);
    if (!out) return xstrdup("");
    for (char *p = out; *p; p++)
        if (*p == '\n') *p = ' ';
    return out;
}

static char *find_ksud(const gl_adb *a, const char *explicit_path, const char *mgrs)
{
    if (explicit_path && *explicit_path) return xstrdup(explicit_path);
    /* 1) libksud.so inside an installed manager APK (same build as the APK) */
    if (mgrs && *mgrs) {
        char *copy = xstrdup(mgrs);
        char *save = NULL;
        for (char *pkg = strtok_r(copy, " ", &save); pkg;
             pkg = strtok_r(NULL, " ", &save)) {
            char *cmd = xasprintf(
                "su -c \"ls -d /data/app/*/%s-*/lib/arm64/libksud.so 2>/dev/null | head -1\"",
                pkg);
            char *out = gl_adb_sh_out(a, cmd, 15000);
            free(cmd);
            if (out) {
                char *t = str_trim(out);
                if (*t) {
                    char *res = xstrdup(t);
                    free(out);
                    free(copy);
                    return res;
                }
                free(out);
            }
        }
        free(copy);
    }
    /* 2) conventional locations */
    const char *cands[] = {"/data/adb/ksu/bin/ksud", "/data/adb/ksud",
                           "/data/local/tmp/ksud", NULL};
    for (int i = 0; cands[i]; i++) {
        char *cmd = xasprintf("su -c \"test -x '%s' && echo y\"", cands[i]);
        char *out = gl_adb_sh_out(a, cmd, 10000);
        free(cmd);
        bool yes = out && strstr(out, "y") != NULL;
        free(out);
        if (yes) return xstrdup(cands[i]);
    }
    return NULL;
}

static char *kmi_for(const char *uname_r)
{
    int major = 0, minor = 0;
    if (sscanf(uname_r, "%d.%d", &major, &minor) != 2) return xstrdup("android13-5.15");
    if (major == 5 && minor == 15) return xstrdup("android13-5.15");
    if (major == 5 && minor == 10) return xstrdup("android13-5.10");
    if (major == 6 && minor == 1) return xstrdup("android14-6.1");
    if (major == 6 && minor == 6) return xstrdup("android15-6.6");
    if (major == 6 && minor == 12) return xstrdup("android16-6.12");
    return xasprintf("%d-%d", major, minor);
}

int cmd_install(void)
{
    char *ko_dir = g_opt.ko_dir ? xstrdup(g_opt.ko_dir) : dir_name(g_opt.pack);

    char **kos = NULL, **apks = NULL;
    int nko = 0, napk = 0;
    char *kos_txt = list_dir_pretty(ko_dir, ".ko", &kos, &nko);
    char *apks_txt = list_dir_pretty(ko_dir, ".apk", &apks, &napk);

    say("==============================================================");
    say(" install-ksu   目录: %s", ko_dir);
    say("==============================================================");
    blank();
    say("[本目录的 ko]");
    if (nko == 0) {
        say("  （没有 .ko）—— 把你这份机型对应的 xxx_kernelsu.ko 放进 %s 再跑", ko_dir);
    } else {
        fputs(kos_txt, stdout);
    }
    blank();
    say("[本目录的 APK]");
    if (napk == 0) {
        say("  （没有 .apk）—— 管理器安装包放这里就能直接装");
    } else {
        fputs(apks_txt, stdout);
    }

    char *serial = gl_env_serial();
    gl_adb a2 = {g_opt.adb_bin, serial};

    char *uname_r = gl_adb_sh_out(&a2, "uname -r", 10000);
    char *cnt = gl_adb_sh_out(&a2, "grep -c kernelsu /proc/modules", 10000);
    char *suid = gl_adb_sh_out(&a2, "su -c id -u 2>/dev/null | head -1", 10000);
    char *mgrs = managers(&a2);

    blank();
    say("[设备状态]");
    say("  uname      : %s", uname_r ? uname_r : "?");
    say("  kernelsu   : %s  （1=内核里已有一个）", cnt ? cnt : "?");
    say("  su         : %s  （0=当前有 root）", suid ? suid : "?");
    say("  管理器     : %s", mgrs && *mgrs ? mgrs : "(none)");

    if (!g_opt.ko_sel && !g_opt.apk_sel) {
        blank();
        say("以上只是预览。用法示例：");
        say("  ghostlock install --ko 1                          # 提权后加载第 1 个 ko");
        say("  ghostlock install --ko 1 --install 1              # 加载 + 装管理器");
        say("  ghostlock install --persist --ko 1                # 以后每次 run 都用这个 ko（需重启生效）");
        free(ko_dir);
        free(kos_txt);
        free(apks_txt);
        free_list(kos, nko);
        free_list(apks, napk);
        free(serial);
        free(uname_r);
        free(cnt);
        free(suid);
        free(mgrs);
        return 0;
    }

    bool has_root = suid && str_eq(str_trim(suid), "0");
    if (!has_root) {
        blank();
        msg_warn("当前没有 root。先跑：ghostlock run（抢到窗口后再回来执行本命令）");
        free(ko_dir);
        free(kos_txt);
        free(apks_txt);
        free_list(kos, nko);
        free_list(apks, napk);
        free(serial);
        free(uname_r);
        free(cnt);
        free(suid);
        free(mgrs);
        return 4;
    }

    char *ksud = find_ksud(&a2, g_opt.ksud_path, mgrs);
    if (!ksud) {
        blank();
        msg_warn("设备上找不到 ksud（加载器）。先装任意一个 KSU 管理器 APK，或 --ksud 指定路径");
        free(ko_dir);
        free(kos_txt);
        free(apks_txt);
        free_list(kos, nko);
        free_list(apks, napk);
        free(serial);
        free(uname_r);
        free(cnt);
        free(suid);
        free(mgrs);
        return 5;
    }

    char *ko = NULL, *apk = NULL;
    if (g_opt.ko_sel && pick_from(nko, kos, g_opt.ko_sel, &ko) != 0) {
        msg_warn("找不到 ko: %s（可用：%s）", g_opt.ko_sel, kos_txt);
        free(ksud);
        free(uname_r);
        return 6;
    }
    if (g_opt.apk_sel && pick_from(napk, apks, g_opt.apk_sel, &apk) != 0) {
        msg_warn("找不到 apk: %s（可用：%s）", g_opt.apk_sel, apks_txt);
        free(ksud);
        free(ko);
        free(uname_r);
        return 7;
    }

    blank();
    say("[计划]");
    say("  loader(ksud) : %s", ksud);
    if (ko) {
        int64_t sz = 0;
        file_size(ko, &sz);
        say("  加载 ko      : %s  (%lld B)", base_name(ko), (long long)sz);
    }
    if (apk) say("  安装管理器   : %s", base_name(apk));
    if (g_opt.persist)
        say("  持久化       : 写 %s/ksud wrapper（以后 run 都用这个 ko）",
            g_opt.dev_dir);
    blank();
    if (g_opt.dry_run) {
        say("[dry-run] 到此为止，什么都没做。去掉 --dry-run 才会执行。");
        free(ko_dir);
        free(kos_txt);
        free(apks_txt);
        free_list(kos, nko);
        free_list(apks, napk);
        free(serial);
        free(uname_r);
        free(cnt);
        free(suid);
        free(mgrs);
        free(ksud);
        free(ko);
        free(apk);
        return 0;
    }
    if (!g_opt.yes) {
        printf("[?] 3 秒后开始（Ctrl-C 取消）…");
        fflush(stdout);
        msleep(3000);
        printf("\n");
    }

    int rc = 0;
    if (ko) {
        char *cur = gl_adb_sh_out(&a2, "grep -c kernelsu /proc/modules", 10000);
        if (cur && str_eq(str_trim(cur), "1")) {
            msg_info("内核里已有 kernelsu 模块 —— 同一个内核里不能有两个，跳过 insmod");
            say("    要换成 %s，必须：ghostlock install --persist --ko %s → adb reboot → ghostlock run",
                base_name(ko), g_opt.ko_sel);
        } else {
            char *remote = xasprintf("%s/incoming.ko", g_opt.dev_dir);
            msg_step("push ko → %s", remote);
            if (gl_adb_push(&a2, ko, remote, 120000) != 0) {
                msg_warn("push 失败");
                rc = 8;
            } else {
                char *cmd = xasprintf("su -c \"chmod 644 '%s'\"", remote);
                char *o = gl_adb_sh_out(&a2, cmd, 10000);
                free(cmd);
                free(o);
                msg_step("insmod（ksuinit loader，vermagic 自动适配）");
                cmd = xasprintf("su -c \"'%s' insmod '%s' allow_shell=1 2>&1\"", ksud,
                                remote);
                char *out = gl_adb_sh_out(&a2, cmd, 60000);
                free(cmd);
                if (out && *out) say("    %s", out);
                free(out);
                bool ok = false;
                for (int i = 0; i < 50; i++) {
                    char *c = gl_adb_sh_out(&a2, "grep -c kernelsu /proc/modules", 8000);
                    bool one = c && str_eq(str_trim(c), "1");
                    free(c);
                    if (one) {
                        ok = true;
                        break;
                    }
                    msleep(100);
                }
                if (ok) msg_ok("kernelsu 已加载");
                else {
                    msg_warn("加载失败（ko 与内核符号/CRC 不匹配？）——看上面 insmod 输出；不会破坏系统分区");
                    rc = 9;
                }
            }
            free(remote);
        }
        free(cur);

        /* bootstrap: with the module already in, late-load only installs userspace */
        char *pkg = NULL;
        if (g_opt.ksu_pkg && *g_opt.ksu_pkg) pkg = xstrdup(g_opt.ksu_pkg);
        else {
            char *m = xstrdup(mgrs ? mgrs : "");
            char *sp = strchr(m, ' ');
            if (sp) *sp = '\0';
            char *t = str_trim(m);
            pkg = xstrdup(*t ? t : "com.sukisu.ultra");
            free(m);
        }
        char *kmi = kmi_for(uname_r ? uname_r : "");
        msg_step("bootstrap：ksud late-load --package-name %s --kmi %s（只做用户态安装）",
                 pkg, kmi);
        char *cmd = xasprintf(
            "su -c \"'%s' late-load --allow-shell --package-name '%s' --kmi '%s' "
            ">/dev/null 2>&1\"",
            ksud, pkg, kmi);
        char *o = gl_adb_sh_out(&a2, cmd, 60000);
        free(cmd);
        free(o);
        msleep(1000);
        cmd = xasprintf("su -c \"'%s' debug info 2>/dev/null\"", ksud);
        char *info = gl_adb_sh_out(&a2, cmd, 30000);
        free(cmd);
        if (info) {
            for (char *p = info; *p; p++)
                if (*p == '\n') *p = ' ';
            say("    内核信息：%.160s", info);
        }
        free(info);
        free(pkg);
        free(kmi);

        if (g_opt.persist) {
            msg_step("持久化：%s/user.ko + ksud wrapper", g_opt.dev_dir);
            if (gl_install_ko_wrapper(&a2, &g_opt, ko) != 0) {
                msg_warn("持久化失败");
                rc = 8;
            } else {
                msg_ok("已持久化：%s/ksud（wrapper）+ %s/user.ko", g_opt.dev_dir,
                       g_opt.dev_dir);
                say("    之后每次 run 都会用这个 ko 去 late-load");
                say("    注意：若安装了 root 脚本候选列表里的管理器（如 com.resukisu.resukisu），");
                say("          脚本会优先用它 APK 内的 ksud，wrapper 可能被绕过");
            }
        }
    }

    if (apk) {
        blank();
        msg_step("安装管理器：%s", base_name(apk));
        int r = gl_adb_install(&a2, apk, 180000);
        if (r != 0) msg_warn("安装失败（签名冲突？先 adb uninstall 旧管理器）");
    }

    blank();
    say("==============================================================");
    say(" 结果");
    say("==============================================================");
    char *c2 = gl_adb_sh_out(&a2, "grep -c kernelsu /proc/modules", 10000);
    char *s2 = gl_adb_sh_out(&a2, "su -c id 2>/dev/null | head -1", 10000);
    char *m2 = managers(&a2);
    char *cmd = xasprintf("su -c \"'%s' debug info 2>/dev/null\"", ksud);
    char *info = gl_adb_sh_out(&a2, cmd, 30000);
    free(cmd);
    if (info)
        for (char *p = info; *p; p++)
            if (*p == '\n') *p = ' ';
    say("  kernelsu   : %s", c2 ? c2 : "?");
    say("  su         : %s", s2 ? s2 : "?");
    say("  内核信息   : %.200s", info ? info : "?");
    say("  已装管理器 : %s", m2 && *m2 ? m2 : "(none)");
    blank();
    say(" 管理器打开后：若显示「需要更新内核」，说明 管理器uapi > 内核uapi，");
    say(" 换一个与该内核 ko 同版本的官方管理器 APK；若显示「工作中」，两边 uapi 一致。");
    say(" 重启后 late-load 失效，重跑 ghostlock run（带 --persist 的话会用你这份 ko）。");

    free(c2);
    free(s2);
    free(m2);
    free(info);
    free(ko_dir);
    free(kos_txt);
    free(apks_txt);
    free_list(kos, nko);
    free_list(apks, napk);
    free(serial);
    free(uname_r);
    free(cnt);
    free(suid);
    free(mgrs);
    free(ksud);
    free(ko);
    free(apk);
    return rc;
}
