/*
 * cmd_basic.c -- inspect / check / status / pull-log / blob.
 */
#include "internal.h"

#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* ---------------------------------------------------------------- inspect */

int cmd_inspect(void)
{
    gl_pack p;
    if (gl_pack_open(g_opt.pack, &p) != 0) return 2;
    say("包：%s  (%llu B, %u 个条目, format=%u)", p.path,
        (unsigned long long)p.file_size, p.n_entries, p.format);
    for (uint32_t i = 0; i < p.n_entries; i++) {
        const gl_pack_entry *e = &p.entries[i];
        if (str_eq(e->name, "release.txt")) {
            gl_buf b;
            gl_buf_init(&b);
            if (gl_pack_read(&p, e, &b) == 0) {
                char *t = str_trim(b.p ? b.p : "");
                say("  %-18s %8llu B   %s", e->name,
                    (unsigned long long)e->size, t);
            }
            gl_buf_free(&b);
        } else {
            say("  %-18s %8llu B", e->name, (unsigned long long)e->size);
        }
    }
    gl_pack_close(&p);
    return 0;
}

/* ------------------------------------------------------------------ check */

static char *device_profile_release(const gl_adb *a, const char *path)
{
    char *cmd = xasprintf(
        "dd if='%s' bs=1 skip=12 count=2 2>/dev/null | od -An -tu1", path);
    char *out = gl_adb_sh_out(a, cmd, 10000);
    free(cmd);
    if (!out) return NULL;
    int v0 = -1, v1 = -1;
    sscanf(out, "%d %d", &v0, &v1);
    free(out);
    if (v0 < 0 || v1 < 0) return NULL;
    int len = v0 | (v1 << 8);
    if (len <= 0 || len > 255) return NULL;
    cmd = xasprintf("dd if='%s' bs=1 skip=16 count=%d 2>/dev/null", path, len);
    char *rel = gl_adb_sh_out(a, cmd, 10000);
    free(cmd);
    if (!rel) return NULL;
    char *t = str_trim(rel);
    if (t != rel) memmove(rel, t, strlen(t) + 1);
    return rel;
}

int cmd_check(void)
{
    char *serial = gl_env_serial();
    gl_adb a2 = {g_opt.adb_bin, serial};

    char *uname_r = gl_adb_sh_out(&a2, "uname -r", 10000);
    char *abi = gl_adb_sh_out(&a2, "getprop ro.product.cpu.abi", 10000);
    char *model = gl_adb_sh_out(&a2, "getprop ro.product.model", 10000);
    char *sdk = gl_adb_sh_out(&a2, "getprop ro.build.version.sdk", 10000);
    char *id = gl_adb_sh_out(&a2, "id", 10000);
    char *selinux = gl_adb_sh_out(&a2, "getenforce 2>/dev/null || echo unknown", 10000);
    char *sec = gl_adb_sh_out(&a2, "grep -i '^Seccomp' /proc/self/status 2>/dev/null", 10000);
    char *lscmd = xasprintf("ls -ld %s 2>/dev/null", g_opt.dev_dir);
    char *dir = gl_adb_sh_out(&a2, lscmd, 10000);
    free(lscmd);

    say("serial     : %s", serial);
    say("uname -r   : %s", uname_r ? uname_r : "?");
    say("abi        : %s", abi ? abi : "?");
    say("model      : %s", model ? model : "?");
    say("sdk        : %s", sdk ? sdk : "?");
    say("uid        : %s", id ? id : "?");
    say("selinux    : %s", selinux ? selinux : "?");
    say("seccomp    : %s", (sec && *sec) ? sec : "(unreadable)");
    if (sec && *sec && !strstr(sec, "Seccomp:\t0") && !strstr(sec, "Seccomp: 0")) {
        msg_warn("adb shell 进程带 seccomp 过滤。App 的 Shizuku 路径要求 Seccomp=0；");
        say("     若本机 adb 子进程被加了过滤，W3 阶段会失败（可先跑一次看日志）。");
    }
    say("dir        : %s", (dir && *dir) ? dir : "(not created)");

    int rc = 0;
    char *profpath = xasprintf("%s/%s", g_opt.dev_dir, gl_opt_profile_name(&g_opt));
    char *havecmd = xasprintf("test -f %s && echo yes", profpath);
    char *have = gl_adb_sh_out(&a2, havecmd, 10000);
    free(havecmd);
    if (!have || !strstr(have, "yes")) {
        say("profile    : missing (run deploy)");
        rc = 1;
    } else {
        char *prel = device_profile_release(&a2, profpath);
        if (!prel) {
            say("profile    : present (header unreadable)");
            rc = 1;
        } else {
            say("profile    : %s (release=%s)", profpath, prel);
            if (uname_r && str_eq(prel, uname_r)) {
                say("match      : YES  (uname -r == profile.release)");
            } else {
                say("match      : *** NO ***");
                say("  设备 uname -r  : %s", uname_r ? uname_r : "?");
                say("  profile release: %s", prel);
                msg_warn("offset 不匹配时漏洞打失败会 panic 重启（设备会自行恢复）");
                rc = 3;
            }
        }
        free(prel);
    }
    free(profpath);
    free(have);
    free(serial);
    free(uname_r);
    free(abi);
    free(model);
    free(sdk);
    free(id);
    free(selinux);
    free(sec);
    free(dir);
    return rc;
}

/* ----------------------------------------------------------------- status */

int cmd_status(void)
{
    char *serial = gl_env_serial();
    gl_adb a2 = {g_opt.adb_bin, serial};

    char *id = gl_adb_sh_out(&a2, "id", 10000);
    char *selinux = gl_adb_sh_out(&a2, "getenforce 2>/dev/null || echo unknown", 10000);
    char *mods = gl_adb_sh_out(
        &a2, "cat /proc/modules 2>/dev/null | grep -i kernelsu || echo '(none / unreadable)'", 10000);
    char *su = gl_adb_sh_out(&a2, "su -c id 2>/dev/null || echo '(su failed)'", 10000);
    char *ksud = gl_adb_sh_out(&a2, "ls -l /data/adb/ksu/bin/ksud 2>/dev/null || echo '(no ksud)'", 10000);
    char *cmd = xasprintf(
        "L=$(ls -t %s/ksu-*.log 2>/dev/null | head -1); "
        "[ -n \"$L\" ] && { echo \"== $L\"; tail -n 25 \"$L\"; } || echo '(no ksu log)'",
        g_opt.dev_dir);
    char *ksulog = gl_adb_sh_out(&a2, cmd, 15000);
    free(cmd);

    say("id        : %s", id ? id : "?");
    say("selinux   : %s", selinux ? selinux : "?");
    say("kernelsu  : %s", mods ? mods : "?");
    say("ksud      : %s", ksud ? ksud : "?");
    say("su -c id  : %s", su ? su : "?");
    say("--- KSU log tail ---");
    say("%s", ksulog ? ksulog : "(none)");

    bool root = (su && strstr(su, "uid=0")) || (id && strstr(id, "uid=0(root)"));
    say("root      : %s", root ? "YES" : "NO");
    if (root) {
        blank();
        say("提示: su 是否长期可用取决于 KernelSU 模块是否 late-load 成功；");
        say("      'kernelsu' 行出现在 /proc/modules 里才算持久化生效。");
    }

    free(serial);
    free(id);
    free(selinux);
    free(mods);
    free(su);
    free(ksud);
    free(ksulog);
    return root ? 0 : 1;
}

/* --------------------------------------------------------------- pull-log */

int cmd_pull_log(const char *out_dir)
{
    char *serial = gl_env_serial();
    gl_adb a2 = {g_opt.adb_bin, serial};

    const char *out = out_dir && *out_dir ? out_dir : "ghostlock-logs";
    if (mkdir_p(out, 0755) != 0) {
        msg_warn("建目录失败：%s", out);
        free(serial);
        return 1;
    }

    char *cmd = xasprintf("ls %s/*.log %s/*.rc 2>/dev/null", g_opt.dev_dir,
                          g_opt.dev_dir);
    char *listing = gl_adb_sh_out(&a2, cmd, 15000);
    free(cmd);
    if (!listing || !*listing) {
        say("no logs on device");
        free(listing);
        free(serial);
        return 1;
    }

    int pulled = 0;
    char *copy = xstrdup(listing);
    char *save = NULL;
    for (char *line = strtok_r(copy, "\n", &save); line;
         line = strtok_r(NULL, "\n", &save)) {
        char *f = str_trim(line);
        if (!*f) continue;
        char *local = path_join(out, base_name(f));
        if (gl_adb_pull(&a2, f, local, 120000) == 0) pulled++;
        free(local);
    }
    free(copy);
    free(listing);
    free(serial);
    say("pulled %d files -> %s", pulled, out);
    return pulled > 0 ? 0 : 1;
}
