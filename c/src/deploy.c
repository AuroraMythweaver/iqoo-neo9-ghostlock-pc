/*
 * deploy.c -- payload staging: release gate, size-based idempotent push, and
 * the optional user-ko wrapper.
 */
#include "internal.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char *const NEEDED[] = {"libghostlock.so", "vrpatch.ko", "profile.bin"};
#define N_NEEDED 3

gl_adb gl_env_adb(void)
{
    gl_adb a;
    a.bin = g_opt.adb_bin;
    a.serial = g_opt.serial;
    return a;
}

/* Resolve the single device (dies with a useful message on ambiguity). */
char *gl_env_serial(void)
{
    gl_adb a = gl_env_adb();
    char *s = gl_pick_device(&a, g_opt.serial);
    g_opt.serial = s;
    return s;
}

const char *gl_opt_profile_name(const gl_opt *o)
{
    return o->profile_file ? o->profile_file : "profile.bin";
}

int gl_load_profile_file(const char *path, gl_profile *prof, char **err)
{
    gl_buf b;
    gl_buf_init(&b);
    if (read_file(path, &b) != 0) {
        if (err) *err = xasprintf("读不到 %s: %s", path, strerror(errno));
        gl_buf_free(&b);
        return -1;
    }
    int rc = gl_profile_parse(b.p, b.len, prof, err);
    if (rc == 0) {
        /* keep release readable for callers; parse already NUL-terminates */
    }
    gl_buf_free(&b);
    return rc;
}

/*
 * Release the payload must match: the blob's own release (what native checks),
 * falling back to release.txt inside the pack.
 */
char *gl_expected_release(const gl_pack *p, const gl_opt *o)
{
    const char *blob_path = o->profile;
    if (blob_path) {
        gl_profile prof;
        char *err = NULL;
        if (gl_load_profile_file(blob_path, &prof, &err) != 0) {
            msg_warn("--profile 解析失败：%s", err ? err : "?");
            free(err);
        } else {
            char *rel = xstrdup(prof.release);
            gl_profile_free(&prof);
            return rel;
        }
    }
    const gl_pack_entry *e = gl_pack_find(p, "release.txt");
    if (e) {
        gl_buf b;
        gl_buf_init(&b);
        char *tmp = xasprintf("/tmp/glrel.%ld", (long)getpid());
        if (gl_pack_extract(p, e, tmp) == 0 && read_file(tmp, &b) == 0) {
            unlink(tmp);
            char *s = str_trim(b.p ? b.p : "");
            char *out = xstrdup(s);
            gl_buf_free(&b);
            return out;
        }
        unlink(tmp);
        gl_buf_free(&b);
    }
    return NULL;
}

static int64_t device_file_size(const gl_adb *a, const char *path)
{
    char *cmd = xasprintf("wc -c < '%s' 2>/dev/null", path);
    char *out = gl_adb_sh_out(a, cmd, 8000);
    free(cmd);
    int64_t sz = -1;
    if (out) {
        char *t = str_trim(out);
        if (*t) sz = strtoll(t, NULL, 10);
    }
    free(out);
    return sz;
}

int gl_need_deploy(const gl_adb *a, const gl_pack *p)
{
    if (g_opt.redeploy) return 1;

    for (int i = 0; i < N_NEEDED; i++) {
        const char *name = NEEDED[i];
        int64_t want = -1;
        if (str_eq(name, "profile.bin") && g_opt.profile) {
            if (file_size(g_opt.profile, &want) != 0) return 1;
        } else {
            const gl_pack_entry *e = gl_pack_find(p, name);
            if (!e) return 1;
            want = (int64_t)e->size;
        }
        const char *devname =
            str_eq(name, "profile.bin") ? gl_opt_profile_name(&g_opt) : name;
        char *devpath = xasprintf("%s/%s", g_opt.dev_dir, devname);
        int64_t have = device_file_size(a, devpath);
        free(devpath);
        if (have != want) return 1;
    }
    char *cmd = xasprintf("test -f %s/%s && echo y", g_opt.dev_dir, GL_DEV_RUNNER);
    char *out = gl_adb_sh_out(a, cmd, 8000);
    free(cmd);
    bool has = out && strstr(out, "y") != NULL;
    free(out);
    return has ? 0 : 1;
}

int gl_do_deploy(const gl_adb *a, const gl_pack *p)
{
    char tmpl[] = "/tmp/glpack.XXXXXX";
    char *tmpdir = mkdtemp(tmpl);
    if (!tmpdir) {
        msg_warn("mkdtemp 失败：%s", strerror(errno));
        return -1;
    }

    const gl_pack_entry *lib = gl_pack_find(p, "libghostlock.so");
    const gl_pack_entry *ko = gl_pack_find(p, "vrpatch.ko");
    const gl_pack_entry *blob = gl_pack_find(p, "profile.bin");
    if (!lib || !ko || !blob) {
        msg_warn("包里缺文件（libghostlock.so / vrpatch.ko / profile.bin）");
        rm_rf(tmpdir);
        return -1;
    }

    char *libp = path_join(tmpdir, "libghostlock.so");
    char *kop = path_join(tmpdir, "vrpatch.ko");
    char *blobp = path_join(tmpdir, "profile.bin");
    char *lenp = NULL;
    char *runnerp = NULL;
    int rc = -1;
    if (gl_pack_extract(p, lib, libp) != 0 ||
        gl_pack_extract(p, ko, kop) != 0) {
        msg_warn("从包里解文件失败");
        goto out;
    }
    if (g_opt.profile) {
        if (copy_file(g_opt.profile, blobp, 0644) != 0) {
            msg_warn("拷贝 --profile %s 失败", g_opt.profile);
            goto out;
        }
    } else if (gl_pack_extract(p, blob, blobp) != 0) {
        msg_warn("从包里解 profile.bin 失败");
        goto out;
    }

    /* profile release gate. Parse failures are reported but do not block when a
     * release.txt exists: the shell driver behaved the same way. */
    gl_buf blobdata;
    gl_buf_init(&blobdata);
    char *release = NULL;
    if (read_file(blobp, &blobdata) == 0) {
        gl_profile prof;
        char *perr = NULL;
        if (gl_profile_parse(blobdata.p, blobdata.len, &prof, &perr) == 0) {
            release = xstrdup(prof.release);
            gl_profile_free(&prof);
        } else {
            msg_warn("profile.bin 解析失败：%s", perr ? perr : "?");
            free(perr);
        }
    }
    if (!release) release = gl_expected_release(p, &g_opt);

    /* 4-byte big-endian length prefix, identical to the App's stdin frame */
    unsigned char len4[4] = {
        (unsigned char)((blobdata.len >> 24) & 0xff),
        (unsigned char)((blobdata.len >> 16) & 0xff),
        (unsigned char)((blobdata.len >> 8) & 0xff),
        (unsigned char)(blobdata.len & 0xff),
    };
    lenp = path_join(tmpdir, "profile.len");
    if (write_file(lenp, len4, sizeof len4, 0644) != 0) {
        msg_warn("写 profile.len 失败");
        gl_buf_free(&blobdata);
        free(release);
        goto out;
    }
    gl_buf_free(&blobdata);

    char *runner = gl_render_runner(&g_opt);
    runnerp = path_join(tmpdir, GL_DEV_RUNNER);
    if (write_file(runnerp, runner, strlen(runner), 0755) != 0) {
        msg_warn("写 glrun.sh 失败");
        free(runner);
        free(release);
        goto out;
    }
    free(runner);

    char *dev_rel = gl_adb_sh_out(a, "uname -r", 10000);
    if (!dev_rel || !*dev_rel) {
        msg_warn("拿不到设备 uname -r");
        free(dev_rel);
        free(release);
        goto out;
    }
    if (release && !str_eq(release, dev_rel)) {
        msg_warn("release 不匹配：");
        say("    设备 uname -r : %s", dev_rel);
        say("    包内 release  : %s", release);
        if (!g_opt.force) {
            msg_warn("拒绝执行。确认包是对的再加 --force。");
            free(dev_rel);
            free(release);
            goto out;
        }
        msg_warn("--force：继续（offset 不对会 panic 重启，设备能自行恢复）");
    }

    msg_step("部署 payload 到 %s", g_opt.dev_dir);
    char *cmd = xasprintf("mkdir -p '%s'", g_opt.dev_dir);
    char *o = gl_adb_sh_out(a, cmd, 20000);
    free(cmd);
    free(o);

    const char *locals[] = {libp, kop, blobp, lenp, runnerp};
    const char *remotes[] = {"libghostlock.so", "vrpatch.ko",
                             gl_opt_profile_name(&g_opt), "profile.len",
                             GL_DEV_RUNNER};
    for (int i = 0; i < 5; i++) {
        char *remote = xasprintf("%s/%s", g_opt.dev_dir, remotes[i]);
        if (gl_adb_push(a, locals[i], remote, 120000) != 0) {
            msg_warn("push %s 失败", remotes[i]);
            free(remote);
            free(dev_rel);
            free(release);
            goto out;
        }
        free(remote);
    }
    cmd = xasprintf(
        "chmod 755 %s/libghostlock.so %s/%s; chmod 644 %s/%s "
        "%s/profile.len %s/vrpatch.ko",
        g_opt.dev_dir, g_opt.dev_dir, GL_DEV_RUNNER, g_opt.dev_dir,
        gl_opt_profile_name(&g_opt), g_opt.dev_dir, g_opt.dev_dir);
    o = gl_adb_sh_out(a, cmd, 20000);
    free(cmd);
    free(o);

    msg_step("部署完成（release=%s）", release ? release : "?");
    rc = 0;
    free(dev_rel);
    free(release);
out:
    free(libp);
    free(kop);
    free(blobp);
    free(lenp);
    free(runnerp);
    rm_rf(tmpdir);
    return rc;
}

/* ------------------------------------------------------------------- ko */

int gl_select_ko(const gl_opt *o, char **ko_path)
{
    *ko_path = NULL;
    char *dir = o->ko_dir ? xstrdup(o->ko_dir) : dir_name(o->pack);
    char **list = NULL;
    int n = 0;
    list_files(dir, ".ko", &list, &n);
    if (n == 0) {
        msg_info("本目录没有 .ko —— 用管理器自带的 ko");
        free_list(list, n);
        free(dir);
        return 1;
    }
    blank();
    say("[本目录的 ko]");
    for (int i = 0; i < n; i++) {
        int64_t sz = 0;
        file_size(list[i], &sz);
        say("  %d) %s  %lld B", i + 1, base_name(list[i]), (long long)sz);
    }
    if (str_eq(o->ko_sel, "none")) {
        msg_info("--no-ko：跳过");
        free_list(list, n);
        free(dir);
        return 1;
    }

    const char *sel = o->ko_sel;
    char *buf = NULL;
    if (!sel && stdin_is_tty()) {
        printf("选哪个 ko？（回车 = 用管理器自带的）: ");
        fflush(stdout);
        char line[128];
        if (fgets(line, sizeof line, stdin)) {
            buf = xstrdup(str_trim(line));
            sel = buf;
        }
    } else if (!sel) {
        msg_info("非交互模式，跳过（--ko N 可指定）");
        free_list(list, n);
        free(dir);
        return 1;
    }
    if (!sel || !*sel) {
        free(buf);
        free_list(list, n);
        free(dir);
        return 1;
    }

    int idx = -1;
    bool numeric = true;
    for (const char *q = sel; *q; q++)
        if (*q < '0' || *q > '9') {
            numeric = false;
            break;
        }
    if (numeric) {
        long v = strtol(sel, NULL, 10);
        if (v >= 1 && v <= n) idx = (int)v - 1;
    } else {
        for (int i = 0; i < n; i++)
            if (str_eq(base_name(list[i]), sel)) {
                idx = i;
                break;
            }
        if (idx < 0)
            for (int i = 0; i < n; i++)
                if (strstr(list[i], sel)) {
                    idx = i;
                    break;
                }
    }
    int rc;
    if (idx >= 0) {
        *ko_path = xstrdup(list[idx]);
        rc = 0;
    } else {
        msg_warn("--ko %s 无效", sel);
        rc = 1;
    }
    free(buf);
    free_list(list, n);
    free(dir);
    return rc;
}

int gl_install_ko_wrapper(const gl_adb *a, const gl_opt *o, const char *ko_path)
{
    if (!ko_path) return 0;
    msg_step("指定 ko：%s", base_name(ko_path));

    char *remote_ko = xasprintf("%s/user.ko", o->dev_dir);
    if (gl_adb_push(a, ko_path, remote_ko, 120000) != 0) {
        msg_warn("push ko 失败");
        free(remote_ko);
        return -1;
    }
    char *cmd = xasprintf("chmod 644 %s", remote_ko);
    char *tmp = gl_adb_sh_out(a, cmd, 10000);
    free(cmd);
    free(tmp);

    char *real = gl_adb_sh_out(
        a, "ls -d /data/app/*/*/lib/arm64/libksud.so 2>/dev/null | head -1", 10000);
    if (real) {
        char *t = str_trim(real);
        if (t != real) memmove(real, t, strlen(t) + 1);
    }

    char *wrapper = NULL;
    gl_render_ksud_wrapper(remote_ko, real, &wrapper);
    char tmpl[] = "/tmp/glksud.XXXXXX";
    int fd = mkstemp(tmpl);
    if (fd < 0) {
        msg_warn("mkstemp 失败");
        free(wrapper);
        free(real);
        free(remote_ko);
        return -1;
    }
    close(fd);
    int rc = -1;
    if (write_file(tmpl, wrapper, strlen(wrapper), 0755) == 0) {
        char *remote_w = xasprintf("%s/ksud", o->dev_dir);
        if (gl_adb_push(a, tmpl, remote_w, 30000) == 0) {
            char *c2 = xasprintf("chmod 755 %s; rm -f %s/.gl_ksu_pkg", remote_w,
                                 o->dev_dir);
            char *t2 = gl_adb_sh_out(a, c2, 10000);
            free(c2);
            free(t2);
            rc = 0;
        } else {
            msg_warn("push wrapper 失败");
        }
        free(remote_w);
    }
    unlink(tmpl);
    free(wrapper);
    free(real);
    free(remote_ko);
    return rc;
}
