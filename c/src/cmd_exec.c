/*
 * cmd_exec.c -- run a command through the root debug terminal that the root
 * script polls: write $HOME/.gl_cmd, read $HOME/.gl_out.
 *
 * The command is base64'd so quoting/UTF-8 never reaches the device shell.
 */
#include "internal.h"

#include <stdlib.h>
#include <string.h>

static int64_t gl_out_size(const gl_adb *a)
{
    char *cmd = xasprintf("wc -c < %s/.gl_out 2>/dev/null || echo 0", g_opt.dev_dir);
    char *out = gl_adb_sh_out(a, cmd, 8000);
    free(cmd);
    if (!out) return 0;
    char *t = str_trim(out);
    int64_t sz = (*t >= '0' && *t <= '9') ? strtoll(t, NULL, 10) : 0;
    free(out);
    return sz;
}

int cmd_exec(char **argv, int nargv)
{
    if (nargv <= 0 || !argv) {
        say("用法：ghostlock exec -- <命令…>");
        return 2;
    }
    char *serial = gl_env_serial();
    gl_adb a2 = {g_opt.adb_bin, serial};

    gl_buf cmd;
    gl_buf_init(&cmd);
    for (int i = 0; i < nargv; i++) {
        if (i) gl_buf_adds(&cmd, " ");
        gl_buf_adds(&cmd, argv[i]);
    }

    int64_t before = gl_out_size(&a2);

    gl_buf b64;
    gl_buf_init(&b64);
    base64_encode((const unsigned char *)cmd.p, cmd.len, &b64);

    char *write = xasprintf("echo %s | base64 -d > %s/.gl_cmd", b64.p,
                            g_opt.dev_dir);
    char *out = gl_adb_sh_out(&a2, write, 15000);
    free(write);
    free(out);
    gl_buf_free(&b64);

    int64_t last = before;
    int64_t deadline = now_ms() + (int64_t)g_opt.timeout * 1000;
    while (now_ms() < deadline) {
        msleep(400);
        int64_t cur = gl_out_size(&a2);
        if (cur > last) {
            last = cur;
            msleep(400);
            int64_t cur2 = gl_out_size(&a2);
            if (cur2 == cur) break;
            last = cur2;
        } else if (cur > before) {
            break;
        }
    }

    if (last <= before) {
        msg_warn("没有输出：root 调试终端没在跑（说明 W2 还没拿到 uid0，或进程已退出）");
        gl_buf_free(&cmd);
        free(serial);
        return 1;
    }

    char *tail = xasprintf("tail -c +%lld %s/.gl_out", (long long)(before + 1),
                           g_opt.dev_dir);
    gl_buf res, err;
    gl_buf_init(&res);
    gl_buf_init(&err);
    int code = -1;
    int rc = gl_adb_shell(&a2, tail, 60000, &res, &err, &code);
    free(tail);
    if (rc == 0 && code == 0 && res.p) {
        size_t w = 0;
        for (size_t i = 0; i < res.len; i++)
            if (res.p[i] != '\r') res.p[w++] = res.p[i];
        fwrite(res.p, 1, w, stdout);
        fflush(stdout);
    }
    gl_buf_free(&res);
    gl_buf_free(&err);
    gl_buf_free(&cmd);
    free(serial);
    return 0;
}
