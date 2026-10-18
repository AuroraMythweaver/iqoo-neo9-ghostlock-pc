/*
 * adb.c -- subprocess execution with a hard timeout, plus thin adb wrappers.
 *
 * Every adb call may hang forever (a rebooting device, a wedged server), so
 * each one runs through gl_exec() with an explicit deadline. The child gets
 * /dev/null on stdin: nothing here ever feeds the device interactively.
 */
#include "gl.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define GL_ARGV_MAX 64

static void drain_fd(int fd, gl_buf *dst)
{
    char tmp[8192];
    for (;;) {
        ssize_t n = read(fd, tmp, sizeof tmp);
        if (n > 0) {
            if (dst) gl_buf_add(dst, tmp, (size_t)n);
            continue;
        }
        if (n == 0) return;
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) return;
        return;
    }
}

/*
 * Run argv to completion, capturing stdout/stderr separately.
 * Returns 0 on success (child exited), -1 on timeout (child killed),
 * -2 on fork/pipe failure. *code receives the child status when available.
 */
int gl_exec(char *const argv[], int timeout_ms,
            gl_buf *out, gl_buf *err, int *exit_code)
{
    int po[2], pe[2];
    if (exit_code) *exit_code = -1;
    if (pipe(po) != 0) return -2;
    if (pipe(pe) != 0) {
        close(po[0]);
        close(po[1]);
        return -2;
    }
    pid_t pid = fork();
    if (pid < 0) {
        close(po[0]);
        close(po[1]);
        close(pe[0]);
        close(pe[1]);
        return -2;
    }
    if (pid == 0) {
        /* child */
        close(po[0]);
        close(pe[0]);
        dup2(po[1], STDOUT_FILENO);
        dup2(pe[1], STDERR_FILENO);
        close(po[1]);
        close(pe[1]);
        int devnull = open("/dev/null", O_RDONLY);
        if (devnull >= 0) {
            dup2(devnull, STDIN_FILENO);
            close(devnull);
        }
        execvp(argv[0], argv);
        _exit(127);
    }
    close(po[1]);
    close(pe[1]);
    fcntl(po[0], F_SETFL, O_NONBLOCK);
    fcntl(pe[0], F_SETFL, O_NONBLOCK);

    int64_t deadline = now_ms() + (timeout_ms > 0 ? timeout_ms : 86400000);
    bool eof_o = false, eof_e = false;
    bool timed_out = false;

    while (!eof_o || !eof_e) {
        int64_t remain = deadline - now_ms();
        if (remain <= 0) {
            timed_out = true;
            break;
        }
        struct pollfd pf[2];
        nfds_t nf = 0;
        int idx_o = -1, idx_e = -1;
        if (!eof_o) {
            pf[nf].fd = po[0];
            pf[nf].events = POLLIN;
            idx_o = (int)nf;
            nf++;
        }
        if (!eof_e) {
            pf[nf].fd = pe[0];
            pf[nf].events = POLLIN;
            idx_e = (int)nf;
            nf++;
        }
        int pr = poll(pf, nf, (int)(remain > 1000 ? 1000 : remain));
        if (pr < 0) {
            if (errno == EINTR) continue;
            timed_out = true;
            break;
        }
        if (pr == 0) continue;
        if (idx_o >= 0 && (pf[idx_o].revents & (POLLIN | POLLHUP | POLLERR))) {
            char tmp[8192];
            ssize_t n = read(po[0], tmp, sizeof tmp);
            if (n > 0) {
                if (out) gl_buf_add(out, tmp, (size_t)n);
            } else if (n == 0 || (errno != EAGAIN && errno != EWOULDBLOCK)) {
                eof_o = true;
            }
        }
        if (idx_e >= 0 && (pf[idx_e].revents & (POLLIN | POLLHUP | POLLERR))) {
            char tmp[8192];
            ssize_t n = read(pe[0], tmp, sizeof tmp);
            if (n > 0) {
                if (err) gl_buf_add(err, tmp, (size_t)n);
            } else if (n == 0 || (errno != EAGAIN && errno != EWOULDBLOCK)) {
                eof_e = true;
            }
        }
    }

    if (timed_out) {
        kill(pid, SIGKILL);
        /* drain what is already buffered, then reap */
        drain_fd(po[0], out);
        drain_fd(pe[0], err);
    }
    close(po[0]);
    close(pe[0]);

    int status = 0;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) break;
    }
    if (timed_out) return -1;
    if (exit_code) {
        if (WIFEXITED(status)) *exit_code = WEXITSTATUS(status);
        else if (WIFSIGNALED(status)) *exit_code = 128 + WTERMSIG(status);
        else *exit_code = -1;
    }
    return 0;
}

int gl_adb_exec(const gl_adb *a, char *const args[], int timeout_ms,
                gl_buf *out, gl_buf *err, int *code)
{
    char *argv[GL_ARGV_MAX];
    int i = 0;
    argv[i++] = (char *)(a && a->bin ? a->bin : "adb");
    if (a && a->serial && *a->serial) {
        argv[i++] = (char *)"-s";
        argv[i++] = (char *)a->serial;
    }
    for (int j = 0; args && args[j] && i < GL_ARGV_MAX - 1; j++) argv[i++] = args[j];
    argv[i] = NULL;
    return gl_exec(argv, timeout_ms, out, err, code);
}

int gl_adb_shell(const gl_adb *a, const char *cmd, int timeout_ms,
                 gl_buf *out, gl_buf *err, int *code)
{
    char *args[3] = {(char *)"shell", (char *)cmd, NULL};
    return gl_adb_exec(a, args, timeout_ms, out, err, code);
}

char *gl_adb_sh_out(const gl_adb *a, const char *cmd, int timeout_ms)
{
    gl_buf out, err;
    gl_buf_init(&out);
    gl_buf_init(&err);
    int code = -1;
    int rc = gl_adb_shell(a, cmd, timeout_ms, &out, &err, &code);
    char *res = NULL;
    if (rc == 0 && code == 0) {
        gl_buf_add(&out, "", 0);
        res = gl_buf_steal(&out);
        /* strip CR from adb shell line endings */
        size_t w = 0;
        for (size_t i = 0; res[i]; i++)
            if (res[i] != '\r') res[w++] = res[i];
        res[w] = '\0';
        char *t = str_trim(res);
        if (t != res) memmove(res, t, strlen(t) + 1);
    }
    gl_buf_free(&out);
    gl_buf_free(&err);
    return res;
}

int gl_adb_push(const gl_adb *a, const char *local, const char *remote,
                int timeout_ms)
{
    char *args[4] = {(char *)"push", (char *)local, (char *)remote, NULL};
    gl_buf out, err;
    gl_buf_init(&out);
    gl_buf_init(&err);
    int code = -1;
    int rc = gl_adb_exec(a, args, timeout_ms, &out, &err, &code);
    if (rc != 0 || code != 0) {
        if (err.len) fprintf(stderr, "[!] adb push: %s", err.p);
        gl_buf_free(&out);
        gl_buf_free(&err);
        return -1;
    }
    gl_buf_free(&out);
    gl_buf_free(&err);
    return 0;
}

int gl_adb_pull(const gl_adb *a, const char *remote, const char *local,
                int timeout_ms)
{
    char *args[4] = {(char *)"pull", (char *)remote, (char *)local, NULL};
    gl_buf out, err;
    gl_buf_init(&out);
    gl_buf_init(&err);
    int code = -1;
    int rc = gl_adb_exec(a, args, timeout_ms, &out, &err, &code);
    if (rc != 0 || code != 0) {
        if (err.len) fprintf(stderr, "[!] adb pull: %s", err.p);
        gl_buf_free(&out);
        gl_buf_free(&err);
        return -1;
    }
    gl_buf_free(&out);
    gl_buf_free(&err);
    return 0;
}

int gl_adb_install(const gl_adb *a, const char *apk, int timeout_ms)
{
    char *args[4] = {(char *)"install", (char *)"-r", (char *)apk, NULL};
    gl_buf out, err;
    gl_buf_init(&out);
    gl_buf_init(&err);
    int code = -1;
    int rc = gl_adb_exec(a, args, timeout_ms, &out, &err, &code);
    if (out.len) {
        /* indent like the shell driver; install output is short */
        fputs("    ", stdout);
        for (size_t i = 0; i < out.len; i++) {
            fputc(out.p[i], stdout);
            if (out.p[i] == '\n' && i + 1 < out.len) fputs("    ", stdout);
        }
        if (out.p[out.len - 1] != '\n') fputc('\n', stdout);
        fflush(stdout);
    }
    gl_buf_free(&out);
    gl_buf_free(&err);
    return (rc == 0 && code == 0) ? 0 : -1;
}

int gl_adb_uninstall(const gl_adb *a, const char *pkg, int timeout_ms)
{
    char *args[3] = {(char *)"uninstall", (char *)pkg, NULL};
    gl_buf out, err;
    gl_buf_init(&out);
    gl_buf_init(&err);
    int code = -1;
    int rc = gl_adb_exec(a, args, timeout_ms, &out, &err, &code);
    if (out.len) printf("    %s", out.p);
    gl_buf_free(&out);
    gl_buf_free(&err);
    return (rc == 0 && code == 0) ? 0 : -1;
}

int gl_adb_reboot(const gl_adb *a)
{
    char *args[2] = {(char *)"reboot", NULL};
    gl_buf out, err;
    gl_buf_init(&out);
    gl_buf_init(&err);
    int code = -1;
    int rc = gl_adb_exec(a, args, 20000, &out, &err, &code);
    gl_buf_free(&out);
    gl_buf_free(&err);
    return rc == 0 ? 0 : -1;
}

int gl_adb_devices(const gl_adb *a, char ***serials, int *n)
{
    *serials = NULL;
    *n = 0;
    char *args[2] = {(char *)"devices", NULL};
    gl_buf out, err;
    gl_buf_init(&out);
    gl_buf_init(&err);
    int code = -1;
    int rc = gl_adb_exec(a, args, 30000, &out, &err, &code);
    if (rc != 0 || code != 0) {
        gl_buf_free(&out);
        gl_buf_free(&err);
        return -1;
    }
    char **list = NULL;
    int cnt = 0, cap = 0;
    char *copy = xstrdup(out.p ? out.p : "");
    char *save = NULL;
    bool first = true;
    for (char *line = strtok_r(copy, "\n", &save); line;
         line = strtok_r(NULL, "\n", &save)) {
        if (first) { /* "List of devices attached" */
            first = false;
            if (strstr(line, "List of devices") || !*str_trim(line)) continue;
        }
        char *l = str_trim(line);
        if (!*l) continue;
        char *serial = l;
        char *sp = strpbrk(l, " \t");
        if (!sp) continue;
        *sp = '\0';
        char *state = str_trim(sp + 1);
        char *state_end = strpbrk(state, " \t");
        if (state_end) *state_end = '\0';
        if (!str_eq(state, "device")) continue;
        if (cnt == cap) {
            cap = cap ? cap * 2 : 4;
            list = xrealloc(list, (size_t)cap * sizeof *list);
        }
        list[cnt++] = xstrdup(serial);
    }
    free(copy);
    gl_buf_free(&out);
    gl_buf_free(&err);
    *serials = list;
    *n = cnt;
    return 0;
}

char *gl_pick_device(const gl_adb *a, const char *want)
{
    char **serials = NULL;
    int n = 0;
    if (gl_adb_devices(a, &serials, &n) != 0)
        die("adb devices 调用失败（adb 装了吗？）");
    if (n == 0) {
        free_list(serials, n);
        die("没看到 adb 设备：先插线 / 开 USB 调试 / 授权这台电脑。");
    }
    if (want && *want) {
        for (int i = 0; i < n; i++)
            if (str_eq(serials[i], want)) {
                char *s = xstrdup(want);
                free_list(serials, n);
                return s;
            }
        fprintf(stderr, "[!] serial %s 不在设备列表里：", want);
        for (int i = 0; i < n; i++) fprintf(stderr, " %s", serials[i]);
        fputc('\n', stderr);
        free_list(serials, n);
        exit(2);
    }
    if (n > 1) {
        fprintf(stderr, "[!] 有 %d 台设备，请用 --serial 指定：", n);
        for (int i = 0; i < n; i++) fprintf(stderr, " %s", serials[i]);
        fputc('\n', stderr);
        free_list(serials, n);
        exit(2);
    }
    char *s = xstrdup(serials[0]);
    free_list(serials, n);
    return s;
}

bool gl_device_alive(const gl_adb *a)
{
    char *out = gl_adb_sh_out(a, "echo ping", 4000);
    bool ok = out && strstr(out, "ping") != NULL;
    free(out);
    return ok;
}

bool gl_wait_shell(const gl_adb *a, int timeout_ms)
{
    int64_t deadline = now_ms() + timeout_ms;
    while (now_ms() < deadline) {
        char *out = gl_adb_sh_out(a, "echo up", 4000);
        bool up = out && strstr(out, "up") != NULL;
        free(out);
        if (up) return true;
        msleep(400);
    }
    return false;
}

bool gl_is_root(const gl_adb *a)
{
    char *out = gl_adb_sh_out(a, "su -c id -u", 6000);
    bool root = false;
    if (out) {
        char *t = str_trim(out);
        root = str_eq(t, "0");
    }
    free(out);
    return root;
}

double gl_uptime(const gl_adb *a, bool *ok)
{
    if (ok) *ok = false;
    char *out = gl_adb_sh_out(a, "cat /proc/uptime 2>/dev/null", 8000);
    if (!out) return -1;
    char *t = str_trim(out);
    if (!*t) {
        free(out);
        return -1;
    }
    char *end = NULL;
    double v = strtod(t, &end);
    bool good = end && end != t;
    free(out);
    if (ok) *ok = good;
    return good ? v : -1;
}
