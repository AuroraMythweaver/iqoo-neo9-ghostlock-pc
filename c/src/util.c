/*
 * util.c -- buffers, logging, filesystem helpers, small string utilities.
 */
#include "gl.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

/* ------------------------------------------------------------------ buffer */

void gl_buf_init(gl_buf *b)
{
    b->p = NULL;
    b->len = 0;
    b->cap = 0;
}

void gl_buf_free(gl_buf *b)
{
    free(b->p);
    gl_buf_init(b);
}

void gl_buf_clear(gl_buf *b)
{
    b->len = 0;
    if (b->p) b->p[0] = '\0';
}

static void buf_grow(gl_buf *b, size_t need)
{
    if (b->len + need + 1 <= b->cap) return;
    size_t cap = b->cap ? b->cap : 256;
    while (cap < b->len + need + 1) cap *= 2;
    b->p = xrealloc(b->p, cap);
    b->cap = cap;
}

void gl_buf_add(gl_buf *b, const void *data, size_t n)
{
    if (!n) return;
    buf_grow(b, n);
    memcpy(b->p + b->len, data, n);
    b->len += n;
    b->p[b->len] = '\0';
}

void gl_buf_adds(gl_buf *b, const char *s)
{
    if (s) gl_buf_add(b, s, strlen(s));
}

void gl_buf_addf(gl_buf *b, const char *fmt, ...)
{
    va_list ap, ap2;
    va_start(ap, fmt);
    va_copy(ap2, ap);
    int n = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (n > 0) {
        buf_grow(b, (size_t)n);
        vsnprintf(b->p + b->len, (size_t)n + 1, fmt, ap2);
        b->len += (size_t)n;
    }
    va_end(ap2);
}

char *gl_buf_steal(gl_buf *b)
{
    char *p = b->p;
    if (!p) p = xstrdup("");
    gl_buf_init(b);
    return p;
}

/* -------------------------------------------------------------------- mem */

void *xmalloc(size_t n)
{
    void *p = malloc(n ? n : 1);
    if (!p) die("out of memory");
    return p;
}

void *xcalloc(size_t n, size_t sz)
{
    void *p = calloc(n ? n : 1, sz ? sz : 1);
    if (!p) die("out of memory");
    return p;
}

void *xrealloc(void *p, size_t n)
{
    void *q = realloc(p, n ? n : 1);
    if (!q) die("out of memory");
    return q;
}

char *xstrdup(const char *s)
{
    char *p = strdup(s ? s : "");
    if (!p) die("out of memory");
    return p;
}

char *xstrndup(const char *s, size_t n)
{
    char *p = strndup(s ? s : "", n);
    if (!p) die("out of memory");
    return p;
}

char *xasprintf(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    char *p = xmalloc((size_t)n + 1);
    va_start(ap, fmt);
    vsnprintf(p, (size_t)n + 1, fmt, ap);
    va_end(ap);
    return p;
}

/* ------------------------------------------------------------------- logs */

void die(const char *fmt, ...)
{
    va_list ap;
    fflush(stdout);
    fputs("[!] ", stderr);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(2);
}

static void vline(const char *prefix, const char *fmt, va_list ap)
{
    fputs(prefix, stdout);
    vprintf(fmt, ap);
    fputc('\n', stdout);
    fflush(stdout);
}

void say(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vline("", fmt, ap);
    va_end(ap);
}

void blank(void)
{
    fputc('\n', stdout);
    fflush(stdout);
}

void msg_info(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vline("[i] ", fmt, ap);
    va_end(ap);
}

void msg_step(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vline("[*] ", fmt, ap);
    va_end(ap);
}

void msg_ok(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vline("[+] ", fmt, ap);
    va_end(ap);
}

void msg_warn(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vline("[!] ", fmt, ap);
    va_end(ap);
}

/* ------------------------------------------------------------------- time */

int64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

void msleep(int64_t ms)
{
    struct timespec ts;
    if (ms <= 0) return;
    ts.tv_sec = (time_t)(ms / 1000);
    ts.tv_nsec = (long)((ms % 1000) * 1000000);
    while (nanosleep(&ts, &ts) == -1 && errno == EINTR) {
    }
}

bool stdin_is_tty(void)
{
    return isatty(STDIN_FILENO) ? true : false;
}

/* ----------------------------------------------------------------- strings */

char *str_trim(char *s)
{
    if (!s) return s;
    while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n') s++;
    size_t n = strlen(s);
    while (n && (s[n - 1] == ' ' || s[n - 1] == '\t' || s[n - 1] == '\r' ||
                 s[n - 1] == '\n'))
        s[--n] = '\0';
    return s;
}

bool str_starts(const char *s, const char *prefix)
{
    return s && prefix && strncmp(s, prefix, strlen(prefix)) == 0;
}

bool str_ends(const char *s, const char *suffix)
{
    if (!s || !suffix) return false;
    size_t ls = strlen(s), lf = strlen(suffix);
    return ls >= lf && memcmp(s + ls - lf, suffix, lf) == 0;
}

bool str_contains(const char *hay, const char *needle)
{
    return hay && needle && strstr(hay, needle) != NULL;
}

bool str_eq(const char *a, const char *b)
{
    return a && b && strcmp(a, b) == 0;
}

/* ---------------------------------------------------------------- file io */

int read_file(const char *path, gl_buf *out)
{
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    char tmp[65536];
    size_t n;
    while ((n = fread(tmp, 1, sizeof tmp, f)) > 0) gl_buf_add(out, tmp, n);
    int bad = ferror(f);
    fclose(f);
    return bad ? -1 : 0;
}

int write_file(const char *path, const void *data, size_t n, int mode)
{
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    if (n && fwrite(data, 1, n, f) != n) {
        fclose(f);
        return -1;
    }
    if (fclose(f) != 0) return -1;
    if (mode && chmod(path, (mode_t)mode) != 0) return -1;
    return 0;
}

int copy_file(const char *src, const char *dst, int mode)
{
    gl_buf b;
    gl_buf_init(&b);
    if (read_file(src, &b) != 0) {
        gl_buf_free(&b);
        return -1;
    }
    int rc = write_file(dst, b.p, b.len, mode);
    gl_buf_free(&b);
    return rc;
}

int file_size(const char *path, int64_t *out_sz)
{
    struct stat st;
    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode)) return -1;
    *out_sz = (int64_t)st.st_size;
    return 0;
}

int mkdir_p(const char *path, int mode)
{
    if (!path || !*path) return -1;
    char *tmp = xstrdup(path);
    size_t n = strlen(tmp);
    while (n > 1 && tmp[n - 1] == '/') tmp[--n] = '\0';
    for (char *p = tmp + 1; *p; p++) {
        if (*p != '/') continue;
        *p = '\0';
        if (mkdir(tmp, (mode_t)mode) != 0 && errno != EEXIST) {
            free(tmp);
            return -1;
        }
        *p = '/';
    }
    int rc = (mkdir(tmp, (mode_t)mode) != 0 && errno != EEXIST) ? -1 : 0;
    free(tmp);
    return rc;
}

static int rm_rf_inner(const char *path, int depth)
{
    struct stat st;
    if (lstat(path, &st) != 0) return errno == ENOENT ? 0 : -1;
    if (!S_ISDIR(st.st_mode)) return unlink(path);
    if (depth > 64) return -1;
    DIR *d = opendir(path);
    if (!d) return -1;
    struct dirent *de;
    int rc = 0;
    while ((de = readdir(d)) != NULL) {
        if (str_eq(de->d_name, ".") || str_eq(de->d_name, "..")) continue;
        char *child = path_join(path, de->d_name);
        if (rm_rf_inner(child, depth + 1) != 0) rc = -1;
        free(child);
    }
    closedir(d);
    if (rc == 0 && rmdir(path) != 0) rc = -1;
    return rc;
}

int rm_rf(const char *path)
{
    return rm_rf_inner(path, 0);
}

char *dir_name(const char *path)
{
    if (!path || !*path) return xstrdup(".");
    const char *slash = strrchr(path, '/');
    if (!slash) return xstrdup(".");
    if (slash == path) return xstrdup("/");
    return xstrndup(path, (size_t)(slash - path));
}

const char *base_name(const char *path)
{
    if (!path) return "";
    const char *slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

char *path_join(const char *a, const char *b)
{
    if (!a || !*a) return xstrdup(b ? b : "");
    if (!b || !*b) return xstrdup(a);
    if (b[0] == '/') return xstrdup(b);
    size_t la = strlen(a);
    bool slash = a[la - 1] == '/';
    return xasprintf("%s%s%s", a, slash ? "" : "/", b);
}

char *path_abs(const char *path)
{
    char *resolved = realpath(path, NULL);
    return resolved;
}

int list_files(const char *dir, const char *suffix, char ***out, int *n)
{
    *out = NULL;
    *n = 0;
    DIR *d = opendir(dir);
    if (!d) return -1;
    char **list = NULL;
    int cnt = 0, cap = 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (de->d_name[0] == '.') continue;
        if (suffix && !str_ends(de->d_name, suffix)) continue;
        char *full = path_join(dir, de->d_name);
        struct stat st;
        if (stat(full, &st) != 0 || !S_ISREG(st.st_mode)) {
            free(full);
            continue;
        }
        if (cnt == cap) {
            cap = cap ? cap * 2 : 8;
            list = xrealloc(list, (size_t)cap * sizeof *list);
        }
        list[cnt++] = full;
    }
    closedir(d);
    /* insertion sort: few entries, stable enough */
    for (int i = 1; i < cnt; i++) {
        char *key = list[i];
        int j = i - 1;
        while (j >= 0 && strcmp(list[j], key) > 0) {
            list[j + 1] = list[j];
            j--;
        }
        list[j + 1] = key;
    }
    *out = list;
    *n = cnt;
    return 0;
}

void free_list(char **list, int n)
{
    if (!list) return;
    for (int i = 0; i < n; i++) free(list[i]);
    free(list);
}

char *find_adb(void)
{
    const char *env = getenv("ADB");
    if (env && *env) return xstrdup(env);
    const char *path = getenv("PATH");
    if (path && *path) {
        char *copy = xstrdup(path);
        char *save = NULL;
        for (char *tok = strtok_r(copy, ":", &save); tok;
             tok = strtok_r(NULL, ":", &save)) {
            char *cand = path_join(tok, "adb");
            if (access(cand, X_OK) == 0) {
                free(copy);
                return cand;
            }
            free(cand);
        }
        free(copy);
    }
    /* common macOS locations from the shell driver */
    const char *mac[] = {
        "/opt/homebrew/bin/adb",
        "/usr/local/bin/adb",
        NULL,
    };
    for (int i = 0; mac[i]; i++)
        if (access(mac[i], X_OK) == 0) return xstrdup(mac[i]);
    return xstrdup("adb");
}

void base64_encode(const unsigned char *in, size_t n, gl_buf *out)
{
    static const char tbl[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t i = 0;
    while (i + 2 < n) {
        unsigned v = ((unsigned)in[i] << 16) | ((unsigned)in[i + 1] << 8) | in[i + 2];
        char q[4] = {tbl[(v >> 18) & 63], tbl[(v >> 12) & 63],
                     tbl[(v >> 6) & 63], tbl[v & 63]};
        gl_buf_add(out, q, 4);
        i += 3;
    }
    if (i < n) {
        unsigned v = (unsigned)in[i] << 16;
        if (i + 1 < n) v |= (unsigned)in[i + 1] << 8;
        char q[4] = {tbl[(v >> 18) & 63], tbl[(v >> 12) & 63],
                     (i + 1 < n) ? tbl[(v >> 6) & 63] : '=',
                     '='};
        gl_buf_add(out, q, 4);
    }
}
