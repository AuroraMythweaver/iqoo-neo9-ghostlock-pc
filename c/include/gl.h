/*
 * gl.h -- shared declarations for the GhostLock C CLI (headless PC driver)
 *
 * The tool is a dependency-free C re-implementation of the v1.1 shell driver
 * (reroot.sh) plus the extras that used to live in scripts/ghostlock_pc.py.
 * It never runs the exploit on the PC: it drives `adb`, deploys the payload
 * pack and races the boot window exactly like the shell script does.
 */
#ifndef GL_H
#define GL_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define GL_VERSION "0.1.0"
#define GL_DEFAULT_DIR "/data/local/tmp/ghostlock-app"
#define GL_DEV_RUNNER "glrun.sh"

/* ------------------------------------------------------------------ buffer */

typedef struct {
    char *p;
    size_t len;
    size_t cap;
} gl_buf;

void gl_buf_init(gl_buf *b);
void gl_buf_free(gl_buf *b);
void gl_buf_clear(gl_buf *b);
void gl_buf_add(gl_buf *b, const void *data, size_t n);
void gl_buf_adds(gl_buf *b, const char *s);
void gl_buf_addf(gl_buf *b, const char *fmt, ...);
char *gl_buf_steal(gl_buf *b);

/* -------------------------------------------------------------------- util */

void *xmalloc(size_t n);
void *xcalloc(size_t n, size_t sz);
void *xrealloc(void *p, size_t n);
char *xstrdup(const char *s);
char *xstrndup(const char *s, size_t n);
char *xasprintf(const char *fmt, ...);

void die(const char *fmt, ...) __attribute__((noreturn, format(printf, 1, 2)));

void say(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void blank(void);
void msg_info(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void msg_step(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void msg_ok(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void msg_warn(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

int64_t now_ms(void);
void msleep(int64_t ms);
bool stdin_is_tty(void);

char *str_trim(char *s);          /* strips leading/trailing spaces + CR/LF in place */
bool str_starts(const char *s, const char *prefix);
bool str_ends(const char *s, const char *suffix);
bool str_contains(const char *hay, const char *needle);
bool str_eq(const char *a, const char *b);

int read_file(const char *path, gl_buf *out);
int write_file(const char *path, const void *data, size_t n, int mode);
int copy_file(const char *src, const char *dst, int mode);
int file_size(const char *path, int64_t *out_sz);

int mkdir_p(const char *path, int mode);
int rm_rf(const char *path);
char *dir_name(const char *path);
const char *base_name(const char *path);
char *path_join(const char *a, const char *b);
char *path_abs(const char *path);

int list_files(const char *dir, const char *suffix, char ***out, int *n);
void free_list(char **list, int n);
char *find_adb(void);

void base64_encode(const unsigned char *in, size_t n, gl_buf *out);

/* --------------------------------------------------------------------- adb */

typedef struct {
    const char *bin;      /* adb executable, usually "adb" */
    const char *serial;   /* -s value, NULL for auto */
} gl_adb;

int gl_exec(char *const argv[], int timeout_ms,
            gl_buf *out, gl_buf *err, int *exit_code);

int gl_adb_exec(const gl_adb *a, char *const args[], int timeout_ms,
                gl_buf *out, gl_buf *err, int *code);
int gl_adb_shell(const gl_adb *a, const char *cmd, int timeout_ms,
                 gl_buf *out, gl_buf *err, int *code);
/* Runs a shell command and returns a malloc'd, CR/LF-trimmed stdout (NULL on
 * failure). Caller frees. */
char *gl_adb_sh_out(const gl_adb *a, const char *cmd, int timeout_ms);
int gl_adb_push(const gl_adb *a, const char *local, const char *remote,
                int timeout_ms);
int gl_adb_pull(const gl_adb *a, const char *remote, const char *local,
                int timeout_ms);
int gl_adb_install(const gl_adb *a, const char *apk, int timeout_ms);
int gl_adb_uninstall(const gl_adb *a, const char *pkg, int timeout_ms);
int gl_adb_reboot(const gl_adb *a);

int gl_adb_devices(const gl_adb *a, char ***serials, int *n);
char *gl_pick_device(const gl_adb *a, const char *want);
bool gl_device_alive(const gl_adb *a);
bool gl_wait_shell(const gl_adb *a, int timeout_ms);
bool gl_is_root(const gl_adb *a);
double gl_uptime(const gl_adb *a, bool *ok);

/* ---------------------------------------------------------------- payload */

typedef struct {
    char name[17];
    uint64_t off;
    uint64_t size;
} gl_pack_entry;

typedef struct {
    char *path;
    uint64_t file_size;
    uint64_t data_start;
    uint32_t n_entries;
    uint32_t format;
    gl_pack_entry *entries;
} gl_pack;

int gl_pack_open(const char *path, gl_pack *p);
void gl_pack_close(gl_pack *p);
const gl_pack_entry *gl_pack_find(const gl_pack *p, const char *name);
int gl_pack_extract(const gl_pack *p, const gl_pack_entry *e, const char *dest);

/* ---------------------------------------------------------------- profile */

typedef struct {
    char *key;
    int64_t value;
} gl_kv;

typedef struct {
    char *name;
    uint32_t count;
    gl_kv *kv;
} gl_group;

typedef struct {
    uint16_t version;
    uint16_t flag_a;
    uint16_t flag_b;
    uint16_t route_id;
    uint16_t release_len;
    uint16_t reserved;
    char release[256];
    uint16_t n_groups;
    gl_group *groups;
} gl_profile;

int gl_profile_parse(const void *data, size_t len, gl_profile *p, char **err);
void gl_profile_free(gl_profile *p);
const char *gl_route_name(uint16_t id);
/* Returns the number of unknown groups/keys; appends human-readable lines to
 * report when non-NULL. */
int gl_profile_validate(const gl_profile *p, gl_buf *report);

/* ------------------------------------------------------------- options/cmd */

typedef struct {
    const char *adb_bin;
    const char *serial;
    const char *dev_dir;
    const char *pack;
    const char *profile;       /* override blob (--profile) */
    const char *ko_dir;        /* where *.ko / *.apk are looked up */
    const char *ko_sel;        /* --ko value; "none" means --no-ko */
    const char *profile_file;  /* on-device blob name */

    int rounds;
    int per_boot;
    int window;
    int timeout;
    int cycle_wait;
    int poll_ms;

    bool force;          /* allow a release mismatch (release gate) */
    bool force_attack;   /* pass --force-attack to the native exploit */
    bool redeploy;
    bool clean_after;
    bool app_call;
    bool dry_run;
    bool yes;
    bool clean_ksu;
    bool clean_uninstall;
    bool clean_reboot;
    const char *apk_sel;      /* install-ksu: --install N */
    const char *ksud_path;    /* install-ksu: --ksud PATH */
    bool persist;             /* install-ksu: --persist */

    const char *main_cpu;
    const char *consumer_cpu;
    const char *ksu_enforce;
    const char *vr_tag_b;
    const char *dump_kernel_log;
    const char *ksu_pkg;
    const char *kmi;
} gl_opt;

extern gl_opt g_opt;

/* command entry points (return process exit code) */
int cmd_run(void);
int cmd_check(void);
int cmd_status(void);
int cmd_inspect(void);
int cmd_deploy(void);
int cmd_pull_log(const char *out_dir);
int cmd_clean(void);
int cmd_install(void);
int cmd_exec(char **argv, int nargv);
int cmd_blob(const char *sub, const char *file, const char *expected_release);

/* device-side runner script (returns malloc'd text) */
char *gl_render_runner(const gl_opt *o);
int gl_render_ksud_wrapper(const char *ko_path, const char *ksud_path,
                           char **out);

#endif /* GL_H */
