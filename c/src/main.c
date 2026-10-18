/*
 * main.c -- CLI entry point, argument parsing and dispatch.
 *
 * Two shapes are accepted on purpose:
 *   ghostlock run --ko 1 --clean-after      (new subcommands)
 *   ghostlock --ko 1 --clean-after          (v1.1 reroot.sh muscle memory)
 */
#include "internal.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

gl_opt g_opt;

/* The default pack path and the resolved adb path are heap-owned; free them on
 * exit so a leak checker sees a clean process. (--pack / --serial point into
 * argv and are not owned.) */
static char *owned_pack;

static void cleanup_globals(void)
{
    free(owned_pack);
    free((void *)g_opt.adb_bin);
    /* g_opt.serial is owned (and freed) by the command that resolves it. */
}

/* dev_dir is embedded in device-side shell strings, so keep it boring. */
static bool valid_dev_dir(const char *s)
{
    if (!s || s[0] != '/') return false;
    for (const char *p = s; *p; p++) {
        char c = *p;
        bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') || c == '/' || c == '.' || c == '_' ||
                  c == '-';
        if (!ok) return false;
    }
    return true;
}

/* Values that end up inside device-side shell strings (quoted or not) must be
 * boring: letters, digits, dot, underscore, dash. */
static bool valid_token(const char *s)
{
    if (!s || !*s || strlen(s) > 64) return false;
    for (const char *p = s; *p; p++) {
        char c = *p;
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-'))
            return false;
    }
    return true;
}

static bool valid_int_str(const char *s)
{
    if (!s || !*s || strlen(s) > 12) return false;
    if (*s == '-') s++;
    if (!*s) return false;
    for (; *s; s++)
        if (*s < '0' || *s > '9') return false;
    return true;
}

static bool all_digits(const char *s)
{
    if (!s || !*s) return false;
    for (const char *p = s; *p; p++)
        if (*p < '0' || *p > '9') return false;
    return true;
}

static int env_int(const char *name, int def)
{
    const char *v = getenv(name);
    if (!v || !*v) return def;
    char *end = NULL;
    long n = strtol(v, &end, 10);
    if (end == v || n <= 0) return def;
    return (int)n;
}

static char *resolve_pack(void)
{
    if (access("ghostlock.bin", R_OK) == 0) return xstrdup("ghostlock.bin");
    char buf[PATH_MAX];
    ssize_t n = readlink("/proc/self/exe", buf, sizeof buf - 1);
    if (n > 0) {
        buf[n] = '\0';
        char *d = dir_name(buf);
        char *p = path_join(d, "ghostlock.bin");
        free(d);
        if (access(p, R_OK) == 0) return p;
        free(p);
    }
    return xstrdup("ghostlock.bin");
}

static void usage(FILE *f)
{
    fprintf(f,
        "ghostlock %s -- iQOO Neo9 (PD2338) 临时 root 的 C 版无 UI 驱动\n"
        "\n"
        "用法:\n"
        "  ghostlock [run] [选项]            抢开机窗口拿临时 root（默认命令）\n"
        "  ghostlock check                   体检：设备 / 内核 / profile release 一致性\n"
        "  ghostlock status                  核验：su / kernelsu / SELinux\n"
        "  ghostlock inspect                 看 payload 包内容\n"
        "  ghostlock deploy                  只部署 payload（不发射）\n"
        "  ghostlock pull-log [--out DIR]    把设备上的日志取回本地\n"
        "  ghostlock clean [--yes ...]       清理残留（默认只列清单）\n"
        "  ghostlock install [...]           提权后：加载 ko / 装管理器\n"
        "  ghostlock exec -- <命令...>       通过 root 调试终端执行\n"
        "  ghostlock blob dump|check <bin>   解析 / 校验 profile blob\n"
        "  ghostlock version                 版本\n"
        "\n"
        "run 常用选项:\n"
        "  --pack FILE          payload 包（默认 ./ghostlock.bin）\n"
        "  --serial S           多设备时指定 adb serial（也认 -s）\n"
        "  --dir DIR            设备端工作目录（默认 %s）\n"
        "  --profile FILE       用这份本地 blob 覆盖包内的 profile.bin\n"
        "  --profile-file NAME  设备上 blob 的文件名（默认 profile.bin）\n"
        "  --ko N|NAME          启动时选本目录第 N 个 .ko（--no-ko 跳过）\n"
        "  --ko-dir DIR         去哪里找 .ko（默认 payload 包所在目录）\n"
        "  --rounds N           最多几轮（也认 `ghostlock 20`）\n"
        "  --per-boot N         每轮窗口内最多发射几次（默认 %d）\n"
        "  --window N           uptime 超过 N 秒就不再刷（默认 %d）\n"
        "  --timeout N          单次观察最长秒数（默认 %d）\n"
        "  --cycle-wait N       等设备自己重启的最长秒数（默认 %d）\n"
        "  --handoff-wait N     root 脚本启动后继续观察的秒数（默认 %d）\n"
        "  --poll MS            日志轮询间隔毫秒（默认 %d）\n"
        "  --force              release 不匹配也打（可能 panic，慎用）\n"
        "  --force-attack       传给 native 的 --force-attack（默认开）\n"
        "  --no-force-attack    不传 --force-attack\n"
        "  --redeploy           强制重推 payload\n"
        "  --clean-after        成功后清理本次残留（保留 user.ko / wrapper）\n"
        "  --app-call           用与 App 一致的 stdin 帧入口（默认 --load-prebuilt-profile）\n"
        "  --main-cpu N --consumer-cpu M   绑核（GHOSTLOCK_MAIN_CPU / CONSUMER_CPU）\n"
        "  --ksu-enforce N      9=只做临时 root；0=最后转 permissive\n"
        "  --vr-tag-b N         GHOSTLOCK_VR_TAG_B（默认不设）\n"
        "  --dump-kernel-log D  传给 native：panic 前把 dmesg/pstore 落到 D\n"
        "  --ksu-pkg PKG        写 .gl_ksu_pkg（root 脚本用它定位管理器 ksud）\n"
        "  --kmi KMI            写 .gl_kmi（默认 android13-5.15）\n"
        "\n"
        "clean:  --yes 执行 | --ksu /data/adb 用户态 | --uninstall 卸载管理器 | --all | --reboot\n"
        "install: --ko N | --install N | --ksud PATH | --pkg PKG | --persist | --dry-run | --yes\n"
        "\n"
        "环境变量: ADB, GL_DIR, TIMEOUT, PER_BOOT, WINDOW, CYCLE_WAIT, GL_HANDOFF_WAIT\n",
        GL_VERSION, GL_DEFAULT_DIR, g_opt.per_boot, g_opt.window, g_opt.timeout,
        g_opt.cycle_wait, g_opt.handoff_wait, g_opt.poll_ms);
}

static bool is_subcommand(const char *s)
{
    static const char *const subs[] = {
        "run", "check", "status", "inspect", "deploy", "pull-log",
        "clean", "install", "exec", "blob", "check-payload", "version",
        "help", NULL,
    };
    for (int i = 0; subs[i]; i++)
        if (str_eq(s, subs[i])) return true;
    return false;
}

int main(int argc, char **argv)
{
    memset(&g_opt, 0, sizeof g_opt);
    atexit(cleanup_globals);
    g_opt.adb_bin = find_adb();
    owned_pack = resolve_pack();
    g_opt.pack = owned_pack;
    g_opt.dev_dir = getenv("GL_DIR") && *getenv("GL_DIR") ? getenv("GL_DIR")
                                                           : GL_DEFAULT_DIR;
    g_opt.rounds = 10;
    g_opt.per_boot = env_int("PER_BOOT", 6);
    g_opt.window = env_int("WINDOW", 90);
    g_opt.timeout = env_int("TIMEOUT", 180);
    g_opt.cycle_wait = env_int("CYCLE_WAIT", 600);
    g_opt.handoff_wait = env_int("GL_HANDOFF_WAIT", 120);
    g_opt.poll_ms = 700;
    g_opt.force_attack = true;
    g_opt.ko_sel = NULL;

    const char *cmd = NULL;
    char *exec_args[64];
    int n_exec = 0;
    char *blob_sub = NULL, *blob_file = NULL, *blob_rel = NULL;
    const char *out_dir = NULL;

#define NEEDVAL()                                                              \
    do {                                                                       \
        if (++i >= argc) die("缺少参数：%s", s);                               \
        v = argv[i];                                                           \
    } while (0)

    for (int i = 1; i < argc; i++) {
        const char *s = argv[i];
        const char *v = NULL;

        if (str_eq(s, "--")) {
            for (int j = i + 1; j < argc && n_exec < 64; j++)
                exec_args[n_exec++] = argv[j];
            break;
        }

        if (str_eq(s, "-h") || str_eq(s, "--help") || str_eq(s, "help")) {
            cmd = "help";
            continue;
        }
        if (str_eq(s, "--version") || str_eq(s, "version")) {
            cmd = "version";
            continue;
        }
        if (str_eq(s, "--check")) { cmd = "check"; continue; }
        if (str_eq(s, "--inspect")) { cmd = "inspect"; continue; }
        if (str_eq(s, "--deploy")) { cmd = "deploy"; continue; }
        if (str_eq(s, "--check-payload")) { cmd = "check-payload"; continue; }
        if (str_eq(s, "--redeploy")) { g_opt.redeploy = true; continue; }
        if (str_eq(s, "--force")) { g_opt.force = true; continue; }
        if (str_eq(s, "--force-attack")) { g_opt.force_attack = true; continue; }
        if (str_eq(s, "--no-force-attack")) { g_opt.force_attack = false; continue; }
        if (str_eq(s, "--clean-after")) { g_opt.clean_after = true; continue; }
        if (str_eq(s, "--app-call")) { g_opt.app_call = true; continue; }
        if (str_eq(s, "--yes") || str_eq(s, "-y")) { g_opt.yes = true; continue; }
        if (str_eq(s, "--dry-run")) { g_opt.dry_run = true; continue; }
        if (str_eq(s, "--persist")) { g_opt.persist = true; continue; }
        if (str_eq(s, "--ksu")) { g_opt.clean_ksu = true; continue; }
        if (str_eq(s, "--uninstall")) { g_opt.clean_uninstall = true; continue; }
        if (str_eq(s, "--all")) {
            g_opt.clean_ksu = true;
            g_opt.clean_uninstall = true;
            continue;
        }
        if (str_eq(s, "--reboot")) { g_opt.clean_reboot = true; continue; }
        if (str_eq(s, "--no-ko")) { g_opt.ko_sel = "none"; continue; }

        if (str_eq(s, "--serial") || str_eq(s, "-s")) {
            NEEDVAL();
            g_opt.serial = v;
        } else if (str_eq(s, "--pack")) {
            NEEDVAL();
            g_opt.pack = v;
        } else if (str_eq(s, "--dir")) {
            NEEDVAL();
            g_opt.dev_dir = v;
        } else if (str_eq(s, "--profile")) {
            NEEDVAL();
            g_opt.profile = v;
        } else if (str_eq(s, "--profile-file")) {
            NEEDVAL();
            g_opt.profile_file = v;
        } else if (str_eq(s, "--ko")) {
            NEEDVAL();
            g_opt.ko_sel = v;
        } else if (str_eq(s, "--ko-dir")) {
            NEEDVAL();
            g_opt.ko_dir = v;
        } else if (str_eq(s, "--rounds")) {
            NEEDVAL();
            g_opt.rounds = atoi(v);
        } else if (str_eq(s, "--per-boot")) {
            NEEDVAL();
            g_opt.per_boot = atoi(v);
        } else if (str_eq(s, "--window")) {
            NEEDVAL();
            g_opt.window = atoi(v);
        } else if (str_eq(s, "--timeout")) {
            NEEDVAL();
            g_opt.timeout = atoi(v);
        } else if (str_eq(s, "--cycle-wait")) {
            NEEDVAL();
            g_opt.cycle_wait = atoi(v);
        } else if (str_eq(s, "--handoff-wait")) {
            NEEDVAL();
            g_opt.handoff_wait = atoi(v);
        } else if (str_eq(s, "--poll")) {
            NEEDVAL();
            g_opt.poll_ms = atoi(v);
        } else if (str_eq(s, "--main-cpu")) {
            NEEDVAL();
            g_opt.main_cpu = v;
        } else if (str_eq(s, "--consumer-cpu")) {
            NEEDVAL();
            g_opt.consumer_cpu = v;
        } else if (str_eq(s, "--ksu-enforce")) {
            NEEDVAL();
            g_opt.ksu_enforce = v;
        } else if (str_eq(s, "--vr-tag-b")) {
            NEEDVAL();
            g_opt.vr_tag_b = v;
        } else if (str_eq(s, "--dump-kernel-log")) {
            NEEDVAL();
            g_opt.dump_kernel_log = v;
        } else if (str_eq(s, "--ksu-pkg")) {
            NEEDVAL();
            g_opt.ksu_pkg = v;
        } else if (str_eq(s, "--kmi")) {
            NEEDVAL();
            g_opt.kmi = v;
        } else if (str_eq(s, "--out")) {
            NEEDVAL();
            out_dir = v;
        } else if (str_eq(s, "--install")) {
            NEEDVAL();
            g_opt.apk_sel = v;
        } else if (str_eq(s, "--ksud")) {
            NEEDVAL();
            g_opt.ksud_path = v;
        } else if (str_eq(s, "--pkg")) {
            NEEDVAL();
            g_opt.ksu_pkg = v;
        } else if (s[0] == '-') {
            fprintf(stderr, "[!] 未知参数: %s（--help 看用法）\n", s);
            return 2;
        } else if (!cmd && is_subcommand(s)) {
            cmd = s;
        } else if (cmd && str_eq(cmd, "blob")) {
            if (!blob_sub) blob_sub = (char *)s;
            else if (!blob_file) blob_file = (char *)s;
            else if (!blob_rel) blob_rel = (char *)s;
            else {
                fprintf(stderr, "[!] blob 参数太多：%s\n", s);
                return 2;
            }
        } else if (cmd && str_eq(cmd, "exec")) {
            if (n_exec < 64) exec_args[n_exec++] = (char *)s;
        } else if (!cmd && all_digits(s)) {
            g_opt.rounds = atoi(s);
        } else if (str_ends(s, ".bin")) {
            g_opt.pack = s;
        } else {
            fprintf(stderr, "[!] 无法识别的参数: %s（--help 看用法）\n", s);
            return 2;
        }
    }
#undef NEEDVAL

    if (!valid_dev_dir(g_opt.dev_dir))
        die("--dir 只支持 [A-Za-z0-9._/-] 的绝对路径：%s", g_opt.dev_dir);

    if (g_opt.profile_file && !valid_token(g_opt.profile_file))
        die("--profile-file 只支持 [A-Za-z0-9._-]：%s", g_opt.profile_file);
    if (g_opt.ksu_pkg && !valid_token(g_opt.ksu_pkg))
        die("--ksu-pkg 只支持 [A-Za-z0-9._-]：%s", g_opt.ksu_pkg);
    if (g_opt.kmi && !valid_token(g_opt.kmi))
        die("--kmi 只支持 [A-Za-z0-9._-]：%s", g_opt.kmi);
    if (g_opt.main_cpu && !valid_int_str(g_opt.main_cpu))
        die("--main-cpu 必须是整数：%s", g_opt.main_cpu);
    if (g_opt.consumer_cpu && !valid_int_str(g_opt.consumer_cpu))
        die("--consumer-cpu 必须是整数：%s", g_opt.consumer_cpu);
    if (g_opt.ksu_enforce && !valid_int_str(g_opt.ksu_enforce))
        die("--ksu-enforce 必须是整数：%s", g_opt.ksu_enforce);
    if (g_opt.vr_tag_b && !valid_int_str(g_opt.vr_tag_b))
        die("--vr-tag-b 必须是整数：%s", g_opt.vr_tag_b);
    if (g_opt.dump_kernel_log && !valid_dev_dir(g_opt.dump_kernel_log))
        die("--dump-kernel-log 只支持 [A-Za-z0-9._/-] 的绝对路径：%s",
            g_opt.dump_kernel_log);

    if (g_opt.rounds < 1) g_opt.rounds = 1;
    if (g_opt.per_boot < 1) g_opt.per_boot = 1;
    if (g_opt.timeout < 5) g_opt.timeout = 5;
    if (g_opt.poll_ms < 100) g_opt.poll_ms = 100;
    if (g_opt.window < 1) g_opt.window = 1;
    if (g_opt.cycle_wait < 1) g_opt.cycle_wait = 1;
    if (g_opt.handoff_wait < 1) g_opt.handoff_wait = 1;

    if (!cmd) {
        /* install-only flags must never silently fall through to `run` and
         * start an exploit race while the user thinks they are installing. */
        if (g_opt.apk_sel || g_opt.ksud_path || g_opt.persist || g_opt.dry_run)
            cmd = "install";
        else
            cmd = "run";
    }

    if (str_eq(cmd, "help")) {
        usage(stdout);
        return 0;
    }
    if (str_eq(cmd, "version")) {
        printf("ghostlock %s\n", GL_VERSION);
        return 0;
    }
    if (str_eq(cmd, "check")) return cmd_check();
    if (str_eq(cmd, "status")) return cmd_status();
    if (str_eq(cmd, "inspect")) return cmd_inspect();
    if (str_eq(cmd, "deploy")) return cmd_deploy();
    if (str_eq(cmd, "pull-log")) return cmd_pull_log(out_dir);
    if (str_eq(cmd, "clean")) return cmd_clean();
    if (str_eq(cmd, "install")) return cmd_install();
    if (str_eq(cmd, "exec")) {
        if (n_exec == 0) {
            say("用法：ghostlock exec -- <命令…>");
            return 2;
        }
        return cmd_exec(exec_args, n_exec);
    }
    if (str_eq(cmd, "blob"))
        return cmd_blob(blob_sub ? blob_sub : "dump", blob_file, blob_rel);
    if (str_eq(cmd, "check-payload")) {
        gl_pack p;
        if (gl_pack_open(g_opt.pack, &p) != 0) return 2;
        gl_env_serial();
        gl_adb a = gl_env_adb();
        bool need = gl_need_deploy(&a, &p);
        if (need)
            say("payload 未就绪（下次运行会推送）");
        else
            say("payload 已就绪（大小与包内一致，不会重推）");
        gl_pack_close(&p);
        return 0;
    }
    if (str_eq(cmd, "run")) return cmd_run();

    fprintf(stderr, "[!] 未知命令: %s\n", cmd);
    return 2;
}
