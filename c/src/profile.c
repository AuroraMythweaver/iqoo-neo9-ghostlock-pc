/*
 * profile.c -- parser + native-whitelist validator for the kernel profile blob.
 *
 * Layout (confirmed against libghostlock.so at 0x67dbc, see docs/PORTING.md §1.3):
 *
 *   0x00 u32 magic = 0x0D000721
 *   0x04 u16 version = 2
 *   0x06 u16 flag_a  (1..2)
 *   0x08 u16 flag_b  (1..2)
 *   0x0a u16 route_id (<=255)
 *   0x0c u16 release_len (native: <=255, stricter than the Java writer)
 *   0x0e u16 reserved
 *   0x10 bytes release[release_len]
 *   ...  u16 group_count
 *   each group: u8 name_len, name, u32 entry_count,
 *               each entry: u8 key_len, key, i64 LE value
 *
 * Unknown groups/keys are silently dropped by the native parser, so a blob can
 * look fine and do nothing. gl_profile_validate() reproduces the native
 * whitelist to surface exactly that class of mistake.
 */
#include "gl.h"

#include <stdlib.h>
#include <string.h>

#define GL_PROFILE_MAGIC 0x0D000721u

typedef struct {
    const char *name;
    const char *const *keys;
} gl_group_spec;

static const char *const K_META[] = {
    "kernel_major", "recommend_shizuku", "fallback_route", "safe_mode",
    "vr_guard", NULL};
static const char *const K_TASK_STRUCT[] = {
    "prio", "normal_prio", "sched_task_group", "pi_lock", "pi_waiters",
    "pi_top_task", "pi_blocked_on", "pid", "tgid", "atomic_flags", "real_cred",
    "cred", "comm", "tasks", "seccomp", NULL};
static const char *const K_CRED[] = {
    "copy_size", "usage_offset", "usage_value", "caps_offset", "caps_count",
    "caps_value", "ref_count", "ref0_offset", "ref0_image", "ref1_offset",
    "ref1_image", "ref2_offset", "ref2_image", "ref3_offset", "ref3_image",
    NULL};
static const char *const K_OFFSET[] = {
    "init_task", "init_cred", "empty_zero_page", "root_task_group",
    "selinux_enforcing", "selinux_blob_sizes", "security_hook_heads",
    "slide_nfulnl_logger", "slide_loggers_0_1", "slide_boot_id",
    "vr_sys_exit_tp", NULL};
static const char *const K_KERNEL[] = {
    "kernel_phys_load", "kernel_phys_offset", "compact_waiter",
    "kernelsnitch_collisions", "mm_struct_sz", NULL};
static const char *const K_EXEC_RECOMMENDED[] = {"main", "consumer", NULL};
static const char *const K_EXEC_HEAP[] = {
    "prepare_max_attempts", "prepare_timeout_ms", "kernelsnitch_timeout_ms",
    NULL};
static const char *const K_EXEC_RACE[] = {
    "route_wait_ms", "route_done_timeout_ms", "setup_settle_us",
    "state_poll_interval_us", NULL};
static const char *const K_EXEC_STAGES[] = {
    "w1_attempts", "w1_settle_us", "w1_scratch_repair_attempts", "w2_attempts",
    "w2_settle_us", "w3_chain_rounds", "w3_attempts", "w3_settle_us", NULL};
static const char *const K_EXEC_HANDOFF[] = {
    "pre_dispatch_settle_ms", "module_poll_attempts", "module_poll_interval_ms",
    "enforce_poll_attempts", "enforce_poll_interval_ms", NULL};
static const char *const K_EXEC_CONSUMER[] = {"max_calls", "burst_calls", NULL};
static const char *const K_ROUTE_TCP[] = {
    "attempts", "arm_sequence", "post_receive_hold_iterations", NULL};
static const char *const K_ROUTE_SELECT[] = {
    "waiter_shift", "compact_waiter", "enter_delay_us", "timeout_us", NULL};
static const char *const K_ROUTE_MULTICAST[] = {
    "waiter_off", "buffer_size", "task_offset", "lock_offset", "attempts",
    "arm_sequence", "arm_hold", NULL};
static const char *const K_VR_GUARD[] = {"tracepoint_funcs", NULL};

static const gl_group_spec SPECS[] = {
    {"meta", K_META},
    {"task_struct", K_TASK_STRUCT},
    {"cred", K_CRED},
    {"offset", K_OFFSET},
    {"kernel", K_KERNEL},
    {"execution.recommended_cpus", K_EXEC_RECOMMENDED},
    {"execution.heap", K_EXEC_HEAP},
    {"execution.race", K_EXEC_RACE},
    {"execution.stages", K_EXEC_STAGES},
    {"execution.handoff", K_EXEC_HANDOFF},
    {"execution.consumer", K_EXEC_CONSUMER},
    {"route.tcp_zerocopy", K_ROUTE_TCP},
    {"route.select_stack", K_ROUTE_SELECT},
    {"route.multicast_waiter", K_ROUTE_MULTICAST},
    {"vr_guard", K_VR_GUARD},
};
#define N_SPECS ((int)(sizeof SPECS / sizeof SPECS[0]))

const char *gl_route_name(uint16_t id)
{
    switch (id) {
    case 1: return "tcp_zerocopy";
    case 2: return "select_stack";
    case 3: return "multicast_waiter";
    default: return "unknown";
    }
}

static uint16_t rd_u16(const unsigned char *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t rd_u32(const unsigned char *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static int64_t rd_i64(const unsigned char *p)
{
    uint64_t v = (uint64_t)p[0] | ((uint64_t)p[1] << 8) | ((uint64_t)p[2] << 16) |
                 ((uint64_t)p[3] << 24) | ((uint64_t)p[4] << 32) |
                 ((uint64_t)p[5] << 40) | ((uint64_t)p[6] << 48) |
                 ((uint64_t)p[7] << 56);
    return (int64_t)v;
}

void gl_profile_free(gl_profile *p)
{
    if (!p) return;
    for (uint16_t i = 0; i < p->n_groups; i++) {
        gl_group *g = &p->groups[i];
        for (uint32_t j = 0; j < g->count; j++) free(g->kv[j].key);
        free(g->kv);
        free(g->name);
    }
    free(p->groups);
    memset(p, 0, sizeof *p);
}

static char *perr(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    char *s = xmalloc((size_t)n + 1);
    va_start(ap, fmt);
    vsnprintf(s, (size_t)n + 1, fmt, ap);
    va_end(ap);
    return s;
}

int gl_profile_parse(const void *data, size_t len, gl_profile *p, char **err)
{
    const unsigned char *b = data;
    memset(p, 0, sizeof *p);
    if (err) *err = NULL;

    if (!b || len < 16) {
        if (err) *err = perr("blob 太短（%zu B < 16）", len);
        return -1;
    }
    uint32_t magic = rd_u32(b);
    if (magic != GL_PROFILE_MAGIC) {
        if (err)
            *err = perr("magic 不对：0x%08X（应为 0x%08X）", magic,
                        GL_PROFILE_MAGIC);
        return -1;
    }
    p->version = rd_u16(b + 4);
    p->flag_a = rd_u16(b + 6);
    p->flag_b = rd_u16(b + 8);
    p->route_id = rd_u16(b + 10);
    p->release_len = rd_u16(b + 12);
    p->reserved = rd_u16(b + 14);

    if (p->version != 2) {
        if (err) *err = perr("version=%u（native 只接受 2）", p->version);
        return -1;
    }
    if (p->flag_a < 1 || p->flag_a > 2 || p->flag_b < 1 || p->flag_b > 2) {
        if (err)
            *err = perr("flag_a/b 越界：%u/%u（应为 1..2）", p->flag_a, p->flag_b);
        return -1;
    }
    if (p->route_id == 0 || p->route_id > 255) {
        if (err) *err = perr("route_id=%u 非法", p->route_id);
        return -1;
    }
    if (p->release_len > 255) {
        if (err) *err = perr("release_len=%u > 255（native 硬限制）", p->release_len);
        return -1;
    }
    if (len < 16 || (size_t)p->release_len > len - 16) {
        if (err) *err = perr("release 越界：len=%zu release_len=%u", len, p->release_len);
        return -1;
    }
    memcpy(p->release, b + 16, p->release_len);
    p->release[p->release_len] = '\0';
    for (size_t i = 0; i < p->release_len; i++)
        if (p->release[i] == '\0') {
            if (err) *err = perr("release 内含 NUL");
            return -1;
        }
    /* The caller's device string is NUL-terminated on the device side; a CR is
     * never legitimate here. */
    if (strchr(p->release, '\r')) {
        if (err) *err = perr("release 内含 CR（uname -r 不应该有）");
        return -1;
    }

    size_t off = 16 + p->release_len;
    if (len < off + 2) {
        if (err) *err = perr("缺少 group_count（off=%zu len=%zu）", off, len);
        return -1;
    }
    uint16_t ng = rd_u16(b + off);
    off += 2;
    if (ng > 256) {
        if (err) *err = perr("group_count=%u 不合理", ng);
        return -1;
    }
    p->groups = xcalloc(ng ? ng : 1, sizeof *p->groups);
    p->n_groups = ng;

    for (uint16_t gi = 0; gi < ng; gi++) {
        gl_group *g = &p->groups[gi];
        if (off + 1 > len) {
            if (err) *err = perr("组 %u：缺 name_len", gi);
            goto fail;
        }
        uint8_t nl = b[off++];
        if (nl == 0 || off + nl > len) {
            if (err) *err = perr("组 %u：name_len=%u 越界", gi, nl);
            goto fail;
        }
        g->name = xstrndup((const char *)b + off, nl);
        off += nl;
        if (off + 4 > len) {
            if (err) *err = perr("组 %s：缺 entry_count", g->name);
            goto fail;
        }
        uint32_t cnt = rd_u32(b + off);
        off += 4;
        if (cnt > 4096) {
            if (err) *err = perr("组 %s：entry_count=%u 不合理", g->name, cnt);
            goto fail;
        }
        g->kv = xcalloc(cnt ? cnt : 1, sizeof *g->kv);
        g->count = cnt;
        for (uint32_t ki = 0; ki < cnt; ki++) {
            if (off + 1 > len) {
                if (err) *err = perr("组 %s 第 %u 项：缺 key_len", g->name, ki);
                goto fail;
            }
            uint8_t kl = b[off++];
            if (kl == 0 || off + kl + 8 > len) {
                if (err) *err = perr("组 %s 第 %u 项：key/value 越界", g->name, ki);
                goto fail;
            }
            g->kv[ki].key = xstrndup((const char *)b + off, kl);
            off += kl;
            g->kv[ki].value = rd_i64(b + off);
            off += 8;
        }
    }
    return 0;

fail:
    gl_profile_free(p);
    return -1;
}

static const gl_group_spec *find_spec(const char *name)
{
    for (int i = 0; i < N_SPECS; i++)
        if (str_eq(SPECS[i].name, name)) return &SPECS[i];
    return NULL;
}

static bool key_known(const char *const *keys, const char *key)
{
    for (int i = 0; keys[i]; i++)
        if (str_eq(keys[i], key)) return true;
    return false;
}

int gl_profile_validate(const gl_profile *p, gl_buf *report)
{
    int unknown = 0;
    for (uint16_t i = 0; i < p->n_groups; i++) {
        const gl_group *g = &p->groups[i];
        const gl_group_spec *spec = find_spec(g->name);
        if (!spec) {
            unknown++;
            if (report) gl_buf_addf(report, "unknown group: %s\n", g->name);
            continue;
        }
        for (uint32_t j = 0; j < g->count; j++) {
            if (!key_known(spec->keys, g->kv[j].key)) {
                unknown++;
                if (report)
                    gl_buf_addf(report, "unknown key: %s.%s\n", g->name,
                                g->kv[j].key);
            }
        }
    }
    /* Only the group matching the header route is consumed natively. */
    const char *want = NULL;
    switch (p->route_id) {
    case 1: want = "route.tcp_zerocopy"; break;
    case 2: want = "route.select_stack"; break;
    case 3: want = "route.multicast_waiter"; break;
    default: break;
    }
    if (report) {
        bool have_route = false;
        if (want) {
            for (uint16_t i = 0; i < p->n_groups; i++)
                if (str_eq(p->groups[i].name, want)) have_route = true;
            if (!have_route)
                gl_buf_addf(report,
                            "note: 没有 %s 组（header route_id=%u），"
                            "native 不会启用任何 route.* 组\n",
                            want, p->route_id);
        }
        for (uint16_t i = 0; i < p->n_groups; i++) {
            if (!str_starts(p->groups[i].name, "route.")) continue;
            if (want && !str_eq(p->groups[i].name, want))
                gl_buf_addf(report,
                            "note: 组 %s 与 header route_id=%u 不匹配，"
                            "native 会忽略它\n",
                            p->groups[i].name, p->route_id);
        }
    }
    return unknown;
}
