/*
 * cmd_blob.c -- `blob dump|check <profile.bin>`: inspect a kernel profile blob
 * without a device. Useful before pushing a regenerated profile.
 */
#include "internal.h"

#include <stdlib.h>
#include <string.h>

static void print_profile(const gl_profile *p)
{
    say("magic     : 0x%08X", 0x0D000721u);
    say("version   : %u", p->version);
    say("flag_a/b  : %u / %u", p->flag_a, p->flag_b);
    say("route     : %u (%s)", p->route_id, gl_route_name(p->route_id));
    say("release   : %s (%u B)", p->release, p->release_len);
    say("reserved  : %u", p->reserved);
    say("groups    : %u", p->n_groups);
    for (uint16_t i = 0; i < p->n_groups; i++) {
        const gl_group *g = &p->groups[i];
        say("  [%s]  %u 项", g->name, g->count);
        for (uint32_t j = 0; j < g->count; j++)
            say("    %-32s = %lld", g->kv[j].key, (long long)g->kv[j].value);
    }
}

int cmd_blob(const char *sub, const char *file, const char *expected_release)
{
    if (!sub || !file) {
        say("用法：ghostlock blob dump|check <profile.bin> [expected-release]");
        return 2;
    }
    gl_buf raw;
    gl_buf_init(&raw);
    if (read_file(file, &raw) != 0) {
        msg_warn("读不到 %s", file);
        gl_buf_free(&raw);
        return 2;
    }
    gl_profile prof;
    char *err = NULL;
    if (gl_profile_parse(raw.p, raw.len, &prof, &err) != 0) {
        msg_warn("解析失败：%s", err ? err : "?");
        free(err);
        gl_buf_free(&raw);
        return 1;
    }
    gl_buf report;
    gl_buf_init(&report);
    int unknown = gl_profile_validate(&prof, &report);

    if (str_eq(sub, "dump")) {
        say("blob      : %s (%zu B)", file, raw.len);
        print_profile(&prof);
    }
    if (report.len) {
        fputs("--- native 白名单检查 ---\n", stdout);
        fputs(report.p, stdout);
    }
    if (str_eq(sub, "dump")) say("unknown   : %d", unknown);

    int rc = 0;
    if (expected_release && *expected_release) {
        if (str_eq(prof.release, expected_release))
            say("match     : YES (release == %s)", expected_release);
        else {
            say("match     : NO   (blob=%s expected=%s)", prof.release,
                expected_release);
            rc = 3;
        }
    }
    if (str_eq(sub, "check")) {
        say("blob      : %s (%zu B)", file, raw.len);
        say("release   : %s (route=%s, groups=%u)", prof.release,
            gl_route_name(prof.route_id), prof.n_groups);
        say("unknown   : %d", unknown);
        if (unknown) rc = 1;
    } else if (unknown) {
        rc = 1;
    }
    gl_buf_free(&report);
    gl_profile_free(&prof);
    gl_buf_free(&raw);
    return rc;
}
