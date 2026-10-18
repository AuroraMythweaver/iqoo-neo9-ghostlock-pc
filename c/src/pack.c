/*
 * pack.c -- GLPACK01 payload container (the same format mkpack.py writes).
 *
 *   0x00   8B   "GLPACK01"
 *   0x08   u64  data_start
 *   0x10   u32  n_entries
 *   0x14   u32  format_version (=1)
 *   0x18   n x 32B { u64 off; u64 size; char name[16]; }
 *   data_start: payload bytes, off is relative to data_start
 *
 * Every header field is bounds-checked against the real file size before any
 * offset is used; a truncated or hostile pack fails closed.
 */
#include "gl.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define GL_PACK_MAGIC "GLPACK01"
#define GL_PACK_HDR 24
#define GL_PACK_ENT 32

static uint64_t rd_u64(const unsigned char *p)
{
    return (uint64_t)p[0] | ((uint64_t)p[1] << 8) | ((uint64_t)p[2] << 16) |
           ((uint64_t)p[3] << 24) | ((uint64_t)p[4] << 32) |
           ((uint64_t)p[5] << 40) | ((uint64_t)p[6] << 48) |
           ((uint64_t)p[7] << 56);
}

static uint32_t rd_u32(const unsigned char *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

int gl_pack_open(const char *path, gl_pack *p)
{
    FILE *f = NULL;
    memset(p, 0, sizeof *p);
    p->path = xstrdup(path);

    int64_t sz = 0;
    if (file_size(path, &sz) != 0) {
        fprintf(stderr, "[!] 找不到 payload 包：%s\n", path);
        goto fail;
    }
    p->file_size = (uint64_t)sz;
    if (p->file_size < GL_PACK_HDR + 1) {
        fprintf(stderr, "[!] 文件太小，不是 GLPACK 包：%s\n", path);
        goto fail;
    }

    f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "[!] 打不开 %s: %s\n", path, strerror(errno));
        goto fail;
    }
    unsigned char hdr[GL_PACK_HDR];
    if (fread(hdr, 1, sizeof hdr, f) != sizeof hdr) {
        fprintf(stderr, "[!] 读包头失败：%s\n", path);
        goto fail;
    }
    if (memcmp(hdr, GL_PACK_MAGIC, 8) != 0) {
        fprintf(stderr, "[!] 不是 GLPACK 包（magic 不是 GLPACK01）：%s\n", path);
        goto fail;
    }
    p->data_start = rd_u64(hdr + 8);
    p->n_entries = rd_u32(hdr + 16);
    p->format = rd_u32(hdr + 20);

    if (p->format != 1) {
        fprintf(stderr, "[!] 不支持的包格式 version=%u（只认 1）\n", p->format);
        goto fail;
    }
    if (p->n_entries > 4096 ||
        p->data_start > p->file_size ||
        (uint64_t)GL_PACK_HDR + (uint64_t)p->n_entries * GL_PACK_ENT >
            p->data_start) {
        fprintf(stderr, "[!] 包头自相矛盾（n=%u data_start=%llu size=%llu）\n",
                p->n_entries, (unsigned long long)p->data_start,
                (unsigned long long)p->file_size);
        goto fail;
    }

    p->entries = xcalloc(p->n_entries ? p->n_entries : 1, sizeof *p->entries);
    for (uint32_t i = 0; i < p->n_entries; i++) {
        unsigned char ent[GL_PACK_ENT];
        if (fseek(f, (long)(GL_PACK_HDR + (uint64_t)i * GL_PACK_ENT), SEEK_SET) != 0 ||
            fread(ent, 1, sizeof ent, f) != sizeof ent) {
            fprintf(stderr, "[!] 读条目表失败（第 %u 项）\n", i);
            goto fail;
        }
        gl_pack_entry *e = &p->entries[i];
        e->off = rd_u64(ent);
        e->size = rd_u64(ent + 8);
        memcpy(e->name, ent + 16, 16);
        e->name[16] = '\0';
        if (e->off > p->file_size || e->size > p->file_size ||
            p->data_start + e->off > p->file_size ||
            e->size > p->file_size - (p->data_start + e->off)) {
            fprintf(stderr, "[!] 条目越界：%s off=%llu size=%llu\n", e->name,
                    (unsigned long long)e->off, (unsigned long long)e->size);
            goto fail;
        }
    }
    fclose(f);
    return 0;

fail:
    if (f) fclose(f);
    gl_pack_close(p);
    return -1;
}

void gl_pack_close(gl_pack *p)
{
    if (!p) return;
    free(p->path);
    free(p->entries);
    memset(p, 0, sizeof *p);
}

const gl_pack_entry *gl_pack_find(const gl_pack *p, const char *name)
{
    for (uint32_t i = 0; i < p->n_entries; i++)
        if (str_eq(p->entries[i].name, name)) return &p->entries[i];
    return NULL;
}

int gl_pack_read(const gl_pack *p, const gl_pack_entry *e, gl_buf *out)
{
    FILE *in = fopen(p->path, "rb");
    if (!in) return -1;
    if (fseek(in, (long)(p->data_start + e->off), SEEK_SET) != 0) {
        fclose(in);
        return -1;
    }
    unsigned char tmp[65536];
    uint64_t left = e->size;
    int rc = 0;
    while (left) {
        size_t want = left > sizeof tmp ? sizeof tmp : (size_t)left;
        size_t got = fread(tmp, 1, want, in);
        if (got == 0) {
            rc = -1;
            break;
        }
        gl_buf_add(out, tmp, got);
        left -= got;
    }
    fclose(in);
    return rc;
}

int gl_pack_extract(const gl_pack *p, const gl_pack_entry *e, const char *dest)
{
    FILE *in = fopen(p->path, "rb");
    if (!in) return -1;
    FILE *out = fopen(dest, "wb");
    if (!out) {
        fclose(in);
        return -1;
    }
    if (fseek(in, (long)(p->data_start + e->off), SEEK_SET) != 0) {
        fclose(in);
        fclose(out);
        unlink(dest);
        return -1;
    }
    unsigned char tmp[65536];
    uint64_t left = e->size;
    int rc = 0;
    while (left) {
        size_t want = left > sizeof tmp ? sizeof tmp : (size_t)left;
        size_t got = fread(tmp, 1, want, in);
        if (got == 0) {
            rc = -1;
            break;
        }
        if (fwrite(tmp, 1, got, out) != got) {
            rc = -1;
            break;
        }
        left -= got;
    }
    if (fclose(out) != 0) rc = -1;
    fclose(in);
    if (rc != 0) unlink(dest);
    return rc;
}
