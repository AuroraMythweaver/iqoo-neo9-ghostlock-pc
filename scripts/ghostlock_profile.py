#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ghostlock_profile.py -- GhostLock 内核 profile 二进制 (.bin) 生成器 / 校验器

用途
----
App (com.ghostlock.app) 把 HOCON 内核配置解析成一个二进制 profile blob，然后通过
stdin 交给 libghostlock.so。命令行侧没有这个 Java 解析器，所以这里用 Python 1:1
复刻 Apk 内的生产者（defpackage.ea1.a()）与解析器（defpackage.fm.C()），
使 PC 端可以自己产出同一份 blob，交给 libghostlock.so
`--ghostlock-app-call`（stdin）或 `--load-prebuilt-profile <bin>` 使用。

blob 布局（字节级，由两侧代码 + native 反汇编三方交叉确认）
------------------------------------------------------------
  off  size  field                     evidence
  0x00  u32  magic = 0x0D000721        native 0x67df0: movz w9,#0x721 / movk w9,#0xd00,lsl16
  0x04  u16  version = 2               native 0x67e00: ldrh w8,[x0,#4]; cmp x8,#2
  0x06  u16  flag_a ∈ {1,2}            native 0x67e0c: ldrh [x0,#6]; (v-1)<=1
  0x08  u16  flag_b ∈ {1,2}            native 0x67e1c: ldrh [x0,#8]; (v-1)<=1
  0x0a  u16  route_id  (1|2|3)         native 0x67e38: ldrb [x8,#0xa] | ldrb [x8,#0xb]<<8
  0x0c  u16  release_len (native ≤255) native 0x67e4c: ldrh [x8,#0xc]; cmp #0xff
  0x0e  u16  reserved (ignored)        Java writer 写 0
  0x10  ...  release[release_len]
  +0    u16  group_count
  per group : u8 name_len, name[name_len], u32 entry_count,
              per entry: u8 key_len, key[key_len], i64 value
               (native 0x68130: ldrb key_len / add x8,key_len / add x27,x8,#8)

native 只接受下列 15 个组名（@0x76608，stride 0x20，已解析出每组的 key 表）和
当前 route_id 对应的 route.<name> 组；未知组/未知 key 会被静默丢弃（不报错）。
本脚本按 native 的 key 白名单做严格校验，避免发出"看起来对、实际被丢掉"的字段。

用法
----
  # 从 assets 里的 .conf 生成 blob（自动叠加 execution-tuning.conf 作为基线）
  python3 ghostlock_profile.py build \
      -c <path>/5.15.197-g708015331567-dirty.conf \
      -o out/profile.bin [--release-override <uname -r>] [--verbose]

  # 校验一份已有 blob（结构 + 语义）
  python3 ghostlock_profile.py dump out/profile.bin

坑（真机实测）
--------------
`.conf` 里 multicast 路由没有 `execution.routes.multicast_waiter.consumer_*`，本工具会给出
`execution.consumer.max_calls = 0`；而在 PD2338/5.15.197 上实测，0 会让 consumer 一次都
不触发（native 日志 `attempts=128 calls=0 success=0`，随后 `Write 1 failed`）。
实战用的是设备上那份 2058 B blob（`max_calls=1 / burst_calls=1`，另带 `compact_waiter=1`
和 `offset.vr_sys_exit_tp`），已备份在 `../evidence/profile.bin`。要现场生成的话，
用 overlay 把 `execution.consumer.max_calls` 顶成 1。
"""
import argparse
import json
import os
import struct
import sys

MAGIC = 0x0D000721
VERSION = 2

ROUTE_IDS = {"tcp_zerocopy": 1, "select_stack": 2, "multicast_waiter": 3}

# ---------------------------------------------------------------------------
# native 侧白名单（从 libghostlock.so .data.rel.ro @0x76608 解析出来的）
# 组名 -> 该组被 native 接受的 key 集合（顺序即 native 表顺序）
# ---------------------------------------------------------------------------
NATIVE_SCHEMA = {
    "meta": ["kernel_major", "recommend_shizuku", "fallback_route", "safe_mode", "vr_guard"],
    "task_struct": ["prio", "normal_prio", "sched_task_group", "pi_lock", "pi_waiters",
                    "pi_top_task", "pi_blocked_on", "pid", "tgid", "atomic_flags",
                    "real_cred", "cred", "comm", "tasks", "seccomp"],
    "cred": ["copy_size", "usage_offset", "usage_value", "caps_offset", "caps_count",
             "caps_value", "ref_count", "ref0_offset", "ref1_offset", "ref2_offset",
             "ref3_offset", "ref0_image", "ref1_image", "ref2_image", "ref3_image"],
    "offset": ["init_task", "init_cred", "empty_zero_page", "root_task_group",
               "selinux_enforcing", "selinux_blob_sizes", "security_hook_heads",
               "slide_nfulnl_logger", "slide_loggers_0_1", "slide_boot_id", "vr_sys_exit_tp"],
    "kernel": ["kernel_phys_load", "kernel_phys_offset", "compact_waiter",
               "kernelsnitch_collisions", "mm_struct_sz"],
    "execution.recommended_cpus": ["main", "consumer"],
    "execution.heap": ["prepare_max_attempts", "prepare_timeout_ms", "kernelsnitch_timeout_ms"],
    "execution.race": ["route_wait_ms", "route_done_timeout_ms", "setup_settle_us",
                       "state_poll_interval_us"],
    "execution.stages": ["w1_attempts", "w1_settle_us", "w1_scratch_repair_attempts",
                         "w2_attempts", "w2_settle_us", "w3_chain_rounds", "w3_attempts",
                         "w3_settle_us"],
    "execution.handoff": ["pre_dispatch_settle_ms", "module_poll_attempts",
                          "module_poll_interval_ms", "enforce_poll_attempts",
                          "enforce_poll_interval_ms"],
    "execution.consumer": ["max_calls", "burst_calls"],
    "route.tcp_zerocopy": ["attempts", "arm_sequence", "post_receive_hold_iterations"],
    "route.select_stack": ["waiter_shift", "compact_waiter", "enter_delay_us", "timeout_us"],
    "route.multicast_waiter": ["waiter_off", "buffer_size", "task_offset", "lock_offset",
                               "attempts", "arm_sequence", "arm_hold"],
    "vr_guard": ["tracepoint_funcs"],
}

# ea1.a() 写出的组顺序（native 按名字查表，与顺序无关；保持一致便于比对）
GROUP_ORDER = ["meta", "task_struct", "cred", "offset", "kernel",
               "execution.recommended_cpus", "execution.heap", "execution.race",
               "execution.stages", "execution.handoff", "execution.consumer"]


# ---------------------------------------------------------------------------
# 极简 HOCON 解析（够用：注释 / 嵌套 / a.b = v / 负整数 / 引号字符串 / null）
# ---------------------------------------------------------------------------
class HoconError(Exception):
    pass


def _strip_comments(text):
    out, i, n = [], 0, len(text)
    in_str = False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == '\\' and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
            out.append(c)
            i += 1
            continue
        if c == '#':
            while i < n and text[i] != '\n':
                i += 1
            continue
        if c == '/' and i + 1 < n and text[i + 1] == '/':
            while i < n and text[i] != '\n':
                i += 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _tokenize(text):
    toks, i, n = [], 0, len(text)
    while i < n:
        c = text[i]
        if c.isspace():
            i += 1
            continue
        if c in '{}[]=,:':
            toks.append(c)
            i += 1
            continue
        if c == '"':
            j, buf = i + 1, []
            while j < n and text[j] != '"':
                if text[j] == '\\' and j + 1 < n:
                    buf.append(text[j + 1])
                    j += 2
                    continue
                buf.append(text[j])
                j += 1
            toks.append(('str', "".join(buf)))
            i = j + 1
            continue
        j = i
        while j < n and not text[j].isspace() and text[j] not in '{}[]=,:':
            j += 1
        toks.append(('atom', text[i:j]))
        i = j
    return toks


def parse_hocon(text):
    """返回嵌套 dict；a.b = v 展平成 'a.b' 键（与 Java 侧 xm1 的点路径一致）。"""
    toks = _tokenize(_strip_comments(text))
    pos = 0

    def parse_value():
        nonlocal pos
        if pos >= len(toks):
            raise HoconError("unexpected EOF")
        t = toks[pos]
        if t == '{':
            pos += 1
            return parse_block()
        if t == '[':
            pos += 1
            arr = []
            if pos < len(toks) and toks[pos] == ']':
                pos += 1
                return arr
            while True:
                arr.append(parse_value())
                if pos < len(toks) and toks[pos] == ',':
                    pos += 1
                    continue
                if pos < len(toks) and toks[pos] == ']':
                    pos += 1
                    return arr
                raise HoconError("bad array")
        if isinstance(t, tuple):
            pos += 1
            return t
        raise HoconError("unexpected token %r" % (t,))

    def parse_block():
        nonlocal pos
        d = {}
        while pos < len(toks):
            if toks[pos] == '}':
                pos += 1
                return d
            keyparts = []
            while pos < len(toks) and toks[pos] not in ('=', '{'):
                if toks[pos] in ('{', '}', ']', ',', ':'):
                    raise HoconError("bad key near %r" % (toks[pos],))
                keyparts.append(str(toks[pos][1] if isinstance(toks[pos], tuple) else toks[pos]))
                pos += 1
            key = ".".join(keyparts)
            if pos < len(toks) and toks[pos] == '{':
                val = parse_value()          # HOCON 允许 `key { ... }`
            elif pos < len(toks) and toks[pos] == '=':
                pos += 1
                val = parse_value()
            else:
                raise HoconError("expected '=' or '{' after key %r" % keyparts)
            _assign(d, key, val)
        raise HoconError("unterminated block")

    def _assign(d, key, val):
        parts = key.split('.')
        cur = d
        for p in parts[:-1]:
            cur = cur.setdefault(p, {})
            if not isinstance(cur, dict):
                raise HoconError("key path conflict at %r" % key)
        cur[parts[-1]] = val

    root = {}
    while pos < len(toks):
        keyparts = []
        while pos < len(toks) and toks[pos] not in ('=', '{'):
            if toks[pos] in ('{', '}', ']', '[', ',', ':'):
                raise HoconError("bad top-level key near %r" % (toks[pos],))
            keyparts.append(str(toks[pos][1] if isinstance(toks[pos], tuple) else toks[pos]))
            pos += 1
        key = ".".join(keyparts)
        if pos < len(toks) and toks[pos] == '{':
            _assign(root, key, parse_value())
            continue
        if pos >= len(toks):
            break
        pos += 1  # '='
        _assign(root, key, parse_value())
    return root


# ---------------------------------------------------------------------------
# 扁平化：嵌套 dict -> {"a.b.c": int}  (与 Java xm1.r 的点路径查找等价)
# ---------------------------------------------------------------------------
def flatten(d, prefix=""):
    out = {}
    for k, v in d.items():
        key = prefix + k
        if isinstance(v, dict):
            out.update(flatten(v, key + "."))
        elif isinstance(v, list):
            continue
        else:
            out[key] = v
    return out


def deep_merge(base, over):
    """over 覆盖 base（两者都是扁平字典）。"""
    out = dict(base)
    for k, v in over.items():
        out[k] = v
    return out


def to_int(v, key):
    if isinstance(v, tuple):
        s = v[1]
        if s.lower() == "null":
            return None
        try:
            return int(s, 0)
        except ValueError:
            raise HoconError("key %r is not an integer: %r" % (key, s))
    if isinstance(v, int):
        return v
    raise HoconError("key %r is not an integer: %r" % (key, v))


def pick_int(flat, key, default=None):
    if key not in flat:
        return default
    return to_int(flat[key], key)


def get_str(v, key):
    if isinstance(v, tuple):
        s = v[1]
        if s.lower() == "null":
            return None
        return s
    raise HoconError("key %r is not a string: %r" % (key, v))


# ---------------------------------------------------------------------------
# 构建 blob
# ---------------------------------------------------------------------------
def build_spec(flat, route_name, fallback_name, release, verbose=False):
    """按 Java c9.c() 的字段映射产出 (groups_order, {group: [(key, i64)]})."""
    groups = {g: [] for g in NATIVE_SCHEMA}
    warnings = []

    kernel_major = pick_int(flat, "kernel_major", 0)
    recommend_shizuku = pick_int(flat, "recommend_shizuku", 0) or 0
    safe_mode = 0  # c9.c() 固定传 0
    fallback_id = ROUTE_IDS.get(fallback_name, 0) if fallback_name else 0
    route_id = ROUTE_IDS[route_name]

    groups["meta"] = [
        ("kernel_major", kernel_major),
        ("recommend_shizuku", recommend_shizuku),
        ("fallback_route", fallback_id),
        ("safe_mode", safe_mode),
    ]

    for k in NATIVE_SCHEMA["task_struct"]:
        v = pick_int(flat, "task_struct." + k, 0) or 0
        groups["task_struct"].append((k, v))

    for k in NATIVE_SCHEMA["cred"]:
        v = pick_int(flat, "cred." + k, 0) or 0
        groups["cred"].append((k, v))

    for k in NATIVE_SCHEMA["offset"]:
        # vr_sys_exit_tp 只在 .conf 里显式给出时才带（App 的 writer 不写它）
        if k == "vr_sys_exit_tp" and ("offset." + k) not in flat:
            continue
        v = pick_int(flat, "offset." + k, 0) or 0
        groups["offset"].append((k, v))

    # kernel 组：只带非 null 的项（ea1 的行为）
    kphys_load = pick_int(flat, "kernel_phys_load")
    if kphys_load is not None:
        groups["kernel"].append(("kernel_phys_load", kphys_load))
    kphys_off = pick_int(flat, "kernel_phys_offset")
    if kphys_off is not None:
        groups["kernel"].append(("kernel_phys_offset", kphys_off))
    # compact_waiter：App 只查顶层 key（c9.c(): k3.i("compact_waiter")）。route 块里的
    # compact_waiter 会被 route 对象丢弃（jt0/kt0 只有 4 个几何字段，没有它），
    # 只有 select_stack 路由对象（xh1）才自带 compact_waiter。这里严格照抄，
    # 保证与 App 产出的 blob 一致；若 profile 需要它，请在 .conf 顶层写
    # compact_waiter = 1（native 认 kernel 组这个 key）。
    cw = pick_int(flat, "compact_waiter")
    if cw is not None:
        groups["kernel"].append(("compact_waiter", cw & 0xFF))
    elif ("route.%s.compact_waiter" % route_name) in flat:
        warnings.append("route.%s.compact_waiter is inert in the App path "
                        "(route object has no such field); native only reads the "
                        "top-level kernel.compact_waiter -- add a top-level "
                        "'compact_waiter = N' if you need it" % route_name)
    coll = pick_int(flat, "kernelsnitch.collisions")
    if coll is not None:
        groups["kernel"].append(("kernelsnitch_collisions", coll))
    mm = pick_int(flat, "kernelsnitch.mm_struct_sz")
    if mm is not None:
        groups["kernel"].append(("mm_struct_sz", mm))

    # CPU：selected_cpus 覆盖 recommended_cpus（Java k3 的行为）
    main_cpu = pick_int(flat, "execution.selected_cpus.main")
    if main_cpu is None:
        main_cpu = pick_int(flat, "execution.recommended_cpus.main", 0)
    cons_cpu = pick_int(flat, "execution.selected_cpus.consumer")
    if cons_cpu is None:
        cons_cpu = pick_int(flat, "execution.recommended_cpus.consumer", 0)
    groups["execution.recommended_cpus"] = [("main", main_cpu or 0),
                                            ("consumer", cons_cpu or 0)]

    for k in NATIVE_SCHEMA["execution.heap"]:
        groups["execution.heap"].append((k, pick_int(flat, "execution.heap." + k, 0) or 0))
    for k in NATIVE_SCHEMA["execution.race"]:
        groups["execution.race"].append((k, pick_int(flat, "execution.race." + k, 0) or 0))
    for k in NATIVE_SCHEMA["execution.stages"]:
        groups["execution.stages"].append((k, pick_int(flat, "execution.stages." + k, 0) or 0))
    for k in NATIVE_SCHEMA["execution.handoff"]:
        groups["execution.handoff"].append((k, pick_int(flat, "execution.handoff." + k, 0) or 0))

    # execution.consumer：Java 取 execution.routes.<route>.consumer_*（缺省 0）
    mc = pick_int(flat, "execution.routes.%s.consumer_max_calls" % route_name)
    bc = pick_int(flat, "execution.routes.%s.consumer_burst_calls" % route_name)
    if mc is None:
        mc = pick_int(flat, "execution.consumer.max_calls", 0)
    if bc is None:
        bc = pick_int(flat, "execution.consumer.burst_calls", 0)
    groups["execution.consumer"] = [("max_calls", mc or 0), ("burst_calls", bc or 0)]

    # route 组：只带该 route 在 native 白名单里的 key
    rg = "route." + route_name
    for k in NATIVE_SCHEMA[rg]:
        v = pick_int(flat, "%s.%s" % (rg, k))
        if v is not None:
            groups[rg].append((k, v))

    # 校验：丢掉 native 不认识的 key，并提示
    for g, items in list(groups.items()):
        allowed = NATIVE_SCHEMA[g]
        keep = []
        for k, v in items:
            if k not in allowed:
                warnings.append("drop unknown-in-native key %s.%s" % (g, k))
                continue
            if not (-(1 << 63) <= v < (1 << 63)):
                raise HoconError("%s.%s out of int64 range" % (g, k))
            keep.append((k, v))
        groups[g] = keep

    order = [g for g in GROUP_ORDER if groups[g]] + [rg]
    return order, groups, route_id, warnings


def serialize(release, route_id, order, groups):
    rel = release.encode()
    if len(rel) > 255:
        raise HoconError("release too long for native parser (>255): %d" % len(rel))
    buf = bytearray()
    buf += struct.pack("<IHHHHHH", MAGIC, VERSION, 1, 1, route_id, len(rel), 0)
    buf += rel
    present = [g for g in order if groups.get(g)]
    buf += struct.pack("<H", len(present))
    for g in present:
        gb = g.encode()
        if len(gb) > 255:
            raise HoconError("group name too long: %s" % g)
        buf += struct.pack("<B", len(gb)) + gb
        items = groups[g]
        buf += struct.pack("<I", len(items))
        for k, v in items:
            kb = k.encode()
            if len(kb) > 255:
                raise HoconError("key too long: %s" % k)
            buf += struct.pack("<B", len(kb)) + kb + struct.pack("<q", v)
    return bytes(buf)


# ---------------------------------------------------------------------------
# 解析器：1:1 复刻 fm.C()（用于自校验 / dump）
# ---------------------------------------------------------------------------
def parse_blob(buf):
    if len(buf) < 16:
        raise HoconError("too short")
    magic, version, fa, fb, route_id, rel_len, _pad = struct.unpack_from("<IHHHHHH", buf, 0)
    if magic != MAGIC:
        raise HoconError("bad magic 0x%08x" % magic)
    if version != 2:
        raise HoconError("bad version %d" % version)
    if fa not in (1, 2) or fb not in (1, 2):
        raise HoconError("bad flags %d %d" % (fa, fb))
    if route_id not in ROUTE_IDS.values():
        raise HoconError("bad route id %d" % route_id)
    off = 16
    release = buf[off:off + rel_len].decode()
    off += rel_len
    (gcount,) = struct.unpack_from("<H", buf, off)
    off += 2
    groups = {}
    for _ in range(gcount):
        (nl,) = struct.unpack_from("<B", buf, off)
        off += 1
        name = buf[off:off + nl].decode()
        off += nl
        (ecount,) = struct.unpack_from("<I", buf, off)
        off += 4
        entries = []
        for _ in range(ecount):
            (kl,) = struct.unpack_from("<B", buf, off)
            off += 1
            key = buf[off:off + kl].decode()
            off += kl
            (val,) = struct.unpack_from("<q", buf, off)
            off += 8
            entries.append((key, val))
        groups[name] = entries
    return {"release": release, "route_id": route_id, "flags": (fa, fb), "groups": groups}


def validate_native(parsed):
    problems = []
    rid = parsed["route_id"]
    route_name = [k for k, v in ROUTE_IDS.items() if v == rid][0]
    allowed_groups = set(NATIVE_SCHEMA) - {"route.tcp_zerocopy", "route.select_stack",
                                           "route.multicast_waiter"}
    allowed_groups.add("route." + route_name)
    for g, items in parsed["groups"].items():
        if g not in allowed_groups:
            problems.append("group %r not accepted by native for route %s" % (g, route_name))
            continue
        for k, _v in items:
            if k not in NATIVE_SCHEMA[g]:
                problems.append("key %s.%s not in native table" % (g, k))
    return problems


def main():
    ap = argparse.ArgumentParser(description="GhostLock kernel profile blob builder")
    sub = ap.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("build", help="HOCON .conf -> binary profile blob")
    b.add_argument("-c", "--conf", required=True, help="device .conf (e.g. 5.15.197-...conf)")
    b.add_argument("-b", "--base", action="append", default=[],
                   help="base conf merged first (repeatable); default: execution-tuning.conf next to -c")
    b.add_argument("-o", "--out", required=True)
    b.add_argument("--release-override", default=None,
                   help="override the release string (must equal `uname -r` on device)")
    b.add_argument("--route", default=None, choices=list(ROUTE_IDS),
                   help="override the primary route")
    b.add_argument("--verbose", action="store_true")

    d = sub.add_parser("dump", help="inspect/validate an existing blob")
    d.add_argument("bin")

    args = ap.parse_args()

    if args.cmd == "build":
        with open(args.conf, encoding="utf-8", errors="replace") as f:
            conf = parse_hocon(f.read())
        flat = flatten(conf)

        bases = args.base
        if not bases:
            auto = os.path.join(os.path.dirname(os.path.abspath(args.conf)),
                                "execution-tuning.conf")
            if os.path.isfile(auto):
                bases = [auto]
        if bases:
            merged = {}
            for bp in bases:
                with open(bp, encoding="utf-8", errors="replace") as f:
                    merged=deep_merge(merged, flatten(parse_hocon(f.read())))
            flat = deep_merge(merged, flat)

        release = args.release_override or get_str(conf.get("release"), "release")
        if not release:
            sys.exit("error: no release in conf")

        route_cfg = conf.get("route")
        if args.route:
            route_name = args.route
        elif isinstance(route_cfg, dict) and route_cfg:
            cand = [k for k in route_cfg if k in ROUTE_IDS]
            if not cand:
                sys.exit("error: no known route in conf route{} block")
            route_name = cand[0]
        else:
            sys.exit("error: conf has no route{} block")

        fb_cfg = conf.get("fallback")
        fallback_name = None
        if isinstance(fb_cfg, dict):
            to = fb_cfg.get("to")
            to_s = get_str(to, "fallback.to") if to is not None else None
            if to_s and to_s != "none" and to_s in ROUTE_IDS:
                fallback_name = to_s

        order, groups, route_id, warnings = build_spec(flat, route_name, fallback_name,
                                                       release, args.verbose)
        blob = serialize(release, route_id, order, groups)
        parsed = parse_blob(blob)
        problems = validate_native(parsed)
        if problems:
            for p in problems:
                print("VALIDATION ERROR:", p, file=sys.stderr)
            sys.exit(2)

        with open(args.out, "wb") as f:
            f.write(blob)

        print("wrote %s  (%d bytes)" % (args.out, len(blob)))
        print("  release   : %s" % release)
        print("  route     : %s (id=%d) fallback=%s" %
              (route_name, route_id, fallback_name or "none"))
        print("  groups    : %d -> %s" % (len(parsed["groups"]), ", ".join(parsed["groups"])))
        for w in warnings:
            print("  note      : " + w)
        if args.verbose:
            print()
            for g, items in parsed["groups"].items():
                print("[%s]" % g)
                for k, v in items:
                    print("   %-28s %d  (0x%x)" % (k, v, v & 0xFFFFFFFFFFFFFFFF))
        return

    if args.cmd == "dump":
        with open(args.bin, "rb") as f:
            blob = f.read()
        parsed = parse_blob(blob)
        problems = validate_native(parsed)
        rid = parsed["route_id"]
        rname = [k for k, v in ROUTE_IDS.items() if v == rid][0]
        print("file      : %s (%d bytes)" % (args.bin, len(blob)))
        print("release   : %s" % parsed["release"])
        print("route     : %s (id=%d)" % (rname, rid))
        print("flags     : %s" % (parsed["flags"],))
        for g, items in parsed["groups"].items():
            print("[%s] %d keys" % (g, len(items)))
            for k, v in items:
                print("   %-28s %d  (0x%x)" % (k, v, v & 0xFFFFFFFFFFFFFFFF))
        print()
        print("native-acceptable:", "YES" if not problems else "NO")
        for p in problems:
            print("  -", p)
        print("json:", json.dumps({k: dict(v) for k, v in parsed["groups"].items()},
                                  default=str)[:400])
        return


if __name__ == "__main__":
    main()
