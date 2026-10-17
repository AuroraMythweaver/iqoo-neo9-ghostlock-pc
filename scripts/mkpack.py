#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mkpack.py -- 把 GhostLock 的设备端 payload 打成一个二进制包（供 reroot.sh 读取）

为什么要打包
------------
设备端需要三个文件：libghostlock.so（exploit CLI）、vrpatch.ko（中和 vr.ko）、
profile.bin（内核参数 blob）。散着放不方便带，所以打成一个 .bin，
PC 侧只留 "一个脚本 + 一个二进制" 两件东西。

容器格式（全部 little-endian，纯 bash 也能解析）
------------------------------------------------
  0x00  8B   magic "GLPACK01"
  0x08  u64  data_start        # 第一段 payload 的绝对偏移
  0x10  u32  n_entries
  0x14  u32  format_version    # = 1
  0x18  n × 32B 条目:
         +0x00 u64  off        # 相对 data_start
         +0x08 u64  size
         +0x10 char name[16]   # NUL 补齐
  data_start: payload 依次排列

用法
----
  python3 mkpack.py -o ../ghostlock.bin \\
      --blob ../evidence/profile.bin \\
      --lib  ../apkout/lib/arm64-v8a/libghostlock.so \\
      --ko   ../apkout/assets/modules/vrpatch.ko

  python3 mkpack.py --list ../ghostlock.bin      # 看包里的东西
"""
import argparse
import json
import os
import struct
import sys

MAGIC = b"GLPACK01"
FORMAT_VERSION = 1
ENTRY = 32


def build(out_path, items):
    """items: [(name, bytes)]"""
    hdr_len = 24 + ENTRY * len(items)
    data_start = hdr_len
    hdr = bytearray()
    hdr += MAGIC
    hdr += struct.pack("<Q", data_start)
    hdr += struct.pack("<I", len(items))
    hdr += struct.pack("<I", FORMAT_VERSION)

    blob = bytearray()
    off = 0
    for name, data in items:
        nb = name.encode()
        if len(nb) > 16:
            raise SystemExit("name too long: %s" % name)
        hdr += struct.pack("<QQ", off, len(data))
        hdr += nb + b"\0" * (16 - len(nb))
        blob += data
        off += len(data)

    with open(out_path, "wb") as f:
        f.write(bytes(hdr) + bytes(blob))
    return hdr_len, len(blob)


def load(path):
    d = open(path, "rb").read()
    if len(d) < 24 or d[:8] != MAGIC:
        raise SystemExit("not a GLPACK file: %s" % path)
    data_start, n, ver = struct.unpack_from("<QII", d, 8)
    if ver != FORMAT_VERSION:
        raise SystemExit("unsupported pack version %d" % ver)
    out = []
    for i in range(n):
        base = 24 + i * ENTRY
        off, size = struct.unpack_from("<QQ", d, base)
        name = d[base + 16:base + 32].split(b"\0")[0].decode()
        out.append((name, d[data_start + off: data_start + off + size]))
    return out


def main():
    ap = argparse.ArgumentParser(description="GhostLock payload packer")
    ap.add_argument("-o", "--out", help="output .bin")
    ap.add_argument("--blob", help="profile.bin（已验证的那份）")
    ap.add_argument("--lib", help="libghostlock.so（APK 里那个 PIE 可执行）")
    ap.add_argument("--ko", help="vrpatch.ko")
    ap.add_argument("--release", default=None,
                    help="内核 release（默认从 blob 头里读）")
    ap.add_argument("--list", metavar="PACK", help="列出包内容")
    args = ap.parse_args()

    if args.list:
        for name, data in load(args.list):
            note = ""
            if name == "release.txt":
                note = data.decode(errors="replace").strip()
            print("%-18s %8d B  %s" % (name, len(data), note))
        return 0

    if not (args.out and args.lib and args.ko and args.blob):
        raise SystemExit("需要 -o/--lib/--ko/--blob")

    blob = open(args.blob, "rb").read()
    if len(blob) < 0x10 or struct.unpack_from("<I", blob, 0)[0] != 0x0D000721:
        raise SystemExit("--blob 看着不像 profile blob（magic 不对）")
    rel_len = struct.unpack_from("<H", blob, 0x0C)[0]
    release = args.release or blob[0x10:0x10 + rel_len].decode()

    items = [
        ("libghostlock.so", open(args.lib, "rb").read()),
        ("vrpatch.ko", open(args.ko, "rb").read()),
        ("profile.bin", blob),
        ("release.txt", (release + "\n").encode()),
    ]
    hdr, body = build(args.out, items)
    print("wrote %s  (%d B: header %d + payload %d)" %
          (args.out, os.path.getsize(args.out), hdr, body))
    print("  release = %s" % release)
    for name, data in items:
        print("  %-18s %8d B" % (name, len(data)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
