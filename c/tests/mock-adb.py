#!/usr/bin/env python3
"""
mock-adb.py -- offline adb stand-in for the ghostlock C CLI test suite.

It emulates just enough of a PD2338 device to run the real driver end to end:
  * a tiny device filesystem under $MOCK_STATE/fs
  * `adb shell` for the exact command shapes the driver sends
  * a launch simulation: glrun.sh writes native + ksu logs, and after a few
    polls the "root" state flips and `KernelSU module loaded` appears
No real device, no root, no exploit is involved.

Unknown commands are logged to $MOCK_STATE/unmatched.log and exit non-zero, so
a test that starts depending on unimplemented behaviour fails loudly.
"""
import base64
import os
import re
import shutil
import sys

STATE = os.environ.get("MOCK_STATE", "/tmp/ghostlock-mock")
FS = os.path.join(STATE, "fs")
SERIAL = "MOCK123"
RELEASE = os.environ.get("MOCK_RELEASE", "5.15.197-g708015331567-dirty")
DEV = "/data/local/tmp/ghostlock-app"


def host(devpath):
    p = devpath.strip().strip("'\"")
    if not p.startswith("/"):
        return None
    return os.path.join(FS, p.lstrip("/"))


def get_state(name, default="0"):
    p = os.path.join(STATE, name)
    try:
        with open(p) as f:
            return f.read().strip()
    except OSError:
        return default


def set_state(name, value):
    os.makedirs(STATE, exist_ok=True)
    with open(os.path.join(STATE, name), "w") as f:
        f.write(str(value))


def unmatched(cmd):
    os.makedirs(STATE, exist_ok=True)
    with open(os.path.join(STATE, "unmatched.log"), "a") as f:
        f.write(cmd.replace("\n", "\\n") + "\n")
    sys.stderr.write("mock-adb: unmatched: %s\n" % cmd)


def emit(s):
    sys.stdout.write(s)


def emitln(s=""):
    sys.stdout.write(s + "\n")


def read_file(p):
    try:
        with open(p, "rb") as f:
            return f.read()
    except OSError:
        return None


def write_file(p, data):
    os.makedirs(os.path.dirname(p), exist_ok=True)
    mode = "wb" if isinstance(data, bytes) else "w"
    with open(p, mode) as f:
        f.write(data)


def sizes_of(devpath):
    hp = host(devpath)
    if hp and os.path.isfile(hp):
        return os.path.getsize(hp)
    return None


def launch(cmd):
    m = re.search(r"GL_RUN_ID=(\S+)", cmd)
    if not m:
        return False
    ts = m.group(1)
    d = host(DEV)
    native = os.path.join(d, "native-%s.log" % ts)
    ksu = os.path.join(d, "ksu-%s.log" % ts)
    write_file(native,
               "=== ghostlock-cli run %s\n"
               "uname : %s\n"
               "id    : uid=2000(shell) gid=2000(shell)\n"
               "seccomp: Seccomp:\t0\tSeccomp_filters: 0\n"
               "domain: u:r:shell:s0\n"
               "selinux: Enforcing\n"
               "argv  : libghostlock.so --load-prebuilt-profile profile.bin\n"
               "[*] boot_ms=40000\n"
               "[*] kernelsnitch: slide=0x1234\n"
               "[*] W1: SELinux attempt 1 -> ok\n"
               "[*] W2: cred swap -> child is root!\n"
               "[*] handoff: root script path=%s/.ghostlock_root.sh\n" % (ts, RELEASE, DEV))
    write_file(ksu, "[*] root script start uid=0 euid=0\n")
    write_file(os.path.join(STATE, "run-%s.cnt" % ts), "0")
    write_file(os.path.join(STATE, "run-%s.ts" % ts), ts)
    emitln("go")
    return True


def advance(ts):
    """Called on each ksu-log size probe; flips device state after a few."""
    cp = os.path.join(STATE, "run-%s.cnt" % ts)
    try:
        with open(cp) as f:
            n = int(f.read().strip() or 0)
    except OSError:
        return
    n += 1
    write_file(cp, str(n))
    d = host(DEV)
    ksu = os.path.join(d, "ksu-%s.log" % ts)
    if n == 2:
        with open(ksu, "a") as f:
            f.write("[*] fixup: attempt 1 -> policyload before=0 after=2 -> rc=0\n")
            f.write("[*] Loaded kernel module: %s/vrpatch.ko  (exit=0)\n" % DEV)
            f.write("[*] late-load pkg=com.resukisu.resukisu kmi=android13-5.15 (exit=0)\n")
    if n == 3:
        with open(ksu, "a") as f:
            f.write("[+] KernelSU module loaded\n[*] script done\n")
        set_state("root", "1")
        set_state("ksu", "1")
    if n == 4:
        write_file(os.path.join(d, "native-%s.rc" % ts), "done\n")


def do_shell(cmd):
    cmd = cmd.strip()
    # strip a leading su -c wrapper (quoted or not)
    m = re.match(r"^su -c \"(.*)\"$", cmd)
    if m:
        cmd = m.group(1)
    m = re.match(r"^su -c '(.*)'$", cmd)
    if m:
        cmd = m.group(1)

    if cmd in ("echo up", "echo ping", "echo alive"):
        emitln(cmd.split()[-1])
        return 0
    if cmd == "echo go":
        emitln("go")
        return 0

    if "setsid sh" in cmd and "GL_RUN_ID=" in cmd:
        return 0 if launch(cmd) else 1

    # ---- simple probes -------------------------------------------------
    if cmd == "uname -r":
        emitln(RELEASE)
        return 0
    if cmd.startswith("getprop "):
        props = {
            "ro.product.cpu.abi": "arm64-v8a",
            "ro.product.model": "PD2338",
            "ro.build.version.sdk": "36",
        }
        emitln(props.get(cmd.split()[1], ""))
        return 0
    if cmd == "id":
        if get_state("root") == "1":
            emitln("uid=0(root) gid=0(root) groups=0(root) context=u:r:ksu:s0")
        else:
            emitln("uid=2000(shell) gid=2000(shell) groups=2000(shell) context=u:r:shell:s0")
        return 0
    if re.match(r"^su -c id -u( 2>.*)?$", cmd):
        if get_state("root") == "1":
            emitln("0")
            return 0
        sys.stderr.write("su: not found\n")
        return 1
    if re.match(r"^su -c id( 2>.*)?$", cmd):
        if get_state("root") == "1":
            emitln("uid=0(root) gid=0(root) groups=0(root) context=u:r:ksu:s0")
            return 0
        sys.stderr.write("su: not found\n")
        return 1
    if cmd.startswith("getenforce"):
        emitln("Enforcing")
        return 0
    if cmd.startswith("grep -i '^Seccomp'"):
        emitln("Seccomp:\t0\tSeccomp_filters: 0")
        return 0
    if cmd.startswith("cat /proc/uptime"):
        emitln("%s 100.00" % get_state("uptime", "40"))
        return 0
    if cmd.startswith("cat /proc/sys/kernel/random/boot_id"):
        emitln("mock-boot-%s" % get_state("boot", "1"))
        return 0
    if cmd == "grep -c kernelsu /proc/modules":
        emitln(get_state("ksu"))
        return 0
    if cmd == "grep -c '^vr ' /proc/modules":
        emitln("0")
        return 0
    if cmd.startswith("cat /proc/modules 2>/dev/null | grep -i kernelsu"):
        if get_state("ksu") == "1":
            emitln("kernelsu 233472 2 - Live 0x0000000000000000 (OE)")
        else:
            emitln("(none / unreadable)")
        return 0
    if cmd.startswith("ps -A 2>/dev/null | grep -c libghostlock"):
        emitln("0")
        return 0
    if cmd.startswith("pm list packages 2>/dev/null | sed -n"):
        emitln("com.resukisu.resukisu")
        return 0
    if cmd.startswith("pm list packages 2>/dev/null | grep -q com.resukisu.resukisu"):
        emitln("是")
        return 0
    if cmd.startswith("pm list packages"):
        emitln("package:com.resukisu.resukisu")
        return 0
    if re.match(r"^ls -d /data/app/\*/.*/lib/arm64/libksud\.so 2>/dev/null \| head -1$", cmd):
        emitln("/data/app/~~mock==/com.resukisu.resukisu-mock/lib/arm64/libksud.so")
        return 0
    if cmd.startswith("ls -l /data/adb/ksu/bin/ksud"):
        if get_state("ksu_user") == "1":
            emitln("-rwxr-xr-x 1 root root 1234 2026-10-18 /data/adb/ksu/bin/ksud")
            return 0
        emitln("(no ksud)")
        return 0
    if cmd.startswith("pkill "):
        return 0

    # ---- filesystem ----------------------------------------------------
    m = re.match(r"^wc -c < '([^']+)' 2>/dev/null$", cmd)
    if m:
        p = m.group(1)
        n = sizes_of(p)
        if n is None:
            return 1
        if "/ksu-" in p:
            mm = re.search(r"ksu-([^.]+)\.log$", p)
            if mm:
                advance(mm.group(1))
        emitln(str(n))
        return 0
    m = re.match(r"^wc -c < (\S+) 2>/dev/null \|\| echo 0$", cmd)
    if m:
        n = sizes_of(m.group(1))
        emitln(str(n if n is not None else 0))
        return 0
    m = re.match(r"^tail -c \+(\d+) '?([^']+?)'?$", cmd)
    if m:
        start = int(m.group(1)) - 1
        hp = host(m.group(2))
        data = read_file(hp) if hp else None
        if data is None:
            return 1
        sys.stdout.buffer.write(data[start:])
        return 0
    m = re.match(r"^tail -n (\d+) '?([^']+?)'?$", cmd)
    if m:
        hp = host(m.group(2))
        data = read_file(hp)
        if data is None:
            return 1
        lines = data.split(b"\n")
        sys.stdout.buffer.write(b"\n".join(lines[-int(m.group(1)):]))
        return 0
    m = re.match(r"^test -[fex] '?([^']+?)'? && echo (\w+)$", cmd)
    if m:
        hp = host(m.group(1))
        if hp and os.path.exists(hp):
            emitln(m.group(2))
            return 0
        return 1
    m = re.match(r"^mkdir -p '?([^']+)'?$", cmd)
    if m:
        hp = host(m.group(1))
        if hp:
            os.makedirs(hp, exist_ok=True)
            return 0
        return 1
    m = re.match(r"^chmod (\d+) (.*)$", cmd)
    if m:
        mode = int(m.group(1), 8)
        for tok in m.group(2).split():
            hp = host(tok)
            if hp and os.path.exists(hp):
                try:
                    os.chmod(hp, mode)
                except OSError:
                    pass
        return 0
    m = re.match(r"^ls -ld (.+) 2>/dev/null$", cmd)
    if m:
        hp = host(m.group(1))
        if hp and os.path.exists(hp):
            emitln("drwxrwxrwt 3 shell shell 4096 2026-10-18 00:00 %s" % m.group(1))
            return 0
        return 1
    m = re.match(r"^du -sh '([^']+)' 2>/dev/null \| cut -f1$", cmd)
    if m:
        hp = host(m.group(1))
        if not hp or not os.path.exists(hp):
            return 1
        total = 0
        for root, _dirs, files in os.walk(hp):
            for f in files:
                total += os.path.getsize(os.path.join(root, f))
        emitln("%dK" % max(1, total // 1024))
        return 0
    m = re.match(r"^ls (.+)/\*\.log (.+)/\*\.rc 2>/dev/null$", cmd)
    if m:
        d = host(m.group(1))
        found = []
        if d and os.path.isdir(d):
            for f in sorted(os.listdir(d)):
                if f.endswith(".log") or f.endswith(".rc"):
                    found.append("%s/%s" % (m.group(1), f))
        if found:
            emitln("\n".join(found))
            return 0
        return 1
    m = re.match(r"^ls -t (.+)/ksu-\*\.log 2>/dev/null \| head -1$", cmd)
    if m:
        d = host(m.group(1))
        logs = []
        if d and os.path.isdir(d):
            logs = [f for f in os.listdir(d) if f.startswith("ksu-") and f.endswith(".log")]
        if logs:
            emitln("%s/%s" % (m.group(1), sorted(logs)[-1]))
            return 0
        return 1
    m = re.match(
        r'^L=\$\(ls -t (.+)/ksu-\*\.log 2>/dev/null \| head -1\); '
        r'\[ -n "\$L" \] && \{ echo "== \$L"; tail -n 25 "\$L"; \} \|\| echo \'\(no ksu log\)\'$',
        cmd)
    if m:
        d = host(m.group(1))
        logs = sorted(f for f in os.listdir(d)
                      if f.startswith("ksu-") and f.endswith(".log")) if d else []
        if logs:
            p = "%s/%s" % (m.group(1), logs[-1])
            emitln("== %s" % p)
            emitln(read_file(host(p)).decode("utf-8", "replace").rstrip("\n"))
            return 0
        emitln("(no ksu log)")
        return 0
    # profile header probes
    m = re.match(r"^dd if='([^']+)' bs=1 skip=12 count=2 2>/dev/null \| od -An -tu1$", cmd)
    if m:
        data = read_file(host(m.group(1)))
        if data is None or len(data) < 14:
            return 1
        emitln("%d %d" % (data[12], data[13]))
        return 0
    m = re.match(r"^dd if='([^']+)' bs=1 skip=16 count=(\d+) 2>/dev/null$", cmd)
    if m:
        data = read_file(host(m.group(1)))
        if data is None:
            return 1
        sys.stdout.buffer.write(data[16:16 + int(m.group(2))])
        return 0
    # root debug terminal: echo <b64> | base64 -d > DIR/.gl_cmd
    m = re.match(r"^echo ([A-Za-z0-9+/=]+) \| base64 -d > (.+)/\.gl_cmd$", cmd)
    if m:
        try:
            text = base64.b64decode(m.group(1)).decode("utf-8", "replace")
        except Exception:
            return 1
        write_file(os.path.join(host(m.group(2)), ".gl_cmd"), text)
        if get_state("root") == "1":
            out = "uid=0(root) gid=0(root) context=u:r:ksu:s0\ncmd=%s\n" % text.strip()
            with open(os.path.join(host(m.group(2)), ".gl_out"), "a") as f:
                f.write(out)
            return 0
        return 0
    m = re.match(r"^rm -f (.*)$", cmd)
    if m:
        for tok in m.group(1).split():
            hp = host(tok)
            if hp and os.path.isfile(hp):
                os.unlink(hp)
        return 0
    m = re.match(r"^rm -rf '([^']+)'$", cmd)
    if m:
        hp = host(m.group(1))
        if hp and os.path.exists(hp):
            shutil.rmtree(hp, ignore_errors=True)
        return 0

    unmatched(cmd)
    return 1


def main(argv):
    args = argv[1:]
    serial = None
    if len(args) >= 2 and args[0] == "-s":
        serial = args[1]
        args = args[2:]
    if not args:
        emitln("usage: adb [-s serial] <command>")
        return 2
    cmd = args[0]
    os.makedirs(STATE, exist_ok=True)

    if cmd == "devices":
        emitln("List of devices attached")
        if os.environ.get("MOCK_OFFLINE") != "1":
            emitln("%s\tdevice" % (serial or SERIAL))
        return 0
    if cmd == "shell":
        if os.environ.get("MOCK_OFFLINE") == "1":
            sys.stderr.write("error: device offline\n")
            return 1
        return do_shell(args[1] if len(args) > 1 else "")
    if cmd == "push":
        src, dst = args[1], args[2]
        hp = host(dst)
        if not hp:
            return 1
        os.makedirs(os.path.dirname(hp), exist_ok=True)
        shutil.copyfile(src, hp)
        emitln("%s: 1 file pushed" % dst)
        return 0
    if cmd == "pull":
        src, dst = args[1], args[2]
        hp = host(src)
        if not hp or not os.path.isfile(hp):
            return 1
        os.makedirs(os.path.dirname(os.path.abspath(dst)), exist_ok=True)
        shutil.copyfile(hp, dst)
        emitln("%s: 1 file pulled" % src)
        return 0
    if cmd == "install":
        emitln("Success")
        return 0
    if cmd == "uninstall":
        emitln("Success")
        return 0
    if cmd == "reboot":
        set_state("root", "0")
        set_state("ksu", "0")
        set_state("uptime", "12")
        set_state("boot", str(int(get_state("boot", "1")) + 1))
        return 0
    unmatched(cmd)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
