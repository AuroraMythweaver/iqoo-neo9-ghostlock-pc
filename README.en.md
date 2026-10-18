# One-tap temporary root for iQOO Neo9 (PC version)

**English** · [中文](README.md)

Takes the root app's job off the phone: drive the original native exploit from your PC over `adb`.
**Plug the phone in → run the script → get temporary root.**

- No bootloader unlock, no flashing, no system-partition writes (system stays erofs + dm-verity green)
- Root lives in memory only: **a reboot takes it away**; just run the script again
- Based on CVE-2026-43499 (GhostLock, a futex-PI race) — the exploit has to land in the first
  ~tens of seconds after boot

> **Supported device/build only** (the script checks `uname -r` and refuses anything else):
> vivo **iQOO Neo9 (PD2338)** · **OriginOS 6, build 16.2.13.2** · kernel **`5.15.197-g708015331567-dirty`**

---

## 1. Phone-side preparation (4 items)

1. Connect over USB, enable **USB debugging**
2. Developer options → turn **"Suspend execution for cached apps"** off (stop limiting child processes)
3. **Remove the lock-screen password / all lock screens**
4. Default USB configuration = **File transfer**

## 2. On the PC

You need `adb`. Linux / WSL / macOS all work (on macOS use `reroot-mac.sh`; no coreutils needed).

```bash
unzip ghostlock-pc-iqoo-neo9-v1.0.0-linux.zip && cd ghostlock-pc-v1.0.0
chmod +x *.sh
./reroot.sh                 # macOS: ./reroot-mac.sh
```

The script loops round after round and prints the result once it lands:

```
[+] 成功：root 已在（KernelSU late-load）
  su      : uid=0(root) gid=0(root) context=u:r:ksu:s0
```

Then:

```bash
adb shell su -c 'id'
```

## 3. What it actually does (plain version)

1. Unpacks the exploit from `ghostlock.bin` and waits for the phone to be **just a few seconds into a boot**
   (measured sweet spot: 30–45 s of uptime)
2. Wins the futex-PI race and turns the current shell into root — **SELinux stays Enforcing**
3. Loads `vrpatch.ko` to neutralise vivo's own `vr.ko`, then uses the manager's `ksud` to load the
   KernelSU module into memory
4. `su` works and the manager shows **"Working · jailbreak mode"**

On a miss the kernel panics → the phone reboots itself → the script waits for it and tries again.
**Several rounds are normal** — this is a probability game.

## 4. The three scripts

| Script | Purpose |
|---|---|
| `reroot.sh` / `reroot-mac.sh` | main script: race the boot window for root (**never reboots the phone by itself**) |
| `install-ksu.sh` | after root: load **your own `.ko`**, install any KSU manager |
| `clean.sh` | cleanup / uninstall (dry-run by default) |

Common flags (`reroot.sh`):

```bash
./reroot.sh --check          # status only
./reroot.sh --inspect        # list what is inside the payload pack
./reroot.sh --deploy         # deploy the payload only, do not fire
./reroot.sh 20               # up to 20 rounds
```

**All-in-one** (list ko -> you pick -> escalate -> clean residue on success -> exit):

```bash
./reroot.sh --ko 1 --clean-after
```

- the local `.ko` files are listed first (omit `--ko` to pick interactively; Enter = use the manager's own)
- picking a ko is local-only and does **not** affect the boot window (the push happens before the wait)
- on success it removes this run's residue but keeps `user.ko` and the `ksud` wrapper, so the next run
  still uses your ko

## 5. Switching / installing a KSU manager

The manager's uapi must **match** the kernel module's uapi, otherwise the home screen only says
"kernel update required".

Put your `xxx_kernelsu.ko` and the manager APK next to the script:

```bash
./install-ksu.sh                     # preview: list the ko / apk here plus the current kernel state
./install-ksu.sh --ko 1              # load ko #1 (needs root)
./install-ksu.sh --ko 1 --install 1  # load + install the manager
./install-ksu.sh --persist --ko 1    # use this ko on every future reroot.sh (takes effect after a reboot)
```

Verified combination: **SukiSU-Ultra v4.2.1 (uapi 5) + `android13-5.15_kernelsu.ko`** → "Working · jailbreak mode".

## 6. Cleanup

```bash
./clean.sh                          # list only (default)
./clean.sh --yes                    # remove payload / logs / test dirs
./clean.sh --yes --all --reboot     # full clean + reboot, back to a stock system
```

Everything in memory (KSU module, vrpatch patch, SELinux state) **disappears on reboot**; files on disk
(payload, logs, KSU userland) are removed by `clean.sh`.

## 7. FAQ

- **Never lands?** It is a probability game; let it run more rounds. If it hangs, the phone reboots itself
  and the script keeps waiting.
- **Root is gone after a reboot?** Expected. late-load is memory-only; run `./reroot.sh` again.
- **Manager says "kernel update required"?** Its uapi is higher than the kernel module's — use a manager
  build that matches the ko.
- **Will repeated attempts damage the phone?** No system-partition writes; a miss is a kernel panic reboot,
  no data loss.
- **Doesn't work on macOS?** Use `reroot-mac.sh` (`reroot.sh` relies on GNU tools).

## 8. Credits and disclaimer

Original author (Coolapk): <https://www.coolapk.com/U/43561117> · "vivo iQOO Neo9 (PD2338) Root 研究"
Upstream GhostLock: [YuKongA/ghostlock-app](https://github.com/YuKongA/ghostlock-app)

`libghostlock.so` / `vrpatch.ko` inside `ghostlock.bin` are the upstream binaries, unmodified; the scripts
and docs here are rewritten. For study and research on devices you own, at your own risk.

## Detailed docs (engineering material, kept out of this file)

| File | Content |
|---|---|
| [`docs/FIELD-NOTES.md`](docs/FIELD-NOTES.md) | measured timing data, pitfalls, macOS compatibility, manager uapi gate |
| [`docs/PORTING.md`](docs/PORTING.md) | the porting process: byte-level protocol evidence, cross-check against the author's post |
| [`docs/ANALYSIS.md`](docs/ANALYSIS.md) | static analysis of the GhostLock APK: exploit chain, `vrpatch.ko` disassembly |
| [`scripts/`](scripts/) | python tuning / forensics tools (not needed day to day) |
