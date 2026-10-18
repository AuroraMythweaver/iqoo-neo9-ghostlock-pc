# GhostLock on PC · One-tap temporary root for iQOO Neo9 (PD2338)

**English** · [中文](README.md)

Take the root app's job off the phone and put it on your PC: **one script + one binary**.
A plain bash script drives the original native exploit over `adb` and races the boot window to get
temporary root (KernelSU late-load). No bootloader unlock, no flashing, no system-partition writes.

> **Status**: root achieved on a real device — iQOO Neo9 / PD2338, kernel `5.15.197-g708015331567-dirty`.
> `su -c id` → `uid=0(root) context=u:r:ksu:s0`; `kernelsu` present in `/proc/modules`; SELinux stays
> **Enforcing**. Raw logs are in [`evidence/`](evidence/).

```
$ ./reroot.sh
================ round 2/10 ================
[*] adb reboot
[i] shell available: uptime=32.5 s
---- round 2 / shot 1 (uptime=32.7s) ----
[+] KSU late-load succeeded
[+] done: root is up (KernelSU late-load)
  su      : uid=0(root) gid=0(root) groups=0(root) context=u:r:ksu:s0
```

---

## Original author & sources (read this first)

| Item | Detail |
|---|---|
| **Original author (Coolapk)** | <https://www.coolapk.com/U/43561117> |
| **Original write-up** | 《vivo iQOO Neo9 (PD2338) Root 研究》 <https://www.coolapk.com/feed/74180094> |
| **Upstream project** | [YuKongA/ghostlock-app](https://github.com/YuKongA/ghostlock-app) — this APK is the iQOO Neo9 fork by linux-tools (`GhostLock-v1.2-IQOO-Neo9(545)-arm64.apk`) |
| **Primitive / tool credits** | x-spy / [CVE-2026-43499-popsicle](https://github.com/x-spy/CVE-2026-43499-popsicle), NebuSec / CyberMeowfia; KernelSU / ReSukiSU |
| **What this repo adds** | Only the **PC-side driver, packaging and a reproducible record**. The exploit itself, the kernel offsets and the `vr.ko` handling all come from the original author and upstream |

> The boot-window heuristic, `vrpatch` usage and KSU late-load path all come from the author's article
> and are cross-checked line by line against real-device logs (see [`docs/PORTING.md`](docs/PORTING.md) §9).
> **Please read the original write-up first.**

## Target device: iQOO Neo9 · OriginOS 6 **specific build**

`ghostlock.bin` in this repo is a **specialised** build for exactly this combination — not a generic pack:

| Item | Value |
|---|---|
| Device | vivo iQOO Neo9 (PD2338 / V2338A, Snapdragon 8 Gen 2 / SM8550) |
| OS | **OriginOS 6**, 16.2.13.2 |
| Kernel | **`5.15.197-g708015331567-dirty`** |
| Based on APK | `GhostLock-v1.2-IQOO-Neo9(545)-arm64.apk` (linux-tools fork) |
| Vulnerability | CVE-2026-43499 (rtmutex / futex-PI race, a.k.a. GhostLock) |

Every `task_struct` / `cred` offset, kernel symbol offset, route geometry and timing value in the profile
was measured on **this exact kernel**. Do **not** reuse it on another model or another OriginOS version
(even another 5.15) — a mismatched offset panics the kernel (the device usually reboots and recovers,
but don't try it on someone else's phone). The script compares the packed `release` against `uname -r`
and refuses to run when they differ.

---

## 1. What this is / what it is not

| It is | It is not |
|---|---|
| A **PC-side driver** for the off-the-shelf **GhostLock v1.2 (CVE-2026-43499)** exploit | Not a new exploit written by me |
| A replacement for the App + Shizuku layer with `adb shell` (same uid 2000 / `Seccomp: 0`) | Not "running the exploit on the PC" — the race can only target the phone's kernel |
| One bash script + one payload pack, **zero python dependency** at runtime | Not a generic root tool — **only works on the matching kernel release** |
| Automatic retries inside the boot window (panic → reboot → wait → retry) | Not persistent root (`late-load` lives in RAM only; a hard reboot loses it) |

**Why bother**: inside the original app the exploit process sits in an app cgroup under app-freeze / LMK
and gets killed halfway through, while the bug needs to hit a few kernel objects **12–45 s after boot**.
Under `adb shell` the process lives in a shell session (`setsid`, survives a PC disconnect) and can be
re-fired as often as you like.

### Advantages over the original APK (Shizuku path)

| Dimension | Original APK (App + Shizuku UserService) | This project (adb driver) |
|---|---|---|
| Process placement | App-related process/session, subject to app-freeze, LMK, power policies | `adb shell` (uid 2000 / `Seccomp: 0` / `u:r:shell:s0`) + `setsid`, **outside app cgroups** |
| Getting killed | Being killed mid-run is normal — a main reason for the low success rate | Unaffected by PC disconnects; keeps running until the device reboots |
| Time to the window | Wait for boot → open the app → Shizuku service ready; usually later | `adb shell` was usable at **11.8 s** uptime in testing (window is 12–45 s) |
| Retries | One manual tap per run; after a panic you must reopen the app | Automatic: reboot → wait for adb → fire → up to 6 shots in-window → next round |
| Dependencies | Install APK + Shizuku + authorise each time | Just `adb` + `bash` (**no python at runtime**) |
| Parameters / reproducibility | Buried in SharedPreferences / assets, edited through the UI | Profile is a file — diff, validate, pack; `GHOSTLOCK_*` env tunes CPU pinning etc. |
| Logs / forensics | Scrolls in the UI, hard to retrieve later | `native-<id>.log` + `ksu-<id>.log` per run, `adb pull`-able |
| Device footprint | Installs an app, leaves app data | Nothing installed; payload only in `/data/local/tmp/ghostlock-app`, delete the dir to clean up |
| Auditability | Native lib + dex black box | ~100 lines of readable bash; only the exploit itself is a binary |

**In one line**: same exploit, hosted somewhere it won't be killed, can fire earlier, retries itself,
and leaves evidence behind.

> Not a clean sweep: **the APK is more fool-proof** (one tap, no PC). For a single attempt the APK is
> simpler; for a higher hit rate, repeated runs and post-mortem logs, this is better.

## Prerequisites (phone side — do this first)

This is what reliably worked in testing. On vivo/OriginOS these toggles are effectively mandatory,
not optional tuning:

| Step | How | Why |
|---|---|---|
| **USB data cable to the PC** | A data cable (not charge-only); `adb devices` must show `device` | Everything runs through `adb shell`; wireless debugging is usually not up early in boot |
| **Developer options → USB debugging** | On, and tick "always allow this computer" | `adb shell` is the execution vehicle (uid 2000, no seccomp filter) |
| **Developer options → stop restricting child processes** (background process limit = standard) | Enable | Keeps the system from reclaiming/freezing our shell child during the window |
| **Remove the lock-screen password** | Settings → Security → turn off screen lock password | `/data` gets decrypted immediately at boot, so `/data/local/tmp` is usable early |
| **Remove all lock screens** (including "skip to home" / auto-enter system) | Settings → Lock screen & password → disable all | One less wait; an earlier window |
| **Default USB configuration = File Transfer (MTP)** | Developer options → Default USB configuration → File transfer | Avoids flaky adb transfers / repeated re-authorisation early in boot |
| (Recommended) Keep the screen on, disable power saving | Developer options → stay awake; or just unlock the screen | Screen-off throttles CPUs and makes the race harder |

Notes:

- **No** GhostLock app, **no** Shizuku and **no** pre-existing root are required (root is the goal).
- If the GhostLock app is already installed, **don't open it**: two drivers racing will fight over the
  same kernel objects.
- PC side: Linux / macOS / WSL, as long as you have `adb` and `bash` (the script doesn't need python).
- **Don't reboot after success** (see §7).

## 2. Quick start

Requires USB debugging on, the phone connected, `adb devices` showing `device`, and the payload matching
your firmware (the script compares `uname -r` and refuses on mismatch).

```bash
git clone <this-repo> && cd <repo>

./reroot.sh                  # up to 10 rounds: wait for a boot window → fire → stop on success (never reboots)
# macOS users: use the mac variant (system tools only)
./reroot-mac.sh              # same behaviour; BSD dd / no `timeout` / zsh friendly
./reroot.sh 20               # more rounds
./reroot.sh --no-reboot      # device just rebooted / you rebooted it: race right away
./reroot.sh --check          # print status only (never reboots)
./reroot.sh --inspect        # show what's inside the payload pack
./reroot.sh --deploy         # stage the payload only, don't run
./reroot.sh --check-payload  # check whether the payload on the device is up to date
```

After success:

```bash
adb shell su -c id           # uid=0(root) ... context=u:r:ksu:s0
```

**Key: do not reboot.** Both the `vrpatch.ko` insmod and `ksud late-load` exist only in RAM; a hard reboot
loses them — just run `./reroot.sh` again after the next boot (per the author, the `vrpatch` text patch
itself survives a *soft* reboot).

## 3. The two files

```
reroot.sh        10 KB    script: pure bash + adb (od/dd unpack, size compare, window race, log watch)
ghostlock.bin   736 KB    payload pack: libghostlock.so + vrpatch.ko + profile.bin + release
```

Container format of `ghostlock.bin` (little-endian; parseable with `od`/`dd`, no python needed):

```
0x00  8B   magic "GLPACK01"
0x08  u64  data_start
0x10  u32  n_entries
0x14  u32  format_version (=1)
0x18  n×32B entries { u64 off; u64 size; char name[16] }
data_start: payloads, concatenated
```

Verified: after the script extracts and pushes the three files, `md5sum` on the device matches the
originals exactly (`eef05feb…` / `07d6eb23…` / `647fba3d…`).

## 4. What the script does

1. Exits immediately if the device is already rooted (idempotent — it will not reboot away a working root);
2. Unpacks the container and compares each file's size with the device copy; pushes only on mismatch
   (`--redeploy` forces a push);
3. Compares the packed `release` with the device `uname -r` and **refuses to run** on mismatch
   (`--force` overrides);
4. Waits until `adb shell` really works → **fires immediately**. The script **never reboots**:
   a crash/hang makes the phone reboot itself; the script just waits for it (and waits for the next
   reboot when the window has already passed);
5. Watches the root-script log; stops as soon as `KernelSU module loaded` appears;
6. On a miss or panic reboot → waits for the device to come back and continues; within the window
   (`WINDOW` seconds) it fires up to `PER_BOOT` shots;
7. **Once the root script starts (uid 0) it stops firing** and only waits for
   policy/vrpatch/late-load to finish — a second shot there panics the kernel and destroys the root
   you just got (learned the hard way).

Environment knobs: `TIMEOUT=180` (watch per shot), `PER_BOOT=6`, `WINDOW=90`, `GL_DIR=...` (device dir).

## Manager app (install it **before** running the script)

When the root script does the late-load it uses the manager app's own `libksud.so` — you can see it in
the log: `ksud=/data/app/~~.../com.resukisu.resukisu-.../lib/arm64/libksud.so`. So install the manager first.

**It must be the official build whose uapi matches the kernel module** (measured on this device):

| Item | Value |
|---|---|
| Kernel module | `v4.2.0-rc3-239e1e88@ReSukiSU (35171/4)` → **uapi 4** |
| ✅ works | official `ReSukiSU_v4.2.0-rc3_35171-arm64-v8a-release.apk` (uapi 4 + official signature) → shows **Working / LKM / jailbreak mode** |
| ❌ rejected | self-built from `main` (`35231/5`, uapi 5 + self-signed) → shows "not installed" plus a red "not an official manager" banner |

The gate is explicit in the source (`manager/.../Natives.kt:203`):

```kotlin
fun isFullFeatured(): Boolean = isManager && kernelUAPIVersion == managerUAPIVersion
```

A self-signed build fails `isManager`, and `main` already moved to uapi 5 while the rc3 kernel module is
uapi 4 — both conditions fail. **Use the official Release APK**; a self-built one only makes sense if you
also move the kernel module to the same uapi.

```bash
adb uninstall com.resukisu.resukisu   # only if a differently-signed build is installed
adb install -r ReSukiSU_v4.2.0-rc3_35171-arm64-v8a-release.apk
```

## 5. Field results: this is a boot-window race

Across all collected logs, `boot_ms` (milliseconds since boot when the native starts) correlates cleanly
with the outcome:

| boot_ms | Result |
|---|---|
| 14.4 s | **W1 passed** → moved on to W2 |
| 38.6 s / 40.6 s / 61.5 s | Reached W2; the **40.6 s** run got root |
| 84 s / 106 s / 178 s / 12 min / 2.9 h / 22 h | Always `Write 1 failed` |

So the point of this project is not parameter tuning but **timing**: reboot, fire the moment a shell is
available, and keep firing inside the window. The author's "about 43 s per round" matches our measurements.

Two other pitfalls (documented in [`docs/PORTING.md`](docs/PORTING.md)):

- **`execution.consumer.max_calls = 0` is fatal**: a blob generated straight from the APK's `.conf` has
  this at 0, and the device log shows `attempts=128 calls=0 success=0` — the consumer thread never fired
  once and the route spun idle. The working blob uses `1/1`.
- **`route.multicast_waiter.compact_waiter` is dropped by the APK's route object** (only the `kernel`
  group and `route.select_stack` accept that key); the working blob carries it as `kernel.compact_waiter = 1`.

## 6. Adapting to another firmware / device

Offsets in the payload are matched **per kernel release**; a mismatch panics and reboots (the device
recovers, but don't feed it a wrong profile). To retarget:

```bash
# 1) rebuild the pack from your own APK extraction
#    (this repo does not ship the APK or its extracted contents — see the disclaimer)
python3 scripts/mkpack.py -o ghostlock.bin \
    --lib  <your>/lib/arm64-v8a/libghostlock.so \
    --ko   <your>/assets/modules/vrpatch.ko \
    --blob evidence/profile.bin          # or a blob you generated for the target kernel

# 2) inspect it
python3 scripts/mkpack.py --list ghostlock.bin
```

`scripts/ghostlock_profile.py` converts the HOCON kernel profile shipped in the APK
(`assets/kernel_profiles/<uname -r>.conf`) into the binary blob the native binary expects, validating
group/key names against the native whitelist:

```bash
python3 scripts/ghostlock_profile.py build -c <uname -r>.conf -o profile.bin
python3 scripts/ghostlock_profile.py dump profile.bin
```

> ⚠ Generating from a `.conf` yields `consumer.max_calls = 0` for the multicast route (the pitfall above).
> After generating, make sure `execution.consumer.max_calls >= 1`.

## 7. Known limitations

- **Matching kernel release only**: the shipped `ghostlock.bin` targets
  `5.15.197-g708015331567-dirty` (iQOO Neo9 / OriginOS 16.2.13.2). The script enforces this.
- **A probabilistic bug**: not every run lands. A miss panics the kernel and the device reboots by itself
  (no data loss), hence "multiple rounds + several shots per window". The author notes that a factory
  reset can restore the hit rate after many misses.
- **Temporary root**: `late-load` lives in RAM; a hard reboot loses it. The vrpatch text patch survives
  a soft reboot.
- **No system-partition writes**: only kernel memory writes, a `cred` swap and `ksud insmod` / `late-load`,
  plus reads/writes under `$HOME` (`/data/local/tmp/ghostlock-app`) and `/sys/fs/selinux/*`.
  `safe_mode=0`, so `/data/adb/modules` is untouched.
- **SELinux ends up Enforcing** (not permissive): root is obtained through a policy fixup plus the
  `ksu` domain.

## 8. Layout

### 8.1 Repository

```
.
├── reroot.sh                 main script (Linux/WSL; never reboots, stops firing after handoff)
├── reroot-mac.sh             macOS variant (BSD dd / no timeout / no seq)
├── clean.sh                  cleanup / uninstall (dry-run by default)
├── ghostlock.bin             payload pack (GLPACK01, format in §3)
├── README.md / README.en.md  docs (zh / en, each self-contained)
├── QUICKSTART.md             shortest usage
├── docs/
│   ├── PORTING.md            porting notes: byte-level protocol evidence, field log, author cross-check
│   ├── ANALYSIS.md           static analysis of the GhostLock v1.2 APK
│   └── root-script.sh.tmpl   root-script template extracted from libghostlock.so (7349 B)
├── scripts/                  tuning / forensics tools (not needed day to day)
│   ├── ghostlock_pc.py       full python driver (check/setup/run/status/exec/pull-log)
│   ├── ghostlock_profile.py  .conf → native binary blob (whitelist-validated)
│   ├── mkpack.py             build / inspect the payload pack
│   └── README.md             script-layer notes
└── evidence/                 raw evidence from the successful run
    ├── profile.bin           the 2058 B blob that actually worked
    ├── ksu-1792264567-6-1.log     root-script log of the successful run
    └── native-1792264567-6-1.log  native log of the successful run (from boot_ms=40663)
```

### 8.2 On the device (deployed automatically by `reroot.sh` / `reroot-mac.sh`)

```
/data/local/tmp/ghostlock-app/          <- working dir (removed by clean.sh --yes)
├── libghostlock.so   484 840 B         from ghostlock.bin
├── vrpatch.ko        249 224 B         from ghostlock.bin
├── profile.bin         2 058 B         from ghostlock.bin
├── glrun.sh                            runtime script (generated by reroot.sh)
├── native-<runid>.log / .rc            native output + exit code (contains kernel addresses)
├── ksu-<runid>.log                     root-script log (policy -> vrpatch -> late-load)
├── .ghostlock_root.sh                  the root script the native binary writes out
├── .ghostlock_iomem                    /proc/iomem cache
└── .gl_out / .gl_cmd                   root debug terminal (background subshell, dies with the script)

/data/adb/ksud              5 679 064 B   ksud deployed by the manager (clean.sh --ksu)
/data/adb/ksu/{bin,lib,log,profile,KernelSU_越狱}   KSU userland (--ksu)
/data/app/~~*/com.resukisu.resukisu-*/lib/arm64/libksud.so   this is what late-load actually runs
com.resukisu.resukisu                     manager APK (clean.sh --uninstall)
```

### 8.3 In memory (gone after a reboot; `clean.sh` cannot and does not remove these)

```
kernelsu           the late-loaded kernel module
vrpatch patch      the 8 bytes at vr.ko .text+0x2ecc (mov w0,#0; ret)
SELinux            the enforcing flag written by W1 + the policy loaded by load_policy
temporary cred     the child's copy of init_cred (gone when the child exits)
```

## 9. Safety boundary

- Only **kernel memory writes + a `cred` swap + `ksud insmod` / `late-load`**; no flashing, no boot
  partition edits, no system-partition writes (the system partition keeps erofs + dm-verity green).
- On the filesystem it only touches `$HOME` (`/data/local/tmp/ghostlock-app`) and `/sys/fs/selinux/*`;
  `safe_mode=0`, so `/data/adb/modules` is left alone.
- A failure means a kernel panic → the device reboots and recovers (no data loss); the script waits and
  continues.
- **Temporary root**: `late-load` lives in RAM and is lost on a hard reboot; the `vrpatch` text patch
  survives a soft reboot.
- SELinux stays **Enforcing** at the end (via policy fixup + the `ksu` domain) — SELinux is not turned off.

## Cleanup / uninstall

The leftovers come in two kinds — deleting files alone is not enough:

| Kind | What | How |
|---|---|---|
| **In memory** | the `kernelsu` late-load module, the 8-byte `vrpatch` patch on `vr.ko`, the SELinux state / `load_policy` patch from W1, the temporary cred | **gone after a reboot** — no files to delete |
| **On disk** | `/data/local/tmp/ghostlock-app` (payload + logs + root script), test dirs, `/data/adb/ksud` + `/data/adb/ksu/*` (~91 MB), the manager APK | delete with `clean.sh` |

```bash
./clean.sh                       # dry-run: list what would be deleted + sizes (default)
./clean.sh --yes                 # delete work/test dirs + stop leftover exploit processes
./clean.sh --yes --ksu           # also remove the KSU userland (/data/adb/ksud, /data/adb/ksu/*)
./clean.sh --yes --uninstall     # also uninstall the manager (com.resukisu.resukisu)
./clean.sh --yes --all --reboot  # back to a clean system in one shot (recommended)
```

**Order matters**: delete files **while root is still there** (some logs under `/data/local/tmp` are owned
by root, the shell cannot remove them), **then reboot** to clear the in-memory state (root goes away too).
`clean.sh` only lists by default; `--yes` is required to actually delete.

> Nothing is ever deleted without your go-ahead. `--ksu` touches the KSU userland (it affects other KSU
> modules) and `--uninstall` removes the manager, so both are explicit opt-in flags.

## 10. Disclaimer

1. **Scope of use**: for **personal study, mobile-security research and maintaining devices you own** only.
   You must own the device or have explicit authorisation to operate it.
2. **At your own risk**: this tool performs **kernel-level privilege escalation**. It can reboot the
   device, cause temporary instability, lose data, void the warranty, break OTA updates, and be detected
   by integrity checks in banking/payment/game apps. Assess the risk yourself and **back up important
   data** before running it.
3. **No warranty (AS-IS)**: provided "as is", without warranty of any kind, express or implied, including
   but not limited to merchantability, fitness for a particular purpose and non-infringement. The authors
   and contributors are **not liable** for any direct, indirect, incidental, special or consequential
   damages arising from the use of, or inability to use, this project.
4. **No abuse**: strictly forbidden to use it on **unauthorised or third-party devices, for mass control,
   to bypass security mechanisms for unlawful purposes, for game cheating, or for commercial
   redistribution**, or in any way that violates applicable laws and regulations (including those of
   mainland China). All legal responsibility and consequences of misuse rest with the user.
5. **Third-party components**: this repo does **not** redistribute the GhostLock APK or its extracted
   contents. `libghostlock.so` and `vrpatch.ko` embedded in `ghostlock.bin` are copyrighted by the
   original author/upstream project; they are packed **verbatim, unmodified**, solely to reproduce the
   result on the matching device. The scripts and docs written here (`reroot.sh`, `scripts/*`, `docs/*`,
   `README*`) may be used under MIT. If a rights holder objects, contact me and it will be removed
   immediately.
6. **Acceptance**: using, cloning or redistributing this project means you have read, understood and
   agreed to all of the above. If you disagree, stop using it and delete the repository.

## 11. Acknowledgements

- **@图灵和冯诺依曼老祖保佑我** (Coolapk <https://www.coolapk.com/U/43561117>) — the article
  《vivo iQOO Neo9 (PD2338) Root 研究》 is the foundation of this work.
- **YuKongA/ghostlock-app** — upstream GhostLock (this APK is the iQOO Neo9 fork by linux-tools).
- **x-spy / CVE-2026-43499-popsicle** — the futex-PI race primitive.
- **NebuSec / CyberMeowfia** — related tooling and methods.
- **KernelSU / ReSukiSU** — kernel module and manager (this device runs `com.resukisu.resukisu`).
