#!/usr/bin/env bash
# run-tests.sh -- offline verification for the ghostlock C CLI.
#
# No phone is touched: tests/mock-adb.py stands in for adb and simulates the
# launch -> handoff -> KernelSU-loaded sequence. The real 736 KB payload pack
# and the real 2058 B profile blob from the repo are used as fixtures, so the
# container/profile parsers are exercised against genuine bytes.
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
REPO="$(cd "$ROOT/.." && pwd)"
BIN="$ROOT/ghostlock"
PACK="$REPO/ghostlock.bin"
BLOB="$REPO/evidence/profile.bin"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

export ADB="$HERE/mock-adb.py"
export MOCK_STATE="$TMP/state"
mkdir -p "$MOCK_STATE/fs"

PASS=0
FAIL=0
ok()   { printf '  ok    %s\n' "$1"; PASS=$((PASS + 1)); }
bad()  { printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL + 1)); }
check() { if eval "$2" >/dev/null 2>&1; then ok "$1"; else bad "$1"; fi; }

[ -x "$BIN" ] || { echo "build first: make"; exit 1; }
[ -f "$PACK" ] || { echo "missing fixture: $PACK"; exit 1; }
[ -f "$BLOB" ] || { echo "missing fixture: $BLOB"; exit 1; }

OUT="$TMP/out"

echo "== binary =="
check "version runs"        "$BIN version >/dev/null"
check "help runs"           "$BIN --help >/dev/null"

echo "== payload container =="
"$BIN" inspect --pack "$PACK" > "$OUT.inspect" 2>&1
check "inspect finds 4 entries"   "grep -q '4 个条目' '$OUT.inspect'"
check "inspect finds libghostlock" "grep -q 'libghostlock.so' '$OUT.inspect'"
check "inspect prints release"    "grep -q '5.15.197-g708015331567-dirty' '$OUT.inspect'"
check "inspect rejects junk"      "! $BIN inspect --pack /etc/hostname >/dev/null 2>&1"

echo "== profile blob =="
"$BIN" blob dump "$BLOB" > "$OUT.blob" 2>&1
check "magic parsed"          "grep -q '0x0D000721' '$OUT.blob'"
check "route is multicast"    "grep -q '3 (multicast_waiter)' '$OUT.blob'"
check "release parsed"        "grep -q '5.15.197-g708015331567-dirty' '$OUT.blob'"
check "consumer.max_calls=1"  "grep -q 'max_calls * = 1' '$OUT.blob'"
check "compact_waiter=1"      "grep -q 'compact_waiter * = 1' '$OUT.blob'"
check "vr_sys_exit_tp present" "grep -q 'vr_sys_exit_tp' '$OUT.blob'"
check "0 unknown keys"        "grep -q '^unknown   : 0' '$OUT.blob'"
"$BIN" blob check "$BLOB" 5.15.197-g708015331567-dirty > "$OUT.blobcheck" 2>&1
check "release match check"   "grep -q 'match     : YES' '$OUT.blobcheck'"
check "release mismatch"      "! $BIN blob check '$BLOB' 9.9.9-wrong >/dev/null 2>&1"

echo "== deploy (mock device) =="
"$BIN" deploy --pack "$PACK" > "$OUT.deploy" 2>&1
DEPLOY_RC=$?
check "deploy exits 0"        "[ $DEPLOY_RC -eq 0 ]"
DEVFS="$MOCK_STATE/fs/data/local/tmp/ghostlock-app"
check "libghostlock pushed"   "[ -s '$DEVFS/libghostlock.so' ]"
check "vrpatch pushed"        "[ -s '$DEVFS/vrpatch.ko' ]"
check "profile pushed"        "[ -s '$DEVFS/profile.bin' ]"
check "runner pushed"         "[ -s '$DEVFS/glrun.sh' ]"
check "profile.len is 4 B"    "[ \$(stat -c%s '$DEVFS/profile.len') -eq 4 ]"
check "runner syntax ok"      "sh -n '$DEVFS/glrun.sh'"
check "runner uses prebuilt"  "grep -q 'load-prebuilt-profile' '$DEVFS/glrun.sh'"
check "runner has force-attack" "grep -q -- '--force-attack' '$DEVFS/glrun.sh'"
check "runner exports KSU log"  "grep -q 'GHOSTLOCK_KSU_LOG' '$DEVFS/glrun.sh'"

python3 - "$PACK" "$DEVFS" <<'PY' && ok "pushed bytes identical to pack" || bad "pushed bytes identical to pack"
import os, struct, sys
pack, dev = sys.argv[1], sys.argv[2]
data = open(pack, "rb").read()
ds = struct.unpack_from("<Q", data, 8)[0]
n = struct.unpack_from("<I", data, 16)[0]
entries = {}
for i in range(n):
    off, size = struct.unpack_from("<QQ", data, 24 + i * 32)
    name = data[24 + i * 32 + 16:24 + i * 32 + 32].split(b"\0")[0].decode()
    entries[name] = (off, size)
bad = 0
for name in ("libghostlock.so", "vrpatch.ko", "profile.bin"):
    off, size = entries[name]
    if open(os.path.join(dev, name), "rb").read() != data[ds + off:ds + off + size]:
        print("mismatch:", name)
        bad = 1
sys.exit(bad)
PY

check "second deploy is idempotent" "grep -q '部署完成' <($BIN deploy --pack '$PACK' 2>&1)"

echo "== profile-file override =="
MOCK_STATE="$TMP/state-pf" "$BIN" deploy --pack "$PACK" --profile-file alt.bin > "$OUT.pf" 2>&1
PFDEV="$TMP/state-pf/fs/data/local/tmp/ghostlock-app"
check "alt profile pushed"    "[ -s '$PFDEV/alt.bin' ]"
check "runner uses alt name"  "grep -q 'alt.bin' '$PFDEV/glrun.sh'"
check "default name absent"   "[ ! -e '$PFDEV/profile.bin' ]"

echo "== input validation =="
if "$BIN" check --dir '/tmp/x;rm -rf /' >/dev/null 2>&1; then
  bad "--dir injection rejected"
else
  ok "--dir injection rejected"
fi
if "$BIN" check --dir 'relative/path' >/dev/null 2>&1; then
  bad "--dir requires absolute path"
else
  ok "--dir requires absolute path"
fi

echo "== release gate =="
MOCK_STATE="$TMP/state2" MOCK_RELEASE="5.15.999-other" "$BIN" deploy --pack "$PACK" --redeploy > "$OUT.gate" 2>&1
check "mismatch refused"      "[ $? -ne 0 ]"
check "mismatch explains"     "grep -q 'release 不匹配' '$OUT.gate'"
MOCK_STATE="$TMP/state3" MOCK_RELEASE="5.15.999-other" "$BIN" deploy --pack "$PACK" --force > "$OUT.gatef" 2>&1
check "--force overrides"     "grep -q '部署完成' '$OUT.gatef'"

MOCK_STATE="$TMP/state3" MOCK_RELEASE="5.15.999-other" "$BIN" check > "$OUT.checkbad" 2>&1
check "check mismatch exits 3"   "[ $? -eq 3 ]"
check "check mismatch explains"  "grep -q '\*\*\* NO \*\*\*' '$OUT.checkbad'"

echo "== no device =="
if MOCK_OFFLINE=1 MOCK_STATE="$TMP/state-off" "$BIN" run --pack "$PACK" --rounds 1 > "$OUT.off" 2>&1; then
  bad "run fails without a device"
else
  ok "run fails without a device"
fi
check "no-device message"      "grep -q '没看到 adb 设备' '$OUT.off'"

echo "== check / status =="
"$BIN" check > "$OUT.check" 2>&1
check "check serial"          "grep -q 'MOCK123' '$OUT.check'"
check "check release match"   "grep -q 'match      : YES' '$OUT.check'"
check "check seccomp zero"    "grep -q 'Seccomp' '$OUT.check'"
"$BIN" status > "$OUT.status0" 2>&1
check "status root NO before" "grep -q 'root      : NO' '$OUT.status0'"

echo "== run (boot window, simulated hit) =="
"$BIN" run --pack "$PACK" --rounds 1 --per-boot 2 --timeout 20 --poll 150 > "$OUT.run" 2>&1
check "run exits 0"           "[ $? -eq 0 ]"
check "run reports success"   "grep -q '成功：root 已在' '$OUT.run'"
check "run observed KSU"      "grep -q 'KSU late-load 成功' '$OUT.run'"
check "run gave diagnostics"  "grep -q 'W1: SELinux' '$OUT.run'"
check "run verified root"     "grep -q 'root      : YES' '$OUT.run'"
check "ksu log on device"     "grep -q 'KernelSU module loaded' '$DEVFS'/ksu-*.log"
"$BIN" status > "$OUT.status1" 2>&1
check "status root YES after" "grep -q 'root      : YES' '$OUT.status1'"
"$BIN" run --pack "$PACK" --rounds 1 > "$OUT.run2" 2>&1
check "run is idempotent"     "grep -q '已经是 root' '$OUT.run2'"

echo "== no refire after root progress =="
MOCK_NO_KSU=1 MOCK_STATE="$TMP/state-nk" "$BIN" run --pack "$PACK" --rounds 1 \
  --per-boot 3 --timeout 15 --poll 150 --handoff-wait 2 --cycle-wait 1 \
  > "$OUT.nk" 2>&1
check "no-refire exits 1"     "[ $? -eq 1 ]"
check "no-refire explains"    "grep -q '不再发射' '$OUT.nk'"
check "exactly one launch"    "[ \$(wc -l < '$TMP/state-nk/launches') -eq 1 ]"

echo "== root terminal / logs =="
"$BIN" exec -- id -u > "$OUT.exec" 2>&1
check "exec returns root"     "grep -q 'uid=0(root)' '$OUT.exec'"
"$BIN" pull-log --out "$TMP/logs" > "$OUT.pull" 2>&1
check "pull-log got files"    "ls '$TMP/logs'/native-*.log >/dev/null 2>&1"
check "pull-log reports count" "grep -q 'pulled 2 files' '$OUT.pull'"

echo "== install (dry-run) =="
mkdir -p "$TMP/ko"
head -c 8192 /dev/zero > "$TMP/ko/android13-5.15_kernelsu.ko"
"$BIN" install --ko-dir "$TMP/ko" --ko 1 --dry-run > "$OUT.inst" 2>&1
check "install lists ko"       "grep -q 'android13-5.15_kernelsu.ko' '$OUT.inst'"
check "install finds loader"   "grep -q 'loader(ksud)' '$OUT.inst'"
check "install plans ko"       "grep -q '加载 ko' '$OUT.inst'"
check "install dry-run stops"  "grep -q 'dry-run' '$OUT.inst'"
check "install shows manager"  "grep -q 'com.resukisu.resukisu' '$OUT.inst'"

echo "== clean =="
"$BIN" clean > "$OUT.clean0" 2>&1
check "clean dry-run keeps dir" "[ -d '$DEVFS' ]"
check "clean dry-run says so"   "grep -q 'DRY-RUN' '$OUT.clean0'"
check "clean lists payload"     "grep -q '/data/local/tmp/ghostlock-app' '$OUT.clean0'"
"$BIN" clean --yes > "$OUT.clean1" 2>&1
check "clean --yes removes dir" "[ ! -e '$DEVFS' ]"

echo "== mock coverage =="
if [ -f "$MOCK_STATE/unmatched.log" ]; then
  BAD_CMDS=$(wc -l < "$MOCK_STATE/unmatched.log")
else
  BAD_CMDS=0
fi
check "no unimplemented adb commands" "[ '$BAD_CMDS' -eq 0 ]"
[ "$BAD_CMDS" -eq 0 ] || sed 's/^/    /' "$MOCK_STATE/unmatched.log"

echo
echo "passed: $PASS   failed: $FAIL"
[ "$FAIL" -eq 0 ]
