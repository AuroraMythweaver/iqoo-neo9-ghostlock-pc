package stage

import (
	"ghostlock/internal/assets"
	"ghostlock/internal/device"
)

func joinLines(lines []string, nl string) string {
	out := ""
	for i, l := range lines {
		if i > 0 {
			out += nl
		}
		out += l
	}
	return out + nl
}

// ksudWrapper is the $HOME_DIR/ksud hook. The embedded root script prefers an
// executable $HOME_DIR/ksud over the manager's libksud.so, so this wrapper gets
// to insmod the user's module first and then hands over to the real ksud, which
// still performs the normal late-load. Two modules in one run, on purpose.
func ksudWrapper(remote, realKsud string) string {
	nl := string([]byte{0x0a})
	q := string([]byte{0x22})
	return joinLines([]string{
		"#!/system/bin/sh",
		"D=" + remote,
		"KO=$D/user.ko",
		"REAL=" + realKsud,
		"if [ -z " + q + "$REAL" + q + " ] || [ ! -x " + q + "$REAL" + q + " ]; then",
		"  for R in /data/adb/ksu/bin/ksud /data/adb/ksud /data/local/tmp/ksud; do",
		"    [ -x " + q + "$R" + q + " ] && { REAL=" + q + "$R" + q + "; break; }",
		"  done",
		"fi",
		"if [ -z " + q + "$REAL" + q + " ]; then",
		"  REAL=$(ls -d /data/app/*/*/lib/arm64/libksud.so 2>/dev/null | head -1)",
		"fi",
		"if [ " + q + "$1" + q + " = late-load ]; then",
		"  shift",
		"  if [ -f " + q + "$KO" + q + " ]; then",
		"    if [ -n " + q + "$REAL" + q + " ] && [ -x " + q + "$REAL" + q + " ]; then",
		"      OUT=$(" + q + "$REAL" + q + " insmod " + q + "$KO" + q + " allow_shell=1 2>&1); RC=$?",
		"    else",
		"      OUT=$(/system/bin/insmod " + q + "$KO" + q + " 2>&1); RC=$?",
		"    fi",
		"    echo " + q + "[wrapper] user.ko insmod rc=$RC $OUT" + q + " >>$D/ksud.log",
		"  fi",
		"  [ -n " + q + "$REAL" + q + " ] && [ -x " + q + "$REAL" + q + " ] || exit 90",
		"  exec " + q + "$REAL" + q + " late-load " + q + "$@" + q,
		"fi",
		"[ -n " + q + "$REAL" + q + " ] && [ -x " + q + "$REAL" + q + " ] || exit 90",
		"exec " + q + "$REAL" + q + " " + q + "$@" + q,
	}, nl)
}

// runScript is the launcher the retry loop fires. It takes a mode argument so
// one boot window can alternate between the two payload builds:
//
//	native  26.1 build, handles the vivo vr guard itself, no insmod
//	vrpatch v1.2 build, needs vrpatch.ko insmod'ed by the root script
func runScript(remote string, forceAttack bool) string {
	nl := string([]byte{0x0a})
	q := string([]byte{0x22})
	force := ""
	if forceAttack {
		force = " --force-attack"
	}
	return joinLines([]string{
		"#!/system/bin/sh",
		"H=" + remote,
		"cd " + q + "$H" + q + " || exit 90",
		"M=$1",
		"TS=$GL_RUN_ID",
		"[ -n " + q + "$TS" + q + " ] || TS=$(date +%s)",
		"export HOME=" + q + "$H" + q + " TMPDIR=" + q + "$H" + q + " GHOSTLOCK_HOME=" + q + "$H" + q,
		"export GHOSTLOCK_KSU_LOG=" + q + "$H/ksu-$TS.log" + q,
		"if [ " + q + "$M" + q + " = vrpatch ]; then",
		"  BIN=" + q + "$H/" + assets.BinaryV12 + q,
		"  export GHOSTLOCK_VRPATCH_KO=" + q + "$H/vrpatch.ko" + q,
		"  export GHOSTLOCK_KSU_ENFORCE=$(cat " + q + "$H/ksu_target" + q + " 2>/dev/null || echo 0)",
		"else",
		"  BIN=" + q + "$H/" + assets.BinaryName + q,
		"fi",
		"echo " + q + "=== run $TS mode=$M uptime=$(cut -d" + q + " " + q + " -f1 /proc/uptime)" + q +
			" > " + q + "$H/native-$TS.log" + q,
		q + "$BIN" + q + " --load-prebuilt-profile " + q + "$H/profile.bin" + q + force +
			" >> " + q + "$H/native-$TS.log" + q + " 2>&1",
		"echo " + q + "=== native exit=$?" + q + " >> " + q + "$H/native-$TS.log" + q,
		"echo done > " + q + "$H/native-$TS.rc" + q,
	}, nl)
}

// discoverKsud finds the manager ksud binary on the device, if installed.
func discoverKsud(a *device.ADB) string {
	out, err := a.ShellTrim("ls -d /data/app/*/*/lib/arm64/libksud.so 2>/dev/null | head -1")
	if err != nil {
		return ""
	}
	return out
}
