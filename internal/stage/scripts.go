package stage

import (
	"ghostlock/internal/device"
)

// ksudWrapper is the $HOME_DIR/ksud hook. The embedded root script prefers an
// executable $HOME_DIR/ksud over the manager's libksud.so, so this wrapper gets
// to insmod the user's module first and then hands over to the real ksud, which
// still performs the normal late-load. Two modules in one run, on purpose.
func ksudWrapper(remote, realKsud string) string {
	nl := string([]byte{0x0a})
	return joinLines([]string{
		"#!/system/bin/sh",
		"D=" + remote,
		"KO=$D/user.ko",
		"REAL=" + realKsud,
		"if [ -z \"$REAL\" ] || [ ! -x \"$REAL\" ]; then",
		"  for R in /data/adb/ksu/bin/ksud /data/adb/ksud /data/local/tmp/ksud; do",
		"    [ -x \"$R\" ] && { REAL=\"$R\"; break; }",
		"  done",
		"fi",
		"if [ -z \"$REAL\" ]; then",
		"  REAL=$(ls -d /data/app/*/*/lib/arm64/libksud.so 2>/dev/null | head -1)",
		"fi",
		"if [ \"$1\" = late-load ]; then",
		"  shift",
		"  if [ -f \"$KO\" ]; then",
		"    if [ -n \"$REAL\" ] && [ -x \"$REAL\" ]; then",
		"      OUT=$(\"$REAL\" insmod \"$KO\" allow_shell=1 2>&1); RC=$?",
		"    else",
		"      OUT=$(/system/bin/insmod \"$KO\" 2>&1); RC=$?",
		"    fi",
		"    echo \"[wrapper] user.ko insmod rc=$RC $OUT\" >>$D/ksud.log",
		"  fi",
		"  [ -n \"$REAL\" ] && [ -x \"$REAL\" ] || exit 90",
		"  exec \"$REAL\" late-load \"$@\"",
		"fi",
		"[ -n \"$REAL\" ] && [ -x \"$REAL\" ] || exit 90",
		"exec \"$REAL\" \"$@\"",
	}, nl)
}

// runScript is the launcher the retry loop fires; each attempt keeps its own
// native output and exit marker so the loop can tell "running" from "finished"
// from "the phone died".
func runScript(remote string, forceAttack bool) string {
	nl := string([]byte{0x0a})
	force := ""
	if forceAttack {
		force = " --force-attack"
	}
	return joinLines([]string{
		"#!/system/bin/sh",
		"H=" + remote,
		"cd \"$H\" || exit 90",
		"TS=$GL_RUN_ID",
		"[ -n \"$TS\" ] || TS=$(date +%s)",
		"export HOME=\"$H\" TMPDIR=\"$H\" GHOSTLOCK_HOME=\"$H\"",
		"export GHOSTLOCK_VRPATCH_KO=\"$H/vrpatch.ko\"",
		"export GHOSTLOCK_KSU_LOG=\"$H/ksu-$TS.log\"",
		"export GHOSTLOCK_KSU_ENFORCE=$(cat \"$H/ksu_target\" 2>/dev/null || echo 0)",
		"echo \"=== run $TS uptime=$(cut -d\" \" -f1 /proc/uptime)\" > \"$H/native-$TS.log\"",
		"\"$H/ghostlock\" --load-prebuilt-profile \"$H/profile.bin\"" + force + " >> \"$H/native-$TS.log\" 2>&1",
		"echo \"=== native exit=$?\" >> \"$H/native-$TS.log\"",
		"echo done > \"$H/native-$TS.rc\"",
	}, nl)
}

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

// discoverKsud finds the manager ksud binary on the device, if installed.
func discoverKsud(a *device.ADB) string {
	out, err := a.ShellTrim("ls -d /data/app/*/*/lib/arm64/libksud.so 2>/dev/null | head -1")
	if err != nil {
		return ""
	}
	return out
}
