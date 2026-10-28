package stage

import (
	"fmt"

	"ghostlock/internal/device"
)

// CleanOptions controls what the post-success wipe removes.
type CleanOptions struct {
	Remote     string
	KeepUserKo bool // keep user.ko + the ksud wrapper so the next run reuses them
	KeepKsud   bool // keep /data/local/tmp/ksud
}

// Clean removes everything this tool put on the phone. KSU is already resident
// in the kernel at this point, so wiping the staging directory does not cost the
// root that was just obtained.
func Clean(a *device.ADB, o CleanOptions) ([]string, error) {
	remote := o.Remote
	if remote == "" {
		remote = RemoteDir
	}
	var removed []string

	keep := ""
	if o.KeepUserKo {
		keep = " -o -name user.ko -o -name ksud"
	}
	// payload + logs + run scripts + root script + state files
	cmd := fmt.Sprintf(
		"cd %s 2>/dev/null && find . -maxdepth 1 -type f ! -name . %s -exec rm -f {} + ; cd / ; rmdir %s 2>/dev/null; echo done",
		remote, keep, remote)
	if _, err := a.Shell(cmd); err != nil {
		return removed, err
	}
	removed = append(removed, remote+"/*")

	if !o.KeepKsud {
		if _, err := a.Shell("rm -f /data/local/tmp/ksud"); err != nil {
			return removed, err
		}
		removed = append(removed, "/data/local/tmp/ksud")
	}

	// leftovers from the embedded root script
	for _, p := range []string{
		"/data/local/tmp/.ghostlock_ksu.log",
		"/data/local/tmp/.ghostlock_iomem",
		"/data/local/tmp/.ghostlock_run_state.json",
	} {
		if _, err := a.Shell("rm -f " + p); err == nil {
			removed = append(removed, p)
		}
	}

	// any native process still parked in the background
	_, _ = a.Shell("pkill -f 'ghostlock --load-prebuilt-profile' 2>/dev/null; true")
	return removed, nil
}
