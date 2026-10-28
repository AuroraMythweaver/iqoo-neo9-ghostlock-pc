package device

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// Uptime returns /proc/uptime in seconds. The exploit's success rate collapses
// once the phone has been up for a while, so every attempt is gated on this.
func (a *ADB) Uptime() (float64, error) {
	out, err := a.ShellTrim("cat /proc/uptime")
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(out)
	if len(fields) == 0 {
		return 0, fmt.Errorf("unexpected /proc/uptime: %q", out)
	}
	return strconv.ParseFloat(fields[0], 64)
}

// Alive reports whether adb still gets a shell — it goes false while the phone
// panics and reboots, which is the normal failure path of the exploit.
func (a *ADB) Alive() bool {
	out, err := a.Shell("echo up")
	if err != nil {
		return false
	}
	return strings.Contains(out, "up")
}

// AliveFast is a short-timeout liveness probe used by the retry loop so a hung
// adb never stalls a whole round.
func (a *ADB) AliveFast() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, a.Bin, a.args("shell", "echo up")...)
	out, err := cmd.Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "up")
}

// WaitShell blocks until adb can run a shell command again, or the deadline
// passes.
func (a *ADB) WaitShell(d time.Duration) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if a.AliveFast() {
			return true
		}
		time.Sleep(400 * time.Millisecond)
	}
	return false
}

// WaitCycle waits for the phone to drop off adb and come back, i.e. for the
// reboot that a failed exploit causes. It returns false when no reboot was
// observed within the window.
func (a *ADB) WaitCycle(d time.Duration) (bool, error) {
	deadline := time.Now().Add(d)
	dropped := false
	for time.Now().Before(deadline) {
		if !a.AliveFast() {
			dropped = true
			break
		}
		time.Sleep(3 * time.Second)
	}
	if !dropped {
		return false, nil
	}
	if !a.WaitShell(300 * time.Second) {
		return false, fmt.Errorf("设备掉线后 300 秒没有回来")
	}
	return true, nil
}

// Reboot reboots the device and waits for it to come back with a shell.
func (a *ADB) Reboot() error {
	if _, err := a.run("reboot"); err != nil {
		// adb reboot often reports a broken pipe while the phone goes down
		_ = err
	}
	// give it a moment to actually drop
	time.Sleep(3 * time.Second)
	if !a.WaitShell(120 * time.Second) {
		return fmt.Errorf("重启后 120 秒没有拿到 shell")
	}
	return nil
}

// HasModule reports whether a kernel module is present in /proc/modules.
func (a *ADB) HasModule(name string) bool {
	out, err := a.ShellTrim("grep -c " + name + " /proc/modules 2>/dev/null")
	if err != nil {
		return false
	}
	return out != "" && out != "0"
}

// IsRoot reports whether su is usable already.
func (a *ADB) IsRoot() bool {
	out, err := a.Shell("su -c id -u 2>/dev/null")
	if err != nil {
		return false
	}
	return strings.Contains(out, "0")
}
