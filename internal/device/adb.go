// Package device wraps the adb client used to talk to the phone.
package device

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
)

// callTimeout bounds every non-streaming adb call. Without it a single
// "adb shell" issued while the phone is rebooting blocks forever and the whole
// retry loop dies silently.
const callTimeout = 25 * time.Second

// ADB is one adb client bound to an optional device serial.
type ADB struct {
	Bin    string
	Serial string
}

// New finds the adb binary and returns a client.
func New(serial string) (*ADB, error) { return NewWith(serial, "") }

// NewWith honours an explicit adb path (flag), GHOSTLOCK_ADB, a remembered
// path, then PATH. Windows users who unzipped platform-tools somewhere can
// just point at the folder.
func NewWith(serial, explicit string) (*ADB, error) {
	bin, err := ResolveADB(explicit)
	if err != nil {
		return nil, err
	}
	return &ADB{Bin: bin, Serial: serial}, nil
}

// Devices lists attached devices in the "device" state.
func (a *ADB) Devices() ([]string, error) {
	out, err := a.run("devices")
	if err != nil {
		return nil, err
	}
	var list []string
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[1] == "device" {
			list = append(list, f[0])
		}
	}
	return list, nil
}

func (a *ADB) args(extra ...string) []string {
	if a.Serial == "" {
		return extra
	}
	return append([]string{"-s", a.Serial}, extra...)
}

func (a *ADB) run(extra ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, a.Bin, a.args(extra...)...)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return "", fmt.Errorf("adb %s: timeout after %s", strings.Join(extra, " "), callTimeout)
	}
	if err != nil {
		msg := strings.TrimSpace(errb.String())
		if msg == "" {
			msg = strings.TrimSpace(out.String())
		}
		return "", fmt.Errorf("adb %s: %v: %s", strings.Join(extra, " "), err, msg)
	}
	return out.String(), nil
}

// Shell runs a command through /system/bin/sh and returns its combined output.
func (a *ADB) Shell(command string) (string, error) {
	return a.run("shell", command)
}

// ShellTrim runs a command and trims the result.
func (a *ADB) ShellTrim(command string) (string, error) {
	out, err := a.Shell(command)
	return strings.TrimSpace(out), err
}

// ShellOK reports whether a command exits 0.
func (a *ADB) ShellOK(command string) bool {
	_, err := a.Shell(command)
	return err == nil
}

// Stream runs a command, echoing every line to w and to the returned buffer.
func (a *ADB) Stream(command string, w io.Writer, idle time.Duration) (string, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := exec.CommandContext(ctx, a.Bin, a.args("shell", command)...)
	cmd.Stderr = cmd.Stdout
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		return "", err
	}
	if err := cmd.Start(); err != nil {
		return "", err
	}
	var all bytes.Buffer
	sc := bufio.NewScanner(pipe)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		all.WriteString(line)
		all.WriteByte('\n')
		if w != nil {
			fmt.Fprintln(w, line)
		}
	}
	err = cmd.Wait()
	return all.String(), err
}

// Push copies a local file to the device.
func (a *ADB) Push(local, remote string) error {
	_, err := a.run("push", local, remote)
	return err
}

// Pull copies a device file to the host.
func (a *ADB) Pull(remote, local string) error {
	_, err := a.run("pull", remote, local)
	return err
}

// WriteFile writes small text content on the device without leaving host temp
// files behind.
func (a *ADB) WriteFile(remote, content string) error {
	tmp, err := os.CreateTemp("", "ghostlock-upload-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(content); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := a.Push(tmp.Name(), remote); err != nil {
		return err
	}
	return nil
}

// Install installs or replaces an APK on the device.
func (a *ADB) Install(apk string) (string, error) {
	return a.run("install", "-r", "-d", apk)
}
