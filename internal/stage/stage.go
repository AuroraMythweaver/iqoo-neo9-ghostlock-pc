// Package stage probes the device and lays out the exploit sandbox.
package stage

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"ghostlock/internal/assets"
	"ghostlock/internal/device"
	"ghostlock/internal/manager"
	"ghostlock/internal/profile"
)

// RemoteDir is the shell-writable sandbox the exploit runs from. It has to be
// exec-mounted and world readable: /data/local/tmp is the only stable choice.
const RemoteDir = "/data/local/tmp/ghostlock"

// ManagerPackages are the KernelSU-family managers the root script knows how to
// drive through their bundled ksud. Order matters: the first installed one wins
// unless the user overrides it.
var ManagerPackages = []string{
	"me.weishu.kernelsu",
	"me.weishu.kernelsu.pr",
	"com.rifsxd.ksunext",
	"com.sukisu.ultra",
	"com.sukisu.sukisu",
	"com.resukisu.resukisu",
	"com.kowx712.supermanager",
	"com.sevenk.core",
	"com.sevenk.core.pr",
}

// Facts is everything the tool learns about the attached device.
type Facts struct {
	Serial        string
	Model         string
	Product       string
	Sdk           int
	AndroidVer    string
	KernelRelease string
	Selinux       string
	Seccomp       int
	Uid           string
	ManagerPkg    string
	KsudPath      string
	Kmi           string
	ProfileFile   string
	ProfileRoute  string
}

// Probe collects device facts with read-only shell commands.
func Probe(a *device.ADB) (*Facts, error) {
	f := &Facts{}
	get := func(cmd string) string {
		out, err := a.ShellTrim(cmd)
		if err != nil {
			return ""
		}
		return out
	}
	f.Serial = get("getprop ro.serialno")
	f.Model = get("getprop ro.product.model")
	f.Product = get("getprop ro.product.device")
	f.AndroidVer = get("getprop ro.build.version.release")
	f.Sdk, _ = strconv.Atoi(get("getprop ro.build.version.sdk"))
	f.KernelRelease = get("uname -r")
	f.Selinux = get("getenforce")
	f.Uid = get("id -u")

	status := get("cat /proc/self/status")
	for _, line := range strings.Split(status, "\n") {
		if strings.HasPrefix(line, "Seccomp:") {
			if n, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "Seccomp:"))); err == nil {
				f.Seccomp = n
			}
		}
	}

	f.Kmi = KMIfromKernel(f.KernelRelease)
	f.ManagerPkg, f.KsudPath = findManager(a)
	return f, nil
}

// KMIfromKernel maps a kernel release to the KMI string the KernelSU module
// loader expects.
func KMIfromKernel(release string) string {
	if release == "" {
		return ""
	}
	base := release
	if i := strings.Index(base, "-"); i > 0 {
		base = base[:i]
	}
	// keep major.minor only: 5.15.41 -> 5.15, 6.12.23 -> 6.12
	if parts := strings.SplitN(base, ".", 3); len(parts) >= 2 {
		base = parts[0] + "." + parts[1]
	}
	switch base {
	case "5.15":
		return "android13-5.15"
	case "6.1":
		return "android14-6.1"
	case "6.6":
		return "android15-6.6"
	case "6.12":
		return "android16-6.12"
	}
	return ""
}

func findManager(a *device.ADB) (pkg, ksud string) {
	// First: the package remembered by "manager install". Official SukiSU
	// release builds ship under a randomised name (rqglxo.qzizju.uholjr 之类),
	// so the hardcoded list below can never find the new build.
	if want := manager.ConfiguredManager(); want != "" {
		if out, err := a.ShellTrim("pm path " + want + " 2>/dev/null"); err == nil && strings.Contains(out, "package:") {
			return want, ksudForPackage(a, want)
		}
	}
	// Do NOT use "pm list packages": right after a reboot PackageManager is
	// still coming up and the listing either fails or arrives too late, which
	// leaves manager uid = 0 in the kernel and makes the manager show
	// "未安装". A per-package "pm path" probe is small and retried.
	for _, p := range ManagerPackages {
		for attempt := 0; attempt < 5; attempt++ {
			// "pm list packages <filter>" answers a single package fast and is
			// available earlier than the full listing; "pm path" exits 0 even
			// for a missing package so its output must be checked.
			out, err := a.ShellTrim("pm list packages " + p + " 2>/dev/null")
			if err == nil && strings.Contains(out, p) {
				return p, ksudForPackage(a, p)
			}
			if err == nil {
				out, err = a.ShellTrim("pm path " + p + " 2>/dev/null")
				if err == nil && strings.Contains(out, "package:") {
					return p, ksudForPackage(a, p)
				}
			}
			time.Sleep(500 * time.Millisecond)
		}
	}
	return "", ""
}

// ksudForPackage resolves the manager's libksud.so — that file *is* the ksud
// binary; the root script shells it for insmod / late-load.
func ksudForPackage(a *device.ADB, pkg string) string {
	out, err := a.ShellTrim("pm path " + pkg)
	if err != nil || out == "" {
		return ""
	}
	apk := strings.TrimSpace(strings.TrimPrefix(strings.Split(out, "\n")[0], "package:"))
	if apk == "" {
		return ""
	}
	dir := apk[:strings.LastIndex(apk, "/")]
	cand := dir + "/lib/arm64/libksud.so"
	if a.ShellOK("test -f " + cand) {
		return cand
	}
	// Newer SukiSU ships ksud under a randomised library name; take the biggest
	// aarch64 .so in the lib dir.
	big, err2 := a.ShellTrim("ls -S " + dir + "/lib/arm64/*.so 2>/dev/null | head -1")
	if err2 == nil && big != "" {
		return big
	}
	return ""
}

// Options controls what gets pushed.
type Options struct {
	Loader      *assets.Loader
	Remote      string
	ProfileBlob []byte
	ManagerPkg  string
	Kmi         string
	WithVrPatch bool
	// KoOverride replaces the embedded vrpatch.ko in the single insmod slot
	// that the root script has, e.g. with a kernelsu lkm the user picked.
	KoOverride     []byte
	KoOverrideName string
	// UserKo is a kernelsu lkm the user picked. It is NOT put into the single
	// insmod slot: it is staged as user.ko next to a ksud wrapper, and the
	// wrapper insmods it right before running the real late-load, so the
	// manager's own module is still loaded afterwards.
	UserKo      []byte
	RunScript   bool
	ForceAttack bool
}

// Files are the host-side payloads staged for one run.
type Files struct {
	Remote      string
	Binary      string
	VrPatch     string
	Profile     string
	KsudLog     string
	KoName      string
	UserKo      string
	RunScript   string
	KsudWrapper string
	ManagerPkg  string
	Kmi         string
}

// Paths describes where every staged file lives, without touching the device.
func Paths(remote string, withVrPatch bool, manager, kmi string) *Files {
	if remote == "" {
		remote = RemoteDir
	}
	f := &Files{
		Remote:     remote,
		Binary:     remote + "/" + assets.BinaryName,
		VrPatch:    remote + "/" + assets.VrPatchName,
		Profile:    remote + "/profile.bin",
		KsudLog:    remote + "/ksud.log",
		ManagerPkg: manager,
		Kmi:        kmi,
	}
	if !withVrPatch {
		f.VrPatch = ""
	}
	f.UserKo = remote + "/user.ko"
	f.RunScript = remote + "/glrun.sh"
	return f
}

// Push uploads the exploit payload, the profile blob and the small state files
// the embedded root script reads (.gl_ksu_pkg / .gl_kmi).
func Push(a *device.ADB, opts Options) (*Files, error) {
	remote := opts.Remote
	if remote == "" {
		remote = RemoteDir
	}
	if _, err := a.Shell("mkdir -p " + remote); err != nil {
		return nil, err
	}
	files := Paths(remote, opts.WithVrPatch, opts.ManagerPkg, opts.Kmi)

	tmp, err := os.MkdirTemp("", "ghostlock-stage-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)

	bin, err := opts.Loader.Read(assets.BinaryName)
	if err != nil {
		return nil, fmt.Errorf("payload %s: %w", assets.BinaryName, err)
	}
	binPath := filepath.Join(tmp, assets.BinaryName)
	if err := os.WriteFile(binPath, bin, 0o755); err != nil {
		return nil, err
	}
	if err := a.Push(binPath, files.Binary); err != nil {
		return nil, err
	}
	if _, err := a.Shell("chmod 755 " + files.Binary); err != nil {
		return nil, err
	}

	if len(opts.KoOverride) > 0 {
		name := opts.KoOverrideName
		if name == "" {
			name = "custom.ko"
		}
		files.VrPatch = remote + "/" + name
		files.KoName = name
		koPath := filepath.Join(tmp, name)
		if err := os.WriteFile(koPath, opts.KoOverride, 0o644); err != nil {
			return nil, err
		}
		if err := a.Push(koPath, files.VrPatch); err != nil {
			return nil, err
		}
		if _, err := a.Shell("chmod 644 " + files.VrPatch); err != nil {
			return nil, err
		}
	} else if opts.WithVrPatch {
		ko, err := opts.Loader.Read(assets.VrPatchName)
		if err != nil {
			return nil, fmt.Errorf("payload %s: %w", assets.VrPatchName, err)
		}
		koPath := filepath.Join(tmp, assets.VrPatchName)
		if err := os.WriteFile(koPath, ko, 0o644); err != nil {
			return nil, err
		}
		if err := a.Push(koPath, files.VrPatch); err != nil {
			return nil, err
		}
		if _, err := a.Shell("chmod 644 " + files.VrPatch); err != nil {
			return nil, err
		}
		files.KoName = assets.VrPatchName
	} else {
		files.VrPatch = ""
	}

	blobPath := filepath.Join(tmp, "profile.bin")
	if err := os.WriteFile(blobPath, opts.ProfileBlob, 0o644); err != nil {
		return nil, err
	}
	if err := a.Push(blobPath, files.Profile); err != nil {
		return nil, err
	}
	if _, err := a.Shell("chmod 644 " + files.Profile); err != nil {
		return nil, err
	}

	if len(opts.UserKo) > 0 {
		koPath := filepath.Join(tmp, "user.ko")
		if err := os.WriteFile(koPath, opts.UserKo, 0o644); err != nil {
			return nil, err
		}
		if err := a.Push(koPath, files.UserKo); err != nil {
			return nil, err
		}
		if _, err := a.Shell("chmod 644 " + files.UserKo); err != nil {
			return nil, err
		}
		real := ""
		if real == "" {
			real = discoverKsud(a)
		}
		if err := a.WriteFile(remote+"/ksud", ksudWrapper(remote, real)); err != nil {
			return nil, err
		}
		if _, err := a.Shell("chmod 755 " + remote + "/ksud"); err != nil {
			return nil, err
		}
		files.KsudWrapper = remote + "/ksud"
	}

	if opts.RunScript {
		if err := a.WriteFile(files.RunScript, runScript(remote, opts.ForceAttack)); err != nil {
			return nil, err
		}
		if _, err := a.Shell("chmod 755 " + files.RunScript); err != nil {
			return nil, err
		}
	}

	if opts.ManagerPkg != "" {
		if err := a.WriteFile(remote+"/.gl_ksu_pkg", opts.ManagerPkg+"\n"); err != nil {
			return nil, err
		}
	}
	if opts.Kmi != "" {
		if err := a.WriteFile(remote+"/.gl_kmi", opts.Kmi+"\n"); err != nil {
			return nil, err
		}
	}
	if _, err := a.Shell("rm -f " + remote + "/.gl_cmd " + remote + "/.gl_run " + remote + "/ksud.log"); err != nil {
		return nil, err
	}
	return files, nil
}

// ProfileFor picks the bundled profile whose release matches the device kernel.
func ProfileFor(loader *assets.Loader, kernelRelease string) (name string, p *profile.Profile, err error) {
	names, err := loader.Profiles()
	if err != nil {
		return "", nil, err
	}
	for _, n := range names {
		if strings.HasSuffix(n, "-template.conf") || n == "index.conf" || strings.HasPrefix(n, "execution-") ||
			strings.HasPrefix(n, "kernel") || strings.HasPrefix(n, "credential") {
			continue
		}
		if strings.TrimSuffix(n, ".conf") == kernelRelease {
			conf, err := loadConf(loader, n)
			if err != nil {
				return "", nil, err
			}
			return n, conf, nil
		}
	}
	return "", nil, fmt.Errorf("no bundled profile for kernel %q — pass --conf with your own profile, or generate one with 'ghostlock profile extract'", kernelRelease)
}

func loadConf(loader *assets.Loader, name string) (*profile.Profile, error) {
	data, err := loader.ReadProfile(name)
	if err != nil {
		return nil, err
	}
	tmp, err := os.CreateTemp("", "ghostlock-conf-*.conf")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return nil, err
	}
	tmp.Close()
	m, err := profile.ParseFile(tmp.Name())
	if err != nil {
		return nil, err
	}
	return profile.Resolve(m, 0)
}

// LoadConfFile resolves an arbitrary .conf file on the host.
func LoadConfFile(path string, safeMode int64) (*profile.Profile, error) {
	m, err := profile.ParseFile(path)
	if err != nil {
		return nil, err
	}
	return profile.Resolve(m, safeMode)
}

// RefreshManager re-detects the manager right before an attempt and rewrites
// .gl_ksu_pkg, because the root script reads that file to tell the kernel which
// package owns root. Doing it late (system fully up) is what makes
// "manager uid" resolve instead of staying 0.
func RefreshManager(a *device.ADB, remote, fallback string) (string, error) {
	if remote == "" {
		remote = RemoteDir
	}
	pkg, _ := findManager(a)
	if pkg == "" {
		pkg = fallback
	}
	if pkg == "" {
		return "", nil
	}
	if err := a.WriteFile(remote+"/.gl_ksu_pkg", pkg+"\n"); err != nil {
		return "", err
	}
	return pkg, nil
}
