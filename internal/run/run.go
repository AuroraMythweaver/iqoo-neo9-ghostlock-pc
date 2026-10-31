// Package run drives one attempt: probe the phone, resolve a profile, stage the
// payload over adb, execute it on the device and interpret the result.
package run

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"ghostlock/internal/assets"
	"ghostlock/internal/device"
	"ghostlock/internal/profile"
	"ghostlock/internal/stage"
)

// Options describes one attempt.
type Options struct {
	ADB         *device.ADB
	Loader      *assets.Loader
	Remote      string
	ConfPath    string
	SafeMode    bool
	TempRoot    bool
	Force       bool
	NoVrPatch   bool
	DryRun      bool
	CleanAfter  bool
	DebugDir    string
	KoPath      string
	BlobPath    string
	MainCPU     string
	ConsumerCPU string
	ManagerPkg  string
	Kmi         string
	Out         io.Writer
}

// Result is the post-mortem of one attempt.
type Result struct {
	ExitCode    int
	TempRoot    bool
	KsuLoaded   bool
	SelinuxOff  bool
	SeccompGone bool
	Notes       []string
}

// nl is the only control character this package needs, kept out of string
// literals so the source stays free of escape sequences.
var nl = string([]byte{0x0a})

func printf(w io.Writer, f string, a ...any) { fmt.Fprintf(w, f, a...) }

// Execute performs the whole flow: probe, resolve profile, stage, run, report.
func Execute(o *Options) (*Result, error) {
	if o.Out == nil {
		o.Out = io.Discard
	}
	facts, err := stage.Probe(o.ADB)
	if err != nil {
		return nil, err
	}
	printf(o.Out, "• 设备    %s (%s) android %s, kernel %s"+nl, facts.Model, facts.Product, facts.AndroidVer, facts.KernelRelease)
	printf(o.Out, "• selinux %s   ksud %s   kmi %s"+nl, facts.Selinux, orDash(facts.KsudPath), orDash(facts.Kmi))

	if !o.Force && rooted(o.ADB) {
		printf(o.Out, nl+"[+] 设备现在已经是 root（内核里有 kernelsu），不需要再打"+nl)
		printf(o.Out, "    要强制重打请显式加 --force-attack（有 panic 风险）"+nl)
		return &Result{TempRoot: true, KsuLoaded: true}, nil
	}

	var blob []byte
	if o.BlobPath == "" && o.ConfPath == "" {
		if b, ok := verifiedBlob(o, facts.KernelRelease); ok {
			blob = b
			printf(o.Out, "• blob    内嵌已验证 profile（%d 字节，与设备 release 一致）"+nl, len(b))
		}
	}
	if blob != nil {
		// already resolved
	} else if o.BlobPath != "" {
		b, rel, err := loadBlob(o.BlobPath, facts.KernelRelease)
		if err != nil {
			return nil, err
		}
		blob = b
		printf(o.Out, "• blob    %s (release %s, %d 字节，直接用现成 blob)"+nl, o.BlobPath, rel, len(b))
	} else {
		p, confName, err := resolveProfile(o, facts)
		if err != nil {
			return nil, err
		}
		printf(o.Out, "• profile %s (route %s idx=%d, fallback=%d)"+nl, confName, p.Route, p.RouteIdx, p.FallbackIdx)
		if problems := p.Validate(); len(problems) > 0 {
			for _, prob := range problems {
				printf(o.Out, "  ! %s"+nl, prob)
			}
			return nil, fmt.Errorf("profile 不可用，已停止（这种状态下强跑会写坏内存触发重启）")
		}
		b, err := p.Encode()
		if err != nil {
			return nil, err
		}
		blob = b
	}
	manager := o.ManagerPkg
	if manager == "" {
		manager = facts.ManagerPkg
	}
	kmi := o.Kmi
	if kmi == "" {
		kmi = facts.Kmi
	}
	if manager == "" && !o.TempRoot {
		printf(o.Out, nl+"! 没有安装 KernelSU 系管理器：late-load 之后没有人接管 root。")
		printf(o.Out, nl+"  先装 SukiSU Ultra / KernelSU-Next，或加 --temp-root 只跑一次性 root 脚本。"+nl)
	}

	var userKo []byte
	if o.KoPath != "" {
		data, name, why, err := loadKo(o.KoPath, facts.KernelRelease)
		if err != nil {
			return nil, err
		}
		userKo = data
		printf(o.Out, "• ko      %s（%s）→ ksud wrapper：先 insmod 它，再跑正常 late-load"+nl, name, why)
	}

	if o.DryRun {
		files := stage.Paths(o.Remote, !o.NoVrPatch, manager, kmi)
		printf(o.Out, nl+"(dry-run) 将要执行的命令:"+nl+"$ %s"+nl, buildCommand(o, files))
		printf(o.Out, nl+"profile blob: %d 字节"+nl, len(blob))
		return &Result{}, nil
	}

	files, err := stage.Push(o.ADB, stage.Options{
		Loader:      o.Loader,
		Remote:      o.Remote,
		ProfileBlob: blob,
		ManagerPkg:  manager,
		Kmi:         kmi,
		WithVrPatch: !o.NoVrPatch,
		UserKo:      userKo,
	})
	if err != nil {
		return nil, err
	}
	if o.DebugDir != "" {
		if _, err := o.ADB.Shell("mkdir -p " + o.DebugDir); err != nil {
			return nil, err
		}
	}

	cmd := buildCommand(o, files)
	printf(o.Out, nl+"$ %s"+nl+nl, cmd)
	started := time.Now()
	out, runErr := o.ADB.Stream(cmd, o.Out, 0)
	elapsed := time.Since(started).Round(time.Second)
	res := interpret(out, runErr)

	printf(o.Out, nl+"— 用时 %s，native exit=%d —"+nl, elapsed, res.ExitCode)
	if logOut, err := o.ADB.ShellTrim("cat " + files.KsudLog + " 2>/dev/null"); err == nil && logOut != "" {
		printf(o.Out, nl+"── root 脚本日志 (%s) ──"+nl+"%s"+nl, files.KsudLog, logOut)
	}
	if o.DebugDir != "" {
		printf(o.Out, nl+"调试产物: %s (kernel-info.txt / kernel-dmesg.log / iomem.txt)"+nl, o.DebugDir)
	}
	if o.CleanAfter && (res.KsuLoaded || res.TempRoot) {
		if gone, err := stage.Clean(o.ADB, stage.CleanOptions{Remote: o.Remote}); err == nil {
			printf(o.Out, nl+"[*] 已清理设备痕迹: %s"+nl, strings.Join(gone, ", "))
		}
	}
	report(o.Out, res, facts)
	return res, nil
}

func resolveProfile(o *Options, facts *stage.Facts) (*profile.Profile, string, error) {
	if o.ConfPath != "" {
		safe := int64(0)
		if o.SafeMode {
			safe = 1
		}
		p, err := stage.LoadConfFile(o.ConfPath, safe)
		return p, o.ConfPath, err
	}
	if !o.SafeMode {
		name, p, err := stage.ProfileFor(o.Loader, facts.KernelRelease)
		return p, name, err
	}
	// Re-resolve the bundled profile with safe_mode=1 so modules stay off.
	name, _, err := stage.ProfileFor(o.Loader, facts.KernelRelease)
	if err != nil {
		return nil, "", err
	}
	data, err := o.Loader.ReadProfile(name)
	if err != nil {
		return nil, "", err
	}
	dir, err := os.MkdirTemp("", "ghostlock-*")
	if err != nil {
		return nil, "", err
	}
	defer os.RemoveAll(dir)
	path := dir + "/" + name
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return nil, "", err
	}
	p, err := stage.LoadConfFile(path, 1)
	return p, name, err
}

func buildCommand(o *Options, f *stage.Files) string {
	enforce := "0"
	if o.TempRoot {
		enforce = "9"
	}
	parts := []string{
		"cd " + f.Remote,
		"GHOSTLOCK_HOME=" + f.Remote,
		"TMPDIR=" + f.Remote,
		"HOME=" + f.Remote,
		"GHOSTLOCK_KSU_LOG=" + f.KsudLog,
		"GHOSTLOCK_KSU_ENFORCE=" + enforce,
	}
	if f.VrPatch != "" {
		parts = append(parts, "GHOSTLOCK_VRPATCH_KO="+f.VrPatch)
	}
	if o.MainCPU != "" {
		parts = append(parts, "GHOSTLOCK_MAIN_CPU="+o.MainCPU)
	}
	if o.ConsumerCPU != "" {
		parts = append(parts, "GHOSTLOCK_CONSUMER_CPU="+o.ConsumerCPU)
	}
	args := []string{"./" + assets.BinaryName, "--load-prebuilt-profile", f.Profile}
	if o.Force {
		args = append(args, "--force-attack")
	}
	if o.DebugDir != "" {
		args = append(args, "--dump-kernel-log", o.DebugDir)
	}
	parts = append(parts, strings.Join(args, " "))
	return strings.Join(parts, " ")
}

func interpret(out string, runErr error) *Result {
	res := &Result{}
	if strings.Contains(out, "child is root!") {
		res.TempRoot = true
	}
	if strings.Contains(out, "KernelSU module loaded") {
		res.KsuLoaded = true
	}
	if strings.Contains(out, "SELinux permissive") {
		res.SelinuxOff = true
	}
	if strings.Contains(out, "seccomp filter bypassed") {
		res.SeccompGone = true
	}
	risks := []string{
		"KernelSnitch mm_struct leak failed",
		"credential copy profile is incomplete",
		"multicast geometry incomplete",
		"profile release mismatch",
		"KernelSU module load failed",
		"temporary root ready; KernelSU module not loaded",
		"route failed",
		"vr guard",
		"terminated by signal",
	}
	for _, r := range risks {
		if strings.Contains(out, r) {
			res.Notes = append(res.Notes, r)
		}
	}
	if runErr != nil {
		res.Notes = append(res.Notes, "adb shell 返回非零")
	}
	if n, ok := lastExitCode(out); ok {
		res.ExitCode = n
	}
	return res
}

func lastExitCode(out string) (int, bool) {
	trimmed := strings.TrimRight(out, nl)
	if trimmed == "" {
		return 0, false
	}
	idx := strings.LastIndex(trimmed, nl)
	tail := strings.TrimSpace(trimmed[idx+1:])
	var n int
	if _, err := fmt.Sscanf(tail, "%d", &n); err != nil {
		return 0, false
	}
	return n, true
}

func report(w io.Writer, res *Result, facts *stage.Facts) {
	printf(w, nl+"═══ 结果 ═══"+nl)
	printf(w, "  临时 root : %s"+nl, yesNo(res.TempRoot))
	printf(w, "  KSU 模块  : %s"+nl, yesNo(res.KsuLoaded))
	printf(w, "  SELinux   : %s"+nl, map[bool]string{true: "permissive", false: "未改动"}[res.SelinuxOff])
	if len(res.Notes) > 0 {
		printf(w, "  诊断记号  : %s"+nl, strings.Join(res.Notes, " | "))
	}
	if res.KsuLoaded {
		printf(w, nl+"下一步: 打开 %s 确认已激活，然后 adb shell su -c id。"+nl, orDash(facts.ManagerPkg))
	} else if res.TempRoot {
		printf(w, nl+"只拿到临时 root：KSU 未加载。检查 ksud / kmi / vrpatch.ko，见 README 排错一节。"+nl)
	} else {
		printf(w, nl+"本轮未拿到 root。失败通常会让设备重启（内存被脏写）。重启后先跑 ghostlock doctor 再重试。"+nl)
	}
}

func yesNo(b bool) string {
	if b {
		return "是"
	}
	return "否"
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// humanSize renders a byte count for the pre-flight report.
func humanSize(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}
