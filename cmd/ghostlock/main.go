// Command ghostlock is a headless, scriptable front-end for the GhostLock
// kernel exploit (vivo iQOO Neo9 / PD2338, 5.15 GKI).
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"ghostlock/internal/assets"
	"ghostlock/internal/device"
	"ghostlock/internal/profile"
	"ghostlock/internal/run"
	"ghostlock/internal/stage"
)

const version = "2.0.1"

// adbPath comes from --adb (also accepted as a global flag on every command).
var adbPath string

func main() {
	if err := dispatch(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "错误: "+err.Error())
		waitForEnter()
		os.Exit(1)
	}
}

// waitForEnter keeps a double-clicked window open long enough to read the
// error. Only when stdin is a terminal, so scripts are unaffected.
func waitForEnter() {
	info, err := os.Stdin.Stat()
	if err != nil || info.Mode()&os.ModeCharDevice == 0 {
		return
	}
	fmt.Println()
	fmt.Print("按回车退出…")
	bufio.NewReader(os.Stdin).ReadString(byte(0x0a))
}

func dispatch(args []string) error {
	if len(args) == 0 {
		return cmdMenu()
	}
	switch args[0] {
	case "doctor":
		return cmdDoctor(args[1:])
	case "run":
		return cmdRun(args[1:])
	case "profile":
		return cmdProfile(args[1:])
	case "assets":
		return cmdAssets(args[1:])
	case "ko":
		return cmdKo(args[1:])
	case "manager":
		return cmdManager(args[1:])
	case "version", "-v", "--version":
		fmt.Println("ghostlock-cli", version)
		return nil
	case "help", "-h", "--help":
		fmt.Print(usageText)
		return nil
	}
	fmt.Print(usageText)
	return fmt.Errorf("未知命令 %q", args[0])
}

type common struct {
	serial  string
	assets  string
	adbPath string
}

func addCommon(fs *flag.FlagSet) *common {
	c := &common{}
	fs.StringVar(&c.serial, "s", "", "device serial")
	fs.StringVar(&c.serial, "serial", "", "device serial")
	fs.StringVar(&c.assets, "assets", "", "payload override directory")
	fs.StringVar(&c.adbPath, "adb", "", "adb 可执行文件或 platform-tools 目录（默认查 PATH）")
	return c
}

func (c *common) adb() (*device.ADB, error) {
	if c.adbPath != "" {
		adbPath = c.adbPath
	}
	return device.NewWith(c.serial, adbPath)
}
func (c *common) loader() *assets.Loader { return assets.New(c.assets) }

func cmdDoctor(args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	c := addCommon(fs)
	fs.Parse(args)

	a, err := c.adb()
	if err != nil {
		return err
	}
	devices, err := a.Devices()
	if err != nil {
		return err
	}
	if len(devices) == 0 {
		return fmt.Errorf("没有连接的设备（adb devices 为空）")
	}
	if c.serial == "" && len(devices) > 1 {
		return fmt.Errorf("连接了多台设备 %v，请用 -s 指定", devices)
	}

	facts, err := stage.Probe(a)
	if err != nil {
		return err
	}
	fmt.Printf("设备      : %s (%s)  android %s (sdk %d)\n", facts.Model, facts.Product, facts.AndroidVer, facts.Sdk)
	fmt.Printf("内核      : %s\n", facts.KernelRelease)
	fmt.Printf("SELinux   : %s\n", facts.Selinux)
	fmt.Printf("Seccomp   : %d  (0 = 无过滤器，adb/shell 流程会跳过 W3)\n", facts.Seccomp)
	fmt.Printf("shell uid : %s\n", facts.Uid)
	fmt.Printf("管理器    : %s\n", dash(facts.ManagerPkg))
	fmt.Printf("ksud      : %s\n", dash(facts.KsudPath))
	fmt.Printf("KMI       : %s\n", dash(facts.Kmi))

	loader := c.loader()
	name, p, err := stage.ProfileFor(loader, facts.KernelRelease)
	if err != nil {
		fmt.Printf("\nprofile   : 缺失 — %v\n", err)
	} else {
		fmt.Printf("\nprofile   : %s\n", name)
		fmt.Printf("  route         : %s (idx %d), fallback %d\n", p.Route, p.RouteIdx, p.FallbackIdx)
		fmt.Printf("  kernel_major  : %d, recommend_shizuku: %d\n", getVal(p, "meta", "kernel_major"), getVal(p, "meta", "recommend_shizuku"))
		fmt.Printf("  init_task     : 0x%x  init_cred: 0x%x  selinux_enforcing: 0x%x\n",
			getVal(p, "offset", "init_task"), getVal(p, "offset", "init_cred"), getVal(p, "offset", "selinux_enforcing"))
		fmt.Printf("  cpus          : main=%d consumer=%d\n",
			getVal(p, "execution.recommended_cpus", "main"), getVal(p, "execution.recommended_cpus", "consumer"))
		if problems := p.Validate(); len(problems) > 0 {
			for _, prob := range problems {
				fmt.Printf("  ! %s\n", prob)
			}
		}
	}

	if facts.KsudPath == "" {
		fmt.Println("\n提示: 没有找到任何 KSU 管理器的 libksud.so — late-load 找不到执行者。")
		fmt.Println("      安装 SukiSU Ultra / KernelSU-Next 后重跑 doctor。")
	}
	if facts.Selinux == "Enforcing" {
		fmt.Println("提示: SELinux 为 Enforcing，脚本会先走 policy 字节修补 + load_policy。")
	}
	return nil
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func getVal(p *profile.Profile, section, key string) int64 {
	for _, s := range p.Sections {
		if s.Name != section {
			continue
		}
		for _, e := range s.Entries {
			if e.Key == key {
				return e.Val
			}
		}
	}
	return 0
}

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	c := addCommon(fs)
	conf := fs.String("conf", "", "custom .conf profile")
	remote := fs.String("remote", stage.RemoteDir, "remote sandbox dir")
	tempRoot := fs.Bool("temp-root", false, "stop after temporary root")
	safeMode := fs.Bool("safe-mode", false, "disable all /data/adb modules on root")
	noVrPatch := fs.Bool("no-vrpatch", false, "skip vrpatch.ko")
	force := fs.Bool("force-attack", false, "attack even if KernelSU already has root")
	mainCPU := fs.String("main-cpu", "", "main thread cpu")
	consumerCPU := fs.String("consumer-cpu", "", "consumer thread cpu")
	manager := fs.String("manager", "", "KSU manager package")
	kmi := fs.String("kmi", "", "KMI string")
	koPath := fs.String("ko", "", "用指定 ko（ksud wrapper 会先 insmod 它）")
	blobPath := fs.String("blob", "", "直接使用现成的 profile blob（跳过 conf 生成）")
	cleanAfter := fs.Bool("clean-after", false, "成功后清理设备上的 payload 与日志")
	loopMode := fs.Bool("loop", false, "脱手循环：失败等重启，回到 uptime 窗口再打")
	rounds := fs.Int("rounds", 10, "循环轮数上限")
	perBoot := fs.Int("per-boot", 6, "每次开机窗口内连发次数")
	window := fs.Int("window", 90, "uptime 窗口上沿（秒）")
	rebootFirst := fs.Bool("reboot-first", false, "先主动重启抢窗口")
	autoReboot := fs.Bool("auto-reboot", true, "干净失败（未 panic）时主动重启进下一轮")
	dryRun := fs.Bool("dry-run", false, "只打印将要执行的命令，不碰设备")
	debugDir := fs.String("debug-dir", "", "失败后把 dmesg/iomem 落到该目录")
	fs.Parse(args)

	a, err := c.adb()
	if err != nil {
		return err
	}
	base := &run.Options{
		ADB:         a,
		Loader:      c.loader(),
		Remote:      *remote,
		ConfPath:    *conf,
		TempRoot:    *tempRoot,
		SafeMode:    *safeMode,
		NoVrPatch:   *noVrPatch,
		Force:       *force,
		DryRun:      *dryRun,
		DebugDir:    *debugDir,
		MainCPU:     *mainCPU,
		ConsumerCPU: *consumerCPU,
		ManagerPkg:  *manager,
		Kmi:         *kmi,
		KoPath:      *koPath,
		BlobPath:    *blobPath,
		CleanAfter:  *cleanAfter,
		Out:         os.Stdout,
	}
	if *loopMode {
		_, err := run.Loop(&run.LoopOptions{
			Base:        base,
			Rounds:      *rounds,
			PerBoot:     *perBoot,
			Window:      *window,
			RebootFirst: *rebootFirst,
			AutoReboot:  *autoReboot,
			Out:         os.Stdout,
		})
		return err
	}
	_, err = run.Execute(base)
	return err
}

func cmdProfile(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("profile 需要子命令: list | show | compile")
	}
	loader := assets.New(os.Getenv("GHOSTLOCK_ASSETS"))
	switch args[0] {
	case "list":
		names, err := loader.Profiles()
		if err != nil {
			return err
		}
		for _, n := range names {
			fmt.Println(strings.TrimSuffix(n, ".conf"))
		}
		return nil
	case "show":
		if len(args) < 2 {
			return fmt.Errorf("用法: ghostlock profile show <release>")
		}
		target := args[1]
		if !strings.HasSuffix(target, ".conf") {
			target += ".conf"
		}
		data, err := loader.ReadProfile(target)
		if err != nil {
			return err
		}
		dir, err := os.MkdirTemp("", "ghostlock-*")
		if err != nil {
			return err
		}
		defer os.RemoveAll(dir)
		path := filepath.Join(dir, target)
		if err := os.WriteFile(path, data, 0o644); err != nil {
			return err
		}
		p, err := stage.LoadConfFile(path, 0)
		if err != nil {
			return err
		}
		printProfile(p)
		return nil
	case "compile":
		if len(args) < 2 {
			return fmt.Errorf("用法: ghostlock profile compile <conf> [-o out.bin]")
		}
		out := "profile.bin"
		if len(args) >= 4 && args[2] == "-o" {
			out = args[3]
		}
		p, err := stage.LoadConfFile(args[1], 0)
		if err != nil {
			return err
		}
		if problems := p.Validate(); len(problems) > 0 {
			for _, prob := range problems {
				fmt.Fprintln(os.Stderr, "警告: "+prob)
			}
		}
		if err := p.WriteFile(out); err != nil {
			return err
		}
		fmt.Printf("已写入 %s (release=%s, route=%s)\n", out, p.Release, p.Route)
		return nil
	}
	return fmt.Errorf("未知子命令 %q", args[0])
}

func printProfile(p *profile.Profile) {
	fmt.Printf("release=%s route=%s(%d) fallback=%d\n", p.Release, p.Route, p.RouteIdx, p.FallbackIdx)
	for _, s := range p.Sections {
		fmt.Printf("[%s]\n", s.Name)
		for _, e := range s.Entries {
			fmt.Printf("  %-34s %d  (0x%x)\n", e.Key, e.Val, e.Val)
		}
	}
	if len(p.InvalidPaths) > 0 {
		fmt.Printf("缺失/为零的字段: %s\n", strings.Join(p.InvalidPaths, ", "))
	}
}

func cmdAssets(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("assets 需要子命令: unpack | import | list")
	}
	loader := assets.New("")
	switch args[0] {
	case "unpack":
		if len(args) < 2 {
			return fmt.Errorf("用法: ghostlock assets unpack <dir>")
		}
		n, err := loader.Unpack(args[1])
		if err != nil {
			return err
		}
		fmt.Printf("已释放 %d 个文件到 %s\n", n, args[1])
		return nil
	case "import":
		if len(args) < 3 {
			return fmt.Errorf("用法: ghostlock assets import <apk> <dir>")
		}
		written, err := assets.ImportAPK(args[1], args[2])
		if err != nil {
			return err
		}
		fmt.Printf("从 %s 导入 %d 个文件到 %s\n", args[1], len(written), args[2])
		return nil
	case "list":
		names, err := loader.Profiles()
		if err != nil {
			return err
		}
		fmt.Printf("payload: %s, %s, %s\n", assets.BinaryName, assets.VrPatchName, assets.ExtractName)
		fmt.Printf("profiles: %d\n", len(names))
		return nil
	}
	return fmt.Errorf("未知子命令 %q", args[0])
}

const usageText = `ghostlock-cli — vivo iQOO Neo9 (PD2338) 无解锁 root，命令行版

用法:
  ghostlock doctor                    体检：设备、内核 profile、SELinux、KSU 管理器
  ghostlock run [选项]                一次完整提权
  ghostlock profile list              列出内置内核 profile
  ghostlock profile show <release>    解析并打印某个 profile 的全部字段
  ghostlock profile compile <conf>    .conf 编译成 native 需要的 profile.bin
  ghostlock assets unpack <dir>       把内置 payload 释放到目录（可替换）
  ghostlock assets import <apk>       从新版 GhostLock APK 刷新 payload
  ghostlock ko list|add|check|pick    管理 / 校验 / 交互挑选本地 ko
  ghostlock ko load <ko>              已有 root 时用 ksud insmod 装指定 ko
  ghostlock manager inspect <apk>     看 APK 内嵌了哪些 <kmi>_kernelsu.ko
  ghostlock manager install <apk>     安装 / 升级 KSU 管理器
  ghostlock version

run 选项:
  -s, --serial <serial>        指定设备
  --conf <file.conf>           用自定义 profile（默认按 uname -r 自动匹配）
  --temp-root                  只拿临时 root，不晚加载 KSU（GHOSTLOCK_KSU_ENFORCE=9）
  --safe-mode                  root 后自动禁用 /data/adb/modules 下全部模块
  --no-vrpatch                 跳过 vrpatch.ko
  --ko <file|name>             用自己下载的 ko 代替 vrpatch.ko
  --force-attack               KernelSU 已有 root 时也强跑
  --main-cpu / --consumer-cpu  覆盖主/消费线程 CPU
  --manager <pkg>              指定 KSU 管理器包名
  --kmi <kmi>                  指定 KMI（默认由 uname -r 推出）
  --assets <dir>               使用外部 payload 目录
`
