package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"ghostlock/internal/assets"
	"ghostlock/internal/ko"
	"ghostlock/internal/stage"
)

var nl = string([]byte{0x0a})

func koDir() string {
	if v := os.Getenv("GHOSTLOCK_KO"); v != "" {
		return v
	}
	return ko.DefaultDir()
}

func cmdKo(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("ko 需要子命令: list | add | check | load | pick")
	}
	dir := koDir()
	switch args[0] {
	case "list":
		mods, err := ko.Scan(dir)
		if err != nil {
			return err
		}
		if len(mods) == 0 {
			fmt.Printf("库存 %s 是空的。"+nl+"用 ghostlock ko add <下载目录或单个.ko> 导入。"+nl, dir)
			return nil
		}
		fmt.Printf("%-3s %-18s %-28s %-9s %s"+nl, "#", "KMI", "vermagic", "大小", "文件")
		for i, m := range mods {
			fmt.Printf("%-3d %-18s %-28s %-9s %s"+nl, i+1, dash(m.KMI), shortVermagic(m.Vermagic), humanSize(m.Size), m.File)
		}
		return nil
	case "add":
		if len(args) < 2 {
			return fmt.Errorf("用法: ghostlock ko add <dir|file.ko> [...]")
		}
		added, err := ko.Add(dir, args[1:])
		if err != nil {
			return err
		}
		fmt.Printf("导入 %d 颗 ko 到 %s"+nl, len(added), dir)
		for _, p := range added {
			fmt.Println("  " + p)
		}
		return nil
	case "check":
		return koCheck(args[1:], dir)
	case "load":
		return koLoad(args[1:], dir)
	case "pick":
		return koPick(args[1:], dir)
	}
	return fmt.Errorf("未知子命令 %q", args[0])
}

// koCheck validates modules against the connected device kernel.
func koCheck(args []string, dir string) error {
	fs := flag.NewFlagSet("ko check", flag.ExitOnError)
	c := addCommon(fs)
	fs.Parse(args)

	a, err := c.adb()
	if err != nil {
		return err
	}
	facts, err := stage.Probe(a)
	if err != nil {
		return err
	}
	fmt.Printf("设备内核: %s   (KMI %s)"+nl+nl, facts.KernelRelease, dash(facts.Kmi))

	targets := args
	if len(targets) == 0 {
		mods, err := ko.Scan(dir)
		if err != nil {
			return err
		}
		if len(mods) == 0 {
			return fmt.Errorf("库存 %s 是空的，先 ghostlock ko add", dir)
		}
		bad := 0
		for _, m := range mods {
			ok, why := m.Compatible(facts.KernelRelease)
			verdict := "可用"
			if !ok {
				verdict = "不可用"
				bad++
			}
			fmt.Printf("[%-6s] %-44s %s"+nl, verdict, m.File, why)
		}
		fmt.Printf(nl+"共 %d 颗，%d 颗可用。"+nl, len(mods), len(mods)-bad)
		return nil
	}
	for _, t := range targets {
		m, err := ko.Resolve(t, dir)
		if err != nil {
			return err
		}
		ok, why := m.Compatible(facts.KernelRelease)
		verdict := "可用"
		if !ok {
			verdict = "不可用"
		}
		fmt.Printf("[%-6s] %-44s %s"+nl, verdict, m.File, why)
	}
	return nil
}

// koLoad loads a module on an already rooted device (KSU active), through ksud.
func koLoad(args []string, dir string) error {
	fs := flag.NewFlagSet("ko load", flag.ExitOnError)
	c := addCommon(fs)
	remote := fs.String("remote", stage.RemoteDir, "remote sandbox dir")
	fs.Parse(args)

	sel := fs.Arg(0)
	if sel == "" {
		return fmt.Errorf("用法: ghostlock ko load <file|name>   (需要设备已经有 root)")
	}
	var (
		mod     *ko.Module
		embPath string
	)
	if sel == "vrpatch" || sel == "vrpatch.ko" || sel == "embedded" {
		data, err := c.loader().Read(assets.VrPatchName)
		if err != nil {
			return err
		}
		tmpf, err := os.CreateTemp("", "ghostlock-vrpatch-*.ko")
		if err != nil {
			return err
		}
		embPath = tmpf.Name()
		defer os.Remove(embPath)
		if _, err := tmpf.Write(data); err != nil {
			tmpf.Close()
			return err
		}
		tmpf.Close()
		mod, err = ko.Inspect(embPath)
		if err != nil {
			return err
		}
	} else {
		var err error
		mod, err = ko.Resolve(sel, dir)
		if err != nil {
			return err
		}
	}
	a, err := c.adb()
	if err != nil {
		return err
	}
	facts, err := stage.Probe(a)
	if err != nil {
		return err
	}
	if ok, why := mod.Compatible(facts.KernelRelease); !ok {
		return fmt.Errorf("%s: %s", mod.File, why)
	}
	if _, err := a.Shell("mkdir -p " + *remote); err != nil {
		return err
	}
	data, err := os.ReadFile(mod.Path)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp("", "ghostlock-ko-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	tmp.Close()
	dst := *remote + "/" + mod.File
	if embPath != "" {
		dst = *remote + "/" + assets.VrPatchName
	}
	if err := a.Push(tmp.Name(), dst); err != nil {
		return err
	}
	if _, err := a.Shell("chmod 644 " + dst); err != nil {
		return err
	}

	attempts := []string{
		"su -c 'ksud insmod " + dst + "'",
		"su -c '/data/adb/ksud insmod " + dst + "'",
		"su -c 'insmod " + dst + "'",
	}
	for _, cmd := range attempts {
		out, err := a.Shell(cmd + " 2>&1")
		out = strings.TrimSpace(out)
		if err != nil {
			fmt.Printf("  %s -> 失败 %s"+nl, cmd, out)
			continue
		}
		fmt.Printf("  %s -> ok%s"+nl, cmd, cond(out != "", ": "+out))
		if mods, _ := a.ShellTrim("grep -c kernelsu /proc/modules"); mods != "" && mods != "0" {
			fmt.Printf(nl+"内核里已经有 kernelsu（%s 条 /proc/modules 记录），管理器应该能识别。"+nl, mods)
			return nil
		}
		fmt.Println("  命令成功但 /proc/modules 里没有 kernelsu，继续尝试下一种方式")
	}
	return fmt.Errorf("三种加载方式都没成功；先确认设备已 root（adb shell su -c id）")
}

// koPick is the interactive selector: it numbers the inventory (compatible
// modules first) and prints the chosen path for use with run --ko.
func koPick(args []string, dir string) error {
	fs := flag.NewFlagSet("ko pick", flag.ExitOnError)
	c := addCommon(fs)
	fs.Parse(args)

	mods, err := ko.Scan(dir)
	if err != nil {
		return err
	}
	if len(mods) == 0 {
		return fmt.Errorf("库存 %s 是空的，先 ghostlock ko add <下载目录>", dir)
	}
	kernelRelease := ""
	if a, err := c.adb(); err == nil {
		if facts, err := stage.Probe(a); err == nil {
			kernelRelease = facts.KernelRelease
		}
	}
	fmt.Printf("库存: %s"+nl, dir)
	if kernelRelease != "" {
		fmt.Printf("设备内核: %s"+nl, kernelRelease)
	}
	fmt.Println()
	for i, m := range mods {
		mark := "  "
		if kernelRelease != "" {
			if ok, _ := m.Compatible(kernelRelease); ok {
				mark = " *"
			}
		}
		fmt.Printf("%s%2d) %-44s %-18s %s"+nl, mark, i+1, m.File, dash(m.KMI), shortVermagic(m.Vermagic))
	}
	fmt.Printf(nl+"(* = 与设备内核匹配)  选择编号 [1-%d]，直接回车取消: ", len(mods))
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString(byte(0x0a))
	if err != nil && line == "" {
		return err
	}
	line = strings.TrimSpace(line)
	if line == "" {
		fmt.Println("已取消")
		return nil
	}
	n, err := strconv.Atoi(line)
	if err != nil || n < 1 || n > len(mods) {
		return fmt.Errorf("无效编号 %q", line)
	}
	chosen := mods[n-1]
	fmt.Printf(nl+"已选择: %s"+nl, chosen.Path)
	if kernelRelease != "" {
		if ok, why := chosen.Compatible(kernelRelease); ok {
			fmt.Println("校验: " + why)
		} else {
			fmt.Println("! 校验失败: " + why)
		}
	}
	fmt.Printf("用法: ghostlock run --ko %s"+nl, chosen.Path)
	return nil
}

func shortVermagic(v string) string {
	if v == "" {
		return "-"
	}
	tok := strings.Fields(v)
	if len(tok) == 0 {
		return "-"
	}
	if len(tok[0]) > 28 {
		return tok[0][:28]
	}
	return tok[0]
}

// humanSize renders a byte count for list/report output.
func humanSize(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}

func cond(b bool, s string) string {
	if b {
		return s
	}
	return ""
}
