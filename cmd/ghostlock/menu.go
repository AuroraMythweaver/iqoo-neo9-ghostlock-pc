package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"ghostlock/internal/assets"
	"ghostlock/internal/device"
	"ghostlock/internal/ko"
	"ghostlock/internal/manager"
	"ghostlock/internal/run"
	"ghostlock/internal/stage"
)

var stdin = bufio.NewReader(os.Stdin)

// stdinEOF flips when input runs out, so a piped script does not loop the menu
// forever (Enter and EOF must not be treated the same).
var stdinEOF bool

// ask prints a prompt and returns the trimmed answer.
func ask(prompt string) string {
	fmt.Print(prompt)
	line, err := stdin.ReadString(byte(0x0a))
	if err != nil && line == "" {
		stdinEOF = true
		return ""
	}
	return strings.TrimSpace(line)
}

func isTTY() bool {
	info, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

// cmdMenu is what ./ghostlock does with no arguments: a numbered menu, no flags
// to remember.
func cmdMenu() error {
	for {
		if stdinEOF {
			return nil
		}
		// adb 找不到时不要直接退出：双击运行的窗口会瞬间关掉，用户什么都看不到。
		a, adbErr := device.NewWith("", adbPath)
		var devices []string
		online := false
		status := "未连接（插线 + 开 USB 调试 + 授权这台电脑）"
		if adbErr != nil {
			status = "没找到 adb —— 按 6 指定 platform-tools 路径"
		} else if ds, derr := a.Devices(); derr == nil {
			devices = ds
			online = len(ds) > 0
		}
		if online {
			a.Serial = devices[0]
			status = devices[0]
			if facts, err := stage.Probe(a); err == nil {
				status = facts.Model + " · " + facts.KernelRelease
				if facts.KsudPath != "" {
					status += " · 管理器已装"
				}
			}
		}

		fmt.Print(nl)
		fmt.Println("  ╔══════════════════════════════════════════════╗")
		fmt.Println("  ║   ghostlock-cli · iQOO Neo9 (PD2338) root    ║")
		fmt.Println("  ╚══════════════════════════════════════════════╝")
		fmt.Printf("     设备: %s"+nl, status)
		fmt.Print(nl)
		fmt.Println("     1) 一键 root（循环重试，脱手）      <- 推荐")
		fmt.Println("     2) 打一次（调试，失败会重启）")
		fmt.Println("     3) 体检（只读）")
		fmt.Println("     4) 选 ko / 装管理器")
		fmt.Println("     5) 清理设备残留")
		fmt.Println("     6) 指定 adb 路径（Windows 常见）")
		fmt.Println("     0) 退出")
		fmt.Print(nl)

		switch ask("     选择> ") {
		case "1", "":
			if err := menuRoot(a, online); err != nil {
				fmt.Println(nl + "     错误: " + err.Error())
			}
		case "2":
			if err := menuOnce(a, online); err != nil {
				fmt.Println(nl + "     错误: " + err.Error())
			}
		case "3":
			if err := cmdDoctor(nil); err != nil {
				fmt.Println(nl + "     错误: " + err.Error())
			}
		case "4":
			if err := menuKo(a); err != nil {
				fmt.Println(nl + "     错误: " + err.Error())
			}
		case "6":
			if err := menuSetADB(); err != nil {
				fmt.Println(nl + "     错误: " + err.Error())
			}
		case "5":
			if err := menuClean(a); err != nil {
				fmt.Println(nl + "     错误: " + err.Error())
			}
		case "0", "q", "Q":
			return nil
		default:
			fmt.Println("     无效选择")
		}
		fmt.Print(nl + "   按回车返回菜单…")
		stdin.ReadString(byte(0x0a))
	}
}

func defaultOptions(a *device.ADB) *run.Options {
	return &run.Options{
		ADB:    a,
		Loader: assets.New(os.Getenv("GHOSTLOCK_ASSETS")),
		Remote: stage.RemoteDir,
		KoPath: os.Getenv("GHOSTLOCK_KO_PICK"),
		Out:    os.Stdout,
	}
}

func menuRoot(a *device.ADB, online bool) error {
	fmt.Print(nl)
	if !online {
		return fmt.Errorf("没有连接的设备")
	}
	o := defaultOptions(a)

	rounds := 10
	if v := ask("     最多几轮？[默认 10] > "); v != "" {
		fmt.Sscanf(v, "%d", &rounds)
	}
	window := 90
	if v := ask("     uptime 窗口（秒）[默认 90] > "); v != "" {
		fmt.Sscanf(v, "%d", &window)
	}
	minUp := 30
	if v := ask("     最早发射的 uptime（秒）[默认 30] > "); v != "" {
		fmt.Sscanf(v, "%d", &minUp)
	}
	reboot := true
	if v := ask("     先主动重启抢窗口？[Y/n] > "); v == "n" || v == "N" {
		reboot = false
	}
	if o.KoPath != "" {
		fmt.Printf("     使用 ko: %s"+nl, o.KoPath)
	} else {
		fmt.Println("     使用管理器自带的 ko（菜单 4 可指定自己的）")
	}

	_, err := run.Loop(&run.LoopOptions{
		Base:        o,
		Rounds:      rounds,
		PerBoot:     6,
		Window:      window,
		Timeout:     180,
		CycleWait:   600,
		RebootFirst: reboot,
		AutoReboot:  true,
		Out:         os.Stdout,
	})
	return err
}

func menuOnce(a *device.ADB, online bool) error {
	if !online {
		return fmt.Errorf("没有连接的设备")
	}
	fmt.Println(nl + "     单次发射，失败大概率触发重启")
	if v := ask("     确定？[y/N] > "); v != "y" && v != "Y" {
		return nil
	}
	_, err := run.Execute(defaultOptions(a))
	return err
}

func menuKo(a *device.ADB) error {
	for {
		fmt.Print(nl)
		fmt.Println("     1) 列出本地 ko（当前目录 + 库存）")
		fmt.Println("     2) 从目录导入 ko 到库存")
		fmt.Println("     3) 选定一颗 ko（本次会话使用）")
		fmt.Println("     4) 安装 / 升级 KSU 管理器 APK")
		fmt.Println("     0) 返回")
		switch ask("     选择> ") {
		case "1":
			cwd, _ := os.Getwd()
			mods, _ := ko.Scan(cwd)
			inv, _ := ko.Scan(koDir())
			if len(mods) > 0 {
				fmt.Printf(nl+"     当前目录 %s:"+nl, cwd)
				for i, m := range mods {
					fmt.Printf("      %2d) %-46s %-16s %s"+nl, i+1, m.File, dash(m.KMI), shortVermagic(m.Vermagic))
				}
			}
			if len(inv) > 0 {
				fmt.Printf(nl+"     库存 %s:"+nl, koDir())
				for i, m := range inv {
					fmt.Printf("      %2d) %-46s %-16s %s"+nl, i+1, m.File, dash(m.KMI), shortVermagic(m.Vermagic))
				}
			}
			if len(mods) == 0 && len(inv) == 0 {
				fmt.Println(nl + "     没找到 .ko：把下载的 ko 放进当前目录，或选 2 导入")
			}
		case "2":
			dir := ask("     ko 所在目录 [默认 当前目录] > ")
			if dir == "" {
				dir, _ = os.Getwd()
			}
			added, err := ko.Add(koDir(), []string{dir})
			if err != nil {
				return err
			}
			fmt.Printf("     导入 %d 颗到 %s"+nl, len(added), koDir())
		case "3":
			mods, _ := ko.Scan(koDir())
			if len(mods) == 0 {
				fmt.Println("     库存是空的，先选 2 导入")
				continue
			}
			kernel := ""
			if a != nil {
				if facts, err := stage.Probe(a); err == nil {
					kernel = facts.KernelRelease
				}
			}
			for i, m := range mods {
				mark := "  "
				if kernel != "" {
					if ok, _ := m.Compatible(kernel); ok {
						mark = " *"
					}
				}
				fmt.Printf("%s %2d) %-46s %s"+nl, mark, i+1, m.File, dash(m.KMI))
			}
			n := ask("     选编号（回车取消）> ")
			if n == "" {
				continue
			}
			var idx int
			if _, err := fmt.Sscanf(n, "%d", &idx); err != nil || idx < 1 || idx > len(mods) {
				fmt.Println("     编号无效")
				continue
			}
			chosen := mods[idx-1]
			if kernel != "" {
				if ok, why := chosen.Compatible(kernel); !ok {
					fmt.Println("     ! " + why)
					continue
				}
			}
			os.Setenv("GHOSTLOCK_KO_PICK", chosen.Path)
			fmt.Printf("     已选定: %s"+nl, chosen.File)
			fmt.Println("     下次「一键 root」会用它：wrapper 先 insmod 它，再跑正常 late-load")
		case "4":
			hint := "     APK 路径（回车 = 自动在 同级目录/当前目录/下载 里找）> "
			apkInput := strings.Trim(ask(hint), string([]byte{0x22, 0x27}))
			apk, all, rerr := manager.ResolveAPK(apkInput)
			if rerr != nil {
				fmt.Println("     " + rerr.Error())
				continue
			}
			if len(all) > 1 {
				fmt.Printf("     找到 %d 个，用最新的：%s"+nl, len(all), apk)
			}
			summary, err := inspectAPK(apk)
			if err != nil {
				return err
			}
			fmt.Printf("     内嵌 ko: %s"+nl, summary)
			if a == nil {
				fmt.Println("     没有设备，跳过安装")
				continue
			}
			if _, err := a.Install(apk); err != nil {
				return err
			}
			fmt.Println("     安装完成")
			if facts, err := stage.Probe(a); err == nil {
				fmt.Printf("     管理器: %s   ksud: %s"+nl, dash(facts.ManagerPkg), dash(facts.KsudPath))
			}
		case "0", "":
			return nil
		}
	}
}

func menuClean(a *device.ADB) error {
	if a == nil {
		return fmt.Errorf("没有连接的设备")
	}
	fmt.Printf(nl+"     将删除 %s 下的 payload 与日志（不影响已获得的 root）"+nl, stage.RemoteDir)
	if v := ask("     确定？[y/N] > "); v != "y" && v != "Y" {
		return nil
	}
	gone, err := stage.Clean(a, stage.CleanOptions{Remote: stage.RemoteDir})
	if err != nil {
		return err
	}
	fmt.Printf("     已清理 %d 处：%s"+nl, len(gone), strings.Join(gone, ", "))
	return nil
}

// menuSetADB lets a Windows user point at platform-tools without touching PATH.
func menuSetADB() error {
	fmt.Println(nl + "     给 adb.exe 的完整路径，或 platform-tools 目录，例如")
	fmt.Println("     C:\\platform-tools  （目录也行，会在里面找 adb.exe）")
	p := strings.Trim(ask("     adb 路径 > "), string([]byte{0x22, 0x27}))
	if p == "" {
		return nil
	}
	got, err := device.ResolveADB(p)
	if err != nil {
		return err
	}
	if err := device.SaveADBPath(p); err != nil {
		return err
	}
	fmt.Printf("     已记住: %s"+nl, got)
	fmt.Println("     下次运行直接用它")
	return nil
}
