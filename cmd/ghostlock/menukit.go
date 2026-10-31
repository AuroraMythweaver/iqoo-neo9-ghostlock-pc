package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"ghostlock/internal/device"
	"ghostlock/internal/manager"
	"ghostlock/internal/stage"
)

// inspectAPK summarises which kernelsu modules an APK carries, for the menu.
func inspectAPK(path string) (string, error) {
	info, err := manager.InspectAPK(path)
	if err != nil {
		return "", err
	}
	if len(info.Embedded) == 0 {
		return "（没找到 <kmi>_kernelsu.ko 表：这个包不带 late-load 模块）", nil
	}
	where := info.KsudEntry
	if filepath.Base(where) != "libksud.so" {
		where += "（改名了，按内容识别）"
	}
	return strings.Join(info.Embedded, ", ") + "   [" + where + "]", nil
}

// installManager installs a manager APK and, crucially, pulls the ksud binary
// out of it onto the phone. Newer SukiSU ships ksud under a randomised library
// name, so the root script's libksud.so lookup misses it; staging it at
// /data/local/tmp/ksud makes late-load use the ko embedded in *this* APK.
func installManager(a *device.ADB, apk string) error {
	info, err := manager.InspectAPK(apk)
	if err != nil {
		return err
	}
	fmt.Printf("     内嵌 ko: %s"+nl, strings.Join(info.Embedded, ", "))
	if info.KsudEntry != "" {
		fmt.Printf("     ksud   : %s (%s)"+nl, info.KsudEntry, humanSize(info.KsudSize))
	}

	if info.Package != "" {
		fmt.Printf("     包名   : %s"+nl, info.Package)
	}
	// 内核里已经挂着 kernelsu（late-load 生效中）时装新版管理器，App 会把
	// /data/adb/ksud 换成新版本，而内核里跑的是旧模块 —— 下一次 late-load 会卡死。
	if a.HasModule("kernelsu") {
		return fmt.Errorf("内核里已经有 kernelsu（late-load 还生效着）。\n" +
			"      现在装新版会覆盖 /data/adb/ksud，而内存里跑的还是旧模块，\n" +
			"      下一次 late-load 会与它冲突，设备会卡死然后重启。\n" +
			"      请先重启设备（adb reboot），再去装管理器。")
	}
	if _, err := a.Install(apk); err != nil {
		msg := err.Error()
		if strings.Contains(msg, "User rejected") || strings.Contains(msg, "INSTALL_FAILED_ABORTED") {
			return fmt.Errorf("安装被设备拒绝：请在手机的安装弹窗里点「允许」\n" +
				"       （vivo 每次 adb 安装都会弹确认，超时也会算拒绝）")
		}
		if strings.Contains(msg, "INSTALL_FAILED_VERIFICATION") {
			return fmt.Errorf("安装被系统校验拦下：先在「设置 → 应用 → 特殊权限 → 安装未知应用」里放开")
		}
		return err
	}
	fmt.Println("     安装完成")
	if info.Package != "" {
		if err := manager.SetConfiguredManager(info.Package); err == nil {
			fmt.Printf("     已记住管理器包名 %s（.gl_ksu_pkg 会用它）"+nl, info.Package)
		}
	}

	if info.KsudEntry == "" {
		return nil
	}
	tmp, err := os.CreateTemp("", "ksud-*")
	if err != nil {
		return err
	}
	ksudPath := tmp.Name()
	tmp.Close()
	defer os.Remove(ksudPath)

	if _, err := manager.ExtractKsud(apk, ksudPath); err != nil {
		return err
	}
	if err := a.Push(ksudPath, "/data/local/tmp/ksud"); err != nil {
		return err
	}
	if _, err := a.Shell("chmod 755 /data/local/tmp/ksud"); err != nil {
		return err
	}
	fmt.Println("     ksud 已就位: /data/local/tmp/ksud（late-load 会用这个包里的最新 ko）")

	if facts, err := stage.Probe(a); err == nil {
		fmt.Printf("     管理器: %s    kmi: %s"+nl, dash(facts.ManagerPkg), dash(facts.Kmi))
	}
	return nil
}
