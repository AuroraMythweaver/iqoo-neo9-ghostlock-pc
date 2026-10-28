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
	if _, err := a.Install(apk); err != nil {
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
