package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"ghostlock/internal/manager"
)

func cmdManager(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("manager 需要子命令: inspect | install")
	}
	switch args[0] {
	case "inspect":
		apk0, all0, aerr := manager.ResolveAPK(fs0Arg(args))
		if aerr != nil {
			return aerr
		}
		if len(all0) > 1 {
			fmt.Printf("找到 %d 个管理器 APK，看最新的：%s"+nl, len(all0), apk0)
		}
		info, err := manager.InspectAPK(apk0)
		if err != nil {
			return err
		}
		fi, _ := os.Stat(apk0)
		fmt.Printf("APK        : %s"+nl, info.File)
		if fi != nil {
			fmt.Printf("大小       : %s"+nl, humanSize(fi.Size()))
		}
		fmt.Printf("ABI        : %s"+nl, dash(strings.Join(info.ABIs, ", ")))
		if info.IsGhostLock {
			fmt.Printf("识别为     : GhostLock 本体" + nl)
		}
		if info.KsudEntry != "" {
			fmt.Printf("ksud       : %s (%s)"+nl, info.KsudEntry, humanSize(info.KsudSize))
			fmt.Printf("内嵌 ko    : %s"+nl, strings.Join(info.Embedded, ", "))
			fmt.Print(nl + "说明: ksud late-load 只从自身内嵌的 <kmi>_kernelsu.ko 取模块，" + nl +
				"      所以「换 ko」= 换这个 APK；新版把 ksud 改名了，这里按内容认。" + nl)
		} else if info.IsGhostLock {
			// nothing extra
		} else {
			fmt.Print(nl + "! 没找到带 <kmi>_kernelsu.ko 表的 ksud：这个包不支持 late-load。" + nl)
		}
		return nil

	case "list":
		fs := flag.NewFlagSet("manager list", flag.ExitOnError)
		c := addCommon(fs)
		fs.Parse(args[1:])
		a, err := c.adb()
		if err != nil {
			return err
		}
		return cmdManagerList(a)

	case "remove":
		fs := flag.NewFlagSet("manager remove", flag.ExitOnError)
		c := addCommon(fs)
		fs.Parse(args[1:])
		a, err := c.adb()
		if err != nil {
			return err
		}
		return cmdManagerRemove(a, fs.Arg(0))

	case "install":
		fs := flag.NewFlagSet("manager install", flag.ExitOnError)
		c := addCommon(fs)
		fs.Parse(args[1:])
		apk, all, err := manager.ResolveAPK(fs.Arg(0))
		if err != nil {
			return err
		}
		if len(all) > 1 {
			fmt.Printf("找到 %d 个管理器 APK，用最新的：%s"+nl, len(all), apk)
		}
		a, err := c.adb()
		if err != nil {
			return err
		}
		fmt.Printf("安装 %s ..."+nl, apk)
		return installManager(a, apk)
	}
	return fmt.Errorf("未知子命令 %q", args[0])
}

// fs0Arg returns args[1] when present (the optional APK path).
func fs0Arg(args []string) string {
	if len(args) > 1 {
		return args[1]
	}
	return ""
}
