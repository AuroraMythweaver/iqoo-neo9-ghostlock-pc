package main

import (
	"fmt"
	"strings"

	"ghostlock/internal/device"
	"ghostlock/internal/manager"
	"ghostlock/internal/stage"
)

// managerVersion reads one package's versionName; empty means not installed.
// Single-package dumpsys is used because whole-system dumpsys puts versionName
// hundreds of lines away from the Package header, so pairing them in one pass is
// unreliable.
func managerVersion(a *device.ADB, pkg string) string {
	out, err := a.ShellTrim("dumpsys package " + pkg + " 2>/dev/null | grep -m1 versionName")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(out), "versionName="))
}

func cmdManagerList(a *device.ADB) error {
	cfg := manager.ConfiguredManager()
	fmt.Printf("当前配置 : %s"+nl, dash(cfg))
	fmt.Printf("已安装   :" + nl)
	seen := map[string]bool{}
	any := false
	check := func(pkg string) {
		if pkg == "" || seen[pkg] {
			return
		}
		seen[pkg] = true
		v := managerVersion(a, pkg)
		if v == "" {
			return
		}
		any = true
		mark := "  "
		if pkg == cfg {
			mark = "* "
		}
		fmt.Printf("  %s%-30s %s"+nl, mark, pkg, v)
	}
	check(cfg)
	for _, p := range stage.ManagerPackages {
		check(p)
	}
	if !any {
		fmt.Println("  （没有已安装的 KSU 管理器）")
		return nil
	}
	fmt.Printf(nl + "  * = 当前配置（.gl_ksu_pkg 用它）" + nl)
	fmt.Printf("  多个共存时用 ghostlock manager remove <旧的> 清掉" + nl)
	return nil
}

func cmdManagerRemove(a *device.ADB, pkg string) error {
	if pkg == "" {
		return fmt.Errorf("用法: ghostlock manager remove <pkg>")
	}
	if pkg == manager.ConfiguredManager() {
		fmt.Println("  这是当前配置的管理器；先 manager install 别的再删")
		return nil
	}
	if _, err := a.Shell("pm uninstall --user 0 " + pkg + " 2>&1"); err != nil {
		return err
	}
	fmt.Printf("  已卸载 %s"+nl, pkg)
	return nil
}
