package device

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// adbConfigPath remembers an adb path the user picked once.
func adbConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".local", "share", "ghostlock", "adb")
}

// ConfiguredADB returns the remembered adb path, if any.
func ConfiguredADB() string {
	p := adbConfigPath()
	if p == "" {
		return ""
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return trimSpace(string(b))
}

// SaveADBPath remembers p for later runs (Windows users often have adb in a
// folder that is not on PATH).
func SaveADBPath(p string) error {
	cfg := adbConfigPath()
	if cfg == "" {
		return fmt.Errorf("无法确定配置目录")
	}
	if err := os.MkdirAll(filepath.Dir(cfg), 0o755); err != nil {
		return err
	}
	return os.WriteFile(cfg, []byte(p+string([]byte{0x0a})), 0o644)
}

// ResolveADB finds the adb client. Order: explicit flag, GHOSTLOCK_ADB,
// remembered path, then PATH. Directories are accepted so a Windows user can
// point at the platform-tools folder instead of the exe.
func ResolveADB(explicit string) (string, error) {
	// An explicitly requested path must be valid or fail loudly: silently
	// falling back to PATH would hide a typo.
	if explicit != "" {
		if p := normalizeADB(explicit); p != "" {
			return p, nil
		}
		return "", fmt.Errorf("--adb 指定的路径无效: %s（要 adb 可执行文件或 platform-tools 目录）", explicit)
	}
	var tried []string
	for _, c := range []string{os.Getenv("GHOSTLOCK_ADB"), ConfiguredADB()} {
		if c == "" {
			continue
		}
		tried = append(tried, c)
		if p := normalizeADB(c); p != "" {
			return p, nil
		}
	}
	if p, err := exec.LookPath("adb"); err == nil {
		return p, nil
	}
	msg := "没找到 adb。装 Android platform-tools 并把它加入 PATH，或用 --adb <路径> 指定"
	if len(tried) > 0 {
		msg += fmt.Sprintf("（试过：%v）", tried)
	}
	return "", fmt.Errorf("%s", msg)
}

// normalizeADB accepts an exe path or a directory containing adb(.exe).
func normalizeADB(p string) string {
	info, err := os.Stat(p)
	if err != nil {
		return ""
	}
	if info.IsDir() {
		for _, name := range []string{"adb", "adb.exe", "platform-tools/adb", "platform-tools/adb.exe"} {
			cand := filepath.Join(p, name)
			if st, err := os.Stat(cand); err == nil && !st.IsDir() {
				return cand
			}
		}
		return ""
	}
	return p
}

func trimSpace(s string) string {
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == 0x0a || s[start] == 0x0d || s[start] == 0x09) {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == 0x0a || s[end-1] == 0x0d || s[end-1] == 0x09) {
		end--
	}
	return s[start:end]
}
