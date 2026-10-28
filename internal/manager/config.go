package manager

import (
	"os"
	"path/filepath"
	"strings"
)

// ConfigDir is where the tool remembers which manager package owns root.
func ConfigDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".ghostlock"
	}
	return filepath.Join(home, ".local", "share", "ghostlock")
}

func configPath() string { return filepath.Join(ConfigDir(), "manager") }

// ConfiguredManager returns the package name remembered from the last
// manager install. Official SukiSU release builds use a randomised package
// name that changes per release, so this has to be discovered from the APK and
// remembered, not hardcoded.
func ConfiguredManager() string {
	b, err := os.ReadFile(configPath())
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// SetConfiguredManager remembers pkg as the manager that owns root.
func SetConfiguredManager(pkg string) error {
	if err := os.MkdirAll(ConfigDir(), 0o755); err != nil {
		return err
	}
	return os.WriteFile(configPath(), []byte(strings.TrimSpace(pkg)+string([]byte{0x0a})), 0o644)
}
