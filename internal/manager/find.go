package manager

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// SearchDirs returns where the tool looks for a manager APK when the user does
// not pass a path: next to the executable (so a single copied binary plus a
// dropped-in APK just works), the current directory, and the usual download
// folders.
func SearchDirs() []string {
	var dirs []string
	if exe, err := os.Executable(); err == nil {
		dirs = append(dirs, filepath.Dir(exe))
	}
	if cwd, err := os.Getwd(); err == nil {
		dirs = append(dirs, cwd)
	}
	if home, err := os.UserHomeDir(); err == nil {
		dirs = append(dirs,
			filepath.Join(home, "Downloads"),
			filepath.Join(home, "Download"),
			filepath.Join(home, "下载"),
		)
	}
	// de-dup, keep order
	seen := map[string]bool{}
	var out []string
	for _, d := range dirs {
		if d == "" || seen[d] {
			continue
		}
		seen[d] = true
		out = append(out, d)
	}
	return out
}

// FindAPKs returns every APK in SearchDirs that actually carries a
// <kmi>_kernelsu.ko table — i.e. a real KernelSU-family manager, whatever its
// package name happens to be. Sorted by file name, newest-looking last.
func FindAPKs() []string {
	var found []string
	seen := map[string]bool{}
	for _, d := range SearchDirs() {
		entries, err := os.ReadDir(d)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".apk") {
				continue
			}
			p := filepath.Join(d, e.Name())
			if abs, err := filepath.Abs(p); err == nil {
				p = abs
			}
			if seen[p] {
				continue
			}
			seen[p] = true
			info, err := InspectAPK(p)
			if err != nil || len(info.Embedded) == 0 {
				continue
			}
			found = append(found, p)
		}
	}
	sort.Strings(found)
	return found
}

// ResolveAPK turns an optional user path into one concrete APK. Without a path
// it picks the newest-looking manager APK from SearchDirs.
func ResolveAPK(explicit string) (string, []string, error) {
	if explicit != "" {
		if _, err := os.Stat(explicit); err != nil {
			return "", nil, fmt.Errorf("找不到 %s", explicit)
		}
		return explicit, nil, nil
	}
	found := FindAPKs()
	if len(found) == 0 {
		return "", nil, fmt.Errorf("这几个目录里都没有 KSU 管理器 APK：%s",
			strings.Join(SearchDirs(), " · "))
	}
	return found[len(found)-1], found, nil
}
