// Package ko inspects and manages kernel modules (kernelsu lkm / vrpatch) that
// are loaded into the device kernel.
package ko

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var nl = string([]byte{0x0a})

// Module is one inspected .ko file.
type Module struct {
	Path        string
	File        string
	Size        int64
	Name        string
	Vermagic    string
	Description string
	License     string
	KMI         string // android13-5.15 style, derived from file name
	KernelMM    string // 5.15, derived from vermagic
}

var kmiPattern = regexp.MustCompile("android([0-9]+)-([0-9]+[.][0-9]+)")

// Inspect reads a .ko header and its .modinfo strings.
func Inspect(path string) (*Module, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) < 64 || data[0] != 0x7f || data[1] != 'E' || data[2] != 'L' || data[3] != 'F' {
		return nil, fmt.Errorf("%s 不是 ELF 文件（.ko 必须是 ELF relocatable）", path)
	}
	m := &Module{
		Path:        path,
		File:        filepath.Base(path),
		Size:        int64(len(data)),
		Name:        modinfoField(data, "name"),
		Vermagic:    modinfoField(data, "vermagic"),
		Description: modinfoField(data, "description"),
		License:     modinfoField(data, "license"),
	}
	m.KMI = KMIFromName(m.File)
	m.KernelMM = kernelMM(m.Vermagic)
	return m, nil
}

// KMIFromName derives androidX-Y.Z from a module file name, which is how the
// upstream KernelSU/SukiSU release assets are named
// (lkm-aarch64-android13-5.15_kernelsu.ko).
func KMIFromName(name string) string {
	if sub := kmiPattern.FindStringSubmatch(name); len(sub) == 3 {
		return "android" + sub[1] + "-" + sub[2]
	}
	return ""
}

// kernelMM returns the "major.minor" of a vermagic or uname -r string.
func kernelMM(s string) string {
	if s == "" {
		return ""
	}
	first := s
	if i := strings.IndexAny(first, " -"); i > 0 {
		first = first[:i]
	}
	parts := strings.SplitN(first, ".", 3)
	if len(parts) < 2 {
		return ""
	}
	return parts[0] + "." + parts[1]
}

func modinfoField(data []byte, field string) string {
	needle := []byte(field + "=")
	for i := 0; i+len(needle) <= len(data); i++ {
		if data[i] != needle[0] {
			continue
		}
		if i > 0 && data[i-1] != 0 {
			continue
		}
		if !bytes.HasPrefix(data[i:], needle) {
			continue
		}
		end := i + len(needle)
		for end < len(data) && data[end] != 0 {
			end++
		}
		return string(data[i+len(needle) : end])
	}
	return ""
}

// Compatible reports whether the module can be loaded into a kernel that
// reports the given uname -r. A mismatched vermagic is the single most common
// reason insmod fails, so this is checked before anything reaches the device.
func (m *Module) Compatible(kernelRelease string) (bool, string) {
	want := kernelMM(kernelRelease)
	if m.Vermagic == "" {
		return true, "无 vermagic 字段，跳过校验"
	}
	if want == "" {
		return true, "无法解析设备内核版本，跳过校验"
	}
	if m.KernelMM != want {
		return false, fmt.Sprintf("vermagic 是 %s，设备内核是 %s — 这颗 ko 装不进去", m.KernelMM, want)
	}
	devKMI := KMIOfKernel(kernelRelease)
	if m.KMI != "" && devKMI != "" && m.KMI != devKMI {
		return false, fmt.Sprintf("ko 面向 %s，设备是 %s", m.KMI, devKMI)
	}
	if strings.Contains(m.Vermagic, kernelRelease) {
		return true, "vermagic 与设备完全一致，insmod 可用"
	}
	return true, fmt.Sprintf("vermagic 是 %s，设备是 %s —— 只能靠 late-load 手动重定位加载；"+
		"走 insmod 会被 GKI 的 vermagic 检查拒绝", shortVermagicOf(m.Vermagic), kernelRelease)
}

// KMIOfKernel maps uname -r to the KMI token used by KernelSU.
func KMIOfKernel(release string) string {
	switch kernelMM(release) {
	case "5.15":
		return "android13-5.15"
	case "6.1":
		return "android14-6.1"
	case "6.6":
		return "android15-6.6"
	case "6.12":
		return "android16-6.12"
	}
	return ""
}

// Scan returns every .ko below dir, sorted by KMI then name.
func Scan(dir string) ([]Module, error) {
	var out []Module
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() || !strings.HasSuffix(info.Name(), ".ko") {
			return nil
		}
		m, err := Inspect(path)
		if err != nil {
			return nil
		}
		out = append(out, *m)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].KMI != out[j].KMI {
			return out[i].KMI < out[j].KMI
		}
		return out[i].File < out[j].File
	})
	return out, nil
}

// DefaultDir is the local ko inventory.
func DefaultDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".ghostlock-ko"
	}
	return filepath.Join(home, ".local", "share", "ghostlock", "ko")
}

// Add copies ko files (or every .ko inside a directory) into the inventory.
func Add(dst string, paths []string) ([]string, error) {
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return nil, err
	}
	var added []string
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			return added, err
		}
		if info.IsDir() {
			mods, err := Scan(p)
			if err != nil {
				return added, err
			}
			for _, m := range mods {
				out := filepath.Join(dst, m.File)
				if err := copyFile(m.Path, out); err != nil {
					return added, err
				}
				added = append(added, out)
			}
			continue
		}
		if !strings.HasSuffix(p, ".ko") {
			continue
		}
		out := filepath.Join(dst, filepath.Base(p))
		if err := copyFile(p, out); err != nil {
			return added, err
		}
		added = append(added, out)
	}
	return added, nil
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0o644)
}

// Resolve turns a user supplied selector (absolute path, file name, or unique
// substring) into a concrete module, searching the working directory first and
// then the inventory.
func Resolve(selector, inventory string) (*Module, error) {
	if selector == "" {
		return nil, fmt.Errorf("empty ko selector")
	}
	if _, err := os.Stat(selector); err == nil {
		return Inspect(selector)
	}
	if inventory != "" {
		if p := filepath.Join(inventory, selector); fileExists(p) {
			return Inspect(p)
		}
		mods, err := Scan(inventory)
		if err == nil {
			var hits []Module
			for _, m := range mods {
				if strings.Contains(m.File, selector) {
					hits = append(hits, m)
				}
			}
			switch len(hits) {
			case 1:
				return &hits[0], nil
			case 0:
			default:
				var names []string
				for _, h := range hits {
					names = append(names, h.File)
				}
				return nil, fmt.Errorf("%q 匹配到多颗 ko: %s", selector, strings.Join(names, ", "))
			}
		}
	}
	return nil, fmt.Errorf("找不到 ko: %s", selector)
}

func fileExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}

// Best picks the module that matches the device kernel best: exact vermagic
// first, then same KMI, then file name containing the kernel release.
func Best(mods []Module, kernelRelease string) (int, bool) {
	bestIdx := -1
	bestScore := -1
	for i, m := range mods {
		score := 0
		if ok, _ := m.Compatible(kernelRelease); !ok {
			continue
		}
		if strings.Contains(m.Vermagic, kernelRelease) {
			score += 4
		}
		if m.KMI != "" && m.KMI == KMIOfKernel(kernelRelease) {
			score += 2
		}
		if score > bestScore {
			bestScore = score
			bestIdx = i
		}
	}
	return bestIdx, bestIdx >= 0
}

// shortVermagicOf returns the kernel-version token of a vermagic string.
func shortVermagicOf(v string) string {
	f := strings.Fields(v)
	if len(f) == 0 {
		return v
	}
	return f[0]
}
