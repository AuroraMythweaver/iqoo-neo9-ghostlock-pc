// Package manager inspects and installs the KernelSU-family manager app that
// owns root after a successful run.
package manager

import (
	"archive/zip"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strings"
)

// APKInfo is what can be learned from a manager APK on the host.
type APKInfo struct {
	Path        string
	File        string
	ABIs        []string
	Package     string // android:package, read from the binary manifest
	KsudEntry   string // zip entry holding the ksud binary
	KsudSize    int64
	Embedded    []string // KMI tokens of <kmi>_kernelsu.ko bundled in ksud
	IsGhostLock bool
}

var kmiAssetPattern = regexp.MustCompile("android[0-9]+-[0-9]+[.][0-9]+_kernelsu[.]ko")

// InspectAPK reads a manager APK without a device.
//
// Why this matters: ksud's late-load takes no module path. It builds the asset
// name "<kmi>_kernelsu.ko" and reads it from the modules embedded in the ksud
// binary itself (rust_embed). So the APK decides which kernel module gets
// loaded. Newer SukiSU builds ship ksud under a randomised name
// (libscibhqvpso.so instead of libksud.so), which is exactly why a hardcoded
// libksud.so lookup breaks after an upstream update. Here the real ksud is
// located by content: the aarch64 PIE carrying the <kmi>_kernelsu.ko table.
func InspectAPK(path string) (*APKInfo, error) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil, fmt.Errorf("打开 APK 失败: %w", err)
	}
	defer zr.Close()

	info := &APKInfo{Path: path, File: filepath.Base(path)}
	if pkg, perr := APKPackage(path); perr == nil {
		info.Package = pkg
	}
	seenABI := map[string]bool{}
	bestName := ""
	var bestSize int64
	var bestKmis []string

	for _, f := range zr.File {
		parts := strings.Split(f.Name, "/")
		if len(parts) >= 3 && parts[0] == "lib" && !seenABI[parts[1]] {
			seenABI[parts[1]] = true
			info.ABIs = append(info.ABIs, parts[1])
		}
		if f.Name == "assets/modules/vrpatch.ko" {
			info.IsGhostLock = true
		}
		if !strings.HasPrefix(f.Name, "lib/arm64-v8a/") || !strings.HasSuffix(f.Name, ".so") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		data, rerr := io.ReadAll(io.LimitReader(rc, 64<<20))
		rc.Close()
		if rerr != nil || len(data) < 4 || data[0] != 0x7f || data[1] != 'E' || data[2] != 'L' || data[3] != 'F' {
			continue
		}
		kmis := kmiAssets(data)
		if len(kmis) == 0 {
			continue
		}
		if int64(len(data)) > bestSize {
			bestName = f.Name
			bestSize = int64(len(data))
			bestKmis = kmis
		}
	}
	info.KsudEntry = bestName
	info.KsudSize = bestSize
	info.Embedded = bestKmis
	return info, nil
}

// kmiAssets finds every <kmi>_kernelsu.ko name embedded in a ksud binary.
func kmiAssets(data []byte) []string {
	matches := kmiAssetPattern.FindAllString(string(data), -1)
	seen := map[string]bool{}
	var out []string
	for _, m := range matches {
		kmi := strings.TrimSuffix(m, "_kernelsu.ko")
		if !seen[kmi] {
			seen[kmi] = true
			out = append(out, kmi)
		}
	}
	return out
}

// ExtractKsud writes the ksud binary found inside the APK to dest.
func ExtractKsud(apkPath, dest string) (string, error) {
	info, err := InspectAPK(apkPath)
	if err != nil {
		return "", err
	}
	if info.KsudEntry == "" {
		return "", fmt.Errorf("%s 里没找到带 <kmi>_kernelsu.ko 表的 ksud", info.File)
	}
	zr, err := zip.OpenReader(apkPath)
	if err != nil {
		return "", err
	}
	defer zr.Close()
	for _, f := range zr.File {
		if f.Name != info.KsudEntry {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return "", err
		}
		defer rc.Close()
		out, err := createFile(dest)
		if err != nil {
			return "", err
		}
		defer out.Close()
		if _, err := io.Copy(out, rc); err != nil {
			return "", err
		}
		return dest, nil
	}
	return "", fmt.Errorf("解压 %s 失败", info.KsudEntry)
}
