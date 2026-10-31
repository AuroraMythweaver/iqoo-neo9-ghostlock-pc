// Package assets carries the payloads extracted from the GhostLock APK.
package assets

import (
	"archive/zip"
	"embed"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

//go:embed payload profiles
var embedded embed.FS

// Names of the files inside payload/.
const (
	// BinaryName is the default payload (26.1 build: handles the vivo vr guard
	// inside the exploit, no vrpatch.ko insmod).
	BinaryName = "ghostlock-261"
	// BinaryV12 is the older v1.2 build; it needs vrpatch.ko insmod before
	// late-load. Kept because the two builds fail in different ways, so
	// alternating them inside one boot window raises the hit rate.
	BinaryV12   = "ghostlock-v12"
	VrPatchName = "vrpatch.ko"
	ExtractName = "ghostlock-extract"
	// VerifiedBlobName is a profile blob taken from a release that was actually
	// observed to work on this kernel. It wins over a conf-generated blob
	// because the shipped .conf can drift from what was field-tested.
	VerifiedBlobName = "profile-verified.bin"
)

// Loader resolves payload files, preferring an on-disk override directory so a
// user can refresh them from a newer APK without rebuilding the tool.
type Loader struct {
	Dir string // optional override directory (payload/ + profiles/)
}

// New returns a loader. dir may be empty to use the embedded set only.
func New(dir string) *Loader { return &Loader{Dir: dir} }

// Read returns the content of payload/<name>.
func (l *Loader) Read(name string) ([]byte, error) {
	if l.Dir != "" {
		p := filepath.Join(l.Dir, "payload", name)
		if b, err := os.ReadFile(p); err == nil {
			return b, nil
		}
	}
	return embedded.ReadFile(path.Join("payload", name))
}

// Profiles lists the bundled kernel profiles (file names in profiles/).
func (l *Loader) Profiles() ([]string, error) {
	var names []string
	if l.Dir != "" {
		entries, err := os.ReadDir(filepath.Join(l.Dir, "profiles"))
		if err == nil {
			for _, e := range entries {
				if !e.IsDir() && strings.HasSuffix(e.Name(), ".conf") {
					names = append(names, e.Name())
				}
			}
		}
	}
	if len(names) == 0 {
		entries, err := embedded.ReadDir("profiles")
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".conf") {
				names = append(names, e.Name())
			}
		}
	}
	sort.Strings(names)
	return names, nil
}

// ReadProfile returns one bundled profile document.
func (l *Loader) ReadProfile(name string) ([]byte, error) {
	if l.Dir != "" {
		if b, err := os.ReadFile(filepath.Join(l.Dir, "profiles", name)); err == nil {
			return b, nil
		}
	}
	return embedded.ReadFile(path.Join("profiles", name))
}

// Unpack copies every bundled payload and profile into dir (created if needed)
// so it can be edited or replaced.
func (l *Loader) Unpack(dir string) (int, error) {
	n := 0
	for _, sub := range []string{"payload", "profiles"} {
		entries, err := embedded.ReadDir(sub)
		if err != nil {
			return n, err
		}
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
			return n, err
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			data, err := embedded.ReadFile(path.Join(sub, e.Name()))
			if err != nil {
				return n, err
			}
			if err := os.WriteFile(filepath.Join(dir, sub, e.Name()), data, 0o644); err != nil {
				return n, err
			}
			n++
		}
	}
	return n, nil
}

// ImportAPK rebuilds the payload directory from a GhostLock APK, so a newer
// release can be adopted with one command and no rebuild.
func ImportAPK(apkPath, dir string) ([]string, error) {
	zr, err := zip.OpenReader(apkPath)
	if err != nil {
		return nil, fmt.Errorf("open apk: %w", err)
	}
	defer zr.Close()

	wanted := map[string]string{
		"lib/arm64-v8a/libghostlock.so": BinaryName,
		"lib/arm64-v8a/libextract.so":   ExtractName,
		"assets/modules/vrpatch.ko":     VrPatchName,
	}
	if err := os.MkdirAll(filepath.Join(dir, "payload"), 0o755); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(dir, "profiles"), 0o755); err != nil {
		return nil, err
	}
	var written []string
	for _, f := range zr.File {
		dst, ok := wanted[f.Name]
		if !ok && !strings.HasPrefix(f.Name, "assets/kernel_profiles/") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return written, err
		}
		var buf []byte
		buf, err = io.ReadAll(rc)
		rc.Close()
		if err != nil {
			return written, err
		}
		var out string
		if ok {
			out = filepath.Join(dir, "payload", dst)
		} else {
			out = filepath.Join(dir, "profiles", path.Base(f.Name))
		}
		if err := os.WriteFile(out, buf, 0o644); err != nil {
			return written, err
		}
		written = append(written, out)
	}
	return written, nil
}
