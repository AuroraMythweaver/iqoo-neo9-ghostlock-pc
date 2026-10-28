package ko

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func vrpatch(t *testing.T) *Module {
	t.Helper()
	m, err := Inspect(filepath.Join("..", "assets", "payload", "vrpatch.ko"))
	if err != nil {
		t.Fatalf("inspect vrpatch.ko: %v", err)
	}
	return m
}

// The module the APK ships is a real aarch64 ko; its .modinfo is the ground
// truth for the parsers below.
func TestInspectRealModule(t *testing.T) {
	m := vrpatch(t)
	if m.Name != "vrpatch" {
		t.Errorf("name = %q", m.Name)
	}
	if m.License != "GPL" {
		t.Errorf("license = %q", m.License)
	}
	if m.KernelMM != "5.15" {
		t.Errorf("kernel mm = %q (vermagic %q)", m.KernelMM, m.Vermagic)
	}
	if m.Description == "" {
		t.Error("description should be parsed")
	}
	if m.Size < 100000 {
		t.Errorf("size = %d", m.Size)
	}
}

func TestKMIFromName(t *testing.T) {
	cases := map[string]string{
		"lkm-aarch64-android13-5.15_kernelsu.ko":     "android13-5.15",
		"lkm-aarch64-android14-6.1_kernelsu.ko":      "android14-6.1",
		"lkm-aarch64-android16-6.12_kernelsu.ko":     "android16-6.12",
		"SukiSU_v4.2.1-r2_41068-release-spoofed.apk": "",
		"vrpatch.ko": "",
	}
	for in, want := range cases {
		if got := KMIFromName(in); got != want {
			t.Errorf("KMIFromName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCompatibleRejectsWrongKernel(t *testing.T) {
	m := vrpatch(t)
	if ok, why := m.Compatible("5.15.41-android13-8-g8dc4c75ab7d8-ab1673212412"); !ok {
		t.Fatalf("5.15 device should accept a 5.15 ko: %s", why)
	}
	if ok, _ := m.Compatible("6.1.138-android14-11-g44bda9e8f6e9-ab13792638"); ok {
		t.Fatal("6.1 device must reject a 5.15 ko")
	}
}

func TestScanAndBest(t *testing.T) {
	dir := t.TempDir()
	src, err := os.ReadFile(filepath.Join("..", "assets", "payload", "vrpatch.ko"))
	if err != nil {
		t.Fatal(err)
	}
	name := "lkm-aarch64-android13-5.15_kernelsu.ko"
	if err := os.WriteFile(filepath.Join(dir, name), src, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	mods, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(mods) != 1 {
		t.Fatalf("scanned %d modules, want 1", len(mods))
	}
	if mods[0].KMI != "android13-5.15" {
		t.Errorf("kmi = %q", mods[0].KMI)
	}
	idx, ok := Best(mods, "5.15.41-android13-8-g8dc4c75ab7d8-ab1673212412")
	if !ok || idx != 0 {
		t.Fatalf("Best did not select the 5.15 module")
	}
	if _, ok := Best(mods, "6.6.118-android15-8-g93e223c276e7-abogki500782043-4k"); ok {
		t.Fatal("Best must not select an incompatible module")
	}
}

func TestResolveBySubstring(t *testing.T) {
	dir := t.TempDir()
	src, _ := os.ReadFile(filepath.Join("..", "assets", "payload", "vrpatch.ko"))
	os.WriteFile(filepath.Join(dir, "lkm-aarch64-android13-5.15_kernelsu.ko"), src, 0o644)
	m, err := Resolve("5.15", dir)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if m.KMI != "android13-5.15" {
		t.Fatalf("resolved %q", m.File)
	}
	if _, err := Resolve("nope", dir); err == nil {
		t.Fatal("unknown selector must fail")
	}
}

// A file whose name claims one KMI but whose vermagic says another is the
// classic way a user breaks their own device: catch it before insmod.
func TestCompatibleRejectsKMIMismatch(t *testing.T) {
	dir := t.TempDir()
	src, err := os.ReadFile(filepath.Join("..", "assets", "payload", "vrpatch.ko"))
	if err != nil {
		t.Fatal(err)
	}
	misnamed := filepath.Join(dir, "lkm-aarch64-android14-6.1_kernelsu.ko")
	if err := os.WriteFile(misnamed, src, 0o644); err != nil {
		t.Fatal(err)
	}
	m, err := Inspect(misnamed)
	if err != nil {
		t.Fatal(err)
	}
	ok, why := m.Compatible("5.15.41-android13-8-g8dc4c75ab7d8-ab1673212412")
	if ok {
		t.Fatalf("must reject android14-6.1 named module on a 5.15 device (vermagic %q)", m.Vermagic)
	}
	if !strings.Contains(why, "android") {
		t.Errorf("reason should mention the KMI mismatch: %s", why)
	}
}
