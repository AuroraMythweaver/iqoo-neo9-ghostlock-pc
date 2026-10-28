package profile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const deviceConf = "5.15.41-android13-8-g8dc4c75ab7d8-ab1673212412.conf"

func testdata(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join("..", "assets", "profiles", name)
}

func resolve(t *testing.T, name string) *Profile {
	t.Helper()
	m, err := ParseFile(testdata(t, name))
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	p, err := Resolve(m, 0)
	if err != nil {
		t.Fatalf("resolve %s: %v", name, err)
	}
	return p
}

func sectionValue(p *Profile, section, key string) (int64, bool) {
	for _, s := range p.Sections {
		if s.Name != section {
			continue
		}
		for _, e := range s.Entries {
			if e.Key == key {
				return e.Val, true
			}
		}
	}
	return 0, false
}

// The iQOO Neo9 (PD2338) profile is the reference: every value below is read
// straight out of the .conf, so a resolver regression fails here first.
func TestDeviceProfileValues(t *testing.T) {
	p := resolve(t, deviceConf)
	if p.Release != "5.15.41-android13-8-g8dc4c75ab7d8-ab1673212412" {
		t.Fatalf("release = %q", p.Release)
	}
	if p.Route != "multicast_waiter" || p.RouteIdx != 3 {
		t.Fatalf("route = %q idx %d", p.Route, p.RouteIdx)
	}
	if p.FallbackIdx != 0 {
		t.Fatalf("fallback idx = %d, want 0 (fallback.to = none)", p.FallbackIdx)
	}

	cases := []struct {
		section, key string
		want         int64
	}{
		{"meta", "kernel_major", 5},
		{"meta", "recommend_shizuku", 1},
		{"meta", "fallback_route", 0},
		{"meta", "safe_mode", 0},
		{"task_struct", "cred", 1944},
		{"task_struct", "real_cred", 1936},
		{"task_struct", "pid", 1496},
		{"task_struct", "seccomp", 2144},
		{"task_struct", "comm", 1960},
		{"cred", "copy_size", 176},
		{"cred", "usage_value", 256},
		{"cred", "caps_count", 3},
		{"cred", "caps_value", 2199023255551},
		{"cred", "ref_count", 4},
		{"cred", "ref0_image", -274696359216},
		{"offset", "init_task", 48505728},
		{"offset", "init_cred", 48223880},
		{"offset", "selinux_enforcing", 49954256},
		{"offset", "slide_boot_id", 50044996},
		{"kernel", "kernel_phys_load", 2818572288},
		{"kernel", "kernel_phys_offset", 2147483648},
		{"kernel", "compact_waiter", 1},
		{"kernel", "kernelsnitch_collisions", 8},
		{"kernel", "mm_struct_sz", 1024},
		{"execution.recommended_cpus", "main", 3},
		{"execution.recommended_cpus", "consumer", 4},
		{"execution.heap", "prepare_timeout_ms", 240000},
		{"execution.race", "route_done_timeout_ms", 300000},
		{"execution.stages", "w1_attempts", 15},
		{"execution.stages", "w3_chain_rounds", 3},
		{"execution.handoff", "module_poll_attempts", 30},
		{"execution.consumer", "max_calls", 1},
		{"route.multicast_waiter", "waiter_off", 96},
		{"route.multicast_waiter", "buffer_size", 264},
		{"route.multicast_waiter", "task_offset", 48},
		{"route.multicast_waiter", "lock_offset", 56},
	}
	for _, c := range cases {
		got, ok := sectionValue(p, c.section, c.key)
		if !ok {
			t.Fatalf("%s.%s missing", c.section, c.key)
		}
		if got != c.want {
			t.Errorf("%s.%s = %d, want %d", c.section, c.key, got, c.want)
		}
	}
	if problems := p.Validate(); len(problems) != 0 {
		t.Fatalf("validate: %v", problems)
	}
}

// The blob has to survive a decode by the same parser rules the native binary
// uses, and the header has to carry the route index the router switches on.
func TestBlobRoundTrip(t *testing.T) {
	p := resolve(t, deviceConf)
	data, err := p.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	d, err := Decode(data)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if d.Frontend != 1 || d.Backend != 1 {
		t.Fatalf("frontend/backend = %d/%d", d.Frontend, d.Backend)
	}
	if d.Route != 3 {
		t.Fatalf("route = %d, want 3 (multicast_waiter)", d.Route)
	}
	if d.Release != p.Release {
		t.Fatalf("release = %q", d.Release)
	}
	if len(d.Sections) != len(p.Sections) {
		t.Fatalf("sections = %d, want %d", len(d.Sections), len(p.Sections))
	}
	if v, ok := d.Get("offset", "init_task"); !ok || v != 48505728 {
		t.Fatalf("decoded init_task = %d (%v)", v, ok)
	}
	if v, ok := d.Get("route.multicast_waiter", "waiter_off"); !ok || v != 96 {
		t.Fatalf("decoded waiter_off = %d (%v)", v, ok)
	}
	// Section and key names must stay ASCII-short: the wire format stores them
	// in a single length byte.
	for _, s := range d.Sections {
		if len(s.Name) > 0xFF {
			t.Fatalf("section name too long: %s", s.Name)
		}
		for _, e := range s.Entries {
			if len(e.Key) > 0xFF {
				t.Fatalf("key too long: %s", e.Key)
			}
		}
	}
}

// Every bundled per-kernel profile must resolve, validate and encode; the
// templates are expected to fail resolution because their fields are null.
func TestAllBundledProfiles(t *testing.T) {
	entries, err := os.ReadDir(filepath.Join("..", "assets", "profiles"))
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	real := 0
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".conf") {
			continue
		}
		if strings.HasSuffix(name, "-template.conf") || name == "index.conf" ||
			strings.HasPrefix(name, "execution-") || strings.HasPrefix(name, "kernel") ||
			strings.HasPrefix(name, "credential") {
			continue
		}
		real++
		m, err := ParseFile(testdata(t, name))
		if err != nil {
			t.Fatalf("%s: parse: %v", name, err)
		}
		p, err := Resolve(m, 0)
		if err != nil {
			t.Fatalf("%s: resolve: %v", name, err)
		}
		if p.Release != strings.TrimSuffix(name, ".conf") {
			t.Errorf("%s: release is %q", name, p.Release)
		}
		if _, err := p.Encode(); err != nil {
			t.Fatalf("%s: encode: %v", name, err)
		}
		if problems := p.Validate(); len(problems) != 0 {
			t.Errorf("%s: validate: %v", name, problems)
		}
	}
	if real < 50 {
		t.Fatalf("only %d real profiles found, the asset set looks truncated", real)
	}
}

func TestSafeModeFlag(t *testing.T) {
	m, err := ParseFile(testdata(t, deviceConf))
	if err != nil {
		t.Fatal(err)
	}
	p, err := Resolve(m, 1)
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := sectionValue(p, "meta", "safe_mode"); v != 1 {
		t.Fatalf("safe_mode = %d", v)
	}
}

func TestSelectStackWaiterShiftIsSigned(t *testing.T) {
	m, err := ParseString("release = " + qq("x") + "\nroute { select_stack { waiter_shift = -128, compact_waiter = 1 } }\nkernel_major = 6\n")
	if err != nil {
		t.Fatal(err)
	}
	p, err := Resolve(m, 0)
	if err != nil {
		t.Fatal(err)
	}
	v, ok := sectionValue(p, "route.select_stack", "waiter_shift")
	if !ok || v != -128 {
		t.Fatalf("waiter_shift = %d (%v), want -128", v, ok)
	}
}

func qq(s string) string { return string([]byte{0x22}) + s + string([]byte{0x22}) }
