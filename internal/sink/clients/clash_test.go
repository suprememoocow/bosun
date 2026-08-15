package clients

import (
	"testing"

	"github.com/suprememoocow/bosun/internal/adguard"
	"github.com/suprememoocow/bosun/internal/config"
	"github.com/suprememoocow/bosun/internal/source"
	"github.com/suprememoocow/bosun/pkg/hostrecord"
)

func recL(name, ip, mac string, labels map[string]string) hostrecord.Host {
	return hostrecord.Host{Name: name, IP: ip, MAC: mac, Labels: labels}
}

func names(p *Plan) map[string]Op {
	m := map[string]Op{}
	for _, a := range p.Actions {
		m[a.Name] = a.Op
	}
	return m
}

// The real-world case: two distinct devices share an Omada name across VLANs.
// A label template disambiguates them deterministically.
func TestClashResolvedByTemplate(t *testing.T) {
	sink := &config.ClientsSink{
		Sources: []string{"omada"},
		OnNameClash: config.NameClash{
			Template: "{{ .Labels.omada_network }}-{{ .Name }}",
			Fallback: "mac_suffix",
		},
	}
	bySource := map[string]source.Result{"omada": {Records: []hostrecord.Host{
		recL("shelly", "192.168.10.5", "aa:bb:cc:00:00:01", map[string]string{"omada.network": "IoT"}),
		recL("shelly", "192.168.20.5", "aa:bb:cc:00:00:02", map[string]string{"omada.network": "Lounge"}),
	}}}
	plan, err := BuildPlan(sink, bySource, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := names(plan)
	if got["iot-shelly"] != OpCreate || got["lounge-shelly"] != OpCreate {
		t.Fatalf("want iot-shelly and lounge-shelly creates, got %v", got)
	}
	if _, ok := got["shelly"]; ok {
		t.Error("bare 'shelly' should not survive a clash (all members prefixed)")
	}
}

func TestClashFallbackMacSuffix(t *testing.T) {
	// No template: fall back to mac_suffix (last 3 octets), unique per device.
	sink := &config.ClientsSink{Sources: []string{"f"}}
	bySource := map[string]source.Result{"f": {Records: []hostrecord.Host{
		recL("nas", "192.168.0.10", "aa:bb:cc:dd:ee:ff", nil),
		recL("nas", "192.168.30.10", "11:22:33:44:55:66", nil),
	}}}
	plan, err := BuildPlan(sink, bySource, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := names(plan)
	if got["nas-ddeeff"] != OpCreate || got["nas-445566"] != OpCreate {
		t.Fatalf("want nas-ddeeff and nas-445566, got %v", got)
	}
}

func TestClashWithVetoedLiveNameIsPrefixed(t *testing.T) {
	// A single desired 'nas' collides with a vetoed (subnet) live 'nas'; it must
	// be prefixed rather than attempt to clobber the hand-maintained client.
	sink := &config.ClientsSink{Sources: []string{"f"}}
	bySource := map[string]source.Result{"f": {Records: []hostrecord.Host{
		recL("nas", "192.168.0.10", "aa:bb:cc:dd:ee:ff", nil),
	}}}
	live := []adguard.PersistentClient{{Name: "nas", IDs: []string{"192.168.0.0/24"}}}
	plan, err := BuildPlan(sink, bySource, live)
	if err != nil {
		t.Fatal(err)
	}
	got := names(plan)
	if got["nas-ddeeff"] != OpCreate {
		t.Fatalf("want nas-ddeeff create, got %v", got)
	}
	if len(plan.Vetoed) != 1 || plan.Vetoed[0] != "nas" {
		t.Errorf("live nas should be vetoed, got %v", plan.Vetoed)
	}
}

func TestClashFallbackError(t *testing.T) {
	sink := &config.ClientsSink{Sources: []string{"f"}, OnNameClash: config.NameClash{Fallback: "error"}}
	bySource := map[string]source.Result{"f": {Records: []hostrecord.Host{
		recL("nas", "192.168.0.10", "aa:bb:cc:dd:ee:ff", nil),
		recL("nas", "192.168.30.10", "11:22:33:44:55:66", nil),
	}}}
	if _, err := BuildPlan(sink, bySource, nil); err == nil {
		t.Fatal("expected clash error with fallback=error")
	}
}

// TestClashDeterminism runs resolution many times; with map iteration randomised
// (and -race), the assignment must be byte-identical every time (design doc §7.5,
// principle 7). Run with: go test -race -run TestClashDeterminism -count=20
func TestClashDeterminism(t *testing.T) {
	sink := &config.ClientsSink{
		Sources:     []string{"omada"},
		OnNameClash: config.NameClash{Template: "{{ .Labels.omada_network }}-{{ .Name }}"},
	}
	bySource := map[string]source.Result{"omada": {Records: []hostrecord.Host{
		recL("shelly", "192.168.10.5", "aa:bb:cc:00:00:01", map[string]string{"omada.network": "IoT"}),
		recL("shelly", "192.168.20.5", "aa:bb:cc:00:00:02", map[string]string{"omada.network": "Lounge"}),
		recL("shelly", "192.168.30.5", "aa:bb:cc:00:00:03", map[string]string{"omada.network": "Guest"}),
	}}}

	var want []string
	for i := 0; i < 50; i++ {
		plan, err := BuildPlan(sink, bySource, nil)
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, a := range plan.Actions {
			got = append(got, string(a.Op)+" "+a.Name)
		}
		if i == 0 {
			want = got
			continue
		}
		if len(got) != len(want) {
			t.Fatalf("run %d: %v != %v", i, got, want)
		}
		for j := range got {
			if got[j] != want[j] {
				t.Fatalf("run %d differs at %d: %q != %q", i, j, got[j], want[j])
			}
		}
	}
}
