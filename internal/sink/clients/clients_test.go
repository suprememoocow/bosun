package clients

import (
	"testing"

	"github.com/suprememoocow/bosun/internal/adguard"
	"github.com/suprememoocow/bosun/internal/config"
	"github.com/suprememoocow/bosun/internal/source"
	"github.com/suprememoocow/bosun/pkg/hostrecord"
)

func rec(name, ip, mac string) hostrecord.Host {
	return hostrecord.Host{Name: name, IP: ip, MAC: mac}
}

func findAction(p *Plan, name string) (Action, bool) {
	for _, a := range p.Actions {
		if a.Name == name {
			return a, true
		}
	}
	return Action{}, false
}

func TestBuildPlanOutcomes(t *testing.T) {
	sink := &config.ClientsSink{Sources: []string{"fixture"}, Prune: true}
	bySource := map[string]source.Result{
		"fixture": {Records: []hostrecord.Host{
			rec("nas", "192.168.0.10", "aa:bb:cc:dd:ee:ff"), // update: live has different id
			rec("printer", "192.168.0.20", ""),              // create: not live
			rec("router", "192.168.0.1", ""),                // noop: matches live
		}},
	}
	live := []adguard.PersistentClient{
		{Name: "nas", IDs: []string{"192.168.0.11"}},         // differs -> update
		{Name: "router", IDs: []string{"192.168.0.1"}},       // same -> noop
		{Name: "oldlaptop", IDs: []string{"192.168.0.50"}},   // owned, absent -> delete
		{Name: "guestnet", IDs: []string{"192.168.30.0/24"}}, // CIDR -> vetoed
		{Name: "doh", IDs: []string{"someclientid"}},         // clientid -> vetoed
	}

	plan, err := BuildPlan(sink, bySource, live)
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}

	if a, ok := findAction(plan, "printer"); !ok || a.Op != OpCreate {
		t.Errorf("printer: want create, got %+v (ok=%v)", a, ok)
	}
	if a, ok := findAction(plan, "nas"); !ok || a.Op != OpUpdate {
		t.Errorf("nas: want update, got %+v (ok=%v)", a, ok)
	}
	if a, ok := findAction(plan, "router"); !ok || a.Op != OpNoop {
		t.Errorf("router: want noop, got %+v (ok=%v)", a, ok)
	}
	if a, ok := findAction(plan, "oldlaptop"); !ok || a.Op != OpDelete {
		t.Errorf("oldlaptop: want delete, got %+v (ok=%v)", a, ok)
	}
	wantVetoed := []string{"doh", "guestnet"}
	if len(plan.Vetoed) != 2 || plan.Vetoed[0] != wantVetoed[0] || plan.Vetoed[1] != wantVetoed[1] {
		t.Errorf("vetoed = %v, want %v", plan.Vetoed, wantVetoed)
	}
}

func TestPruneDisabledIgnoresInsteadOfDeletes(t *testing.T) {
	sink := &config.ClientsSink{Sources: []string{"f"}, Prune: false}
	bySource := map[string]source.Result{"f": {}}
	live := []adguard.PersistentClient{{Name: "leftover", IDs: []string{"192.168.0.9"}}}

	plan, err := BuildPlan(sink, bySource, live)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Actions) != 0 {
		t.Errorf("expected no actions with prune off, got %v", plan.Actions)
	}
	if len(plan.Ignored) != 1 || plan.Ignored[0] != "leftover" {
		t.Errorf("ignored = %v, want [leftover]", plan.Ignored)
	}
}

func TestOwnershipExcludeProtectsFromPrune(t *testing.T) {
	sink := &config.ClientsSink{
		Sources:   []string{"f"},
		Prune:     true,
		Ownership: config.Ownership{Include: []string{"*"}, Exclude: []string{"keep-*"}},
	}
	bySource := map[string]source.Result{"f": {}}
	live := []adguard.PersistentClient{
		{Name: "keep-me", IDs: []string{"192.168.0.5"}},
		{Name: "delete-me", IDs: []string{"192.168.0.6"}},
	}
	plan, err := BuildPlan(sink, bySource, live)
	if err != nil {
		t.Fatal(err)
	}
	if a, ok := findAction(plan, "delete-me"); !ok || a.Op != OpDelete {
		t.Errorf("delete-me: want delete, got %+v", a)
	}
	if _, ok := findAction(plan, "keep-me"); ok {
		t.Error("keep-me should be excluded from pruning")
	}
}

func TestDualHomedGroupsIntoOneClient(t *testing.T) {
	sink := &config.ClientsSink{Sources: []string{"f"}}
	bySource := map[string]source.Result{"f": {Records: []hostrecord.Host{
		rec("nas", "192.168.0.10", "aa:bb:cc:dd:ee:ff"),
		rec("nas", "192.168.1.10", "aa:bb:cc:dd:ee:ff"),
	}}}
	plan, err := BuildPlan(sink, bySource, nil)
	if err != nil {
		t.Fatal(err)
	}
	a, ok := findAction(plan, "nas")
	if !ok || a.Op != OpCreate {
		t.Fatalf("nas: want create, got %+v", a)
	}
	// One client with both IPs and the MAC.
	want := []string{"192.168.0.10", "192.168.1.10", "aa:bb:cc:dd:ee:ff"}
	if len(a.IDs) != len(want) {
		t.Fatalf("ids = %v, want %v", a.IDs, want)
	}
	for i := range want {
		if a.IDs[i] != want[i] {
			t.Errorf("ids[%d] = %q, want %q", i, a.IDs[i], want[i])
		}
	}
}

func TestNameClashFailsInM0(t *testing.T) {
	sink := &config.ClientsSink{Sources: []string{"f"}}
	bySource := map[string]source.Result{"f": {Records: []hostrecord.Host{
		rec("nas", "192.168.0.10", "aa:bb:cc:dd:ee:ff"),
		rec("nas", "192.168.30.10", "11:22:33:44:55:66"), // same name, different MAC
	}}}
	if _, err := BuildPlan(sink, bySource, nil); err == nil {
		t.Fatal("expected name clash error")
	}
}
