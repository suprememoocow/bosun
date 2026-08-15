package clients

import (
	"slices"
	"testing"

	"github.com/suprememoocow/bosun/internal/adguard"
	"github.com/suprememoocow/bosun/internal/config"
	"github.com/suprememoocow/bosun/internal/source"
	"github.com/suprememoocow/bosun/pkg/hostrecord"
	"gopkg.in/yaml.v3"
)

// enrichmentRules parses YAML into enrichment rules so tests exercise the same
// predicate unmarshalling the config uses.
func enrichmentRules(t *testing.T, src string) []config.EnrichmentRule {
	t.Helper()
	var rules []config.EnrichmentRule
	if err := yaml.Unmarshal([]byte(src), &rules); err != nil {
		t.Fatalf("unmarshal enrichment: %v", err)
	}
	return rules
}

func actionFor(p *Plan, name string) (Action, bool) {
	for _, a := range p.Actions {
		if a.Name == name {
			return a, true
		}
	}
	return Action{}, false
}

func TestEnrichmentSetAndMerge(t *testing.T) {
	rules := enrichmentRules(t, `
- match: { ip: 192.168.138.3 }
  set:
    tags: [user_regular]
- match: { cidr: 192.168.138.0/24 }
  merge:
    tags: [device_other]
`)
	sink := &config.ClientsSink{Sources: []string{"f"}, Enrichment: rules}
	bySource := map[string]source.Result{"f": {Records: []hostrecord.Host{
		{Name: "phone", IP: "192.168.138.3", MAC: "aa:bb:cc:dd:ee:01"},
		{Name: "printer", IP: "192.168.138.9", MAC: "aa:bb:cc:dd:ee:02"},
	}}}
	plan, err := BuildPlan(sink, bySource, nil)
	if err != nil {
		t.Fatal(err)
	}

	phone, _ := actionFor(plan, "phone")
	if !slices.Equal(phone.Tags, []string{"device_other", "user_regular"}) {
		t.Errorf("phone tags = %v, want [device_other user_regular]", phone.Tags)
	}
	printer, _ := actionFor(plan, "printer")
	if !slices.Equal(printer.Tags, []string{"device_other"}) {
		t.Errorf("printer tags = %v, want [device_other]", printer.Tags)
	}
}

func TestTagsDriveUpdateOnlyWhenEnrichmentConfigured(t *testing.T) {
	records := []hostrecord.Host{{Name: "nas", IP: "192.168.0.10", MAC: "aa:bb:cc:dd:ee:ff"}}
	bySource := map[string]source.Result{"f": {Records: records}}
	// Live client already has the right ids but stray hand-set tags.
	live := []adguard.PersistentClient{{Name: "nas", IDs: []string{"192.168.0.10", "aa:bb:cc:dd:ee:ff"}, Tags: []string{"os_linux"}}}

	// No enrichment: tags are not managed, so the client is a noop despite the
	// stray tag.
	plan, err := BuildPlan(&config.ClientsSink{Sources: []string{"f"}}, bySource, live)
	if err != nil {
		t.Fatal(err)
	}
	if a, _ := actionFor(plan, "nas"); a.Op != OpNoop {
		t.Errorf("no-enrichment: want noop, got %s", a.Op)
	}

	// With enrichment (that sets no tag for this client), tags become managed and
	// the stray tag is reconciled away -> update.
	rules := enrichmentRules(t, `[{match: {ip: 10.0.0.1}, set: {tags: [user_admin]}}]`)
	plan, err = BuildPlan(&config.ClientsSink{Sources: []string{"f"}, Enrichment: rules}, bySource, live)
	if err != nil {
		t.Fatal(err)
	}
	if a, _ := actionFor(plan, "nas"); a.Op != OpUpdate {
		t.Errorf("with-enrichment: want update (tags reconciled), got %s", a.Op)
	}
}
