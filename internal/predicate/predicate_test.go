package predicate

import (
	"testing"

	"github.com/suprememoocow/bosun/pkg/hostrecord"
	"gopkg.in/yaml.v3"
)

func parseFilter(t *testing.T, src string) Filter {
	t.Helper()
	var f Filter
	if err := yaml.Unmarshal([]byte(src), &f); err != nil {
		t.Fatalf("unmarshal filter: %v", err)
	}
	return f
}

func host(name, ip, mac string, labels map[string]string) Subject {
	return Subject{Host: hostrecord.Host{Name: name, IP: ip, MAC: mac, Labels: labels}}
}

func TestFilterMatch(t *testing.T) {
	// Mirrors the sketch in the design doc §5: an implicit `all` of a cidr `any`
	// and a `not name`.
	f := parseFilter(t, `
- any:
    - cidr: 192.168.0.0/24
    - cidr: 192.168.1.0/24
- not:
    name: "android-*"
`)

	tests := []struct {
		name string
		s    Subject
		want bool
	}{
		{"in range, not android", host("nas", "192.168.0.10", "", nil), true},
		{"in second range", host("tv", "192.168.1.5", "", nil), true},
		{"android excluded", host("android-abc", "192.168.0.11", "", nil), false},
		{"out of range", host("x", "10.0.0.1", "", nil), false},
	}
	for _, tt := range tests {
		if got := f.Matches(tt.s); got != tt.want {
			t.Errorf("%s: Matches = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestEmptyFilterMatchesAll(t *testing.T) {
	var f Filter
	if !f.Matches(host("anything", "10.0.0.1", "", nil)) {
		t.Error("zero-value filter should match everything")
	}
}

func TestLeafNodes(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		s    Subject
		want bool
	}{
		{"ip exact match", `ip: 192.168.0.10`, host("a", "192.168.0.10", "", nil), true},
		{"ip list", `ip: [192.168.0.1, 192.168.0.2]`, host("a", "192.168.0.2", "", nil), true},
		{"ip no match", `ip: 192.168.0.10`, host("a", "192.168.0.11", "", nil), false},
		{"mac full", `mac: aa:bb:cc:dd:ee:ff`, host("a", "1.1.1.1", "aa:bb:cc:dd:ee:ff", nil), true},
		{"mac oui prefix", `mac: aa:bb:cc`, host("a", "1.1.1.1", "aa:bb:cc:dd:ee:ff", nil), true},
		{"mac oui no partial octet", `mac: aa:bb:c`, host("a", "1.1.1.1", "aa:bb:cd:ee:ff:00", nil), false},
		{"name glob", `name: "nas-*"`, host("nas-01", "1.1.1.1", "", nil), true},
		{"name regexp", `name: "re:^web[0-9]+$"`, host("web12", "1.1.1.1", "", nil), true},
		{"name regexp no match", `name: "re:^web[0-9]+$"`, host("webx", "1.1.1.1", "", nil), false},
		{"label match", `label: {omada.network: Servers}`, host("a", "1.1.1.1", "", map[string]string{"omada.network": "Servers"}), true},
		{"label glob", `label: {omada.network: "Serv*"}`, host("a", "1.1.1.1", "", map[string]string{"omada.network": "Servers"}), true},
		{"label missing key", `label: {omada.network: Servers}`, host("a", "1.1.1.1", "", nil), false},
		{"has_mac true", `has_mac: true`, host("a", "1.1.1.1", "aa:bb:cc:dd:ee:ff", nil), true},
		{"has_mac false", `has_mac: false`, host("a", "1.1.1.1", "", nil), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var n Node
			if err := yaml.Unmarshal([]byte(tt.yaml), &n); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if got := n.Match(tt.s); got != tt.want {
				t.Errorf("Match = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSourceNode(t *testing.T) {
	var n Node
	if err := yaml.Unmarshal([]byte(`source: [omada, npm]`), &n); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !n.Match(Subject{Source: "omada"}) {
		t.Error("expected omada to match")
	}
	if n.Match(Subject{Source: "static"}) {
		t.Error("expected static not to match")
	}
}

func TestUnknownNode(t *testing.T) {
	var n Node
	err := yaml.Unmarshal([]byte(`bogus: true`), &n)
	if err == nil {
		t.Fatal("expected error for unknown node")
	}
}

func TestMultiKeyNodeRejected(t *testing.T) {
	var n Node
	err := yaml.Unmarshal([]byte("{ip: 1.1.1.1, name: x}"), &n)
	if err == nil {
		t.Fatal("expected error for multi-key node")
	}
}
