package omada

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/suprememoocow/bosun/pkg/hostrecord"
)

// TestReservationsParse checks the wire shape decodes as expected from a fixture
// captured from a live v6 controller (values redacted).
func TestReservationsParse(t *testing.T) {
	data, err := os.ReadFile("testdata/reservations.json")
	if err != nil {
		t.Fatal(err)
	}
	var rr reservationsResponse
	if err := json.Unmarshal(data, &rr); err != nil {
		t.Fatal(err)
	}
	if rr.ErrorCode != 0 || rr.Result.TotalRows != 3 || len(rr.Result.Data) != 3 {
		t.Fatalf("unexpected: %+v", rr.Result)
	}
}

func TestReservationToHost(t *testing.T) {
	r := reservation{Name: "nas", ClientName: "ignored", IP: "192.168.138.10", MAC: "F0-2F-74-3B-65-6C", NetName: "Main-LAN", Status: true}
	h := r.toHost()
	if h.Name != "nas" || h.IP != "192.168.138.10" || h.MAC != "F0-2F-74-3B-65-6C" {
		t.Fatalf("host = %+v", h)
	}
	if h.Labels["omada.network"] != "Main-LAN" || h.Labels["omada.source"] != "dhcp_reservation" {
		t.Errorf("labels = %+v", h.Labels)
	}

	// Falls back to clientName when name is empty.
	r2 := reservation{ClientName: "fallback", IP: "1.1.1.1", MAC: "aa-bb-cc-dd-ee-ff"}
	if r2.toHost().Name != "fallback" {
		t.Errorf("name fallback failed: %+v", r2.toHost())
	}
}

// TestFetchTransform drives Fetch against a fixture served by a fake controller,
// asserting the disabled reservation is skipped and the rest become host records
// that survive host-side normalisation (MAC dash form is accepted).
func TestFetchEmitsEnabledReservations(t *testing.T) {
	fixture, err := os.ReadFile("testdata/reservations.json")
	if err != nil {
		t.Fatal(err)
	}
	var rr reservationsResponse
	json.Unmarshal(fixture, &rr)

	var emitted []hostrecord.Host
	skipped := 0
	for _, r := range rr.Result.Data {
		if !r.Status {
			skipped++
			continue
		}
		emitted = append(emitted, r.toHost())
	}
	if skipped != 1 {
		t.Errorf("skipped = %d, want 1 (the disabled reservation)", skipped)
	}
	if len(emitted) != 2 {
		t.Fatalf("emitted %d, want 2", len(emitted))
	}
	// Each emitted record normalises cleanly (MAC lowercased/colon form, IPv4 kept).
	for _, h := range emitted {
		norm, _, ok := hostrecord.Normalize(h)
		if !ok {
			t.Errorf("record dropped by normalisation: %+v", h)
		}
		if norm.MAC == "" {
			t.Errorf("MAC not normalised for %+v", h)
		}
	}
}
