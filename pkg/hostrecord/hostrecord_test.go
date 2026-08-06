package hostrecord

import (
	"slices"
	"testing"
)

func diagReasons(diags []Diag) []string {
	reasons := make([]string, len(diags))
	for i, d := range diags {
		reasons[i] = d.Reason
	}
	return reasons
}

func TestNormalize(t *testing.T) {
	tests := []struct {
		name        string
		in          Host
		wantOK      bool
		wantName    string
		wantIP      string
		wantMAC     string
		wantReasons []string
	}{
		{
			name:     "clean ipv4 record",
			in:       Host{Name: "NAS", IP: "192.168.0.10", MAC: "AA:BB:CC:DD:EE:FF"},
			wantOK:   true,
			wantName: "nas",
			wantIP:   "192.168.0.10",
			wantMAC:  "aa:bb:cc:dd:ee:ff",
		},
		{
			name:     "name trimmed lowercased",
			in:       Host{Name: "  Living-Room TV  ", IP: "192.168.0.20"},
			wantOK:   true,
			wantName: "living-room tv",
			wantIP:   "192.168.0.20",
		},
		{
			name:        "ipv6 dropped leaves no address",
			in:          Host{Name: "nas", IP: "fd00::10", MAC: "aa:bb:cc:dd:ee:ff"},
			wantOK:      false,
			wantReasons: []string{"ipv6_dropped"},
		},
		{
			name:        "invalid mac dropped but record survives on ip",
			in:          Host{Name: "printer", IP: "192.168.0.30", MAC: "not-a-mac"},
			wantOK:      true,
			wantName:    "printer",
			wantIP:      "192.168.0.30",
			wantMAC:     "",
			wantReasons: []string{"invalid_mac"},
		},
		{
			name:        "loopback dropped",
			in:          Host{Name: "x", IP: "127.0.0.1"},
			wantOK:      false,
			wantReasons: []string{"loopback_ip"},
		},
		{
			name:        "unspecified dropped",
			in:          Host{Name: "x", IP: "0.0.0.0"},
			wantOK:      false,
			wantReasons: []string{"unspecified_ip"},
		},
		{
			// A zoned link-local parses fine; the zone is stripped and then the
			// address is dropped as IPv6 (v1). This exercises the WithZone path
			// without asserting a v6 id, which will change post-v1.
			name:        "ipv6 with zone dropped not error",
			in:          Host{Name: "x", IP: "fe80::1%eth0"},
			wantOK:      false,
			wantReasons: []string{"ipv6_dropped"},
		},
		{
			name:        "garbage ip dropped as invalid",
			in:          Host{Name: "x", IP: "not-an-ip"},
			wantOK:      false,
			wantReasons: []string{"invalid_ip"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, diags, ok := Normalize(tt.in)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v (diags: %v)", ok, tt.wantOK, diags)
			}
			if !ok {
				if got := diagReasons(diags); !slices.Equal(got, tt.wantReasons) {
					t.Errorf("diag reasons = %v, want %v", got, tt.wantReasons)
				}
				return
			}
			if h.Name != tt.wantName {
				t.Errorf("name = %q, want %q", h.Name, tt.wantName)
			}
			if h.IP != tt.wantIP {
				t.Errorf("ip = %q, want %q", h.IP, tt.wantIP)
			}
			if h.MAC != tt.wantMAC {
				t.Errorf("mac = %q, want %q", h.MAC, tt.wantMAC)
			}
			if tt.wantReasons != nil {
				if got := diagReasons(diags); !slices.Equal(got, tt.wantReasons) {
					t.Errorf("diag reasons = %v, want %v", got, tt.wantReasons)
				}
			}
		})
	}
}

func TestSanitizeDNSLabel(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"nas", "nas"},
		{"Living Room TV", "living-room-tv"},
		{"foo_bar.baz", "foo-bar-baz"},
		{"--weird--", "weird"},
		{"a!!!b", "a-b"},
	}
	for _, tt := range tests {
		if got := SanitizeDNSLabel(tt.in); got != tt.want {
			t.Errorf("SanitizeDNSLabel(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
