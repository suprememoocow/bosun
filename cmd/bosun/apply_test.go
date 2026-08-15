package main

import (
	"testing"

	"github.com/suprememoocow/bosun/internal/config"
)

func TestCheckDeleteRails(t *testing.T) {
	tests := []struct {
		name           string
		deletes        int
		manageableLive int
		maxDeletes     int
		maxFraction    float64
		wantErr        bool
	}{
		{"no deletes always ok", 0, 0, 0, 0.0, false},
		{"under both limits", 1, 10, -1, 0.2, false},
		{"at fraction limit ok", 2, 10, -1, 0.2, false},
		{"over fraction limit", 3, 10, -1, 0.2, true},
		{"over max-deletes", 5, 100, 4, 0.9, true},
		{"unlimited max-deletes, under fraction", 4, 100, -1, 0.2, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkDeleteRails(tt.deletes, tt.manageableLive, tt.maxDeletes, tt.maxFraction)
			if (err != nil) != tt.wantErr {
				t.Errorf("checkDeleteRails() err = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCreateDefaults(t *testing.T) {
	// Unset defaults: inherit global filtering (never create unprotected).
	in := &clientsPlanInputs{cfg: &config.Config{Clients: &config.ClientsSink{}}}
	if ug, f := createDefaults(in); !ug || !f {
		t.Errorf("unset defaults = (%v,%v), want (true,true)", ug, f)
	}

	no := false
	in.cfg.Clients.Defaults = config.ClientDefaults{UseGlobalSettings: &no}
	if ug, f := createDefaults(in); ug || !f {
		t.Errorf("use_global_settings=false = (%v,%v), want (false,true)", ug, f)
	}
}
