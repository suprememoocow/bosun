package config

import (
	"strings"
	"testing"
	"time"
)

const fullConfig = `
version: 1
plugins:
  dir: /usr/local/libexec/bosun
  timeout: 30s
  max_concurrency: 4
adguard:
  address: http://192.168.0.3:3000
  username: ${env:ADGUARD_USER}
  password: ${env:ADGUARD_PASSWORD}
sources:
  - id: omada
    type: omada
    config:
      address: https://192.168.0.1:8043
      site: Default
adguard_clients:
  sources: [omada]
  filter:
    - cidr: 192.168.0.0/24
  enrichment:
    - match: { ip: 192.168.138.3 }
      set:
        tags: [user_regular]
  managed_id_kinds: [ip, mac]
  on_mixed_ids: skip
  prune: true
`

func TestParseFullConfig(t *testing.T) {
	t.Setenv("ADGUARD_USER", "admin")
	t.Setenv("ADGUARD_PASSWORD", "s3cr3t")

	cfg, warnings, err := Parse([]byte(fullConfig), LoadOptions{})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(warnings) != 0 {
		t.Errorf("unexpected warnings: %v", warnings)
	}
	if cfg.Plugins.Timeout.Duration() != 30*time.Second {
		t.Errorf("timeout = %v, want 30s", cfg.Plugins.Timeout.Duration())
	}
	if cfg.Adguard.Username != "admin" {
		t.Errorf("username = %q, want admin", cfg.Adguard.Username)
	}
	if cfg.Adguard.Password.Reveal() != "s3cr3t" {
		t.Errorf("password not expanded")
	}
	if cfg.Adguard.Password.String() != "[redacted]" {
		t.Errorf("password not redacted in String()")
	}
	if len(cfg.Sources) != 1 || cfg.Sources[0].ID != "omada" {
		t.Fatalf("sources not parsed: %+v", cfg.Sources)
	}
	if cfg.Clients == nil || !cfg.Clients.Prune {
		t.Fatal("clients sink not parsed")
	}
}

func TestValidateErrors(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{
			name:    "wrong version",
			yaml:    "version: 2\nadguard: {address: x}\nadguard_clients: {sources: []}",
			wantErr: "version must be 1",
		},
		{
			name:    "missing adguard address",
			yaml:    "version: 1\nadguard_clients:\n  sources: [x]\nsources:\n  - {id: x, type: t}",
			wantErr: "adguard.address is required",
		},
		{
			name:    "unknown source ref",
			yaml:    "version: 1\nadguard: {address: x}\nadguard_clients:\n  sources: [ghost]",
			wantErr: `unknown source "ghost"`,
		},
		{
			name:    "invalid enrichment tag",
			yaml:    "version: 1\nadguard: {address: x}\nsources:\n  - {id: s, type: t}\nadguard_clients:\n  sources: [s]\n  enrichment:\n    - match: {ip: 1.1.1.1}\n      set: {tags: [not_a_tag]}",
			wantErr: "invalid tag",
		},
		{
			name:    "rewrites prune without include",
			yaml:    "version: 1\nadguard: {address: x}\nsources:\n  - {id: s, type: t}\nadguard_rewrites:\n  sources: [s]\n  prune: true",
			wantErr: "prune requires an explicit ownership.include",
		},
		{
			name:    "bad managed id kind",
			yaml:    "version: 1\nadguard: {address: x}\nsources:\n  - {id: s, type: t}\nadguard_clients:\n  sources: [s]\n  managed_id_kinds: [ip, cidr]",
			wantErr: "not a manageable kind",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := Parse([]byte(tt.yaml), LoadOptions{})
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want substring %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestPlaintextSecretWarns(t *testing.T) {
	yaml := "version: 1\nadguard:\n  address: x\n  password: hunter2\nsources:\n  - {id: s, type: t}\nadguard_clients:\n  sources: [s]"
	_, warnings, err := Parse([]byte(yaml), LoadOptions{})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	found := false
	for _, w := range warnings {
		if strings.Contains(w, "plaintext secret") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected plaintext secret warning, got %v", warnings)
	}
}
