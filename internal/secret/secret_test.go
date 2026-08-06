package secret

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestRedaction(t *testing.T) {
	s := New("hunter2")
	if got := s.String(); got != Redacted {
		t.Errorf("String() = %q, want %q", got, Redacted)
	}
	if got := s.Reveal(); got != "hunter2" {
		t.Errorf("Reveal() = %q, want hunter2", got)
	}

	b, err := json.Marshal(struct{ P String }{s})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "hunter2") {
		t.Errorf("JSON leaked secret: %s", b)
	}

	if out := fmt.Sprintf("%s", s); out != Redacted {
		t.Errorf("fmt %%s = %q, want %q", out, Redacted)
	}
}

func TestExpandTree(t *testing.T) {
	t.Setenv("MY_USER", "admin")
	dir := t.TempDir()
	secretPath := filepath.Join(dir, "pw")
	if err := os.WriteFile(secretPath, []byte("filepass\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	src := `
adguard:
  username: ${env:MY_USER}
  password: ${file:` + secretPath + `}
sources:
  - config:
      token: literal-token
`
	var root yaml.Node
	if err := yaml.Unmarshal([]byte(src), &root); err != nil {
		t.Fatal(err)
	}
	warnings, err := Expander{}.ExpandTree(&root)
	if err != nil {
		t.Fatalf("ExpandTree: %v", err)
	}

	var got struct {
		Adguard struct {
			Username string `yaml:"username"`
			Password string `yaml:"password"`
		} `yaml:"adguard"`
	}
	if err := root.Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Adguard.Username != "admin" {
		t.Errorf("username = %q, want admin", got.Adguard.Username)
	}
	if got.Adguard.Password != "filepass" {
		t.Errorf("password = %q, want filepass", got.Adguard.Password)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "token") {
		t.Errorf("warnings = %v, want one about plaintext token", warnings)
	}
}

func TestExpandMissingEnvFails(t *testing.T) {
	src := `password: ${env:DEFINITELY_NOT_SET_XYZ}`
	var root yaml.Node
	if err := yaml.Unmarshal([]byte(src), &root); err != nil {
		t.Fatal(err)
	}
	if _, err := (Expander{}).ExpandTree(&root); err == nil {
		t.Fatal("expected error for unset env var")
	}
}

func TestCmdDisabledByDefault(t *testing.T) {
	src := `x: ${cmd:echo hi}`
	var root yaml.Node
	if err := yaml.Unmarshal([]byte(src), &root); err != nil {
		t.Fatal(err)
	}
	if _, err := (Expander{}).ExpandTree(&root); err == nil {
		t.Fatal("expected error: cmd disabled")
	}
	// Re-parse because the failed pass mutates in place.
	if err := yaml.Unmarshal([]byte(src), &root); err != nil {
		t.Fatal(err)
	}
	if _, err := (Expander{AllowCmd: true}).ExpandTree(&root); err != nil {
		t.Fatalf("cmd enabled should succeed: %v", err)
	}
}
