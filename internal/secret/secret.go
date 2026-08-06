// Package secret provides a redacting string type and expansion of
// ${env:...}, ${file:...} and (opt-in) ${cmd:...} references in configuration.
//
// Expansion runs over the parsed YAML node tree after parse and before
// validation, so both the host's own fields and the opaque per-source config
// blocks (passed verbatim to plugins) are expanded uniformly. See the design
// doc §5 (secret expansion).
package secret

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Redacted is the placeholder returned wherever a secret would otherwise be
// rendered.
const Redacted = "[redacted]"

// String is a secret value that never renders its contents. Its String,
// MarshalText and MarshalYAML methods all return the redaction placeholder, so
// a stray log line or error message cannot leak it. Use Reveal to obtain the
// real value at the point of use.
type String struct {
	v string
}

// New wraps a plaintext value.
func New(v string) String { return String{v: v} }

// Reveal returns the underlying plaintext. This is the only way to read it, so
// call sites that leak secrets are greppable.
func (s String) Reveal() string { return s.v }

// IsZero reports whether the secret is empty.
func (s String) IsZero() bool { return s.v == "" }

func (s String) String() string { return Redacted }

// MarshalText ensures fmt %s, JSON encoders and slog all redact.
func (s String) MarshalText() ([]byte, error) { return []byte(Redacted), nil }

// MarshalYAML redacts when a config is round-tripped.
func (s String) MarshalYAML() (any, error) { return Redacted, nil }

// UnmarshalYAML captures the (already expanded) scalar verbatim.
func (s *String) UnmarshalYAML(value *yaml.Node) error {
	return value.Decode(&s.v)
}

// LogValue keeps secrets redacted in structured slog output.
func (s String) LogValue() any { return Redacted }

// Expander resolves secret references. AllowCmd gates ${cmd:...}, which is
// disabled by default because it executes arbitrary commands.
type Expander struct {
	AllowCmd bool
}

var refRE = regexp.MustCompile(`\$\{(env|file|cmd):([^}]*)\}`)

// ExpandTree walks a YAML node tree, expanding every scalar in place, and
// returns warnings for plaintext secrets (values under a secret-looking key
// that contain no reference). It fails closed: an unresolved reference is an
// error rather than an empty value.
func (e Expander) ExpandTree(n *yaml.Node) (warnings []string, err error) {
	switch n.Kind {
	case yaml.DocumentNode, yaml.SequenceNode:
		for _, c := range n.Content {
			w, err := e.ExpandTree(c)
			if err != nil {
				return warnings, err
			}
			warnings = append(warnings, w...)
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			key, val := n.Content[i], n.Content[i+1]
			if val.Kind == yaml.ScalarNode && looksSecret(key.Value) && !refRE.MatchString(val.Value) && val.Value != "" {
				warnings = append(warnings, fmt.Sprintf("plaintext secret in field %q: prefer ${env:...} or ${file:...}", key.Value))
			}
			w, err := e.ExpandTree(val)
			if err != nil {
				return warnings, err
			}
			warnings = append(warnings, w...)
		}
	case yaml.ScalarNode:
		// Only scalars that actually contain a reference are touched. A scalar
		// with no reference keeps its original tag and style so that ints, bools
		// and the like still decode into their typed fields.
		if !refRE.MatchString(n.Value) {
			return warnings, nil
		}
		expanded, err := e.expandString(n.Value)
		if err != nil {
			return warnings, err
		}
		n.Value = expanded
		// A resolved secret is always a string; force the tag and quote it so a
		// value like a numeric password is not reinterpreted as an int.
		n.Style = yaml.DoubleQuotedStyle
		n.Tag = "!!str"
	}
	return warnings, nil
}

func looksSecret(key string) bool {
	k := strings.ToLower(key)
	return strings.Contains(k, "password") || strings.Contains(k, "secret") || strings.Contains(k, "token")
}

// expandString replaces every reference in s.
func (e Expander) expandString(s string) (string, error) {
	var resolveErr error
	out := refRE.ReplaceAllStringFunc(s, func(match string) string {
		if resolveErr != nil {
			return match
		}
		m := refRE.FindStringSubmatch(match)
		kind, arg := m[1], m[2]
		v, err := e.resolve(kind, arg)
		if err != nil {
			resolveErr = err
			return match
		}
		return v
	})
	return out, resolveErr
}

func (e Expander) resolve(kind, arg string) (string, error) {
	switch kind {
	case "env":
		v, ok := os.LookupEnv(arg)
		if !ok {
			return "", fmt.Errorf("environment variable %q is not set", arg)
		}
		return v, nil
	case "file":
		data, err := os.ReadFile(arg)
		if err != nil {
			return "", fmt.Errorf("reading secret file %q: %w", arg, err)
		}
		return strings.TrimRight(string(data), "\r\n"), nil
	case "cmd":
		if !e.AllowCmd {
			return "", fmt.Errorf("${cmd:...} is disabled; enable it explicitly to use %q", arg)
		}
		out, err := exec.Command("sh", "-c", arg).Output()
		if err != nil {
			return "", fmt.Errorf("running secret command: %w", err)
		}
		return strings.TrimRight(string(out), "\r\n"), nil
	default:
		return "", fmt.Errorf("unknown secret reference kind %q", kind)
	}
}
