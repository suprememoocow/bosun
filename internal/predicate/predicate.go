// Package predicate implements the composable filter/match tree used by sink
// filters and by enrichment selectors.
//
// The tree is a single Predicate interface plus a registry keyed on the one map
// key of each YAML node. A custom UnmarshalYAML dispatches on that key, which is
// what lets the language grow without a schema explosion: adding a node type is
// registering one constructor. See the design doc §5 (predicate language).
package predicate

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"

	"github.com/suprememoocow/bosun/pkg/hostrecord"
	"gopkg.in/yaml.v3"
)

// Subject is what a predicate is evaluated against: a host record together with
// the id of the source it came from. Source is needed by the `source` node in
// multi-source sinks and is not part of the wire record.
type Subject struct {
	Host   hostrecord.Host
	Source string
}

// Predicate is one node in the filter tree.
type Predicate interface {
	Match(Subject) bool
}

// constructor builds a predicate from the YAML value node found under a
// registered key.
type constructor func(value *yaml.Node) (Predicate, error)

var registry = map[string]constructor{}

func register(key string, c constructor) { registry[key] = c }

// Node wraps a single predicate node for YAML unmarshalling (a mapping with
// exactly one key). It is the field type to embed in config structs, e.g. an
// enrichment rule's `match`.
type Node struct {
	Predicate
}

// UnmarshalYAML parses a single predicate node.
func (n *Node) UnmarshalYAML(value *yaml.Node) error {
	p, err := parseNode(value)
	if err != nil {
		return err
	}
	n.Predicate = p
	return nil
}

// Filter is a top-level filter: a sequence of predicate nodes combined with an
// implicit `all`. A bare mapping (single node) is also accepted. The zero
// value (absent filter) matches everything.
type Filter struct {
	Root Predicate
}

// Matches reports whether the subject satisfies the filter. An absent filter
// (nil root) matches everything.
func (f Filter) Matches(s Subject) bool {
	if f.Root == nil {
		return true
	}
	return f.Root.Match(s)
}

// UnmarshalYAML parses a top-level filter as an implicit `all`.
func (f *Filter) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.SequenceNode:
		preds, err := parseSeq(value)
		if err != nil {
			return err
		}
		f.Root = all(preds)
	case yaml.MappingNode:
		p, err := parseNode(value)
		if err != nil {
			return err
		}
		f.Root = p
	default:
		return fmt.Errorf("filter: expected a list or mapping, got %s", kindName(value.Kind))
	}
	return nil
}

// parseNode parses a mapping with exactly one key and dispatches on it.
func parseNode(value *yaml.Node) (Predicate, error) {
	if value.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("predicate: expected a mapping, got %s", kindName(value.Kind))
	}
	if len(value.Content) != 2 {
		return nil, fmt.Errorf("predicate: each node must have exactly one key, got %d", len(value.Content)/2)
	}
	key := value.Content[0].Value
	c, ok := registry[key]
	if !ok {
		return nil, fmt.Errorf("predicate: unknown node %q", key)
	}
	p, err := c(value.Content[1])
	if err != nil {
		return nil, fmt.Errorf("predicate %q: %w", key, err)
	}
	return p, nil
}

// parseSeq parses a sequence of predicate nodes.
func parseSeq(value *yaml.Node) ([]Predicate, error) {
	if value.Kind != yaml.SequenceNode {
		return nil, fmt.Errorf("expected a list, got %s", kindName(value.Kind))
	}
	preds := make([]Predicate, 0, len(value.Content))
	for _, item := range value.Content {
		p, err := parseNode(item)
		if err != nil {
			return nil, err
		}
		preds = append(preds, p)
	}
	return preds, nil
}

func kindName(k yaml.Kind) string {
	switch k {
	case yaml.SequenceNode:
		return "list"
	case yaml.MappingNode:
		return "mapping"
	case yaml.ScalarNode:
		return "scalar"
	default:
		return "value"
	}
}

// decodeStrings decodes a scalar or sequence YAML node into a slice of strings,
// so every list-accepting node also accepts a bare scalar.
func decodeStrings(value *yaml.Node) ([]string, error) {
	if value.Kind == yaml.SequenceNode {
		var s []string
		if err := value.Decode(&s); err != nil {
			return nil, err
		}
		return s, nil
	}
	var s string
	if err := value.Decode(&s); err != nil {
		return nil, err
	}
	return []string{s}, nil
}

// --- boolean combinators ---

type all []Predicate

func (a all) Match(s Subject) bool {
	for _, p := range a {
		if !p.Match(s) {
			return false
		}
	}
	return true
}

type any []Predicate

func (a any) Match(s Subject) bool {
	for _, p := range a {
		if p.Match(s) {
			return true
		}
	}
	return false
}

type not struct{ inner Predicate }

func (n not) Match(s Subject) bool { return !n.inner.Match(s) }

func init() {
	register("all", func(v *yaml.Node) (Predicate, error) {
		preds, err := parseSeq(v)
		if err != nil {
			return nil, err
		}
		return all(preds), nil
	})
	register("any", func(v *yaml.Node) (Predicate, error) {
		preds, err := parseSeq(v)
		if err != nil {
			return nil, err
		}
		return any(preds), nil
	})
	register("not", func(v *yaml.Node) (Predicate, error) {
		p, err := parseNode(v)
		if err != nil {
			return nil, err
		}
		return not{p}, nil
	})
}

// --- leaf nodes ---

type cidrPred []netip.Prefix

func (c cidrPred) Match(s Subject) bool {
	addr, err := netip.ParseAddr(s.Host.IP)
	if err != nil {
		return false
	}
	for _, p := range c {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

type ipPred []netip.Addr

func (ip ipPred) Match(s Subject) bool {
	addr, err := netip.ParseAddr(s.Host.IP)
	if err != nil {
		return false
	}
	for _, a := range ip {
		if a == addr {
			return true
		}
	}
	return false
}

// macPred matches a host MAC against a full address or an OUI prefix. Entries
// with fewer than six octets match on an octet boundary (so "aa:bb:cc" matches
// "aa:bb:cc:dd:ee:ff" but never a partial octet).
type macPred []string

func (m macPred) Match(s Subject) bool {
	if s.Host.MAC == "" {
		return false
	}
	for _, e := range m {
		if s.Host.MAC == e || strings.HasPrefix(s.Host.MAC, e+":") {
			return true
		}
	}
	return false
}

type namePred struct {
	re *regexp.Regexp
}

func (n namePred) Match(s Subject) bool { return n.re.MatchString(s.Host.Name) }

type labelPred map[string]*regexp.Regexp

func (l labelPred) Match(s Subject) bool {
	for k, re := range l {
		v, ok := s.Host.Labels[k]
		if !ok || !re.MatchString(v) {
			return false
		}
	}
	return true
}

type sourcePred []string

func (sp sourcePred) Match(s Subject) bool {
	for _, id := range sp {
		if s.Source == id {
			return true
		}
	}
	return false
}

type hasMACPred bool

func (h hasMACPred) Match(s Subject) bool { return (s.Host.MAC != "") == bool(h) }

func init() {
	register("cidr", func(v *yaml.Node) (Predicate, error) {
		raw, err := decodeStrings(v)
		if err != nil {
			return nil, err
		}
		prefixes := make(cidrPred, 0, len(raw))
		for _, r := range raw {
			p, err := netip.ParsePrefix(r)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR %q: %w", r, err)
			}
			prefixes = append(prefixes, p.Masked())
		}
		return prefixes, nil
	})

	register("ip", func(v *yaml.Node) (Predicate, error) {
		raw, err := decodeStrings(v)
		if err != nil {
			return nil, err
		}
		addrs := make(ipPred, 0, len(raw))
		for _, r := range raw {
			a, err := netip.ParseAddr(r)
			if err != nil {
				return nil, fmt.Errorf("invalid IP %q: %w", r, err)
			}
			addrs = append(addrs, a)
		}
		return addrs, nil
	})

	register("mac", func(v *yaml.Node) (Predicate, error) {
		raw, err := decodeStrings(v)
		if err != nil {
			return nil, err
		}
		entries := make(macPred, 0, len(raw))
		for _, r := range raw {
			entries = append(entries, strings.ToLower(strings.TrimSpace(r)))
		}
		return entries, nil
	})

	register("name", func(v *yaml.Node) (Predicate, error) {
		var s string
		if err := v.Decode(&s); err != nil {
			return nil, err
		}
		re, err := compileMatch(s)
		if err != nil {
			return nil, err
		}
		return namePred{re}, nil
	})

	register("label", func(v *yaml.Node) (Predicate, error) {
		var m map[string]string
		if err := v.Decode(&m); err != nil {
			return nil, err
		}
		lp := make(labelPred, len(m))
		for k, glob := range m {
			re, err := compileMatch(glob)
			if err != nil {
				return nil, fmt.Errorf("label %q: %w", k, err)
			}
			lp[k] = re
		}
		return lp, nil
	})

	register("source", func(v *yaml.Node) (Predicate, error) {
		raw, err := decodeStrings(v)
		if err != nil {
			return nil, err
		}
		return sourcePred(raw), nil
	})

	register("has_mac", func(v *yaml.Node) (Predicate, error) {
		var b bool
		if err := v.Decode(&b); err != nil {
			return nil, err
		}
		return hasMACPred(b), nil
	})
}

// compileMatch turns a match expression into a regexp: a "re:"-prefixed value
// is compiled as a regular expression (unanchored), anything else is treated as
// an anchored glob supporting * and ?.
func compileMatch(expr string) (*regexp.Regexp, error) {
	if rest, ok := strings.CutPrefix(expr, "re:"); ok {
		return regexp.Compile(rest)
	}
	return globToRegexp(expr)
}

// Glob compiles a glob pattern (supporting * and ?) into an anchored regexp. It
// is exported for reuse by ownership matching in the sinks.
func Glob(pattern string) (*regexp.Regexp, error) { return globToRegexp(pattern) }

func globToRegexp(glob string) (*regexp.Regexp, error) {
	var b strings.Builder
	b.WriteByte('^')
	for _, r := range glob {
		switch r {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteByte('.')
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	b.WriteByte('$')
	return regexp.Compile(b.String())
}
