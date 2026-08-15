// Package config defines Bosun's YAML schema and loads it: parse, secret
// expansion, then validation. Per-source config is captured opaquely and passed
// through verbatim, so adding a source type needs no host change (design doc
// §4.4, §5).
package config

import (
	"fmt"
	"os"
	"time"

	"github.com/suprememoocow/bosun/internal/predicate"
	"github.com/suprememoocow/bosun/internal/secret"
	"gopkg.in/yaml.v3"
)

// Config is the whole bosun.yaml document.
type Config struct {
	Version  int           `yaml:"version"`
	Plugins  Plugins       `yaml:"plugins"`
	Adguard  Adguard       `yaml:"adguard"`
	Sources  []Source      `yaml:"sources"`
	Clients  *ClientsSink  `yaml:"adguard_clients"`
	Rewrites *RewritesSink `yaml:"adguard_rewrites"`
}

// Plugins holds host-wide plugin execution settings.
type Plugins struct {
	Dir            string   `yaml:"dir"`
	Timeout        Duration `yaml:"timeout"`
	MaxConcurrency int      `yaml:"max_concurrency"`
	// MaxRecords caps how many host records a single plugin may emit before the
	// runner aborts it as a runaway (design doc §4.3).
	MaxRecords int `yaml:"max_records"`
}

// Plugin execution defaults, applied when a field is left zero (design doc §5).
const (
	defaultPluginTimeout  = 30 * time.Second
	defaultMaxConcurrency = 4
	defaultMaxRecords     = 50000
)

// Adguard is the sink endpoint.
type Adguard struct {
	Address  string        `yaml:"address"`
	Username string        `yaml:"username"`
	Password secret.String `yaml:"password"`
}

// Source is one record source. The host owns a closed set of keys; Config is an
// opaque subtree handed to the plugin verbatim (design doc §5).
type Source struct {
	ID      string    `yaml:"id"`
	Type    string    `yaml:"type"`
	Command string    `yaml:"command"`
	Timeout Duration  `yaml:"timeout"`
	Config  yaml.Node `yaml:"config"`
}

// ClientsSink configures the AdGuard persistent-clients reconciler.
type ClientsSink struct {
	Sources        []string         `yaml:"sources"`
	Filter         predicate.Filter `yaml:"filter"`
	Defaults       ClientDefaults   `yaml:"defaults"`
	Enrichment     []EnrichmentRule `yaml:"enrichment"`
	ManagedIDKinds []string         `yaml:"managed_id_kinds"`
	OnMixedIDs     string           `yaml:"on_mixed_ids"`
	OnNameClash    NameClash        `yaml:"on_name_clash"`
	Ownership      Ownership        `yaml:"ownership"`
	Prune          bool             `yaml:"prune"`
}

// ClientDefaults are applied to every client the tool creates. Modelled as
// pointers so "unset" is distinguishable from "false"; expanded in M2.
type ClientDefaults struct {
	UseGlobalSettings *bool `yaml:"use_global_settings"`
	FilteringEnabled  *bool `yaml:"filtering_enabled"`
}

// EnrichmentRule pairs a selector with the mutation to apply. set replaces a
// field; merge unions lists and maps. All matching rules apply, in order.
type EnrichmentRule struct {
	Match predicate.Node `yaml:"match"`
	Set   Enrichment     `yaml:"set"`
	Merge Enrichment     `yaml:"merge"`
}

// Enrichment is the set of fields an enrichment rule can write. Grows in M2.
type Enrichment struct {
	Tags []string `yaml:"tags"`
}

// NameClash configures deterministic name-clash resolution (design doc §7.5).
type NameClash struct {
	Template string `yaml:"template"`
	Fallback string `yaml:"fallback"`
}

// Ownership bounds which live objects the tool may delete when pruning.
type Ownership struct {
	Include []string `yaml:"include"`
	Exclude []string `yaml:"exclude"`
}

// RewritesSink configures the DNS-rewrites reconciler.
type RewritesSink struct {
	Sources   []string         `yaml:"sources"`
	Filter    predicate.Filter `yaml:"filter"`
	Domain    DomainConfig     `yaml:"domain"`
	Conflict  string           `yaml:"conflict"`
	Ownership Ownership        `yaml:"ownership"`
	Prune     bool             `yaml:"prune"`
}

// DomainConfig templates a bare hostname into an FQDN, with per-source overrides.
type DomainConfig struct {
	Template  string            `yaml:"template"`
	PerSource map[string]string `yaml:"per_source"`
}

// Duration is a time.Duration that unmarshals from a Go duration string ("30s").
type Duration time.Duration

func (d Duration) Duration() time.Duration { return time.Duration(d) }

func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	*d = Duration(parsed)
	return nil
}

// applyDefaults fills in zero-valued plugin execution settings.
func (c *Config) applyDefaults() {
	if c.Plugins.Timeout == 0 {
		c.Plugins.Timeout = Duration(defaultPluginTimeout)
	}
	if c.Plugins.MaxConcurrency == 0 {
		c.Plugins.MaxConcurrency = defaultMaxConcurrency
	}
	if c.Plugins.MaxRecords == 0 {
		c.Plugins.MaxRecords = defaultMaxRecords
	}
}

// LoadOptions tunes loading.
type LoadOptions struct {
	// AllowCmd enables ${cmd:...} secret expansion.
	AllowCmd bool
}

// Load reads, expands and validates a config file. It returns the config, any
// non-fatal warnings (e.g. plaintext secrets), and a fatal error.
func Load(path string, opts LoadOptions) (*Config, []string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("reading config: %w", err)
	}
	return Parse(data, opts)
}

// Parse expands and validates config from bytes (Load without the file read, so
// tests need no temp files).
func Parse(data []byte, opts LoadOptions) (*Config, []string, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, nil, fmt.Errorf("parsing YAML: %w", err)
	}

	warnings, err := secret.Expander{AllowCmd: opts.AllowCmd}.ExpandTree(&root)
	if err != nil {
		return nil, warnings, fmt.Errorf("expanding secrets: %w", err)
	}

	var cfg Config
	if err := root.Decode(&cfg); err != nil {
		return nil, warnings, fmt.Errorf("decoding config: %w", err)
	}
	cfg.applyDefaults()

	vWarnings, err := cfg.Validate()
	warnings = append(warnings, vWarnings...)
	if err != nil {
		return nil, warnings, err
	}
	return &cfg, warnings, nil
}
