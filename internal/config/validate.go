package config

import (
	"errors"
	"fmt"
	"slices"
	"text/template"

	"github.com/suprememoocow/bosun/internal/adguard"
)

// Validate checks structural and semantic invariants. It returns warnings
// (non-fatal) and a joined error of every hard failure found, so a single run
// surfaces all problems rather than the first.
func (c *Config) Validate() (warnings []string, err error) {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	if c.Version != 1 {
		add("version must be 1, got %d", c.Version)
	}
	if c.Adguard.Address == "" {
		add("adguard.address is required")
	}

	sourceIDs := map[string]bool{}
	for i, s := range c.Sources {
		switch {
		case s.ID == "":
			add("sources[%d]: id is required", i)
		case sourceIDs[s.ID]:
			add("sources[%d]: duplicate source id %q", i, s.ID)
		default:
			sourceIDs[s.ID] = true
		}
		if s.Type == "" && s.Command == "" {
			add("source %q: one of type or command is required", s.ID)
		}
	}

	if c.Clients != nil {
		warnings = append(warnings, c.validateClients(add, sourceIDs)...)
	}
	if c.Rewrites != nil {
		c.validateRewrites(add, sourceIDs)
	}

	if c.Clients == nil && c.Rewrites == nil {
		add("no sinks configured: define adguard_clients and/or adguard_rewrites")
	}

	return warnings, errors.Join(errs...)
}

func (c *Config) validateClients(add func(string, ...any), sourceIDs map[string]bool) (warnings []string) {
	cl := c.Clients
	if len(cl.Sources) == 0 {
		add("adguard_clients.sources must reference at least one source")
	}
	for _, id := range cl.Sources {
		if !sourceIDs[id] {
			add("adguard_clients.sources: unknown source %q", id)
		}
	}

	for _, k := range cl.ManagedIDKinds {
		if k != "ip" && k != "mac" {
			add("adguard_clients.managed_id_kinds: %q is not a manageable kind (only ip, mac)", k)
		}
	}

	switch cl.OnMixedIDs {
	case "", "skip", "preserve":
	default:
		add("adguard_clients.on_mixed_ids: %q (want skip or preserve)", cl.OnMixedIDs)
	}

	switch cl.OnNameClash.Fallback {
	case "", "mac_suffix", "source", "error":
	default:
		add("adguard_clients.on_name_clash.fallback: %q (want mac_suffix, source or error)", cl.OnNameClash.Fallback)
	}
	if tmpl := cl.OnNameClash.Template; tmpl != "" {
		if _, terr := template.New("clash").Parse(tmpl); terr != nil {
			add("adguard_clients.on_name_clash.template: %v", terr)
		}
	}

	// Enrichment tags must be part of AdGuard's fixed vocabulary; an invalid tag
	// fails the whole update call at apply time (design doc §7.1).
	for i, rule := range cl.Enrichment {
		for _, tag := range slices.Concat(rule.Set.Tags, rule.Merge.Tags) {
			if !adguard.ValidTag(tag) {
				add("adguard_clients.enrichment[%d]: invalid tag %q (not in AdGuard vocabulary)", i, tag)
			}
		}
	}
	return warnings
}

func (c *Config) validateRewrites(add func(string, ...any), sourceIDs map[string]bool) {
	rw := c.Rewrites
	if len(rw.Sources) == 0 {
		add("adguard_rewrites.sources must reference at least one source")
	}
	for _, id := range rw.Sources {
		if !sourceIDs[id] {
			add("adguard_rewrites.sources: unknown source %q", id)
		}
	}

	switch rw.Conflict {
	case "", "first_wins", "last_wins", "error":
	default:
		add("adguard_rewrites.conflict: %q (want first_wins, last_wins or error)", rw.Conflict)
	}

	// For rewrites there is no implicit ownership boundary, so pruning without an
	// explicit include would delete every hand-made rewrite (design doc §7.4).
	if rw.Prune && len(rw.Ownership.Include) == 0 {
		add("adguard_rewrites: prune requires an explicit ownership.include (e.g. \"*.example.com\")")
	}

	if tmpl := rw.Domain.Template; tmpl != "" {
		if _, terr := template.New("domain").Parse(tmpl); terr != nil {
			add("adguard_rewrites.domain.template: %v", terr)
		}
	}
	for src, tmpl := range rw.Domain.PerSource {
		if _, terr := template.New("domain").Parse(tmpl); terr != nil {
			add("adguard_rewrites.domain.per_source[%q]: %v", src, terr)
		}
	}
}
