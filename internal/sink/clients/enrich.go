package clients

import (
	"slices"

	"github.com/suprememoocow/bosun/internal/config"
	"github.com/suprememoocow/bosun/internal/predicate"
)

// applyEnrichment evaluates the enrichment rules against a group's records and
// returns the resulting client tags (design doc §5, §7.1). Rules are applied in
// order and a rule applies to the client if it matches any of the group's
// records: `set` replaces the accumulated tags, `merge` unions into them. The
// result is sorted and de-duplicated for determinism.
func applyEnrichment(rules []config.EnrichmentRule, subjects []predicate.Subject) []string {
	if len(rules) == 0 {
		return nil
	}
	var tags []string
	for _, rule := range rules {
		if !matchesAny(rule.Match, subjects) {
			continue
		}
		if len(rule.Set.Tags) > 0 {
			tags = slices.Clone(rule.Set.Tags)
		}
		if len(rule.Merge.Tags) > 0 {
			tags = union(tags, rule.Merge.Tags)
		}
	}
	if len(tags) == 0 {
		return nil
	}
	slices.Sort(tags)
	return slices.Compact(tags)
}

// matchesAny reports whether the predicate matches any subject in the group. An
// absent match (nil predicate) never applies.
func matchesAny(node predicate.Node, subjects []predicate.Subject) bool {
	if node.Predicate == nil {
		return false
	}
	for _, s := range subjects {
		if node.Match(s) {
			return true
		}
	}
	return false
}

func union(a, b []string) []string {
	seen := make(map[string]bool, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, s := range append(slices.Clone(a), b...) {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
