// Package clients builds the desired AdGuard persistent-client state from host
// records and reconciles it against live state as a plan.
//
// M0 implements the create/update/no-op/delete diff with the id-kind veto and
// ownership boundary. Enrichment, defaults, (name, MAC) tag handling and
// deterministic clash resolution arrive in M2; where a clash would occur, M0
// fails the sink rather than emit a plan AdGuard would reject.
package clients

import (
	"fmt"
	"slices"

	"github.com/suprememoocow/bosun/internal/adguard"
	"github.com/suprememoocow/bosun/internal/config"
	"github.com/suprememoocow/bosun/internal/predicate"
	"github.com/suprememoocow/bosun/internal/source"
)

// Op is the kind of operation an action represents.
type Op string

const (
	OpCreate Op = "create"
	OpUpdate Op = "update"
	OpDelete Op = "delete"
	OpNoop   Op = "noop"
)

// Action is one planned operation against a client.
type Action struct {
	Op     Op       `json:"op"`
	Name   string   `json:"name"`
	IDs    []string `json:"ids"` // desired ids (create/update) or live ids (delete)
	Reason string   `json:"reason,omitempty"`
}

// Plan is the reconciliation plan for the clients sink.
type Plan struct {
	Actions []Action `json:"actions"`
	// Vetoed lists live client names excluded because they use unmanaged id
	// kinds (subnet/ClientID/mixed). Surfaced so the operator can see them.
	Vetoed []string `json:"vetoed,omitempty"`
	// Ignored lists live, manageable, unowned clients not in desired state —
	// correct behaviour, but a long list may mean ownership.include is wrong.
	Ignored []string `json:"ignored,omitempty"`
}

// Counts returns the number of actions per op, for summaries and safety rails.
func (p *Plan) Counts() map[Op]int {
	c := map[Op]int{}
	for _, a := range p.Actions {
		c[a.Op]++
	}
	return c
}

// BuildPlan reconciles desired client state (built from the sink's sources)
// against live AdGuard clients.
func BuildPlan(sink *config.ClientsSink, bySource map[string]source.Result, live []adguard.PersistentClient) (*Plan, error) {
	desired, err := buildDesired(sink, bySource)
	if err != nil {
		return nil, err
	}
	return diff(sink, desired, live)
}

// desiredClient is a fanned-in client: one name, a set of ids.
type desiredClient struct {
	Name string
	IDs  []string
}

// buildDesired concatenates the sink's sources in order, filters, and groups
// records into clients by (name, MAC) (design doc §7.1).
func buildDesired(sink *config.ClientsSink, bySource map[string]source.Result) ([]desiredClient, error) {
	type group struct {
		name string
		ips  map[string]bool
		macs map[string]bool
	}
	groups := map[string]*group{}
	var order []string // group keys in first-seen order, for determinism

	for _, id := range sink.Sources {
		res, ok := bySource[id]
		if !ok {
			// A source that failed to fetch fails only the sinks referencing it;
			// here it is simply absent. The caller decides whether that is fatal.
			continue
		}
		for _, h := range res.Records {
			if !sink.Filter.Matches(predicate.Subject{Host: h, Source: id}) {
				continue
			}
			key := h.Name + "\x00" + h.MAC // (name, MAC); MAC may be empty
			g, ok := groups[key]
			if !ok {
				g = &group{name: h.Name, ips: map[string]bool{}, macs: map[string]bool{}}
				groups[key] = g
				order = append(order, key)
			}
			if h.IP != "" {
				g.ips[h.IP] = true
			}
			if h.MAC != "" {
				g.macs[h.MAC] = true
			}
		}
	}

	desired := make([]desiredClient, 0, len(order))
	seenNames := map[string]bool{}
	for _, key := range order {
		g := groups[key]
		ids := make([]string, 0, len(g.ips)+len(g.macs))
		for ip := range g.ips {
			ids = append(ids, ip)
		}
		for mac := range g.macs {
			ids = append(ids, mac)
		}
		slices.Sort(ids)
		if seenNames[g.name] {
			// Deterministic clash resolution is M2; until then, refuse rather than
			// emit a plan AdGuard rejects (design doc §7.5).
			return nil, fmt.Errorf("name clash on %q: two distinct devices resolve to the same client name (clash resolution arrives in M2)", g.name)
		}
		seenNames[g.name] = true
		desired = append(desired, desiredClient{Name: g.name, IDs: ids})
	}
	slices.SortFunc(desired, func(a, b desiredClient) int {
		if a.Name < b.Name {
			return -1
		}
		if a.Name > b.Name {
			return 1
		}
		return 0
	})
	return desired, nil
}
