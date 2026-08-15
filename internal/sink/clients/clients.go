// Package clients builds the desired AdGuard persistent-client state from host
// records and reconciles it against live state as a plan.
//
// The pipeline (design doc §7): concat the sink's sources in order, filter,
// group records into clients by (name, MAC), enrich (tags), resolve name
// clashes deterministically, then diff against live state with the id-kind veto
// and ownership boundary. The plan drives create/update/delete; apply executes
// it with safety rails.
package clients

import (
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
	IDs    []string `json:"ids"`            // desired ids (create/update) or live ids (delete)
	Tags   []string `json:"tags,omitempty"` // desired tags (create/update)
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
	// ManageableLive is the number of live clients that are not vetoed. Safety
	// rails compute the delete fraction over this, not over all live clients.
	ManageableLive int `json:"manageable_live"`
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
	// on_mixed_ids: preserve is an open question (design doc §7.2, open q1); M2
	// ships skip. Refuse rather than silently behave like skip.
	if sink.OnMixedIDs == "preserve" {
		return nil, errPreserveUnsupported
	}

	desired := buildDesired(sink, bySource)

	managed := newManagedKinds(sink.ManagedIDKinds)
	liveByName := make(map[string]adguard.PersistentClient, len(live))
	vetoed := map[string]bool{}
	for _, c := range live {
		liveByName[c.Name] = c
		if !managed.manageable(c.IDs) {
			vetoed[c.Name] = true
		}
	}

	// Resolve name clashes before diffing: two desired clients sharing a name, or
	// a desired name colliding with a vetoed live client that cannot be updated
	// (design doc §7.5).
	if err := resolveClashes(desired, vetoed, sink.OnNameClash); err != nil {
		return nil, err
	}

	return diff(sink, desired, live, liveByName, vetoed)
}

// desiredClient is a fanned-in client: one name, a set of ids and tags, plus the
// data needed to resolve a name clash deterministically.
type desiredClient struct {
	Name string
	IDs  []string
	Tags []string
	// repr is a representative record for the group, used to render the clash
	// template; macSuffix and source feed the clash fallbacks.
	repr      templateData
	macSuffix string
	source    string
}

// buildDesired concatenates the sink's sources in order, filters, groups records
// into clients by (name, MAC) (design doc §7.1) and enriches tags.
func buildDesired(sink *config.ClientsSink, bySource map[string]source.Result) []desiredClient {
	type group struct {
		name     string
		ips      map[string]bool
		macs     map[string]bool
		labels   map[string]string // merged, first-source-wins
		subjects []predicate.Subject
		source   string // first contributing source
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
				g = &group{name: h.Name, ips: map[string]bool{}, macs: map[string]bool{}, labels: map[string]string{}, source: id}
				groups[key] = g
				order = append(order, key)
			}
			if h.IP != "" {
				g.ips[h.IP] = true
			}
			if h.MAC != "" {
				g.macs[h.MAC] = true
			}
			for k, v := range h.Labels {
				if _, exists := g.labels[k]; !exists {
					g.labels[k] = v
				}
			}
			g.subjects = append(g.subjects, predicate.Subject{Host: h, Source: id})
		}
	}

	desired := make([]desiredClient, 0, len(order))
	for _, key := range order {
		g := groups[key]
		ids := make([]string, 0, len(g.ips)+len(g.macs))
		for ip := range g.ips {
			ids = append(ids, ip)
		}
		var firstMAC string
		for mac := range g.macs {
			ids = append(ids, mac)
			if firstMAC == "" || mac < firstMAC {
				firstMAC = mac
			}
		}
		slices.Sort(ids)

		var firstIP string
		for ip := range g.ips {
			if firstIP == "" || ip < firstIP {
				firstIP = ip
			}
		}

		desired = append(desired, desiredClient{
			Name:      g.name,
			IDs:       ids,
			Tags:      applyEnrichment(sink.Enrichment, g.subjects),
			repr:      newTemplateData(g.name, firstIP, firstMAC, g.labels),
			macSuffix: macSuffix(firstMAC),
			source:    g.source,
		})
	}
	slices.SortFunc(desired, func(a, b desiredClient) int {
		return cmpString(a.Name, b.Name)
	})
	return desired
}

func cmpString(a, b string) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}
