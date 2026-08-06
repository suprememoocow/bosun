package clients

import (
	"fmt"
	"regexp"
	"slices"
	"sort"

	"github.com/suprememoocow/bosun/internal/adguard"
	"github.com/suprememoocow/bosun/internal/config"
	"github.com/suprememoocow/bosun/internal/predicate"
)

// ownership compiles include/exclude globs once for reuse across the diff.
type ownership struct {
	include []*regexp.Regexp
	exclude []*regexp.Regexp
}

func compileOwnership(o config.Ownership) (ownership, error) {
	include := o.Include
	if len(include) == 0 {
		include = []string{"*"} // default per design doc §7.4
	}
	own := ownership{}
	for _, p := range include {
		re, err := predicate.Glob(p)
		if err != nil {
			return own, fmt.Errorf("ownership.include %q: %w", p, err)
		}
		own.include = append(own.include, re)
	}
	for _, p := range o.Exclude {
		re, err := predicate.Glob(p)
		if err != nil {
			return own, fmt.Errorf("ownership.exclude %q: %w", p, err)
		}
		own.exclude = append(own.exclude, re)
	}
	return own, nil
}

// owns reports whether a manageable client is within the ownership boundary and
// so eligible for pruning.
func (o ownership) owns(name string) bool {
	matched := false
	for _, re := range o.include {
		if re.MatchString(name) {
			matched = true
			break
		}
	}
	if !matched {
		return false
	}
	for _, re := range o.exclude {
		if re.MatchString(name) {
			return false
		}
	}
	return true
}

// diff computes the plan from desired and live state.
func diff(sink *config.ClientsSink, desired []desiredClient, live []adguard.PersistentClient) (*Plan, error) {
	managed := newManagedKinds(sink.ManagedIDKinds)
	own, err := compileOwnership(sink.Ownership)
	if err != nil {
		return nil, err
	}

	liveByName := make(map[string]adguard.PersistentClient, len(live))
	vetoed := map[string]bool{}
	for _, c := range live {
		liveByName[c.Name] = c
		if !managed.manageable(c.IDs) {
			vetoed[c.Name] = true
		}
	}

	plan := &Plan{}
	desiredNames := map[string]bool{}

	for _, d := range desired {
		desiredNames[d.Name] = true
		liveClient, exists := liveByName[d.Name]
		switch {
		case !exists:
			plan.Actions = append(plan.Actions, Action{Op: OpCreate, Name: d.Name, IDs: d.IDs})
		case vetoed[d.Name]:
			// Desired name collides with a vetoed live client, which cannot be
			// updated or clobbered. Deterministic disambiguation is M2 (§7.2/§7.5);
			// until then, refuse rather than risk destroying the live client.
			return nil, fmt.Errorf("client %q collides with a hand-maintained (vetoed) client of the same name; disambiguation arrives in M2", d.Name)
		case idsEqual(d.IDs, liveClient.IDs):
			plan.Actions = append(plan.Actions, Action{Op: OpNoop, Name: d.Name, IDs: d.IDs})
		default:
			plan.Actions = append(plan.Actions, Action{
				Op:     OpUpdate,
				Name:   d.Name,
				IDs:    d.IDs,
				Reason: fmt.Sprintf("ids %v -> %v", sortedCopy(liveClient.IDs), d.IDs),
			})
		}
	}

	// Deletes and ignores over live clients not in desired state.
	for _, c := range live {
		if desiredNames[c.Name] {
			continue
		}
		if vetoed[c.Name] {
			plan.Vetoed = append(plan.Vetoed, c.Name)
			continue
		}
		if sink.Prune && own.owns(c.Name) {
			plan.Actions = append(plan.Actions, Action{Op: OpDelete, Name: c.Name, IDs: sortedCopy(c.IDs)})
		} else {
			plan.Ignored = append(plan.Ignored, c.Name)
		}
	}

	sort.Strings(plan.Vetoed)
	sort.Strings(plan.Ignored)
	sortActions(plan.Actions)
	return plan, nil
}

// idsEqual compares two id lists as sets.
func idsEqual(a, b []string) bool {
	return slices.Equal(sortedCopy(a), sortedCopy(b))
}

func sortedCopy(s []string) []string {
	out := slices.Clone(s)
	slices.Sort(out)
	return out
}

// sortActions orders actions deterministically: by op then name.
func sortActions(actions []Action) {
	order := map[Op]int{OpCreate: 0, OpUpdate: 1, OpDelete: 2, OpNoop: 3}
	slices.SortFunc(actions, func(a, b Action) int {
		if order[a.Op] != order[b.Op] {
			return order[a.Op] - order[b.Op]
		}
		switch {
		case a.Name < b.Name:
			return -1
		case a.Name > b.Name:
			return 1
		default:
			return 0
		}
	})
}
