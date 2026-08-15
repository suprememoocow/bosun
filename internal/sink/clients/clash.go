package clients

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"text/template"

	"github.com/suprememoocow/bosun/internal/config"
)

// errPreserveUnsupported is returned when on_mixed_ids: preserve is configured;
// M2 ships skip (design doc §7.2, open question 1).
var errPreserveUnsupported = errors.New("on_mixed_ids: preserve is not implemented yet (M2 ships skip)")

// templateData is what the clash template is rendered against. Label keys have
// '.' and '-' replaced with '_' so a label like "omada.network" is reachable as
// {{ .Labels.omada_network }} (design doc §5, §7.5).
type templateData struct {
	Name   string
	IP     string
	MAC    string
	Labels map[string]string
}

func newTemplateData(name, ip, mac string, labels map[string]string) templateData {
	t := templateData{Name: name, IP: ip, MAC: mac, Labels: make(map[string]string, len(labels))}
	for k, v := range labels {
		t.Labels[templateKey(k)] = v
	}
	return t
}

var templateKeyReplacer = strings.NewReplacer(".", "_", "-", "_")

func templateKey(k string) string { return templateKeyReplacer.Replace(k) }

// macSuffix returns the last three octets of a normalised MAC without
// separators (e.g. "aa:bb:cc:dd:ee:ff" -> "ddeeff"), or "" if unavailable.
func macSuffix(mac string) string {
	if mac == "" {
		return ""
	}
	parts := strings.Split(mac, ":")
	if len(parts) < 3 {
		return ""
	}
	return strings.Join(parts[len(parts)-3:], "")
}

// resolveClashes renames desired clients whose names collide, in place. A name
// clashes if two desired clients share it, or it collides with a vetoed live
// client that cannot be updated or clobbered. Every member of a clash is
// prefixed (not just the losers) so each final name is a function of that
// client's own content, making the result deterministic across runs regardless
// of map iteration order (design doc §7.5, principle 7).
func resolveClashes(desired []desiredClient, vetoed map[string]bool, policy config.NameClash) error {
	count := map[string]int{}
	for i := range desired {
		count[desired[i].Name]++
	}

	// taken: names already fixed. Non-clashing desired clients keep their name;
	// vetoed live names are reserved.
	taken := make(map[string]bool, len(desired))
	for n := range vetoed {
		taken[n] = true
	}
	var clashing []int
	for i := range desired {
		if count[desired[i].Name] > 1 || vetoed[desired[i].Name] {
			clashing = append(clashing, i)
		} else {
			taken[desired[i].Name] = true
		}
	}
	if len(clashing) == 0 {
		return nil
	}

	// Assign in a content-derived order so `taken` checks are deterministic.
	sort.Slice(clashing, func(a, b int) bool {
		da, db := &desired[clashing[a]], &desired[clashing[b]]
		if da.Name != db.Name {
			return da.Name < db.Name
		}
		if da.macSuffix != db.macSuffix {
			return da.macSuffix < db.macSuffix
		}
		return strings.Join(da.IDs, ",") < strings.Join(db.IDs, ",")
	})

	var tmpl *template.Template
	if policy.Template != "" {
		// Syntax was validated at config load; a parse failure here just means we
		// fall through to the fallback.
		tmpl, _ = template.New("clash").Option("missingkey=zero").Parse(policy.Template)
	}

	for _, i := range clashing {
		d := &desired[i]
		cand := ""
		if tmpl != nil {
			cand = renderTemplate(tmpl, d.repr)
		}
		if cand == "" || taken[cand] {
			fb, err := fallbackName(d, policy.Fallback)
			if err != nil {
				return fmt.Errorf("name clash on %q: %w", d.Name, err)
			}
			cand = fb
		}
		if cand == "" || taken[cand] {
			return fmt.Errorf("name clash on %q: could not derive a unique name (got %q); set on_name_clash.template or fallback", d.Name, cand)
		}
		d.Name = cand
		taken[cand] = true
	}
	return nil
}

func renderTemplate(tmpl *template.Template, td templateData) string {
	var b strings.Builder
	if err := tmpl.Execute(&b, td); err != nil {
		return ""
	}
	// Lowercase for consistency with normalised device names (design doc §7.5
	// renders e.g. "iot-nas"), and trim surrounding hyphens left by an empty
	// label expansion.
	return strings.Trim(strings.ToLower(strings.TrimSpace(b.String())), "-")
}

// fallbackName derives a disambiguated name when the template does not (design
// doc §7.5). mac_suffix (the default) is unique within a group keyed on MAC.
func fallbackName(d *desiredClient, fallback string) (string, error) {
	switch fallback {
	case "", "mac_suffix":
		if d.macSuffix == "" {
			return "", errors.New("fallback mac_suffix needs a MAC but this client has none")
		}
		return d.Name + "-" + d.macSuffix, nil
	case "source":
		if d.source == "" {
			return "", errors.New("fallback source needs a source id")
		}
		return d.source + "-" + d.Name, nil
	case "error":
		return "", errors.New("clashing names and on_name_clash.fallback is \"error\"")
	default:
		return "", fmt.Errorf("unknown on_name_clash.fallback %q", fallback)
	}
}
