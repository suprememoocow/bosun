package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/suprememoocow/bosun/internal/sink/clients"
)

// renderPlan writes the clients plan in the requested format.
func renderPlan(w io.Writer, plan *clients.Plan, format string, noColor bool) error {
	switch format {
	case "json":
		return renderJSON(w, plan)
	case "text", "":
		return renderText(w, plan, noColor)
	default:
		return fmt.Errorf("unknown output format %q (want text or json)", format)
	}
}

func renderJSON(w io.Writer, plan *clients.Plan) error {
	counts := map[string]int{}
	for op, n := range plan.Counts() {
		counts[string(op)] = n
	}
	out := struct {
		Sink    string           `json:"sink"`
		Counts  map[string]int   `json:"counts"`
		Actions []clients.Action `json:"actions"`
		Vetoed  []string         `json:"vetoed,omitempty"`
		Ignored []string         `json:"ignored,omitempty"`
	}{
		Sink:    "clients",
		Counts:  counts,
		Actions: plan.Actions,
		Vetoed:  plan.Vetoed,
		Ignored: plan.Ignored,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func renderText(w io.Writer, plan *clients.Plan, noColor bool) error {
	c := colors(noColor)
	counts := plan.Counts()
	fmt.Fprintf(w, "clients: %d create, %d update, %d delete, %d noop (%d vetoed, %d ignored)\n",
		counts[clients.OpCreate], counts[clients.OpUpdate], counts[clients.OpDelete], counts[clients.OpNoop],
		len(plan.Vetoed), len(plan.Ignored))

	for _, a := range plan.Actions {
		if a.Op == clients.OpNoop {
			continue // keep the diff focused on changes
		}
		sym, col := symbol(a.Op)
		line := fmt.Sprintf("  %s %-8s %-24s [%s]", sym, a.Op, a.Name, strings.Join(a.IDs, ", "))
		if len(a.Tags) > 0 {
			line += " tags:[" + strings.Join(a.Tags, ", ") + "]"
		}
		if a.Reason != "" {
			line += "  (" + a.Reason + ")"
		}
		fmt.Fprintln(w, c(col, line))
	}

	if len(plan.Vetoed) > 0 {
		fmt.Fprintf(w, "  vetoed (unmanaged id kinds): %s\n", strings.Join(plan.Vetoed, ", "))
	}
	if len(plan.Ignored) > 0 {
		fmt.Fprintf(w, "  ignored (unowned): %s\n", strings.Join(plan.Ignored, ", "))
	}
	return nil
}

func symbol(op clients.Op) (string, string) {
	switch op {
	case clients.OpCreate:
		return "+", "green"
	case clients.OpUpdate:
		return "~", "yellow"
	case clients.OpDelete:
		return "-", "red"
	default:
		return " ", ""
	}
}

// colors returns a colouring function honouring the --no-color flag.
func colors(noColor bool) func(color, s string) string {
	codes := map[string]string{"green": "32", "yellow": "33", "red": "31"}
	return func(color, s string) string {
		code, ok := codes[color]
		if noColor || !ok {
			return s
		}
		return "\x1b[" + code + "m" + s + "\x1b[0m"
	}
}
