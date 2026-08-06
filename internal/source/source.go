// Package source fetches host records for a configured source. In M0 the only
// source type is the built-in "static" source, which reads records straight
// from config and is the permanent test-fixture mechanism (design doc §9). The
// plugin runner is added as another provider in M1.
package source

import (
	"context"
	"fmt"

	"github.com/suprememoocow/bosun/internal/config"
	"github.com/suprememoocow/bosun/pkg/hostrecord"
)

// Result is the outcome of fetching one source: the normalised records plus any
// diagnostics produced during normalisation.
type Result struct {
	Records []hostrecord.Host
	Diags   []hostrecord.Diag
}

// Fetch resolves and fetches a single source. Records are normalised host-side
// (design doc §4.4) before being returned, so callers never see raw plugin
// output.
func Fetch(ctx context.Context, src config.Source) (Result, error) {
	var raw []hostrecord.Host
	var err error

	switch src.Type {
	case "static":
		raw, err = fetchStatic(src)
	case "":
		return Result{}, fmt.Errorf("source %q: no type set (explicit command sources arrive in M1)", src.ID)
	default:
		return Result{}, fmt.Errorf("source %q: type %q requires a plugin, not supported until M1", src.ID, src.Type)
	}
	if err != nil {
		return Result{}, fmt.Errorf("source %q: %w", src.ID, err)
	}

	return normalize(raw), nil
}

// normalize applies host-side normalisation, dropping records left with no
// usable address and collecting diagnostics.
func normalize(raw []hostrecord.Host) Result {
	var res Result
	for _, r := range raw {
		h, diags, ok := hostrecord.Normalize(r)
		res.Diags = append(res.Diags, diags...)
		if ok {
			res.Records = append(res.Records, h)
		}
	}
	return res
}
