package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/suprememoocow/bosun/internal/adguard"
	"github.com/suprememoocow/bosun/internal/config"
	"github.com/suprememoocow/bosun/internal/sink/clients"
	"github.com/suprememoocow/bosun/internal/source"
)

func cmdPlan(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("plan", flag.ContinueOnError)
	g := registerGlobal(fs)
	sinkFlag := fs.String("sink", "", "limit to a single sink: clients or rewrites")
	output := fs.String("o", "text", "output format: text or json")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	log := g.logger()

	cfg, warnings, err := config.Load(g.config, config.LoadOptions{AllowCmd: g.allowCmd})
	for _, w := range warnings {
		log.Warn("config warning", "detail", w)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid config: %v\n", err)
		return 1
	}

	switch *sinkFlag {
	case "", "clients", "rewrites":
	default:
		fmt.Fprintf(os.Stderr, "unknown sink %q (want clients or rewrites)\n", *sinkFlag)
		return 2
	}

	if *sinkFlag == "rewrites" || (*sinkFlag == "" && cfg.Rewrites != nil && cfg.Clients == nil) {
		fmt.Fprintln(os.Stderr, "rewrites planning is implemented in M3")
		return 1
	}

	if cfg.Clients == nil {
		fmt.Fprintln(os.Stderr, "no adguard_clients sink configured")
		return 1
	}

	// Fetch each referenced source exactly once (design doc principle 2).
	bySource, err := fetchSources(ctx, cfg, cfg.Clients.Sources, log)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}

	ag, err := adguard.New(cfg.Adguard.Address, cfg.Adguard.Username, cfg.Adguard.Password.Reveal())
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}
	live, err := ag.ListClients(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "reading live AdGuard clients: %v\n", err)
		return 1
	}

	plan, err := clients.BuildPlan(cfg.Clients, bySource, live)
	if err != nil {
		fmt.Fprintf(os.Stderr, "building clients plan: %v\n", err)
		return 1
	}

	if err := renderPlan(os.Stdout, plan, *output, g.noColor); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}
	return 0
}

// fetchSources fetches the given source ids once each, keyed by id.
func fetchSources(ctx context.Context, cfg *config.Config, ids []string, log logger) (map[string]source.Result, error) {
	byID := map[string]config.Source{}
	for _, s := range cfg.Sources {
		byID[s.ID] = s
	}
	results := map[string]source.Result{}
	for _, id := range ids {
		if _, done := results[id]; done {
			continue
		}
		src, ok := byID[id]
		if !ok {
			return nil, fmt.Errorf("sink references unknown source %q", id)
		}
		res, err := source.Fetch(ctx, src)
		if err != nil {
			return nil, err
		}
		for _, d := range res.Diags {
			log.Warn("record dropped", "source", id, "reason", d.Reason, "detail", d.Msg)
		}
		results[id] = res
	}
	return results, nil
}

// logger is the subset of *slog.Logger used here, kept small for readability.
type logger interface {
	Warn(msg string, args ...any)
}
