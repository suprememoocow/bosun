package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
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

	switch *sinkFlag {
	case "", "clients":
	case "rewrites":
		fmt.Fprintln(os.Stderr, "rewrites planning is implemented in M3")
		return 1
	default:
		fmt.Fprintf(os.Stderr, "unknown sink %q (want clients or rewrites)\n", *sinkFlag)
		return 2
	}

	in, err := loadClientsPlan(ctx, g, log)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}
	if err := renderPlan(os.Stdout, in.plan, *output, g.noColor); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}
	return 0
}

// clientsPlanInputs bundles everything a plan or apply needs for the clients sink.
type clientsPlanInputs struct {
	cfg        *config.Config
	ag         *adguard.Client
	live       []adguard.PersistentClient
	liveByName map[string]adguard.PersistentClient
	plan       *clients.Plan
}

// loadClientsPlan loads config, fetches sources once, reads live AdGuard state
// and builds the clients reconciliation plan. It makes no mutating calls.
func loadClientsPlan(ctx context.Context, g *globalFlags, log *slog.Logger) (*clientsPlanInputs, error) {
	cfg, warnings, err := config.Load(g.config, config.LoadOptions{AllowCmd: g.allowCmd})
	for _, w := range warnings {
		log.Warn("config warning", "detail", w)
	}
	if err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	if cfg.Clients == nil {
		return nil, errors.New("no adguard_clients sink configured")
	}

	bySource, err := fetchSources(ctx, cfg, cfg.Clients.Sources, log)
	if err != nil {
		return nil, err
	}

	ag, err := adguard.New(cfg.Adguard.Address, cfg.Adguard.Username, cfg.Adguard.Password.Reveal())
	if err != nil {
		return nil, err
	}
	live, err := ag.ListClients(ctx)
	if err != nil {
		return nil, fmt.Errorf("reading live AdGuard clients: %w", err)
	}

	plan, err := clients.BuildPlan(cfg.Clients, bySource, live)
	if err != nil {
		return nil, fmt.Errorf("building clients plan: %w", err)
	}

	byName := make(map[string]adguard.PersistentClient, len(live))
	for _, c := range live {
		byName[c.Name] = c
	}
	return &clientsPlanInputs{cfg: cfg, ag: ag, live: live, liveByName: byName, plan: plan}, nil
}

// fetchSources fetches the given source ids once each (bounded concurrency,
// diagnostics logged), keyed by id — via the source.Fetcher, which dispatches
// static sources inline and plugin sources through the runner.
func fetchSources(ctx context.Context, cfg *config.Config, ids []string, log *slog.Logger) (map[string]source.Result, error) {
	byID := make(map[string]config.Source, len(cfg.Sources))
	for _, s := range cfg.Sources {
		byID[s.ID] = s
	}
	return source.NewFetcher(cfg.Plugins, log).FetchAll(ctx, byID, ids)
}
