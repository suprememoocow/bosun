package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/suprememoocow/bosun/internal/config"
	"github.com/suprememoocow/bosun/internal/source"
)

func cmdSources(ctx context.Context, args []string) int {
	if len(args) < 1 || args[0] != "run" {
		fmt.Fprintln(os.Stderr, "usage: bosun sources run [flags] <id>")
		return 2
	}

	fs := flag.NewFlagSet("sources run", flag.ContinueOnError)
	g := registerGlobal(fs)

	// Accept the id before or after flags: Go's flag package stops at the first
	// positional, so pull a leading id out before parsing the remaining flags.
	rest := args[1:]
	id := ""
	if len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
		id, rest = rest[0], rest[1:]
	}
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	if id == "" {
		id = fs.Arg(0)
	}
	if id == "" {
		fmt.Fprintln(os.Stderr, "usage: bosun sources run [flags] <id>")
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

	var src *config.Source
	for i := range cfg.Sources {
		if cfg.Sources[i].ID == id {
			src = &cfg.Sources[i]
			break
		}
	}
	if src == nil {
		fmt.Fprintf(os.Stderr, "unknown source %q\n", id)
		return 1
	}

	// Dump the raw NDJSON to stdout; completeness is still enforced, so a
	// non-zero exit means the dump is not trustworthy.
	if err := source.NewFetcher(cfg.Plugins, log).DumpNDJSON(ctx, *src, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}
	return 0
}
