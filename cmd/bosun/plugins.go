package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/suprememoocow/bosun/internal/config"
	"github.com/suprememoocow/bosun/internal/runner"
)

func cmdPlugins(ctx context.Context, args []string) int {
	if len(args) < 1 || args[0] != "list" {
		fmt.Fprintln(os.Stderr, "usage: bosun plugins list")
		return 2
	}
	fs := flag.NewFlagSet("plugins list", flag.ContinueOnError)
	g := registerGlobal(fs)
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	log := g.logger()

	// Config is optional here — listing plugins should work without a valid
	// sink config. We only want plugins.dir if it is available.
	dir := ""
	if cfg, _, err := config.Load(g.config, config.LoadOptions{AllowCmd: g.allowCmd}); err == nil {
		dir = cfg.Plugins.Dir
	}

	plugins := discoverPlugins(dir)
	if len(plugins) == 0 {
		fmt.Println("no bosun-plugin-* binaries found")
		return 0
	}

	r := &runner.Runner{Log: log}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "BINARY\tTYPE\tVERSION\tCAPABILITIES\tPATH")
	for _, p := range plugins {
		dctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		d, err := r.Describe(dctx, runner.Spec{Command: p})
		cancel()
		base := filepath.Base(p)
		if err != nil {
			fmt.Fprintf(tw, "%s\t?\t?\t?\t%s (describe failed)\n", base, p)
			continue
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", base, d.Type, d.Version, strings.Join(d.Capabilities, ","), p)
	}
	if err := tw.Flush(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

// discoverPlugins finds bosun-plugin-* binaries, searching the configured
// plugins dir (if any), then always the executable's own dir, then $PATH,
// deduplicated by binary name.
func discoverPlugins(dir string) []string {
	var dirs []string
	if dir != "" {
		dirs = append(dirs, dir)
	}
	if exe, err := os.Executable(); err == nil {
		dirs = append(dirs, filepath.Dir(exe))
	}
	dirs = append(dirs, filepath.SplitList(os.Getenv("PATH"))...)

	seen := map[string]bool{}
	var out []string
	for _, d := range dirs {
		matches, _ := filepath.Glob(filepath.Join(d, "bosun-plugin-*"))
		for _, m := range matches {
			base := filepath.Base(m)
			if seen[base] {
				continue
			}
			info, err := os.Stat(m)
			if err != nil || info.IsDir() || info.Mode()&0o111 == 0 {
				continue
			}
			seen[base] = true
			out = append(out, m)
		}
	}
	return out
}
