// Command bosun reconciles desired network state into AdGuard Home config.
//
// Verbs: `plan`, `apply` (create/update only in M1), `validate`,
// `sources run`, `plugins list`, `version` (design doc §8).
package main

import (
	"context"
	"fmt"
	"os"
)

// version is overridden at build time with -ldflags "-X main.version=...".
var version = "0.0.0-dev"

const usage = `bosun — declarative home network configuration

Usage:
  bosun <command> [flags]

Commands:
  plan             Show the reconciliation diff without mutating AdGuard
  apply            Apply the plan (create/update; deletes/pruning land in M2)
  validate         Parse and validate the configuration
  sources run <id> Dump a source's raw NDJSON output (debugging)
  plugins list     List discovered plugin binaries and their describe output
  version          Print the version

Run "bosun <command> -h" for command-specific flags.
`

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		return 2
	}

	cmd, rest := args[0], args[1:]
	ctx := context.Background()

	switch cmd {
	case "plan":
		return cmdPlan(ctx, rest)
	case "apply":
		return cmdApply(ctx, rest)
	case "validate":
		return cmdValidate(ctx, rest)
	case "sources":
		return cmdSources(ctx, rest)
	case "plugins":
		return cmdPlugins(ctx, rest)
	case "version":
		fmt.Println(version)
		return 0
	case "-h", "--help", "help":
		fmt.Fprint(os.Stdout, usage)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "bosun: unknown command %q\n\n%s", cmd, usage)
		return 2
	}
}
