// Command bosun reconciles desired network state into AdGuard Home config.
//
// In M0 the working verbs are `validate`, `plan` and `version`; `apply`,
// `sources` and `plugins` are stubbed until later milestones (design doc §8).
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
  plan       Show the reconciliation diff without mutating AdGuard (default)
  validate   Parse and validate the configuration
  apply      Apply the plan (not implemented until M1)
  sources    Inspect sources (not implemented until M1)
  plugins    Inspect plugins (not implemented until M1)
  version    Print the version

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
	case "validate":
		return cmdValidate(ctx, rest)
	case "version":
		fmt.Println(version)
		return 0
	case "apply", "sources", "plugins":
		fmt.Fprintf(os.Stderr, "bosun %s: not implemented yet\n", cmd)
		return 1
	case "-h", "--help", "help":
		fmt.Fprint(os.Stdout, usage)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "bosun: unknown command %q\n\n%s", cmd, usage)
		return 2
	}
}
