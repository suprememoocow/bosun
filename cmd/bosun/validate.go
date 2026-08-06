package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/suprememoocow/bosun/internal/config"
)

func cmdValidate(_ context.Context, args []string) int {
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	g := registerGlobal(fs)
	if err := fs.Parse(args); err != nil {
		return 2
	}

	_, warnings, err := config.Load(g.config, config.LoadOptions{AllowCmd: g.allowCmd})
	for _, w := range warnings {
		fmt.Fprintf(os.Stderr, "warning: %s\n", w)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid config: %v\n", err)
		return 1
	}
	fmt.Printf("%s: OK\n", g.config)
	return 0
}
