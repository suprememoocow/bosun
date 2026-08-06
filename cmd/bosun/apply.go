package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/suprememoocow/bosun/internal/adguard"
	"github.com/suprememoocow/bosun/internal/sink/clients"
)

func cmdApply(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("apply", flag.ContinueOnError)
	g := registerGlobal(fs)
	autoApprove := fs.Bool("auto-approve", false, "apply without an interactive confirmation")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	log := g.logger()

	in, err := loadClientsPlan(ctx, g, log)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}

	// Show the diff first, exactly as `plan` would.
	if err := renderPlan(os.Stdout, in.plan, "text", g.noColor); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}

	counts := in.plan.Counts()
	changes := counts[clients.OpCreate] + counts[clients.OpUpdate]
	if changes == 0 {
		fmt.Println("nothing to apply")
		return 0
	}
	if !*autoApprove && !confirm(os.Stdin, os.Stdout) {
		fmt.Println("aborted")
		return 1
	}

	// Actions are already ordered create, update, delete (§7.6), so creates and
	// updates land before any (skipped) delete.
	start := time.Now()
	var created, updated, deletesSkipped, failed int
	for _, a := range in.plan.Actions {
		switch a.Op {
		case clients.OpCreate:
			if err := in.ag.AddClient(ctx, adguard.PersistentClient{Name: a.Name, IDs: a.IDs}); err != nil {
				log.Error("create failed", "name", a.Name, "err", err)
				failed++
			} else {
				created++
			}
		case clients.OpUpdate:
			live := in.liveByName[a.Name]
			if err := in.ag.UpdateClient(ctx, live, a.IDs); err != nil {
				log.Error("update failed", "name", a.Name, "err", err)
				failed++
			} else {
				updated++
			}
		case clients.OpDelete:
			// Pruning + safety rails land in M2; never delete in M1.
			log.Warn("skipping delete (pruning lands in M2)", "name", a.Name)
			deletesSkipped++
		}
	}

	// Machine-readable summary suitable for a metrics scrape (§7.6).
	log.Info("apply summary",
		"sink", "clients",
		"created", created,
		"updated", updated,
		"deletes_skipped", deletesSkipped,
		"failed", failed,
		"duration_ms", time.Since(start).Milliseconds(),
	)
	if failed > 0 {
		return 1
	}
	return 0
}

// confirm reads a y/N answer from in, prompting on out. Anything but yes aborts.
func confirm(in *os.File, out *os.File) bool {
	fmt.Fprint(out, "\nApply these changes? [y/N] ")
	line, _ := bufio.NewReader(in).ReadString('\n')
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true
	default:
		return false
	}
}
