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
	maxDeletes := fs.Int("max-deletes", -1, "abort if the plan deletes more than N clients (-1 = unlimited)")
	maxDeleteFraction := fs.Float64("max-delete-fraction", 0.2, "abort if deletes exceed this fraction of manageable live clients")
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
	changes := counts[clients.OpCreate] + counts[clients.OpUpdate] + counts[clients.OpDelete]
	if changes == 0 {
		fmt.Println("nothing to apply")
		return 0
	}

	// Safety rails: abort before any mutation if the plan deletes too much (§7.6).
	// The fraction is computed over manageable live clients only, so vetoed
	// hand-maintained clients cannot dilute the guard.
	if err := checkDeleteRails(counts[clients.OpDelete], in.plan.ManageableLive, *maxDeletes, *maxDeleteFraction); err != nil {
		fmt.Fprintf(os.Stderr, "aborting: %v\n", err)
		return 1
	}

	if !*autoApprove && !confirm(os.Stdin, os.Stdout) {
		fmt.Println("aborted")
		return 1
	}

	useGlobal, filtering := createDefaults(in)
	manageTags := len(in.cfg.Clients.Enrichment) > 0

	// Actions are ordered create, update, delete (§7.6), so a rename (create+
	// delete) never leaves a gap.
	start := time.Now()
	var created, updated, deleted, failed int
	for _, a := range in.plan.Actions {
		switch a.Op {
		case clients.OpCreate:
			err := in.ag.AddClient(ctx, adguard.ClientCreate{
				Name:              a.Name,
				IDs:               a.IDs,
				Tags:              a.Tags,
				UseGlobalSettings: useGlobal,
				FilteringEnabled:  filtering,
			})
			if err != nil {
				log.Error("create failed", "name", a.Name, "err", err)
				failed++
			} else {
				created++
			}
		case clients.OpUpdate:
			live := in.liveByName[a.Name]
			if err := in.ag.UpdateClient(ctx, live, a.IDs, a.Tags, manageTags); err != nil {
				log.Error("update failed", "name", a.Name, "err", err)
				failed++
			} else {
				updated++
			}
		case clients.OpDelete:
			if err := in.ag.DeleteClient(ctx, a.Name); err != nil {
				log.Error("delete failed", "name", a.Name, "err", err)
				failed++
			} else {
				deleted++
			}
		}
	}

	// Machine-readable summary suitable for a metrics scrape (§7.6).
	log.Info("apply summary",
		"sink", "clients",
		"created", created,
		"updated", updated,
		"deleted", deleted,
		"failed", failed,
		"duration_ms", time.Since(start).Milliseconds(),
	)
	if failed > 0 {
		return 1
	}
	return 0
}

// checkDeleteRails enforces the delete backstops (§7.6).
func checkDeleteRails(deletes, manageableLive, maxDeletes int, maxFraction float64) error {
	if deletes == 0 {
		return nil
	}
	if maxDeletes >= 0 && deletes > maxDeletes {
		return fmt.Errorf("plan deletes %d clients, over --max-deletes=%d", deletes, maxDeletes)
	}
	if manageableLive > 0 {
		frac := float64(deletes) / float64(manageableLive)
		if frac > maxFraction {
			return fmt.Errorf("plan deletes %d of %d manageable clients (%.0f%%), over --max-delete-fraction=%.2f",
				deletes, manageableLive, frac*100, maxFraction)
		}
	}
	return nil
}

// createDefaults resolves the client `defaults` for newly created clients,
// falling back to inheriting global filtering so a new client is never created
// with all protection off.
func createDefaults(in *clientsPlanInputs) (useGlobal, filtering bool) {
	useGlobal, filtering = true, true
	if d := in.cfg.Clients.Defaults.UseGlobalSettings; d != nil {
		useGlobal = *d
	}
	if d := in.cfg.Clients.Defaults.FilteringEnabled; d != nil {
		filtering = *d
	}
	return useGlobal, filtering
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
