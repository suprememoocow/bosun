package plugin

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/suprememoocow/bosun/pkg/hostrecord"
)

// Source is the interface a plugin implements. Fetch emits one record per call
// to emit; returning a non-nil error means "incomplete" — Main suppresses the
// terminal end record and exits non-zero, which is what makes the completeness
// contract (§4.3) the default rather than something each author must remember.
type Source interface {
	Describe() Descriptor
	Fetch(ctx context.Context, cfg json.RawMessage, emit func(hostrecord.Host) error) error
}

// Main is a plugin binary's entry point: func main() { plugin.Main(mySource) }.
// It dispatches the mode, handles I/O and signals, and exits the process.
func Main(s Source) {
	os.Exit(run(s, os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// run is Main's testable core: it never calls os.Exit and takes explicit I/O.
func run(s Source, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	log := slog.New(slog.NewTextHandler(stderr, nil))
	if len(args) < 1 {
		fmt.Fprintln(stderr, "usage: <plugin> describe|fetch")
		return 2
	}

	switch args[0] {
	case "describe":
		d := s.Describe()
		if d.APIVersion == 0 {
			d.APIVersion = APIVersion
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(d); err != nil {
			fmt.Fprintln(stderr, "describe:", err)
			return 1
		}
		return 0
	case "fetch":
		return runFetch(s, stdin, stdout, log)
	default:
		fmt.Fprintf(stderr, "unknown mode %q (want describe or fetch)\n", args[0])
		return 2
	}
}

func runFetch(s Source, stdin io.Reader, stdout io.Writer, log *slog.Logger) int {
	var req Request
	if err := json.NewDecoder(stdin).Decode(&req); err != nil {
		log.Error("decoding request", "err", err)
		return 1
	}

	ctx := context.Background()
	if !req.Deadline.IsZero() {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, req.Deadline)
		defer cancel()
	}
	// The host enforces the deadline with SIGTERM then SIGKILL; cancelling the
	// context on those signals lets a well-behaved Fetch bail before the kill.
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	w := bufio.NewWriter(stdout)
	count := 0
	emit := func(h hostrecord.Host) error {
		if err := writeLine(w, HostLine{Kind: KindHost, Host: h}); err != nil {
			return err
		}
		count++
		return nil
	}

	if err := s.Fetch(ctx, req.Config, emit); err != nil {
		// Incomplete: emit an error diag, suppress end, flush, exit non-zero.
		_ = writeLine(w, DiagLine{Kind: KindDiag, Level: "error", Msg: err.Error()})
		_ = w.Flush()
		log.Error("fetch failed", "err", err)
		return 1
	}

	if err := writeLine(w, EndLine{Kind: KindEnd, Count: count}); err != nil {
		log.Error("writing end", "err", err)
		return 1
	}
	if err := w.Flush(); err != nil {
		log.Error("flushing output", "err", err)
		return 1
	}
	return 0
}

// writeLine marshals v to one NDJSON line.
func writeLine(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	_, err = w.Write(b)
	return err
}
