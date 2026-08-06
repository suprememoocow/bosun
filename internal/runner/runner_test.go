package runner

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeFetchPlugin writes an executable fake plugin whose `fetch` mode runs body
// (a /bin/sh snippet). It always drains stdin first so the host's request write
// never hits a closed pipe.
func writeFetchPlugin(t *testing.T, dir, typ, body string) {
	t.Helper()
	script := "#!/bin/sh\ncat >/dev/null\n" + body + "\n"
	path := filepath.Join(dir, "bosun-plugin-"+typ)
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
}

func testRunner(t *testing.T, dir string) *Runner {
	t.Helper()
	return &Runner{
		Dir:            dir,
		DefaultTimeout: 5 * time.Second,
		MaxRecords:     50000,
		KillGrace:      500 * time.Millisecond,
		Log:            slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

const twoHosts = `printf '%s\n' '{"kind":"host","name":"nas","ip":"192.168.0.10"}' '{"kind":"host","name":"printer","ip":"192.168.0.20"}'`

func TestRunHappyPath(t *testing.T) {
	dir := t.TempDir()
	writeFetchPlugin(t, dir, "ok", twoHosts+`
printf '%s\n' '{"kind":"end","count":2}'`)

	hosts, err := testRunner(t, dir).Run(context.Background(), Spec{SourceID: "ok", Type: "ok"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(hosts) != 2 || hosts[0].Name != "nas" || hosts[1].IP != "192.168.0.20" {
		t.Fatalf("hosts = %+v", hosts)
	}
}

func TestRunMissingEndFails(t *testing.T) {
	dir := t.TempDir()
	writeFetchPlugin(t, dir, "noend", twoHosts) // no end record, exits 0

	_, err := testRunner(t, dir).Run(context.Background(), Spec{SourceID: "noend", Type: "noend"})
	if err == nil || !strings.Contains(err.Error(), "terminal end record") {
		t.Fatalf("want missing-end error, got %v", err)
	}
}

func TestRunCountMismatchFails(t *testing.T) {
	dir := t.TempDir()
	writeFetchPlugin(t, dir, "mismatch", twoHosts+`
printf '%s\n' '{"kind":"end","count":5}'`)

	_, err := testRunner(t, dir).Run(context.Background(), Spec{SourceID: "mismatch", Type: "mismatch"})
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("want count-mismatch error, got %v", err)
	}
}

func TestRunNonZeroExitFails(t *testing.T) {
	dir := t.TempDir()
	writeFetchPlugin(t, dir, "exit1", twoHosts+`
printf '%s\n' '{"kind":"end","count":2}'
exit 1`)

	_, err := testRunner(t, dir).Run(context.Background(), Spec{SourceID: "exit1", Type: "exit1"})
	if err == nil || !strings.Contains(err.Error(), "non-zero") {
		t.Fatalf("want non-zero-exit error, got %v", err)
	}
}

func TestRunUnknownKindFails(t *testing.T) {
	dir := t.TempDir()
	writeFetchPlugin(t, dir, "weird", `printf '%s\n' '{"kind":"wat"}'`)

	_, err := testRunner(t, dir).Run(context.Background(), Spec{SourceID: "weird", Type: "weird"})
	if err == nil || !strings.Contains(err.Error(), "unknown record kind") {
		t.Fatalf("want unknown-kind error, got %v", err)
	}
}

func TestRunOversizedLineFails(t *testing.T) {
	dir := t.TempDir()
	writeFetchPlugin(t, dir, "big", `printf '{"kind":"host","name":"'
head -c 1100000 </dev/zero | tr '\0' a
printf '","ip":"1.1.1.1"}\n'
printf '%s\n' '{"kind":"end","count":1}'`)

	_, err := testRunner(t, dir).Run(context.Background(), Spec{SourceID: "big", Type: "big"})
	if err == nil || !strings.Contains(err.Error(), "exceeded") {
		t.Fatalf("want oversized-line error, got %v", err)
	}
}

func TestRunRecordCapFails(t *testing.T) {
	dir := t.TempDir()
	writeFetchPlugin(t, dir, "flood", `printf '%s\n' '{"kind":"host","name":"a","ip":"1.1.1.1"}' '{"kind":"host","name":"b","ip":"1.1.1.2"}' '{"kind":"host","name":"c","ip":"1.1.1.3"}'
printf '%s\n' '{"kind":"end","count":3}'`)

	r := testRunner(t, dir)
	r.MaxRecords = 2
	_, err := r.Run(context.Background(), Spec{SourceID: "flood", Type: "flood"})
	if err == nil || !strings.Contains(err.Error(), "record cap") {
		t.Fatalf("want record-cap error, got %v", err)
	}
}

func TestRunDeadlineTerminatesPlugin(t *testing.T) {
	dir := t.TempDir()
	writeFetchPlugin(t, dir, "slow", `sleep 30`)

	r := testRunner(t, dir)
	start := time.Now()
	_, err := r.Run(context.Background(), Spec{SourceID: "slow", Type: "slow", Timeout: 200 * time.Millisecond})
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("want deadline error")
	}
	if elapsed > 3*time.Second {
		t.Fatalf("took %v — SIGTERM should have killed a plain sleep quickly", elapsed)
	}
}

func TestRunSigkillEscalation(t *testing.T) {
	dir := t.TempDir()
	// Ignores SIGTERM and sleeps; only SIGKILL (after the grace) can stop it.
	writeFetchPlugin(t, dir, "stubborn", `trap '' TERM
sleep 30`)

	r := testRunner(t, dir)
	r.KillGrace = 300 * time.Millisecond
	start := time.Now()
	_, err := r.Run(context.Background(), Spec{SourceID: "stubborn", Type: "stubborn", Timeout: 200 * time.Millisecond})
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("want error after SIGKILL escalation")
	}
	if elapsed > 4*time.Second {
		t.Fatalf("took %v — WaitDelay should have escalated to SIGKILL", elapsed)
	}
}

func TestResolvePrefersExplicitCommand(t *testing.T) {
	r := &Runner{}
	got, err := r.resolve(Spec{SourceID: "x", Command: "/usr/local/bin/thing"})
	if err != nil || got != "/usr/local/bin/thing" {
		t.Fatalf("resolve = %q, %v", got, err)
	}
}

func TestResolveFindsInDir(t *testing.T) {
	dir := t.TempDir()
	writeFetchPlugin(t, dir, "omada", `:`)
	r := &Runner{Dir: dir}
	got, err := r.resolve(Spec{SourceID: "omada", Type: "omada"})
	if err != nil || got != filepath.Join(dir, "bosun-plugin-omada") {
		t.Fatalf("resolve = %q, %v", got, err)
	}
}

func TestResolveMissingFails(t *testing.T) {
	r := &Runner{Dir: t.TempDir()}
	if _, err := r.resolve(Spec{SourceID: "ghost", Type: "ghost"}); err == nil {
		t.Fatal("want not-found error")
	}
}

func TestDescribe(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bosun-plugin-omada")
	script := `#!/bin/sh
if [ "$1" = describe ]; then
  printf '%s\n' '{"api_version":1,"type":"omada","version":"0.1.0","capabilities":["hosts"]}'
fi`
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	d, err := testRunner(t, dir).Describe(context.Background(), Spec{SourceID: "omada", Type: "omada"})
	if err != nil {
		t.Fatalf("Describe: %v", err)
	}
	if d.Type != "omada" || d.Version != "0.1.0" || len(d.Capabilities) != 1 {
		t.Fatalf("descriptor = %+v", d)
	}
}
