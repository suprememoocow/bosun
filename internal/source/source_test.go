package source

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/suprememoocow/bosun/internal/config"
	"gopkg.in/yaml.v3"
)

func mustSource(t *testing.T, y string) config.Source {
	t.Helper()
	var s config.Source
	if err := yaml.Unmarshal([]byte(y), &s); err != nil {
		t.Fatal(err)
	}
	return s
}

func discardFetcher(plugins config.Plugins) *Fetcher {
	return NewFetcher(plugins, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func TestFetchStatic(t *testing.T) {
	src := mustSource(t, `
id: fixture
type: static
config:
  hosts:
    - {name: NAS, ip: 192.168.0.10, mac: aa:bb:cc:dd:ee:ff}
    - {name: v6only, ip: fd00::5}
`)
	res, err := discardFetcher(config.Plugins{}).Fetch(context.Background(), src)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	// v6only drops out (IPv6), leaving one normalised record.
	if len(res.Records) != 1 || res.Records[0].Name != "nas" {
		t.Fatalf("records = %+v", res.Records)
	}
	if len(res.Diags) == 0 {
		t.Error("expected an ipv6_dropped diag")
	}
}

func writePlugin(t *testing.T, dir, typ, body string) {
	t.Helper()
	script := "#!/bin/sh\ncat >/dev/null\n" + body + "\n"
	if err := os.WriteFile(filepath.Join(dir, "bosun-plugin-"+typ), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestFetchPlugin(t *testing.T) {
	dir := t.TempDir()
	writePlugin(t, dir, "fake", `printf '%s\n' '{"kind":"host","name":"gw","ip":"192.168.0.1"}' '{"kind":"end","count":1}'`)

	src := mustSource(t, "id: p\ntype: fake\nconfig: {foo: bar}")
	f := discardFetcher(config.Plugins{Dir: dir, Timeout: config.Duration(5 * time.Second), MaxRecords: 100})
	res, err := f.Fetch(context.Background(), src)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(res.Records) != 1 || res.Records[0].Name != "gw" {
		t.Fatalf("records = %+v", res.Records)
	}
}

func TestFetchAllRunsSourceOnce(t *testing.T) {
	dir := t.TempDir()
	counter := filepath.Join(dir, "runs")
	// Each invocation appends a byte to the counter file.
	writePlugin(t, dir, "counted", `printf x >>`+counter+`
printf '%s\n' '{"kind":"host","name":"a","ip":"10.0.0.1"}' '{"kind":"end","count":1}'`)

	byID := map[string]config.Source{
		"c": mustSource(t, "id: c\ntype: counted"),
	}
	f := discardFetcher(config.Plugins{Dir: dir, Timeout: config.Duration(5 * time.Second), MaxConcurrency: 4, MaxRecords: 100})

	// Two references to the same source id must fetch it exactly once.
	results, err := f.FetchAll(context.Background(), byID, []string{"c", "c"})
	if err != nil {
		t.Fatalf("FetchAll: %v", err)
	}
	if len(results) != 1 || len(results["c"].Records) != 1 {
		t.Fatalf("results = %+v", results)
	}
	runs, err := os.ReadFile(counter)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 1 {
		t.Errorf("source ran %d times, want 1 (once-per-run)", len(runs))
	}
}

func TestFetchAllUnknownSource(t *testing.T) {
	f := discardFetcher(config.Plugins{})
	if _, err := f.FetchAll(context.Background(), map[string]config.Source{}, []string{"ghost"}); err == nil {
		t.Fatal("expected unknown-source error")
	}
}
