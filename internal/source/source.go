// Package source fetches host records for configured sources. The built-in
// "static" source reads records straight from config (the permanent test-fixture
// mechanism, §9); every other type is an out-of-process plugin executed via the
// runner. Records from both paths are normalised host-side (§4.4) before return,
// so callers never see raw plugin output.
package source

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"sync"

	"github.com/suprememoocow/bosun/internal/config"
	"github.com/suprememoocow/bosun/internal/runner"
	"github.com/suprememoocow/bosun/pkg/hostrecord"
	"github.com/suprememoocow/bosun/pkg/plugin"
	"gopkg.in/yaml.v3"
)

// Result is the outcome of fetching one source: the normalised records plus any
// diagnostics produced during normalisation.
type Result struct {
	Records []hostrecord.Host
	Diags   []hostrecord.Diag
}

// Fetcher resolves and fetches sources, delegating plugin types to the runner.
type Fetcher struct {
	plugins config.Plugins
	runner  *runner.Runner
	log     *slog.Logger
}

// NewFetcher builds a Fetcher from the host's plugin settings.
func NewFetcher(plugins config.Plugins, log *slog.Logger) *Fetcher {
	if log == nil {
		log = slog.Default()
	}
	return &Fetcher{
		plugins: plugins,
		log:     log,
		runner: &runner.Runner{
			Dir:            plugins.Dir,
			DefaultTimeout: plugins.Timeout.Duration(),
			MaxRecords:     plugins.MaxRecords,
			Log:            log,
		},
	}
}

// Fetch resolves and fetches a single source.
func (f *Fetcher) Fetch(ctx context.Context, src config.Source) (Result, error) {
	var raw []hostrecord.Host
	switch src.Type {
	case "static":
		got, err := fetchStatic(src)
		if err != nil {
			return Result{}, fmt.Errorf("source %q: %w", src.ID, err)
		}
		raw = got
	default:
		// Everything else is a plugin (by type, or by explicit command). The
		// runner already scopes its errors to the source id.
		got, err := f.fetchPlugin(ctx, src)
		if err != nil {
			return Result{}, err
		}
		raw = got
	}
	return normalize(raw), nil
}

// FetchAll fetches each referenced source exactly once (principle 2), with
// bounded concurrency. Diagnostics are logged as they arrive. A source that
// fails is reported via the returned error; successful sources are still
// returned so a caller can proceed with sinks that do not reference the failure.
func (f *Fetcher) FetchAll(ctx context.Context, byID map[string]config.Source, ids []string) (map[string]Result, error) {
	unique := make([]string, 0, len(ids))
	seen := map[string]bool{}
	for _, id := range ids {
		if !seen[id] {
			seen[id] = true
			unique = append(unique, id)
		}
	}

	limit := f.plugins.MaxConcurrency
	if limit < 1 {
		limit = 1
	}
	sem := make(chan struct{}, limit)

	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		results  = make(map[string]Result, len(unique))
		firstErr error
	)
	for _, id := range unique {
		src, ok := byID[id]
		if !ok {
			return nil, fmt.Errorf("sink references unknown source %q", id)
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(id string, src config.Source) {
			defer wg.Done()
			defer func() { <-sem }()
			res, err := f.Fetch(ctx, src)
			mu.Lock()
			defer mu.Unlock()
			for _, d := range res.Diags {
				f.log.Warn("record dropped", "source", id, "reason", d.Reason, "detail", d.Msg)
			}
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
				return
			}
			results[id] = res
		}(id, src)
	}
	wg.Wait()
	return results, firstErr
}

// DumpNDJSON writes a source's raw NDJSON envelope to w — the plumbing behind
// `bosun sources run`. For a plugin source it is the plugin's verbatim stdout
// (completeness still enforced); for the static source it is synthesised from
// the configured records so the debugging command works uniformly.
func (f *Fetcher) DumpNDJSON(ctx context.Context, src config.Source, w io.Writer) error {
	if src.Type == "static" {
		raw, err := fetchStatic(src)
		if err != nil {
			return fmt.Errorf("source %q: %w", src.ID, err)
		}
		enc := json.NewEncoder(w)
		for _, h := range raw {
			if err := enc.Encode(plugin.HostLine{Kind: plugin.KindHost, Host: h}); err != nil {
				return err
			}
		}
		return enc.Encode(plugin.EndLine{Kind: plugin.KindEnd, Count: len(raw)})
	}

	cfgJSON, err := configToJSON(src.Config)
	if err != nil {
		return fmt.Errorf("source %q: encoding config: %w", src.ID, err)
	}
	_, err = f.runner.RunRaw(ctx, runner.Spec{
		SourceID: src.ID,
		Type:     src.Type,
		Command:  src.Command,
		Config:   cfgJSON,
		Timeout:  src.Timeout.Duration(),
	}, w)
	return err
}

func (f *Fetcher) fetchPlugin(ctx context.Context, src config.Source) ([]hostrecord.Host, error) {
	cfgJSON, err := configToJSON(src.Config)
	if err != nil {
		return nil, fmt.Errorf("source %q: encoding config: %w", src.ID, err)
	}
	return f.runner.Run(ctx, runner.Spec{
		SourceID: src.ID,
		Type:     src.Type,
		Command:  src.Command,
		Config:   cfgJSON,
		Timeout:  src.Timeout.Duration(),
	})
}

// configToJSON converts a source's opaque YAML config block to the JSON handed
// to the plugin verbatim (§4.2).
func configToJSON(node yaml.Node) (json.RawMessage, error) {
	if node.Kind == 0 {
		return json.RawMessage("null"), nil
	}
	var v any
	if err := node.Decode(&v); err != nil {
		return nil, err
	}
	return json.Marshal(v)
}

// normalize applies host-side normalisation, dropping records left with no
// usable address and collecting diagnostics.
func normalize(raw []hostrecord.Host) Result {
	var res Result
	for _, r := range raw {
		h, diags, ok := hostrecord.Normalize(r)
		res.Diags = append(res.Diags, diags...)
		if ok {
			res.Records = append(res.Records, h)
		}
	}
	return res
}
