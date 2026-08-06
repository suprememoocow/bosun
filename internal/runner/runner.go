// Package runner executes source plugin binaries and decodes their NDJSON output
// envelope, enforcing the completeness contract (§4.3): a stream is a failed
// source unless it ends with a terminal `end` record whose count matches the
// host records observed and the process exits zero. That contract is the only
// thing standing between a flaky controller and a wiped client list, so it is
// enforced here rather than inferred from the exit code.
package runner

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/suprememoocow/bosun/pkg/hostrecord"
	"github.com/suprememoocow/bosun/pkg/plugin"
)

// maxLineBytes caps a single NDJSON line (§4.3), guarding against a runaway
// plugin emitting one enormous line.
const maxLineBytes = 1 << 20 // 1 MiB

// defaultKillGrace is how long a plugin has to exit after SIGTERM before SIGKILL.
const defaultKillGrace = 5 * time.Second

// Spec describes one source invocation.
type Spec struct {
	SourceID string
	Type     string          // resolves to bosun-plugin-<type> unless Command is set
	Command  string          // explicit binary path override
	Config   json.RawMessage // opaque config passed through verbatim
	Timeout  time.Duration   // per-source; falls back to Runner.DefaultTimeout
}

// Runner executes plugins found in Dir, alongside the bosun binary, or on $PATH.
type Runner struct {
	// Dir is plugins.dir, searched first when set. The directory holding the
	// bosun binary itself is *always* searched next, so a plugin shipped
	// alongside bosun is found without configuration and is preferred over a
	// stale one on $PATH (design doc open question 4).
	Dir            string
	DefaultTimeout time.Duration
	MaxRecords     int
	KillGrace      time.Duration
	Log            *slog.Logger
}

func (r *Runner) log() *slog.Logger {
	if r.Log != nil {
		return r.Log
	}
	return slog.Default()
}

// Describe runs a plugin's `describe` mode and returns its descriptor.
func (r *Runner) Describe(ctx context.Context, spec Spec) (plugin.Descriptor, error) {
	bin, err := r.resolve(spec)
	if err != nil {
		return plugin.Descriptor{}, err
	}
	out, err := exec.CommandContext(ctx, bin, "describe").Output()
	if err != nil {
		return plugin.Descriptor{}, fmt.Errorf("plugin %q describe: %w", bin, err)
	}
	var d plugin.Descriptor
	if err := json.Unmarshal(out, &d); err != nil {
		return plugin.Descriptor{}, fmt.Errorf("plugin %q describe: invalid JSON: %w", bin, err)
	}
	return d, nil
}

// Run executes a plugin's `fetch` mode and returns the raw (un-normalised) host
// records once the completeness contract is satisfied.
func (r *Runner) Run(ctx context.Context, spec Spec) ([]hostrecord.Host, error) {
	return r.run(ctx, spec, nil)
}

// RunRaw is Run but also copies the plugin's stdout verbatim to raw as it is
// read — the plumbing behind `bosun sources run`. Completeness is still
// enforced, so the exit status reflects whether the dump is trustworthy.
func (r *Runner) RunRaw(ctx context.Context, spec Spec, raw io.Writer) ([]hostrecord.Host, error) {
	return r.run(ctx, spec, raw)
}

func (r *Runner) run(ctx context.Context, spec Spec, raw io.Writer) ([]hostrecord.Host, error) {
	bin, err := r.resolve(spec)
	if err != nil {
		return nil, err
	}

	timeout := spec.Timeout
	if timeout <= 0 {
		timeout = r.DefaultTimeout
	}
	deadline := time.Now().Add(timeout)
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	reqJSON, err := json.Marshal(plugin.Request{
		APIVersion: plugin.APIVersion,
		SourceID:   spec.SourceID,
		Deadline:   deadline,
		Config:     spec.Config,
	})
	if err != nil {
		return nil, fmt.Errorf("source %q: marshalling request: %w", spec.SourceID, err)
	}

	grace := r.KillGrace
	if grace <= 0 {
		grace = defaultKillGrace
	}

	cmd := exec.Command(bin, "fetch")
	cmd.Stdin = bytes.NewReader(reqJSON)
	// Run the plugin in its own process group so a SIGTERM reaches its children
	// too: a plugin implemented as a shell script leaves an orphaned child
	// (holding the stdout pipe open, blocking our decode) if only the shell is
	// signalled. Signalling the group avoids that.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("source %q: starting plugin: %w", spec.SourceID, err)
	}

	// Watchdog: on deadline/cancel, SIGTERM the group, then SIGKILL after grace.
	done := make(chan struct{})
	go r.watchdog(ctx, cmd.Process.Pid, grace, done)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		r.drainStderr(spec.SourceID, stderr)
	}()

	hosts, decodeErr := r.decode(spec.SourceID, stdout, raw)
	wg.Wait()
	waitErr := cmd.Wait()
	close(done)

	// A completeness violation seen while decoding takes priority: it is the most
	// specific description of what went wrong.
	if decodeErr != nil {
		return nil, fmt.Errorf("source %q: %w", spec.SourceID, decodeErr)
	}
	// Non-zero exit is a failure even if an end record was seen (§4.3).
	if waitErr != nil {
		return nil, fmt.Errorf("source %q: plugin exited non-zero: %w", spec.SourceID, waitErr)
	}
	return hosts, nil
}

// watchdog terminates the plugin's process group when the context is done. It
// asks with SIGTERM, then escalates to SIGKILL if the group has not exited
// within the grace period (§4.2). pid is the group leader (Setpgid), so -pid
// targets the whole group.
func (r *Runner) watchdog(ctx context.Context, pid int, grace time.Duration, done <-chan struct{}) {
	select {
	case <-done:
		return
	case <-ctx.Done():
	}
	_ = syscall.Kill(-pid, syscall.SIGTERM)
	select {
	case <-done:
	case <-time.After(grace):
		_ = syscall.Kill(-pid, syscall.SIGKILL)
	}
}

// decode reads the NDJSON envelope and enforces the completeness contract. When
// raw is non-nil the plugin's stdout is copied to it verbatim as it is read.
func (r *Runner) decode(sourceID string, stdout io.Reader, raw io.Writer) ([]hostrecord.Host, error) {
	if raw != nil {
		stdout = io.TeeReader(stdout, raw)
	}
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 0, 64*1024), maxLineBytes)

	var hosts []hostrecord.Host
	endSeen := false
	endCount := 0

	for sc.Scan() {
		line := sc.Bytes()
		if endSeen {
			return nil, errors.New("records emitted after the end record")
		}
		var probe struct {
			Kind string `json:"kind"`
		}
		if err := json.Unmarshal(line, &probe); err != nil {
			return nil, fmt.Errorf("invalid NDJSON line: %w", err)
		}
		switch probe.Kind {
		case plugin.KindHost:
			if r.MaxRecords > 0 && len(hosts) >= r.MaxRecords {
				return nil, fmt.Errorf("record cap %d exceeded", r.MaxRecords)
			}
			var hl plugin.HostLine
			if err := json.Unmarshal(line, &hl); err != nil {
				return nil, fmt.Errorf("invalid host record: %w", err)
			}
			hosts = append(hosts, hl.Host)
		case plugin.KindDiag:
			var dl plugin.DiagLine
			if err := json.Unmarshal(line, &dl); err == nil {
				r.log().Warn("plugin diag", "source_id", sourceID, "level", dl.Level, "msg", dl.Msg)
			}
		case plugin.KindEnd:
			var el plugin.EndLine
			if err := json.Unmarshal(line, &el); err != nil {
				return nil, fmt.Errorf("invalid end record: %w", err)
			}
			endCount = el.Count
			endSeen = true
		default:
			return nil, fmt.Errorf("unknown record kind %q", probe.Kind)
		}
	}
	if err := sc.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			return nil, fmt.Errorf("output line exceeded %d bytes", maxLineBytes)
		}
		return nil, fmt.Errorf("reading plugin output: %w", err)
	}

	if !endSeen {
		return nil, errors.New("stream ended without a terminal end record (source is incomplete)")
	}
	if endCount != len(hosts) {
		return nil, fmt.Errorf("end count %d does not match %d host records observed", endCount, len(hosts))
	}
	return hosts, nil
}

// drainStderr logs a plugin's free-form stderr at debug level.
func (r *Runner) drainStderr(sourceID string, stderr io.Reader) {
	sc := bufio.NewScanner(stderr)
	sc.Buffer(make([]byte, 0, 64*1024), maxLineBytes)
	for sc.Scan() {
		if line := strings.TrimSpace(sc.Text()); line != "" {
			r.log().Debug("plugin stderr", "source_id", sourceID, "line", line)
		}
	}
}

// resolve finds the plugin binary for a spec: an explicit Command wins,
// otherwise bosun-plugin-<type> is looked up in the configured Dir (if any),
// then always in the directory holding the bosun binary, then on $PATH.
func (r *Runner) resolve(spec Spec) (string, error) {
	if spec.Command != "" {
		return spec.Command, nil
	}
	if spec.Type == "" {
		return "", fmt.Errorf("source %q: neither type nor command set", spec.SourceID)
	}
	name := "bosun-plugin-" + spec.Type

	// Candidate directories in priority order: the configured plugins.dir, then
	// the bosun binary's own directory (always checked). Duplicates are skipped
	// so a plugins.dir that already is the exe dir is not reported twice.
	var dirs []string
	if r.Dir != "" {
		dirs = append(dirs, r.Dir)
	}
	if exe, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exe)
		if len(dirs) == 0 || dirs[0] != exeDir {
			dirs = append(dirs, exeDir)
		}
	}

	for _, dir := range dirs {
		cand := filepath.Join(dir, name)
		if isExecutable(cand) {
			return cand, nil
		}
	}
	if p, err := exec.LookPath(name); err == nil {
		return p, nil
	}

	searched := "$PATH"
	if len(dirs) > 0 {
		searched = strings.Join(quoteAll(dirs), ", ") + " or $PATH"
	}
	return "", fmt.Errorf("source %q: plugin %q not found in %s", spec.SourceID, name, searched)
}

// quoteAll double-quotes each path for a readable error message.
func quoteAll(paths []string) []string {
	out := make([]string, len(paths))
	for i, p := range paths {
		out[i] = fmt.Sprintf("%q", p)
	}
	return out
}

func isExecutable(path string) bool {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return false
	}
	return info.Mode()&0o111 != 0
}
