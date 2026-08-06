package plugin

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/suprememoocow/bosun/pkg/hostrecord"
)

// fakeSource is a Source driven entirely by test-supplied closures.
type fakeSource struct {
	desc  Descriptor
	fetch func(ctx context.Context, cfg json.RawMessage, emit func(hostrecord.Host) error) error
}

func (f fakeSource) Describe() Descriptor { return f.desc }
func (f fakeSource) Fetch(ctx context.Context, cfg json.RawMessage, emit func(hostrecord.Host) error) error {
	return f.fetch(ctx, cfg, emit)
}

func TestDescribeMode(t *testing.T) {
	src := fakeSource{desc: Descriptor{Type: "omada", Version: "1.2.3", Capabilities: []string{"hosts"}}}
	var out, errb bytes.Buffer
	if code := run(src, []string{"describe"}, strings.NewReader(""), &out, &errb); code != 0 {
		t.Fatalf("exit = %d, stderr=%s", code, errb.String())
	}
	var d Descriptor
	if err := json.Unmarshal(out.Bytes(), &d); err != nil {
		t.Fatal(err)
	}
	if d.Type != "omada" || d.APIVersion != APIVersion {
		t.Errorf("descriptor = %+v", d)
	}
}

func TestFetchHappyPath(t *testing.T) {
	src := fakeSource{fetch: func(_ context.Context, _ json.RawMessage, emit func(hostrecord.Host) error) error {
		_ = emit(hostrecord.Host{Name: "nas", IP: "192.168.0.10"})
		_ = emit(hostrecord.Host{Name: "printer", IP: "192.168.0.20"})
		return nil
	}}
	req, _ := json.Marshal(Request{APIVersion: APIVersion, SourceID: "omada"})
	var out, errb bytes.Buffer
	if code := run(src, []string{"fetch"}, bytes.NewReader(req), &out, &errb); code != 0 {
		t.Fatalf("exit = %d, stderr=%s", code, errb.String())
	}

	kinds, end := parseEnvelope(t, out.Bytes())
	if len(kinds) != 3 || kinds[0] != KindHost || kinds[1] != KindHost || kinds[2] != KindEnd {
		t.Fatalf("kinds = %v", kinds)
	}
	if end.Count != 2 {
		t.Errorf("end.count = %d, want 2", end.Count)
	}
}

func TestFetchErrorSuppressesEnd(t *testing.T) {
	src := fakeSource{fetch: func(_ context.Context, _ json.RawMessage, emit func(hostrecord.Host) error) error {
		_ = emit(hostrecord.Host{Name: "partial", IP: "192.168.0.10"})
		return errors.New("controller session expired")
	}}
	req, _ := json.Marshal(Request{APIVersion: APIVersion})
	var out, errb bytes.Buffer
	code := run(src, []string{"fetch"}, bytes.NewReader(req), &out, &errb)
	if code == 0 {
		t.Fatal("expected non-zero exit on fetch error")
	}
	// No end record; a diag error is present. This is the completeness contract.
	kinds, _ := parseEnvelope(t, out.Bytes())
	for _, k := range kinds {
		if k == KindEnd {
			t.Fatal("end record must be suppressed on error")
		}
	}
	if kinds[len(kinds)-1] != KindDiag {
		t.Errorf("expected trailing diag, kinds=%v", kinds)
	}
}

func TestUnknownMode(t *testing.T) {
	src := fakeSource{}
	var out, errb bytes.Buffer
	if code := run(src, []string{"bogus"}, strings.NewReader(""), &out, &errb); code != 2 {
		t.Errorf("exit = %d, want 2", code)
	}
}

// parseEnvelope returns the kind of each NDJSON line and the decoded end line.
func parseEnvelope(t *testing.T, data []byte) ([]string, EndLine) {
	t.Helper()
	var kinds []string
	var end EndLine
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := sc.Bytes()
		var probe struct {
			Kind string `json:"kind"`
		}
		if err := json.Unmarshal(line, &probe); err != nil {
			t.Fatalf("bad line %q: %v", line, err)
		}
		kinds = append(kinds, probe.Kind)
		if probe.Kind == KindEnd {
			if err := json.Unmarshal(line, &end); err != nil {
				t.Fatal(err)
			}
		}
	}
	return kinds, end
}
