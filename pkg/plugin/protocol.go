// Package plugin is the exported SDK for Bosun source plugins. It defines the
// host<->plugin wire protocol (§4.1–§4.3) and Main, which handles mode dispatch,
// stdin decode, NDJSON envelope emission, completeness accounting, signal
// handling and exit codes — so a plugin's main() is one line (§4.5).
//
// A plugin is invoked in two modes:
//
//	<plugin> describe    # prints a Descriptor as JSON on stdout, no stdin
//	<plugin> fetch       # reads a Request on stdin, writes NDJSON on stdout
package plugin

import (
	"encoding/json"
	"time"

	"github.com/suprememoocow/bosun/pkg/hostrecord"
)

// APIVersion is the protocol version the host and this SDK speak.
const APIVersion = 1

// Request is the JSON object the host writes to a plugin's stdin in `fetch`
// mode. Config is opaque and passed through verbatim (§4.2). Deadline is
// advisory — the host also enforces it with SIGTERM then SIGKILL.
type Request struct {
	APIVersion int             `json:"api_version"`
	SourceID   string          `json:"source_id"`
	Deadline   time.Time       `json:"deadline"`
	Config     json.RawMessage `json:"config"`
}

// Descriptor is the single JSON object a plugin prints in `describe` mode, used
// by `bosun validate` and `bosun plugins list` (§4.1).
type Descriptor struct {
	APIVersion   int             `json:"api_version"`
	Type         string          `json:"type"`
	Version      string          `json:"version"`
	Capabilities []string        `json:"capabilities"`
	ConfigSchema json.RawMessage `json:"config_schema,omitempty"`
}

// Envelope record kinds. Every NDJSON line on stdout has a "kind" discriminator.
const (
	KindHost = "host"
	KindDiag = "diag"
	KindEnd  = "end"
)

// HostLine is a `kind:host` record: the Host fields inline plus the kind
// discriminator (the embedded struct flattens into the same JSON object).
type HostLine struct {
	Kind string `json:"kind"`
	hostrecord.Host
}

// DiagLine is a `kind:diag` record — a structured diagnostic merged into the
// host's log with the source id attached (§4.3).
type DiagLine struct {
	Kind  string `json:"kind"`
	Level string `json:"level"`
	Msg   string `json:"msg"`
}

// EndLine is the terminal `kind:end` record. Count must equal the number of
// host records emitted; its presence is what makes a stream complete (§4.3).
type EndLine struct {
	Kind  string `json:"kind"`
	Count int    `json:"count"`
}
