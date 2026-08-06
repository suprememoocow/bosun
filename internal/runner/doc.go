// Package runner executes source plugin binaries with bounded concurrency and
// a per-source deadline, decodes their NDJSON output envelope, and enforces the
// completeness contract (terminal end record, matching count, zero exit).
//
// Implemented in milestone M1; see the design doc §4.3.
package runner
