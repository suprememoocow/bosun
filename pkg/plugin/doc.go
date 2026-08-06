// Package plugin is the exported SDK for third-party Bosun source plugins.
//
// It will provide the Descriptor and Source types plus Main, which handles
// mode dispatch (describe/fetch), stdin decode, NDJSON envelope emission,
// completeness accounting, signal handling and exit codes.
//
// Implemented in milestone M1; see the design doc §4.5.
package plugin
