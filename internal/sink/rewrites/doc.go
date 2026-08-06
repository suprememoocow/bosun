// Package rewrites builds desired AdGuard DNS rewrite entries and reconciles
// them against live state: domain templating, multi-source concat, conflict
// policy, wildcard veto and delete-then-add semantics.
//
// Implemented in milestone M3; see the design doc §7.4.
package rewrites
