package clients

import (
	"net"
	"net/netip"
	"strings"
)

// IDKind classifies an AdGuard client id. The classification is the ownership
// boundary in a stateless world (design doc §7.2): the tool only manages ids it
// understands and emits.
type IDKind string

const (
	KindCIDR     IDKind = "cidr"     // contains '/', including /32 and /128 — never managed
	KindIP       IDKind = "ip"       // parses as an address
	KindMAC      IDKind = "mac"      // parses as a hardware address
	KindClientID IDKind = "clientid" // anything else (DoT/DoH/DoQ) — never managed
)

// classifyID returns the kind of a single id.
//
// Any string containing '/' is a CIDR — including single-address prefixes —
// because a slash was typed by a human and signals hand-maintenance (§7.2).
func classifyID(id string) IDKind {
	if strings.Contains(id, "/") {
		return KindCIDR
	}
	if _, err := netip.ParseAddr(id); err == nil {
		return KindIP
	}
	if _, err := net.ParseMAC(id); err == nil {
		return KindMAC
	}
	return KindClientID
}

// managedKinds is the set of id kinds the tool is allowed to manage.
type managedKinds map[IDKind]bool

func newManagedKinds(kinds []string) managedKinds {
	if len(kinds) == 0 {
		// Default per design doc §5.
		return managedKinds{KindIP: true, KindMAC: true}
	}
	m := managedKinds{}
	for _, k := range kinds {
		m[IDKind(k)] = true
	}
	return m
}

// manageable reports whether every id on the client is of a managed kind. A
// client failing this is vetoed from every operation — creates, updates and
// deletes — because client update is a full replacement and would destroy the
// unmanaged id (design doc §7.2).
func (m managedKinds) manageable(ids []string) bool {
	for _, id := range ids {
		if !m[classifyID(id)] {
			return false
		}
	}
	return true
}
