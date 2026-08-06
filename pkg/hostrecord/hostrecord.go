// Package hostrecord defines the wire types exchanged between source plugins
// and the Bosun host, together with the host-side normalisation applied to
// every record on ingest.
//
// A source emits one Host record per address (a dual-homed device emits two
// records sharing a name and MAC); regrouping into a single AdGuard client
// happens later, in the clients sink. See the design doc §4.4.
package hostrecord

import (
	"net"
	"net/netip"
	"strconv"
	"strings"

	"golang.org/x/text/unicode/norm"
)

// Host is a single (name, address) record as emitted by a source plugin.
//
// Labels is the extension point that keeps this wire format stable: source
// specific attributes (Omada network/SSID, NPM enabled flag, and so on) travel
// as labels and become available to the predicate language without any schema
// change.
type Host struct {
	Name   string            `json:"name"`
	IP     string            `json:"ip,omitempty"`
	MAC    string            `json:"mac,omitempty"`
	Labels map[string]string `json:"labels,omitempty"`
}

// DiagLevel is the severity of a normalisation diagnostic.
type DiagLevel string

const (
	DiagInfo DiagLevel = "info"
	DiagWarn DiagLevel = "warn"
)

// Diag is a structured diagnostic produced while normalising a record. It
// carries enough context to be merged into the host's logs with the offending
// value attached, without ever aborting the run.
type Diag struct {
	Level DiagLevel `json:"level"`
	Msg   string    `json:"msg"`
	// Reason is a stable machine-readable code (e.g. "ipv6_dropped",
	// "invalid_mac") suitable for counting.
	Reason string `json:"reason"`
}

// Normalize applies host-side normalisation to a single raw record so that
// plugins may be sloppy about formatting. It returns the normalised record and
// any diagnostics produced along the way.
//
// The returned ok reports whether the record survived: a record left with no
// usable address is dropped entirely rather than becoming an id-less client.
//
// Rules (design doc §4.4):
//
//   - MAC is lowercased and colon-separated; an unparseable MAC is dropped with
//     a diag (the rest of the record is kept).
//   - IP is parsed with netip; the zone identifier is stripped; unspecified and
//     loopback addresses are dropped. IPv6 addresses are dropped in v1 with a
//     counted diag — this is the single choke point, so lifting the restriction
//     later is a one-line change here.
//   - Name is trimmed, lowercased and NFC-normalised. The name is preserved
//     verbatim for the clients sink; DNS-label sanitisation for the rewrites
//     sink is a separate step (see SanitizeDNSLabel).
func Normalize(raw Host) (h Host, diags []Diag, ok bool) {
	h = Host{
		Name:   NormalizeName(raw.Name),
		Labels: raw.Labels,
	}

	if raw.MAC != "" {
		if mac, err := NormalizeMAC(raw.MAC); err != nil {
			diags = append(diags, Diag{
				Level:  DiagWarn,
				Reason: "invalid_mac",
				Msg:    "dropped unparseable MAC " + strconv.Quote(raw.MAC),
			})
		} else {
			h.MAC = mac
		}
	}

	if raw.IP != "" {
		addr, reason := normalizeIP(raw.IP)
		if reason != "" {
			diags = append(diags, Diag{
				Level:  DiagWarn,
				Reason: reason,
				Msg:    "dropped address " + strconv.Quote(raw.IP) + ": " + reason,
			})
		} else {
			h.IP = addr.String()
		}
	}

	// A host with no usable address is not a client. Keep MAC-only records out
	// of the pipeline entirely.
	ok = h.IP != ""
	return h, diags, ok
}

// NormalizeName trims, lowercases and NFC-normalises a name.
func NormalizeName(name string) string {
	return norm.NFC.String(strings.ToLower(strings.TrimSpace(name)))
}

// NormalizeMAC parses and canonicalises a MAC address to lowercase,
// colon-separated form.
func NormalizeMAC(mac string) (string, error) {
	hw, err := net.ParseMAC(strings.TrimSpace(mac))
	if err != nil {
		return "", err
	}
	return strings.ToLower(hw.String()), nil
}

// SanitizeDNSLabel converts a normalised name into a valid DNS label for the
// rewrites sink: characters outside [a-z0-9-] become hyphens, leading and
// trailing hyphens are trimmed, and the result is truncated to 63 octets. The
// clients sink does not use this — AdGuard client names are free-form (design
// doc §4.4).
func SanitizeDNSLabel(name string) string {
	var b strings.Builder
	b.Grow(len(name))
	prevHyphen := false
	for _, r := range NormalizeName(name) {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
			prevHyphen = false
		default:
			// Collapse runs of invalid characters into a single hyphen.
			if !prevHyphen && b.Len() > 0 {
				b.WriteByte('-')
				prevHyphen = true
			}
		}
	}
	label := strings.Trim(b.String(), "-")
	if len(label) > 63 {
		label = strings.TrimRight(label[:63], "-")
	}
	return label
}

// normalizeIP parses an address, strips any zone, and rejects addresses that
// must not become client ids. It returns a non-empty reason code when the
// address is dropped.
func normalizeIP(ip string) (netip.Addr, string) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return netip.Addr{}, "invalid_ip"
	}
	addr = addr.WithZone("")
	switch {
	case addr.IsUnspecified():
		return netip.Addr{}, "unspecified_ip"
	case addr.IsLoopback():
		return netip.Addr{}, "loopback_ip"
	case addr.Is6():
		// IPv6 is deferred to post-v1 (design doc §4.4). Dropping here — the one
		// place addresses enter the pipeline — keeps the restriction to a single
		// switch arm.
		return netip.Addr{}, "ipv6_dropped"
	}
	return addr, ""
}
