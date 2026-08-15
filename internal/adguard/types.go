package adguard

import "encoding/json"

// PersistentClient is an AdGuard Home persistent client. Its primary key is Name.
//
// The reconciler reasons about Name/IDs/Tags, but client update is a full
// replacement (design doc §7.3): sending a constructed object would clobber
// fields the tool does not manage (blocked_services, upstreams, safe-search…).
// Raw therefore preserves the complete live object so UpdateClient can overlay
// only the managed field(s) and copy the rest through untouched.
type PersistentClient struct {
	Name string   `json:"name"`
	IDs  []string `json:"ids"`
	Tags []string `json:"tags,omitempty"`
	// Raw is the full object as returned by AdGuard; excluded from marshalling
	// (writes build their own bodies) and populated by UnmarshalJSON.
	Raw map[string]json.RawMessage `json:"-"`
}

// UnmarshalJSON captures the whole object into Raw and mirrors the fields the
// reconciler needs into typed fields.
func (c *PersistentClient) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	c.Raw = raw
	if v, ok := raw["name"]; ok {
		if err := json.Unmarshal(v, &c.Name); err != nil {
			return err
		}
	}
	if v, ok := raw["ids"]; ok {
		if err := json.Unmarshal(v, &c.IDs); err != nil {
			return err
		}
	}
	if v, ok := raw["tags"]; ok {
		if err := json.Unmarshal(v, &c.Tags); err != nil {
			return err
		}
	}
	return nil
}

// clientsResponse is the shape of GET /control/clients.
type clientsResponse struct {
	Clients []PersistentClient `json:"clients"`
	// AutoClients are runtime-discovered and never managed; ignored.
	AutoClients []PersistentClient `json:"auto_clients"`
}

// Rewrite is an AdGuard Home DNS rewrite entry. It carries no metadata beyond
// its domain and answer, which is why stateless ownership for rewrites relies
// on the domain itself (design doc §7.4).
type Rewrite struct {
	Domain string `json:"domain"`
	Answer string `json:"answer"`
}
