package adguard

// PersistentClient is an AdGuard Home persistent client. Its primary key is Name.
//
// In M0 only the fields the reconciler reasons about are modelled. Client
// update is a full replacement (design doc §7.3), so preserving unmanaged
// fields for the managed-field overlay is added with the write path in M2.
type PersistentClient struct {
	Name string   `json:"name"`
	IDs  []string `json:"ids"`
	Tags []string `json:"tags,omitempty"`
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
