package omada

import "github.com/suprememoocow/bosun/pkg/hostrecord"

// Config is the omada source's opaque config block (§5), decoded from the JSON
// the host passes on stdin. Secrets are already expanded host-side.
type Config struct {
	Address            string   `json:"address"`
	Username           string   `json:"username"`
	Password           string   `json:"password"`
	Site               string   `json:"site"`
	InsecureSkipVerify bool     `json:"insecure_skip_verify"`
	Include            []string `json:"include"`
}

// envelope is the common Omada response wrapper.
type envelope struct {
	ErrorCode int    `json:"errorCode"`
	Msg       string `json:"msg"`
}

type infoResponse struct {
	envelope
	Result struct {
		ControllerVer string `json:"controllerVer"`
		OmadacID      string `json:"omadacId"`
	} `json:"result"`
}

type loginResponse struct {
	envelope
	Result struct {
		Token string `json:"token"`
	} `json:"result"`
}

type sitesResponse struct {
	envelope
	Result struct {
		TotalRows int `json:"totalRows"`
		Data      []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"data"`
	} `json:"result"`
}

// reservation is one DHCP address reservation as returned by
// /sites/{id}/setting/service/dhcp on an Omada v6 controller.
type reservation struct {
	Name       string `json:"name"`
	ClientName string `json:"clientName"`
	IP         string `json:"ip"`
	MAC        string `json:"mac"`
	NetName    string `json:"netName"`
	Status     bool   `json:"status"`
}

type reservationsResponse struct {
	envelope
	Result struct {
		TotalRows int           `json:"totalRows"`
		Data      []reservation `json:"data"`
	} `json:"result"`
}

// toHost maps a reservation to a host record. A reservation always has a MAC and
// a static IP, which is exactly the stable, offline-present data the clients
// sink wants (§6.1). Labels carry the Omada network name and the record source.
func (r reservation) toHost() hostrecord.Host {
	name := r.Name
	if name == "" {
		name = r.ClientName
	}
	return hostrecord.Host{
		Name: name,
		IP:   r.IP,
		MAC:  r.MAC,
		Labels: map[string]string{
			"omada.network": r.NetName,
			"omada.source":  "dhcp_reservation",
		},
	}
}
