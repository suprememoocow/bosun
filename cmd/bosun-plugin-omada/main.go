// Command bosun-plugin-omada is the Omada SDN controller source plugin. It
// emits one host record per enabled DHCP reservation (§6.1). The SDK handles
// mode dispatch, the NDJSON envelope, and the completeness contract.
package main

import (
	"github.com/suprememoocow/bosun/internal/omada"
	"github.com/suprememoocow/bosun/pkg/plugin"
)

func main() {
	plugin.Main(omada.NewSource())
}
