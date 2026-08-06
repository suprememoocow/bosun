package omada

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"

	"github.com/suprememoocow/bosun/pkg/hostrecord"
	"github.com/suprememoocow/bosun/pkg/plugin"
)

// testedControllerVersion is the Omada controller this plugin was built and
// tested against. The API is treated as unstable (§6.1); record it here so a
// mismatch is diagnosable.
const testedControllerVersion = "6.2.14.11"

// Source is the omada plugin's implementation of plugin.Source.
type Source struct{}

// NewSource returns the omada source.
func NewSource() Source { return Source{} }

func (Source) Describe() plugin.Descriptor {
	return plugin.Descriptor{
		Type:         "omada",
		Version:      "0.1.0",
		Capabilities: []string{"hosts"},
		ConfigSchema: json.RawMessage(configSchema),
	}
}

// Fetch logs into the controller and emits one host record per enabled DHCP
// reservation. Returning an error means "incomplete", so the SDK suppresses the
// end record and the run fails safe (§4.3).
func (Source) Fetch(ctx context.Context, cfgJSON json.RawMessage, emit func(hostrecord.Host) error) error {
	var cfg Config
	if err := json.Unmarshal(cfgJSON, &cfg); err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}
	if cfg.Address == "" {
		return errors.New("address is required")
	}
	if cfg.Site == "" {
		cfg.Site = "Default"
	}
	include := cfg.Include
	if len(include) == 0 {
		include = []string{"dhcp_reservations"}
	}

	c, err := Dial(ctx, cfg)
	if err != nil {
		return err
	}
	if c.version != testedControllerVersion {
		fmt.Fprintf(os.Stderr, "omada: controller version %q differs from tested %q; proceeding\n",
			c.version, testedControllerVersion)
	}

	siteID, err := c.SiteID(ctx, cfg.Site)
	if err != nil {
		return err
	}

	if other := unsupportedIncludes(include); len(other) > 0 {
		fmt.Fprintf(os.Stderr, "omada: ignoring unsupported include(s) %v (only dhcp_reservations in this version)\n", other)
	}

	if slices.Contains(include, "dhcp_reservations") {
		reservations, err := c.Reservations(ctx, siteID)
		if err != nil {
			return err
		}
		skipped := 0
		for _, r := range reservations {
			if !r.Status {
				skipped++ // disabled reservation: not authoritative
				continue
			}
			if err := emit(r.toHost()); err != nil {
				return err
			}
		}
		if skipped > 0 {
			fmt.Fprintf(os.Stderr, "omada: skipped %d disabled reservation(s)\n", skipped)
		}
	}
	return nil
}

func unsupportedIncludes(include []string) []string {
	var other []string
	for _, i := range include {
		if i != "dhcp_reservations" {
			other = append(other, i)
		}
	}
	return other
}

const configSchema = `{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "required": ["address"],
  "properties": {
    "address": {"type": "string", "description": "Base URL of the local Omada controller, e.g. https://192.168.0.1:8043"},
    "username": {"type": "string"},
    "password": {"type": "string"},
    "site": {"type": "string", "default": "Default"},
    "insecure_skip_verify": {"type": "boolean", "default": false},
    "include": {"type": "array", "items": {"type": "string", "enum": ["dhcp_reservations"]}}
  }
}`
