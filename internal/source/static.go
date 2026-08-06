package source

import (
	"github.com/suprememoocow/bosun/internal/config"
	"github.com/suprememoocow/bosun/pkg/hostrecord"
)

// staticConfig is the opaque config block of a `type: static` source.
type staticConfig struct {
	Hosts []hostrecord.Host `yaml:"hosts"`
}

// fetchStatic reads host records directly from the source's config block.
func fetchStatic(src config.Source) ([]hostrecord.Host, error) {
	var cfg staticConfig
	if err := src.Config.Decode(&cfg); err != nil {
		return nil, err
	}
	return cfg.Hosts, nil
}
