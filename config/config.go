package config

import (
	"fmt"
	"net/url"
	"os"

	"gopkg.in/yaml.v3"
)

// Policy represents the action to take for matched traffic
type Policy string

const (
	PolicyProxy  Policy = "PROXY"
	PolicyDirect Policy = "DIRECT"
	PolicyReject Policy = "REJECT"
)

// Config represents the main configuration structure
type Config struct {
	// Listen address for the transparent proxy (e.g., ":12345")
	Listen string `yaml:"listen"`

	// Upstream proxy URL (http:// or socks5://)
	Upstream string `yaml:"upstream"`

	// DNS configuration
	DNS DNSConfig `yaml:"dns"`

	// Clash-compatible rules
	Rules []string `yaml:"rules"`

	// Log level (debug, info, warn, error)
	LogLevel string `yaml:"log_level"`

	// Parsed upstream URL
	UpstreamURL *url.URL `yaml:"-"`
}

// DNSConfig represents DNS proxy configuration
type DNSConfig struct {
	// Remote DNS servers (forwarded via upstream proxy)
	Nameservers []string `yaml:"nameservers"`

	// Local DNS servers (forwarded directly)
	LocalNameservers []string `yaml:"local_nameservers"`

	// Custom DNS rules (e.g., ["suffix:lan,DIRECT", "prefix:dev-,DIRECT"])
	Rules []string `yaml:"rules"`
}

// Load reads and parses a configuration file
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// Validate checks the configuration and parses the upstream URL
func (c *Config) Validate() error {
	if c.Listen == "" {
		return fmt.Errorf("listen address is required")
	}

	if c.Upstream != "" {
		u, err := url.Parse(c.Upstream)
		if err != nil {
			return fmt.Errorf("invalid upstream URL: %w", err)
		}

		if u.Scheme != "http" && u.Scheme != "socks5" {
			return fmt.Errorf("upstream must be http:// or socks5://, got %s", u.Scheme)
		}

		c.UpstreamURL = u
	}

	return nil
}
