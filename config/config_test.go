package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_ValidConfig(t *testing.T) {
	content := `
listen: ":12345"
upstream: "http://proxy.example.com:8080"
rules:
  - IP-CIDR,127.0.0.0/8,DIRECT
  - DOMAIN-SUFFIX,google.com,PROXY
  - MATCH,DIRECT
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.Listen != ":12345" {
		t.Errorf("Listen = %v, want :12345", cfg.Listen)
	}
	if cfg.Upstream != "http://proxy.example.com:8080" {
		t.Errorf("Upstream = %v", cfg.Upstream)
	}
	if len(cfg.Rules) != 3 {
		t.Errorf("len(Rules) = %v, want 3", len(cfg.Rules))
	}
	if cfg.UpstreamURL == nil {
		t.Error("UpstreamURL should be parsed")
	}
	if cfg.UpstreamURL.Scheme != "http" {
		t.Errorf("UpstreamURL.Scheme = %v, want http", cfg.UpstreamURL.Scheme)
	}
}

func TestLoad_SOCKS5Upstream(t *testing.T) {
	content := `
listen: ":12345"
upstream: "socks5://user:pass@proxy.example.com:1080"
rules:
  - MATCH,PROXY
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.UpstreamURL.Scheme != "socks5" {
		t.Errorf("Scheme = %v, want socks5", cfg.UpstreamURL.Scheme)
	}
	if cfg.UpstreamURL.User.Username() != "user" {
		t.Errorf("Username = %v, want user", cfg.UpstreamURL.User.Username())
	}
}

func TestLoad_MissingListen(t *testing.T) {
	content := `
upstream: "http://proxy.example.com:8080"
rules:
  - MATCH,DIRECT
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := Load(configPath)
	if err == nil {
		t.Error("Expected error for missing listen")
	}
}

func TestLoad_MissingUpstream(t *testing.T) {
	content := `
listen: ":12345"
rules:
  - MATCH,DIRECT
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := Load(configPath)
	if err == nil {
		t.Error("Expected error for missing upstream")
	}
}

func TestLoad_InvalidUpstreamScheme(t *testing.T) {
	content := `
listen: ":12345"
upstream: "ftp://invalid.scheme"
rules:
  - MATCH,DIRECT
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := Load(configPath)
	if err == nil {
		t.Error("Expected error for invalid upstream scheme")
	}
}

func TestLoad_FileNotFound(t *testing.T) {
	_, err := Load("/nonexistent/config.yaml")
	if err == nil {
		t.Error("Expected error for missing file")
	}
}

func TestValidate(t *testing.T) {
	cfg := &Config{
		Listen:   ":12345",
		Upstream: "http://proxy:8080",
	}

	err := cfg.Validate()
	if err != nil {
		t.Errorf("Validate() error = %v", err)
	}
	if cfg.UpstreamURL == nil {
		t.Error("UpstreamURL should be set after Validate()")
	}
}
