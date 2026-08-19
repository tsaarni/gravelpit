// Tests for configuration helpers.
package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// loadFrom writes a config file into a temporary HOME and loads it.
func loadFrom(t *testing.T, yaml string) *Config {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, ".config", "gravelpit")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return cfg
}

func TestCacheDefaults(t *testing.T) {
	cfg := loadFrom(t, "log_level: info\n")
	if cfg.Cache.DecisionEntries != DefaultDecisionEntries {
		t.Errorf("DecisionEntries = %d, want %d", cfg.Cache.DecisionEntries, DefaultDecisionEntries)
	}
	if cfg.Cache.ProcessEntries != DefaultProcessEntries {
		t.Errorf("ProcessEntries = %d, want %d", cfg.Cache.ProcessEntries, DefaultProcessEntries)
	}
}

func TestCacheSizesFromFile(t *testing.T) {
	cfg := loadFrom(t, "cache:\n  decision_entries: 42\n  process_entries: 7\n")
	if cfg.Cache.DecisionEntries != 42 {
		t.Errorf("DecisionEntries = %d, want 42", cfg.Cache.DecisionEntries)
	}
	if cfg.Cache.ProcessEntries != 7 {
		t.Errorf("ProcessEntries = %d, want 7", cfg.Cache.ProcessEntries)
	}
}

// An explicit zero or a negative number must not reach the cache constructor,
// which would clamp it to a single entry and make the cache useless.
func TestCacheSizesClampedToDefault(t *testing.T) {
	cfg := loadFrom(t, "cache:\n  decision_entries: 0\n  process_entries: -1\n")
	if cfg.Cache.DecisionEntries != DefaultDecisionEntries {
		t.Errorf("DecisionEntries = %d, want %d", cfg.Cache.DecisionEntries, DefaultDecisionEntries)
	}
	if cfg.Cache.ProcessEntries != DefaultProcessEntries {
		t.Errorf("ProcessEntries = %d, want %d", cfg.Cache.ProcessEntries, DefaultProcessEntries)
	}
}

// The cache section must appear in "config explain", which is built from struct
// tags, so a field added without a description is visible.
func TestExplainIncludesCache(t *testing.T) {
	text := FormatExplainConfig(ExplainConfig())
	for _, want := range []string{"cache", "decision_entries", "process_entries"} {
		if !strings.Contains(text, want) {
			t.Errorf("explain output missing %q", want)
		}
	}
}

func TestConfigureSlogRejectsInvalidLevel(t *testing.T) {
	tests := []struct {
		level   string
		wantErr bool
	}{
		{"debug", false},
		{"info", false},
		{"warn", false},
		{"warning", false},
		{"error", false},
		{"INFO", false},
		{"Debug", false},
		{"", true},
		{"trace", true},
		{"verbose", true},
		{"all", true},
	}

	for _, tt := range tests {
		t.Run(tt.level, func(t *testing.T) {
			err := ConfigureSlog(tt.level)
			if tt.wantErr && err == nil {
				t.Fatalf("ConfigureSlog(%q) = nil, want error", tt.level)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("ConfigureSlog(%q) = %v, want nil", tt.level, err)
			}
		})
	}
}
