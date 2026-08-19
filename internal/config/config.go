// Package config loads and provides the gravelpit daemon configuration.
package config

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config holds the daemon configuration.
type Config struct {
	SocketPath         string      `yaml:"socket_path" jsonschema:"description=Unix socket path for supervisor RPC. Default: $XDG_RUNTIME_DIR/gravelpit/supervisor.sock."`
	PolicyDir          string      `yaml:"policy_dir" jsonschema:"description=Directory containing policy YAML files. Default: ~/.config/gravelpit/policies."`
	Audit              AuditConfig `yaml:"audit" jsonschema:"description=Audit logging settings."`
	Cache              CacheConfig `yaml:"cache" jsonschema:"description=In-memory table sizes. Both are bounded so a long session cannot grow without limit."`
	DefaultDenyMessage string      `yaml:"default_deny_message" jsonschema:"description=Fallback message shown to the sandboxed process when a deny rule has no message field."`
	LogLevel           string      `yaml:"log_level" jsonschema:"description=Log level for supervisor output: debug\\, info\\, warn\\, error. Default: info."`
}

// AuditConfig holds audit logging settings.
type AuditConfig struct {
	File  string `yaml:"file" jsonschema:"description=File path for audit log output (JSON lines). Default: ~/.local/share/gravelpit/audit.jsonl."`
	Level string `yaml:"level" jsonschema:"description=Which decisions to log: all or denials. Default: all."`
}

// CacheConfig holds the sizes of the two in-memory LRU tables. Both evict the
// least recently used entry when full, so a value that is too small costs
// accuracy or speed, never correctness.
type CacheConfig struct {
	DecisionEntries int `yaml:"decision_entries" jsonschema:"description=Maximum number of cached policy decisions. Eviction only causes re-evaluation. Roughly 200 bytes per entry. Default: 10000."`
	ProcessEntries  int `yaml:"process_entries" jsonschema:"description=Maximum number of processes tracked for audit attribution and startedBy(). Eviction makes exe fall back to a /proc read and loses ancestry for the pid. Roughly 200 bytes per entry. Default: 4096."`
}

// Default cache sizes. Both are per sandbox session and cost about 200 bytes per
// entry, so the pair stays around 3 MB at defaults.
const (
	DefaultDecisionEntries = 10000
	DefaultProcessEntries  = 4096
)

// Load reads ~/.config/gravelpit/config.yaml and returns the configuration.
// If the file does not exist, defaults are returned.
func Load() (*Config, error) {
	cfg := defaults()

	home, err := os.UserHomeDir()
	if err != nil {
		return cfg, nil // can't find home, use defaults
	}

	path := filepath.Join(home, ".config", "gravelpit", "config.yaml")
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return cfg, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	// Expand env vars in string paths.
	cfg.SocketPath = expandPath(cfg.SocketPath)
	cfg.PolicyDir = expandPath(cfg.PolicyDir)
	cfg.Audit.File = expandPath(cfg.Audit.File)

	// If socket_path was not set in the file, apply the default fallback chain.
	if cfg.SocketPath == "" {
		cfg.SocketPath = DefaultSocketPath()
	}

	// A config file that sets a cache size to zero or a negative number would
	// otherwise ask for an unusable table, so fall back to the default and say
	// so rather than running with a one-entry cache.
	cfg.Cache.DecisionEntries = clampEntries("cache.decision_entries", cfg.Cache.DecisionEntries, DefaultDecisionEntries)
	cfg.Cache.ProcessEntries = clampEntries("cache.process_entries", cfg.Cache.ProcessEntries, DefaultProcessEntries)

	return cfg, nil
}

// clampEntries replaces a non-positive cache size with the default.
func clampEntries(name string, value, def int) int {
	if value > 0 {
		return value
	}
	slog.Warn("invalid cache size, using default", "field", name, "value", value, "default", def)
	return def
}

// defaults returns a Config populated with all default values.
func defaults() *Config {
	home := os.Getenv("HOME")
	if home == "" {
		if h, err := os.UserHomeDir(); err == nil {
			home = h
		}
	}

	xdgDataHome := os.Getenv("XDG_DATA_HOME")
	if xdgDataHome == "" {
		xdgDataHome = filepath.Join(home, ".local", "share")
	}

	return &Config{
		SocketPath: DefaultSocketPath(),
		PolicyDir:  filepath.Join(home, ".config", "gravelpit", "policies"),
		Audit: AuditConfig{
			File:  filepath.Join(xdgDataHome, "gravelpit", "audit.jsonl"),
			Level: "all",
		},
		Cache: CacheConfig{
			DecisionEntries: DefaultDecisionEntries,
			ProcessEntries:  DefaultProcessEntries,
		},
		DefaultDenyMessage: "You are running in a sandbox and the request was denied by policy. Stop, describe what happened and ask the user for instructions.",
		LogLevel:           "info",
	}
}

// DefaultSocketPath returns the socket path using the XDG fallback chain:
//
//	$XDG_RUNTIME_DIR/gravelpit/supervisor.sock
//	-> /run/user/<uid>/gravelpit/supervisor.sock
//	-> /tmp/gravelpit-<uid>/supervisor.sock
//
// The socket is created inside a 0700 directory so the mode of the socket
// itself does not matter and umask cannot weaken it. This keeps other local
// users out. It does not keep the agent out (that is the deny rule on connect).
func DefaultSocketPath() string {
	uid := os.Getuid()

	xdgRuntime := os.Getenv("XDG_RUNTIME_DIR")
	if xdgRuntime != "" {
		return filepath.Join(xdgRuntime, "gravelpit", "supervisor.sock")
	}

	// First fallback: /run/user/<uid>
	runUser := fmt.Sprintf("/run/user/%d", uid)
	if fi, err := os.Stat(runUser); err == nil && fi.IsDir() {
		return filepath.Join(runUser, "gravelpit", "supervisor.sock")
	}

	// Final fallback: /tmp/gravelpit-<uid>
	return fmt.Sprintf("/tmp/gravelpit-%d/supervisor.sock", uid)
}

// expandPath expands environment variables and ~ in a path.
func expandPath(p string) string {
	if p == "" {
		return p
	}
	// Expand ${VAR} and $VAR.
	p = os.ExpandEnv(p)

	// Expand leading ~.
	if strings.HasPrefix(p, "~/") {
		home := os.Getenv("HOME")
		if home == "" {
			if h, err := os.UserHomeDir(); err == nil {
				home = h
			}
		}
		p = filepath.Join(home, p[2:])
	} else if p == "~" {
		home := os.Getenv("HOME")
		if home == "" {
			if h, err := os.UserHomeDir(); err == nil {
				home = h
			}
		}
		p = home
	}

	return p
}

// ConfigureSlog sets up the global slog logger based on the configured level.
// Valid levels: debug, info, warn, error.
func ConfigureSlog(level string) error {
	var lvl slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lvl = slog.LevelDebug
	case "info":
		lvl = slog.LevelInfo
	case "warn", "warning":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		return fmt.Errorf("invalid log level %q, must be one of: debug, info, warn, error", level)
	}
	slog.SetDefault(slog.New(&shortHandler{level: lvl}))
	return nil
}

// shortHandler is a compact log handler that prints: HH:MM:SS.mmm LEVEL message key=value ...
type shortHandler struct {
	level slog.Level
	attrs []slog.Attr
	group string
}

func (h *shortHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level
}

func (h *shortHandler) Handle(_ context.Context, r slog.Record) error {
	var buf strings.Builder
	buf.WriteString("\033[2m") // dim
	buf.WriteString(r.Time.Format("15:04:05.000"))
	buf.WriteString("\033[0m")
	buf.WriteByte(' ')

	switch r.Level {
	case slog.LevelDebug:
		buf.WriteString("\033[36mDBG\033[0m") // cyan
	case slog.LevelInfo:
		buf.WriteString("\033[32mINF\033[0m") // green
	case slog.LevelWarn:
		buf.WriteString("\033[33mWRN\033[0m") // yellow
	case slog.LevelError:
		buf.WriteString("\033[31mERR\033[0m") // red
	default:
		buf.WriteString("???")
	}

	buf.WriteByte(' ')
	buf.WriteString(r.Message)

	// Pre-set attrs from WithAttrs.
	for _, a := range h.attrs {
		buf.WriteByte(' ')
		buf.WriteString("\033[2m") // dim
		buf.WriteString(a.Key)
		buf.WriteByte('=')
		buf.WriteString(fmt.Sprintf("%v", a.Value.Any()))
		buf.WriteString("\033[0m")
	}

	// Per-record attrs.
	r.Attrs(func(a slog.Attr) bool {
		buf.WriteByte(' ')
		buf.WriteString("\033[2m") // dim
		buf.WriteString(a.Key)
		buf.WriteByte('=')
		buf.WriteString(fmt.Sprintf("%v", a.Value.Any()))
		buf.WriteString("\033[0m")
		return true
	})

	buf.WriteByte('\n')
	_, err := os.Stderr.WriteString(buf.String())
	return err
}

func (h *shortHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &shortHandler{level: h.level, attrs: append(h.attrs, attrs...), group: h.group}
}

func (h *shortHandler) WithGroup(name string) slog.Handler {
	return &shortHandler{level: h.level, attrs: h.attrs, group: name}
}
