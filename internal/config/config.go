// Package config loads aegisd's runtime configuration from an optional YAML file,
// with environment variables taking precedence and built-in defaults last.
//
// Precedence (highest first): environment variable → YAML file → default.
package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config is aegisd's resolved runtime configuration.
type Config struct {
	Addr string `yaml:"addr"` // bind address host:port
	DB   string `yaml:"db"`   // SQLite file path
}

// Resolve loads the YAML file at path (if it exists), then overlays environment
// variables, then fills defaults. A missing file is not an error.
func Resolve(path string) (Config, error) {
	var file Config
	if path != "" {
		b, err := os.ReadFile(path)
		switch {
		case err == nil:
			if err := yaml.Unmarshal(b, &file); err != nil {
				return Config{}, fmt.Errorf("config: parse %s: %w", path, err)
			}
		case os.IsNotExist(err):
			// no file — fine
		default:
			return Config{}, fmt.Errorf("config: read %s: %w", path, err)
		}
	}
	return Config{
		Addr: pick(os.Getenv("AEGIS_ADDR"), file.Addr, "127.0.0.1:8080"),
		DB:   pick(os.Getenv("AEGIS_DB"), file.DB, filepath.Join("db", "aegis.db")),
	}, nil
}

// pick returns the first non-empty value.
func pick(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
