package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveDefaults(t *testing.T) {
	os.Unsetenv("AEGIS_ADDR")
	os.Unsetenv("AEGIS_DB")
	c, err := Resolve("")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if c.Addr != "127.0.0.1:8080" || c.DB != filepath.Join("db", "aegis.db") {
		t.Fatalf("defaults wrong: %+v", c)
	}
}

func TestResolveFileThenEnv(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aegis.yaml")
	if err := os.WriteFile(path, []byte("addr: 0.0.0.0:9000\ndb: /data/x.db\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// File values apply when env is unset.
	os.Unsetenv("AEGIS_ADDR")
	os.Unsetenv("AEGIS_DB")
	c, _ := Resolve(path)
	if c.Addr != "0.0.0.0:9000" || c.DB != "/data/x.db" {
		t.Fatalf("file values not applied: %+v", c)
	}

	// Env overrides the file.
	t.Setenv("AEGIS_ADDR", "127.0.0.1:7000")
	c, _ = Resolve(path)
	if c.Addr != "127.0.0.1:7000" || c.DB != "/data/x.db" {
		t.Fatalf("env should override addr, keep file db: %+v", c)
	}
}

func TestResolveMissingFileOK(t *testing.T) {
	if _, err := Resolve("/no/such/aegis.yaml"); err != nil {
		t.Fatalf("missing file must not error: %v", err)
	}
}
