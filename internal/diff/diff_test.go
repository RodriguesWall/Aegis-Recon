package diff

import (
	"testing"

	"github.com/RodriguesWall/aegis-recon/internal/model"
)

func f(scanner, host string, port int, title string) model.Finding {
	return model.Finding{Scanner: scanner, Target: model.Target{Host: host, Port: port}, Title: title}
}

func TestScansClassifies(t *testing.T) {
	prev := []model.Finding{
		f("port", "a.com", 80, "open 80"),  // stays -> unchanged
		f("port", "a.com", 443, "open 443"), // gone -> resolved
	}
	curr := []model.Finding{
		f("port", "a.com", 80, "open 80"),  // unchanged
		f("tls", "a.com", 443, "weak ciph"), // appears -> new
	}

	r := Scans(curr, prev)
	c := r.Counts()
	if c.New != 1 || c.Resolved != 1 || c.Unchanged != 1 {
		t.Fatalf("want new=1 resolved=1 unchanged=1, got %+v", c)
	}
	if r.New[0].Scanner != "tls" {
		t.Fatalf("new finding wrong: %+v", r.New[0])
	}
	if r.Resolved[0].Target.Port != 443 || r.Resolved[0].Scanner != "port" {
		t.Fatalf("resolved finding wrong: %+v", r.Resolved[0])
	}
}

func TestScansNilPreviousAllNew(t *testing.T) {
	curr := []model.Finding{f("dns", "a.com", 0, "A record"), f("port", "a.com", 22, "open 22")}
	r := Scans(curr, nil)
	c := r.Counts()
	if c.New != 2 || c.Resolved != 0 || c.Unchanged != 0 {
		t.Fatalf("nil previous should make all new, got %+v", c)
	}
}

func TestScansEmptyCurrentAllResolved(t *testing.T) {
	prev := []model.Finding{f("port", "a.com", 80, "open 80")}
	r := Scans(nil, prev)
	c := r.Counts()
	if c.Resolved != 1 || c.New != 0 || c.Unchanged != 0 {
		t.Fatalf("empty current should resolve all, got %+v", c)
	}
}

func TestScansDedupsWithinScan(t *testing.T) {
	// Duplicate fingerprints in either scan must collapse to one entry.
	dup := f("port", "a.com", 80, "open 80")
	r := Scans([]model.Finding{dup, dup}, []model.Finding{dup, dup})
	c := r.Counts()
	if c.Unchanged != 1 || c.New != 0 || c.Resolved != 0 {
		t.Fatalf("duplicates must collapse, got %+v", c)
	}
}
