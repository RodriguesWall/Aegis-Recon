package dnssec

import (
	"context"
	"errors"
	"testing"

	"github.com/RodriguesWall/aegis-recon/internal/model"
)

// fakeQueryer is a scripted queryer for table tests.
type fakeQueryer struct {
	signed    bool
	signedErr error
	ns        []string
	nsErr     error
	axfr      map[string]int // ns -> records handed over
	axfrErr   map[string]error
}

func (f fakeQueryer) Signed(context.Context, string) (bool, error) { return f.signed, f.signedErr }
func (f fakeQueryer) NS(context.Context, string) ([]string, error) { return f.ns, f.nsErr }
func (f fakeQueryer) AXFR(_ context.Context, ns, _ string) (int, error) {
	if f.axfrErr != nil {
		if err := f.axfrErr[ns]; err != nil {
			return 0, err
		}
	}
	return f.axfr[ns], nil
}

func titles(fs []model.Finding) map[string]model.Severity {
	m := map[string]model.Severity{}
	for _, f := range fs {
		m[f.Title] = f.Severity
	}
	return m
}

func TestCheck_AXFRLeakIsHigh(t *testing.T) {
	q := fakeQueryer{
		ns:   []string{"ns1.example.com.", "ns2.example.com."},
		axfr: map[string]int{"ns2.example.com": 42}, // only the secondary leaks
	}
	got := titles(check(context.Background(), "example.com", q))
	if sev, ok := got["DNS zone transfer (AXFR) allowed"]; !ok || sev != model.SeverityHigh {
		t.Fatalf("want high AXFR finding, got %v", got)
	}
}

func TestCheck_NoLeakNoFinding(t *testing.T) {
	q := fakeQueryer{ns: []string{"ns1.example.com"}, axfr: map[string]int{}}
	if fs := check(context.Background(), "example.com", q); len(fs) != 0 {
		t.Fatalf("want no findings, got %v", fs)
	}
}

func TestCheck_SignedIsInfo_UnsignedSilent(t *testing.T) {
	signed := titles(check(context.Background(), "example.com", fakeQueryer{signed: true}))
	if sev, ok := signed["DNSSEC enabled (zone signed)"]; !ok || sev != model.SeverityInfo {
		t.Fatalf("want info DNSSEC finding, got %v", signed)
	}
	if fs := check(context.Background(), "example.com", fakeQueryer{signed: false}); len(fs) != 0 {
		t.Fatalf("unsigned must be silent, got %v", fs)
	}
}

func TestCheck_AXFRDedupsAndIgnoresErrors(t *testing.T) {
	q := fakeQueryer{
		ns:      []string{"NS1.example.com.", "ns1.example.com", "ns2.example.com"},
		axfr:    map[string]int{"ns1.example.com": 10},
		axfrErr: map[string]error{"ns2.example.com": errors.New("refused")},
	}
	fs := check(context.Background(), "example.com", q)
	if len(fs) != 1 {
		t.Fatalf("want 1 finding (deduped ns1, ns2 errored), got %d: %v", len(fs), fs)
	}
}

func TestCheck_EmptyDomain(t *testing.T) {
	if fs := check(context.Background(), "  ", fakeQueryer{signed: true}); fs != nil {
		t.Fatalf("empty domain must yield nil, got %v", fs)
	}
}
