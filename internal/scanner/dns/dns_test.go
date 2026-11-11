package dns_test

import (
	"context"
	"net"
	"testing"

	"github.com/RodriguesWall/aegis-recon/internal/model"
	"github.com/RodriguesWall/aegis-recon/internal/scanner/dns"
)

// fakeResolver returns fixed answers, so the scanner is tested without network.
type fakeResolver struct{}

func (fakeResolver) LookupHost(context.Context, string) ([]string, error) {
	return []string{"93.184.216.34"}, nil
}
func (fakeResolver) LookupMX(context.Context, string) ([]*net.MX, error) {
	return []*net.MX{{Host: "mail.example.com.", Pref: 10}}, nil
}
func (fakeResolver) LookupTXT(context.Context, string) ([]string, error) {
	return []string{"v=spf1 -all"}, nil
}
func (fakeResolver) LookupNS(context.Context, string) ([]*net.NS, error) {
	return []*net.NS{{Host: "ns1.example.com."}}, nil
}
func (fakeResolver) LookupCNAME(context.Context, string) (string, error) {
	return "example.com.", nil // equals name+"." -> should be skipped
}

func TestScan_EmitsRecords(t *testing.T) {
	s := dns.New(fakeResolver{})

	var got []model.Finding
	err := s.Scan(context.Background(), model.Target{Domain: "example.com"}, func(f model.Finding) {
		got = append(got, f)
	})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	// A, MX, NS, TXT emitted; CNAME skipped (equals name+".").
	byTitle := map[string]bool{}
	for _, f := range got {
		byTitle[f.Title] = true
		if f.Scanner != "dns" {
			t.Fatalf("scanner = %q", f.Scanner)
		}
	}
	for _, want := range []string{"resolved addresses", "MX records", "NS records", "TXT records"} {
		if !byTitle[want] {
			t.Errorf("missing finding %q (got %v)", want, byTitle)
		}
	}
	if byTitle["CNAME record"] {
		t.Errorf("CNAME equal to name should be skipped")
	}
}

func TestScan_EmptyTarget(t *testing.T) {
	s := dns.New(fakeResolver{})
	err := s.Scan(context.Background(), model.Target{}, func(model.Finding) {})
	if err == nil {
		t.Fatal("expected error on empty target")
	}
}
