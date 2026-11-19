package emailposture

import (
	"context"
	"net"
	"testing"

	"github.com/RodriguesWall/aegis-recon/internal/model"
)

// fakeResolver returns TXT records from a map; everything else is empty.
type fakeResolver struct{ txt map[string][]string }

func (f fakeResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	return f.txt[name], nil
}
func (fakeResolver) LookupHost(context.Context, string) ([]string, error) { return nil, nil }
func (fakeResolver) LookupMX(context.Context, string) ([]*net.MX, error)  { return nil, nil }
func (fakeResolver) LookupNS(context.Context, string) ([]*net.NS, error)  { return nil, nil }
func (fakeResolver) LookupCNAME(context.Context, string) (string, error)  { return "", nil }

func titles(fs []model.Finding) map[string]model.Severity {
	m := map[string]model.Severity{}
	for _, f := range fs {
		m[f.Title] = f.Severity
	}
	return m
}

func TestAllMissing(t *testing.T) {
	// No TXT at all: missing SPF, missing DMARC, missing DKIM.
	got := Check(context.Background(), "example.com", fakeResolver{txt: map[string][]string{}})
	ts := titles(got)
	if ts["no SPF record (email spoofing risk)"] != model.SeverityMedium {
		t.Fatalf("expected missing-SPF medium, got %+v", ts)
	}
	if ts["no DMARC record (email spoofing risk)"] != model.SeverityMedium {
		t.Fatalf("expected missing-DMARC medium, got %+v", ts)
	}
	if ts["no DKIM key found on common selectors (low confidence)"] != model.SeverityInfo {
		t.Fatalf("expected DKIM info, got %+v", ts)
	}
}

func TestPermissiveSPFAndWeakDMARC(t *testing.T) {
	r := fakeResolver{txt: map[string][]string{
		"example.com":               {"v=spf1 include:_spf.example.com +all"},
		"_dmarc.example.com":        {"v=DMARC1; p=none; rua=mailto:x@example.com"},
		"default._domainkey.example.com": {"v=DKIM1; k=rsa; p=MIGf..."},
	}}
	ts := titles(Check(context.Background(), "example.com", r))
	if ts["SPF allows any sender (+all)"] != model.SeverityHigh {
		t.Fatalf("expected +all high, got %+v", ts)
	}
	if ts["DMARC policy is p=none (monitoring only)"] != model.SeverityLow {
		t.Fatalf("expected p=none low, got %+v", ts)
	}
	// DKIM present on default selector -> no DKIM finding.
	if _, ok := ts["no DKIM key found on common selectors (low confidence)"]; ok {
		t.Fatalf("DKIM should be detected, got %+v", ts)
	}
}

func TestGoodPostureNoFindings(t *testing.T) {
	r := fakeResolver{txt: map[string][]string{
		"example.com":                    {"v=spf1 include:_spf.example.com -all"},
		"_dmarc.example.com":             {"v=DMARC1; p=reject"},
		"google._domainkey.example.com":  {"v=DKIM1; k=rsa; p=abc"},
	}}
	if got := Check(context.Background(), "example.com", r); len(got) != 0 {
		t.Fatalf("strong posture should yield no findings, got %+v", got)
	}
}

func TestMultipleSPF(t *testing.T) {
	r := fakeResolver{txt: map[string][]string{
		"example.com":                   {"v=spf1 -all", "v=spf1 include:x -all"},
		"_dmarc.example.com":            {"v=DMARC1; p=reject"},
		"default._domainkey.example.com": {"v=DKIM1; p=x"},
	}}
	ts := titles(Check(context.Background(), "example.com", r))
	if ts["multiple SPF records (invalid)"] != model.SeverityMedium {
		t.Fatalf("expected multiple-SPF medium, got %+v", ts)
	}
}
