package subdomain

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

// fakeResolver resolves only www.example.com, so brute keeps just that host.
type fakeResolver struct{}

func (fakeResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	if host == "www.example.com" {
		return []string{"1.2.3.4"}, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}
func (fakeResolver) LookupMX(context.Context, string) ([]*net.MX, error) { return nil, nil }
func (fakeResolver) LookupTXT(context.Context, string) ([]string, error) { return nil, nil }
func (fakeResolver) LookupNS(context.Context, string) ([]*net.NS, error) { return nil, nil }
func (fakeResolver) LookupCNAME(context.Context, string) (string, error) { return "", nil }

func TestDiscover_PassiveAndBrute(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"name_value":"api.example.com\n*.example.com"},{"name_value":"mail.example.com"}]`))
	}))
	defer ts.Close()

	// Point crt.sh at the fake server for this test.
	old := crtShURL
	crtShURL = ts.URL
	defer func() { crtShURL = old }()

	d := New(fakeResolver{},
		WithClient(ts.Client()),
		WithWordlist([]string{"www", "doesnotexist"}),
	)

	hosts, err := d.Discover(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("discover: %v", err)
	}

	got := map[string]bool{}
	for _, h := range hosts {
		got[h] = true
	}
	// passive: api, mail, and *.example.com stripped to example.com
	// brute: www resolves; doesnotexist does not
	for _, want := range []string{"api.example.com", "mail.example.com", "example.com", "www.example.com"} {
		if !got[want] {
			t.Errorf("missing host %q (got %v)", want, hosts)
		}
	}
	if got["doesnotexist.example.com"] {
		t.Errorf("non-resolving brute host should be dropped")
	}
}

func TestDiscover_PassiveOnly(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"name_value":"api.example.com"}]`))
	}))
	defer ts.Close()
	old := crtShURL
	crtShURL = ts.URL
	defer func() { crtShURL = old }()

	d := New(fakeResolver{}, WithClient(ts.Client()), WithPassiveOnly())
	hosts, err := d.Discover(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if len(hosts) != 1 || hosts[0] != "api.example.com" {
		t.Fatalf("passive-only hosts = %v, want [api.example.com]", hosts)
	}
}
