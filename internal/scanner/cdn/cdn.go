// Package cdn detects whether a host sits behind a CDN or WAF, using pure-Go
// heuristics: response-header signatures and the host's CNAME chain. No ASN
// database or external service is used. Findings are informational — they add
// context to other findings rather than flagging a weakness.
package cdn

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/RodriguesWall/aegis-recon/internal/model"
)

// kind distinguishes a content-delivery network from a web application firewall
// in the finding title.
type kind string

const (
	kindCDN kind = "CDN"
	kindWAF kind = "WAF"
)

// headerRule matches a response header. value is a lowercased substring that
// must be present; an empty value means the header only has to exist.
type headerRule struct {
	name  string
	value string
}

// sig is one provider's fingerprint: any header rule OR any CNAME suffix match
// identifies it.
type sig struct {
	provider string
	kind     kind
	headers  []headerRule
	cnames   []string // matched as suffixes of the host's CNAME
}

// signatures lists the providers detected. Ordered: the first match wins.
var signatures = []sig{
	{"Cloudflare", kindCDN,
		[]headerRule{{"Server", "cloudflare"}, {"CF-Ray", ""}, {"CF-Cache-Status", ""}},
		[]string{"cloudflare.net", "cloudflare.com"}},
	{"Sucuri", kindWAF,
		[]headerRule{{"Server", "sucuri"}, {"X-Sucuri-ID", ""}, {"X-Sucuri-Cache", ""}},
		nil},
	{"Imperva Incapsula", kindWAF,
		[]headerRule{{"X-Iinfo", ""}, {"X-CDN", "incapsula"}},
		[]string{"incapdns.net"}},
	{"Akamai", kindCDN,
		[]headerRule{{"Server", "akamaighost"}, {"X-Akamai-Transformed", ""}, {"X-Akamai-Request-ID", ""}},
		[]string{"akamaiedge.net", "akamai.net", "edgekey.net", "edgesuite.net", "akamaihd.net"}},
	{"AWS CloudFront", kindCDN,
		[]headerRule{{"X-Amz-Cf-Id", ""}, {"X-Amz-Cf-Pop", ""}, {"Via", "cloudfront"}},
		[]string{"cloudfront.net"}},
	{"Fastly", kindCDN,
		[]headerRule{{"X-Fastly-Request-ID", ""}, {"Server", "fastly"}},
		[]string{"fastly.net", "fastlylb.net"}},
	{"Azure", kindCDN,
		[]headerRule{{"X-Azure-Ref", ""}},
		[]string{"azureedge.net", "azurefd.net", "trafficmanager.net"}},
	{"Google", kindCDN,
		[]headerRule{{"Via", "google"}, {"Server", "gws"}},
		nil},
	{"StackPath", kindCDN, nil, []string{"stackpathdns.com", "hwcdn.net"}},
	{"KeyCDN", kindCDN, nil, []string{"kxcdn.com"}},
	{"CDN77", kindCDN, nil, []string{"cdn77.org"}},
}

// Scanner detects CDN/WAF presence for a host.
type Scanner struct {
	resolver model.Resolver
	client   *http.Client
	scheme   string
}

// Option configures the scanner.
type Option func(*Scanner)

// WithClient injects an HTTP client (tests pass httptest's client).
func WithClient(c *http.Client) Option { return func(s *Scanner) { s.client = c } }

// WithScheme forces "http" or "https" (default "https").
func WithScheme(scheme string) Option { return func(s *Scanner) { s.scheme = scheme } }

// New builds a CDN/WAF scanner using the given resolver (for CNAME lookups).
func New(r model.Resolver, opts ...Option) *Scanner {
	s := &Scanner{resolver: r, scheme: "https"}
	for _, o := range opts {
		o(s)
	}
	if s.client == nil {
		s.client = &http.Client{Timeout: 10 * time.Second}
	}
	return s
}

func (s *Scanner) Name() string { return "cdn" }

// Scan detects the CDN/WAF in front of the host, if any, and emits a single
// informational finding. Header evidence is preferred; a CNAME match is the
// fallback. Errors (host down, no CNAME) are non-fatal: they just mean no finding.
func (s *Scanner) Scan(ctx context.Context, t model.Target, emit model.EmitFunc) error {
	host := t.Host
	if host == "" {
		host = t.Domain
	}
	if host == "" {
		return nil
	}

	header := s.fetchHeaders(ctx, host)
	cname := s.lookupCNAME(ctx, host)

	for _, sg := range signatures {
		if sig, ok := matchHeaders(sg, header); ok {
			emit(s.finding(t, sg, sig))
			return nil
		}
		if cn, ok := matchCNAME(sg, cname); ok {
			emit(s.finding(t, sg, "cname:"+cn))
			return nil
		}
	}
	return nil
}

func (s *Scanner) finding(t model.Target, sg sig, signal string) model.Finding {
	return model.Finding{
		Scanner:  "cdn",
		Target:   t,
		Severity: model.SeverityInfo,
		Title:    "behind " + string(sg.kind) + ": " + sg.provider,
		Evidence: map[string]any{"provider": sg.provider, "kind": string(sg.kind), "signal": signal},
	}
}

// fetchHeaders does a best-effort GET and returns the response headers (nil on
// failure). The body is discarded.
func (s *Scanner) fetchHeaders(ctx context.Context, host string) http.Header {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.scheme+"://"+host, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Aegis-Recon/0.1 (+authorized-use-only)")
	resp, err := s.client.Do(req)
	if err != nil {
		return nil
	}
	_ = resp.Body.Close()
	return resp.Header
}

func (s *Scanner) lookupCNAME(ctx context.Context, host string) string {
	cn, err := s.resolver.LookupCNAME(ctx, host)
	if err != nil {
		return ""
	}
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(cn)), ".")
}

// matchHeaders returns the matching signal (e.g. "header:CF-Ray") if any rule
// matches the response headers.
func matchHeaders(sg sig, h http.Header) (string, bool) {
	if h == nil {
		return "", false
	}
	for _, r := range sg.headers {
		v := h.Get(r.name)
		if v == "" {
			continue
		}
		if r.value == "" || strings.Contains(strings.ToLower(v), r.value) {
			return "header:" + r.name, true
		}
	}
	return "", false
}

// matchCNAME returns the matched suffix if the CNAME ends with one of the
// provider's suffixes.
func matchCNAME(sg sig, cname string) (string, bool) {
	if cname == "" {
		return "", false
	}
	for _, suf := range sg.cnames {
		if cname == suf || strings.HasSuffix(cname, "."+suf) {
			return suf, true
		}
	}
	return "", false
}
