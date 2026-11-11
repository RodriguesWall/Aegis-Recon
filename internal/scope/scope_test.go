package scope_test

import (
	"context"
	"testing"
	"time"

	"github.com/RodriguesWall/aegis-recon/internal/scope"
)

func TestInScope(t *testing.T) {
	s := scope.New("example.com")
	cases := map[string]bool{
		"example.com":          true,
		"www.example.com":      true,
		"a.b.example.com":      true,
		"EXAMPLE.COM":          true, // case-insensitive
		"evil.com":             false,
		"example.com.evil.com": false, // suffix trick
		"notexample.com":       false,
		"":                     false,
	}
	for host, want := range cases {
		if got := s.InScope(host); got != want {
			t.Errorf("InScope(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestFilter_DedupAndScope(t *testing.T) {
	s := scope.New("example.com")
	in := []string{
		"www.example.com",
		"www.example.com", // dup
		"*.example.com",   // wildcard -> example.com
		"evil.com",        // off-scope
		"API.EXAMPLE.COM", // normalized
	}
	out := s.Filter(in)

	got := map[string]bool{}
	for _, h := range out {
		got[h] = true
	}
	if got["evil.com"] {
		t.Error("off-scope host passed the filter")
	}
	for _, want := range []string{"www.example.com", "example.com", "api.example.com"} {
		if !got[want] {
			t.Errorf("missing %q in %v", want, out)
		}
	}
	if len(out) != 3 {
		t.Errorf("expected 3 unique in-scope hosts, got %v", out)
	}
}

func TestRateLimiter(t *testing.T) {
	r := scope.NewRateLimiter(50 * time.Millisecond)
	start := time.Now()
	for i := 0; i < 3; i++ {
		if err := r.Wait(context.Background(), "h"); err != nil {
			t.Fatalf("wait: %v", err)
		}
	}
	// 3 calls, 2 gaps of 50ms -> at least 100ms.
	if elapsed := time.Since(start); elapsed < 100*time.Millisecond {
		t.Errorf("rate limiter too fast: %v", elapsed)
	}
}
