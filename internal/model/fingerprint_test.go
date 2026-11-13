package model

import "testing"

func TestFingerprintStable(t *testing.T) {
	a := Finding{Scanner: "port", Target: Target{Host: "example.com", Port: 443}, Title: "Open port 443"}
	b := Finding{Scanner: "port", Target: Target{Host: "example.com", Port: 443}, Title: "Open port 443"}
	if a.Fingerprint() != b.Fingerprint() {
		t.Fatalf("same finding must hash equal: %s != %s", a.Fingerprint(), b.Fingerprint())
	}
}

func TestFingerprintNormalizesTitleAndHost(t *testing.T) {
	a := Finding{Scanner: "port", Target: Target{Host: "example.com", Port: 443}, Title: "Open port 443"}
	// Different casing and surrounding whitespace must not fork the fingerprint.
	b := Finding{Scanner: "PORT", Target: Target{Host: "EXAMPLE.com", Port: 443}, Title: "  open PORT 443  "}
	if a.Fingerprint() != b.Fingerprint() {
		t.Fatalf("casing/whitespace must not change fingerprint: %s != %s", a.Fingerprint(), b.Fingerprint())
	}
}

func TestFingerprintPortDistinct(t *testing.T) {
	p80 := Finding{Scanner: "port", Target: Target{Host: "example.com", Port: 80}, Title: "Open port"}
	p443 := Finding{Scanner: "port", Target: Target{Host: "example.com", Port: 443}, Title: "Open port"}
	if p80.Fingerprint() == p443.Fingerprint() {
		t.Fatal("same host on different ports must hash distinct")
	}
}

func TestFingerprintHostFallsBackToDomain(t *testing.T) {
	// dns findings carry Domain only; it must still produce a stable fingerprint.
	a := Finding{Scanner: "dns", Target: Target{Domain: "example.com"}, Title: "A record"}
	b := Finding{Scanner: "dns", Target: Target{Domain: "example.com"}, Title: "A record"}
	if a.Fingerprint() != b.Fingerprint() {
		t.Fatal("domain-only finding must hash stable")
	}
	if a.Fingerprint() == "" {
		t.Fatal("fingerprint must not be empty")
	}
}

func TestFingerprintNoFieldRunTogether(t *testing.T) {
	// Without a separator "ab"+"c" and "a"+"bc" would collide. The NUL join
	// must keep these distinct.
	a := Finding{Scanner: "ab", Target: Target{Host: "c"}, Title: "x"}
	b := Finding{Scanner: "a", Target: Target{Host: "bc"}, Title: "x"}
	if a.Fingerprint() == b.Fingerprint() {
		t.Fatal("field boundaries must not collide")
	}
}
