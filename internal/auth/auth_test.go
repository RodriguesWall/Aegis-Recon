package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDisabledByDefault(t *testing.T) {
	t.Setenv("AEGIS_ADMIN_PASSWORD", "")
	if Enabled() {
		t.Fatal("auth should be disabled when password unset")
	}
}

func TestCheckPassword(t *testing.T) {
	t.Setenv("AEGIS_ADMIN_PASSWORD", "s3cret")
	if !Enabled() {
		t.Fatal("should be enabled")
	}
	if !CheckPassword("s3cret") {
		t.Fatal("correct password rejected")
	}
	if CheckPassword("wrong") {
		t.Fatal("wrong password accepted")
	}
}

func TestSessionRoundTrip(t *testing.T) {
	t.Setenv("AEGIS_ADMIN_PASSWORD", "s3cret")
	t.Setenv("AEGIS_SECRET_KEY", "key")

	rec := httptest.NewRecorder()
	IssueCookie(rec)
	req := httptest.NewRequest("GET", "/api/x", nil)
	for _, c := range rec.Result().Cookies() {
		req.AddCookie(c)
	}
	if !Valid(req) {
		t.Fatal("freshly issued cookie should be valid")
	}

	// Tampered cookie is rejected.
	bad := httptest.NewRequest("GET", "/api/x", nil)
	bad.AddCookie(&http.Cookie{Name: cookieName, Value: "9999999999.deadbeef"})
	if Valid(bad) {
		t.Fatal("tampered cookie accepted")
	}
}

func TestMiddlewareGuards(t *testing.T) {
	t.Setenv("AEGIS_ADMIN_PASSWORD", "s3cret")
	h := Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))

	// Protected API path without a cookie -> 401.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/api/projects", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rec.Code)
	}
	// Public paths pass.
	for _, p := range []string{"/health", "/api/login", "/api/auth"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", p, nil))
		if rec.Code != 200 {
			t.Fatalf("%s should be public, got %d", p, rec.Code)
		}
	}
}
