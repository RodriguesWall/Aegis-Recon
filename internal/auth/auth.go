// Package auth provides single-admin authentication: a password from the
// AEGIS_ADMIN_PASSWORD environment variable and a stateless, HMAC-signed session
// cookie. When the variable is unset, auth is disabled (open) so existing
// single-user deployments keep working.
package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	cookieName = "aegis_session"
	ttl        = 24 * time.Hour
)

// Enabled reports whether authentication is on (admin password configured).
func Enabled() bool { return os.Getenv("AEGIS_ADMIN_PASSWORD") != "" }

// CheckPassword constant-time compares pw against the configured admin password.
func CheckPassword(pw string) bool {
	want := os.Getenv("AEGIS_ADMIN_PASSWORD")
	if want == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(pw), []byte(want)) == 1
}

// signingKey derives the HMAC key from AEGIS_SECRET_KEY, falling back to the
// admin password so a session key always exists when auth is enabled.
func signingKey() []byte {
	k := os.Getenv("AEGIS_SECRET_KEY")
	if k == "" {
		k = os.Getenv("AEGIS_ADMIN_PASSWORD")
	}
	h := sha256.Sum256([]byte(k))
	return h[:]
}

// token builds "<exp>.<hmac(exp)>".
func token(exp int64) string {
	msg := strconv.FormatInt(exp, 10)
	mac := hmac.New(sha256.New, signingKey())
	mac.Write([]byte(msg))
	return msg + "." + hex.EncodeToString(mac.Sum(nil))
}

// IssueCookie sets a fresh session cookie.
func IssueCookie(w http.ResponseWriter) {
	exp := time.Now().Add(ttl).Unix()
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: token(exp), Path: "/",
		HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: int(ttl.Seconds()),
	})
}

// ClearCookie expires the session cookie.
func ClearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", HttpOnly: true, MaxAge: -1})
}

// Valid reports whether the request carries a valid, unexpired session cookie.
func Valid(r *http.Request) bool {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return false
	}
	dot := strings.LastIndexByte(c.Value, '.')
	if dot < 0 {
		return false
	}
	exp, err := strconv.ParseInt(c.Value[:dot], 10, 64)
	if err != nil || time.Now().Unix() >= exp {
		return false
	}
	return hmac.Equal([]byte(c.Value), []byte(token(exp)))
}

// Middleware guards /api/* (except login and the auth-status endpoint) when auth
// is enabled; /health is always open.
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !Enabled() {
			next.ServeHTTP(w, r)
			return
		}
		p := r.URL.Path
		if p == "/health" || p == "/api/login" || p == "/api/auth" || !strings.HasPrefix(p, "/api/") {
			next.ServeHTTP(w, r)
			return
		}
		if !Valid(r) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"authentication required"}`))
			return
		}
		next.ServeHTTP(w, r)
	})
}
