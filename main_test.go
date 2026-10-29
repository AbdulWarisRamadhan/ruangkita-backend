package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestTokenUniqueAndHash(t *testing.T) {
	first, err := generateToken()
	if err != nil {
		t.Fatal(err)
	}
	second, err := generateToken()
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 64 || first == second || tokenHash(first) == first || tokenHash(first) == tokenHash(second) {
		t.Fatal("token tidak memenuhi persyaratan")
	}
}
func TestBearerToken(t *testing.T) {
	token, _ := generateToken()
	for _, tc := range []struct {
		header string
		ok     bool
	}{{"Bearer " + token, true}, {"Bearer abc", false}, {"Basic " + token, false}, {"", false}} {
		r := httptest.NewRequest(http.MethodGet, "/me", nil)
		r.Header.Set("Authorization", tc.header)
		_, err := bearerToken(r)
		if (err == nil) != tc.ok {
			t.Fatalf("header %q: %v", tc.header, err)
		}
	}
}
func TestDecodeJSON(t *testing.T) {
	for _, tc := range []struct {
		body string
		ok   bool
	}{{`{"username":"a"}`, true}, {`{"unknown":1}`, false}, {`{"username":"a"} {}`, false}, {`{`, false}} {
		r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(tc.body))
		w := httptest.NewRecorder()
		var out struct {
			Username string `json:"username"`
		}
		err := decodeJSON(w, r, &out)
		if (err == nil) != tc.ok {
			t.Fatalf("body %q: %v", tc.body, err)
		}
	}
}
func TestValidation(t *testing.T) {
	if !validText("  nama  ", 1, 4) || validText("", 1, 5) || validText("abcde", 1, 4) || validText(string([]byte{0xff}), 1, 4) {
		t.Fatal("validasi teks salah")
	}
}
func TestCORS(t *testing.T) {
	app := &App{}
	for _, tc := range []struct {
		origin, method string
		status         int
	}{
		{"https://ruangkita-697.pages.dev", "POST", 204},
		{"https://evil.example", "POST", 403},
		{"https://ruangkita-697.pages.dev", "DELETE", 405},
		{"", "POST", 403},
	} {
		r := httptest.NewRequest(http.MethodOptions, "/login", nil)
		r.Header.Set("Origin", tc.origin)
		r.Header.Set("Access-Control-Request-Method", tc.method)
		w := httptest.NewRecorder()
		app.routes().ServeHTTP(w, r)
		if w.Code != tc.status {
			t.Fatalf("origin=%q method=%q status=%d", tc.origin, tc.method, w.Code)
		}
	}
}
func TestLimiter(t *testing.T) {
	ip := "192.0.2.254"
	clearLoginFailures(ip)
	defer clearLoginFailures(ip)
	for i := 0; i < maxLoginFails; i++ {
		if blockedLogin(ip) {
			t.Fatalf("terblokir terlalu awal: %d", i)
		}
		failedLogin(ip)
	}
	if !blockedLogin(ip) {
		t.Fatal("tidak diblokir")
	}
	loginLimiter.Lock()
	loginLimiter.records[ip] = attemptRecord{count: maxLoginFails, windowEnds: time.Now().Add(-time.Second)}
	loginLimiter.Unlock()
	if blockedLogin(ip) {
		t.Fatal("blokir tidak kedaluwarsa")
	}
}
func TestHealthWrongMethod(t *testing.T) {
	app := &App{}
	r := httptest.NewRequest(http.MethodPost, "/health", nil)
	w := httptest.NewRecorder()
	app.routes().ServeHTTP(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatal(w.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || body["error"] == "" {
		t.Fatal("error JSON invalid")
	}
}
