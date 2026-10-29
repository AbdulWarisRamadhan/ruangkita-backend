
package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGenerateToken(t *testing.T) {
	first, err := generateToken()
	if err != nil {
		t.Fatal(err)
	}

	second, err := generateToken()
	if err != nil {
		t.Fatal(err)
	}

	if len(first) != 64 || len(second) != 64 {
		t.Fatal("Panjang token salah")
	}

	if first == second {
		t.Fatal("Token tidak boleh sama")
	}

	if tokenHash(first) == first {
		t.Fatal("Hash token tidak boleh sama dengan token asli")
	}
}

func TestBearerToken(t *testing.T) {
	token, err := generateToken()
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	got, err := bearerToken(req)
	if err != nil || got != token {
		t.Fatal("Bearer token valid ditolak")
	}

	req.Header.Set("Authorization", "Bearer invalid")

	if _, err := bearerToken(req); err == nil {
		t.Fatal("Token tidak valid diterima")
	}
}

func TestValidText(t *testing.T) {
	if !validText("Halo", 1, 10) {
		t.Fatal("Teks valid ditolak")
	}

	if validText("   ", 1, 10) {
		t.Fatal("Teks kosong diterima")
	}

	if !validText("你好", 2, 2) {
		t.Fatal("Unicode valid ditolak")
	}
}

func TestValidPassword(t *testing.T) {
	if validPassword("pendek") {
		t.Fatal("Password pendek diterima")
	}

	if !validPassword("PasswordAman12345") {
		t.Fatal("Password valid ditolak")
	}

	if validPassword(strings.Repeat("x", 73)) {
		t.Fatal("Password terlalu panjang diterima")
	}
}

func TestDecodeJSON(t *testing.T) {
	var input struct {
		Name string `json:"name"`
	}

	req := httptest.NewRequest(
		http.MethodPost,
		"/test",
		bytes.NewBufferString(`{"name":"Alin"}`),
	)

	w := httptest.NewRecorder()

	if err := decodeJSON(w, req, &input); err != nil {
		t.Fatal(err)
	}

	if input.Name != "Alin" {
		t.Fatal("Hasil decode salah")
	}
}

func TestDecodeJSONRejectUnknownField(t *testing.T) {
	var input struct {
		Name string `json:"name"`
	}

	req := httptest.NewRequest(
		http.MethodPost,
		"/test",
		bytes.NewBufferString(`{"name":"Alin","admin":true}`),
	)

	w := httptest.NewRecorder()

	if err := decodeJSON(w, req, &input); err == nil {
		t.Fatal("Field tidak dikenal diterima")
	}
}

func TestLoginLimiter(t *testing.T) {
	limiter := newLoginLimiter()
	ip := "127.0.0.1"

	for i := 0; i < maxLoginFails; i++ {
		limiter.failed(ip)
	}

	if !limiter.blocked(ip) {
		t.Fatal("Rate limiter gagal memblokir")
	}

	limiter.clear(ip)

	if limiter.blocked(ip) {
		t.Fatal("Rate limiter gagal direset")
	}
}

func TestHealthMethodNotAllowed(t *testing.T) {
	app := &App{}

	req := httptest.NewRequest(
		http.MethodPost,
		"/health",
		nil,
	)

	w := httptest.NewRecorder()
	app.health(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("Status salah: %d", w.Code)
	}
}

func TestCORS(t *testing.T) {
	app := &App{}
	handler := app.routes()

	req := httptest.NewRequest(
		http.MethodOptions,
		"/login",
		nil,
	)
	req.Header.Set("Origin", allowedOrigin)

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("Preflight gagal: %d", w.Code)
	}

	if w.Header().Get("Access-Control-Allow-Origin") != allowedOrigin {
		t.Fatal("CORS origin salah")
	}

	req2 := httptest.NewRequest(
		http.MethodOptions,
		"/login",
		nil,
	)
	req2.Header.Set("Origin", "https://evil.example")

	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)

	if w2.Code != http.StatusForbidden {
		t.Fatal("Origin asing tidak ditolak")
	}
}

func TestJSONError(t *testing.T) {
	w := httptest.NewRecorder()

	writeError(
		w,
		http.StatusBadRequest,
		"Kesalahan",
	)

	var result map[string]string

	if err := json.Unmarshal(
		w.Body.Bytes(),
		&result,
	); err != nil {
		t.Fatal(err)
	}

	if result["error"] != "Kesalahan" {
		t.Fatal("Format error salah")
	}
}
