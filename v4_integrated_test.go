package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestV4AllowedOrigins(t *testing.T) {
	original, had := os.LookupEnv("V4_ALLOWED_ORIGINS")
	t.Cleanup(func() {
		if had {
			os.Setenv("V4_ALLOWED_ORIGINS", original)
		} else {
			os.Unsetenv("V4_ALLOWED_ORIGINS")
		}
	})
	os.Setenv("V4_ALLOWED_ORIGINS", "http://localhost:5173,https://v4-test.example.org")
	cases := []struct {
		origin  string
		allowed bool
	}{
		{"http://localhost:5173", true}, {"https://v4-test.example.org", true},
		{"http://localhost:5174", false}, {"https://v4-test.example.org.evil.test", false},
		{"https://ruangkita-697.pages.dev", true}, {"https://evil.example.org", false},
	}
	for _, tc := range cases {
		t.Run(tc.origin, func(t *testing.T) {
			if got := isAllowedOrigin(tc.origin); got != tc.allowed {
				t.Fatalf("origin=%q allowed=%v want=%v", tc.origin, got, tc.allowed)
			}
		})
	}
}
func TestV4DeleteRejectsBadIDs(t *testing.T) {
	a := &App{}
	u := &User{ID: 1}
	for _, tc := range []struct {
		path    string
		content string
	}{
		{"/v4/messages/not-a-number?scope=me", "ID pesan tidak valid"},
		{"/v4/media/bad?scope=me", "ID media tidak valid"},
	} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodDelete, tc.path, nil)
		if strings.HasPrefix(tc.path, "/v4/messages/") {
			a.deleteMessageV4(w, r, u)
		} else {
			a.deleteMediaV4(w, r, u)
		}
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), tc.content) {
			t.Fatalf("path=%s status=%d body=%s", tc.path, w.Code, w.Body.String())
		}
	}
}
