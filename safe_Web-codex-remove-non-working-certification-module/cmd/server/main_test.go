package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"safe_web/internal/session"
	"safe_web/internal/store"
)

func TestBuildPublicTLSConfig(t *testing.T) {
	cfg, err := buildPublicTLSConfig()
	if err != nil {
		t.Fatalf("build tls config: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil tls config")
	}
}

func TestPasswordComplexity(t *testing.T) {
	if !checkPasswordComplexity("StrongPass123!") {
		t.Fatal("expected strong password to pass")
	}
	if checkPasswordComplexity("weak") {
		t.Fatal("expected weak password to fail")
	}
}

func TestParseServerRole(t *testing.T) {
	pub, adm, err := parseServerRole("public")
	if err != nil || !pub || adm {
		t.Fatalf("public role parse failed: pub=%v admin=%v err=%v", pub, adm, err)
	}

	pub, adm, err = parseServerRole("admin")
	if err != nil || pub || !adm {
		t.Fatalf("admin role parse failed: pub=%v admin=%v err=%v", pub, adm, err)
	}

	pub, adm, err = parseServerRole("all")
	if err != nil || !pub || !adm {
		t.Fatalf("all role parse failed: pub=%v admin=%v err=%v", pub, adm, err)
	}

	if _, _, err = parseServerRole("bad"); err == nil {
		t.Fatal("expected parse error for invalid role")
	}
}

func TestPublicDenyAdminPaths(t *testing.T) {
	app := &App{Store: store.NewMemoryStore()}
	handler := app.publicDenyAdminPaths(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/admin/whitelist", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for admin path on public handler, got %d", w.Code)
	}
}

func TestCSRFCookiesSeparatedByScope(t *testing.T) {
	app := &App{
		PublicCSRFCookie: "public_csrf_token",
		AdminCSRFCookie:  "admin_csrf_token",
		PublicTLS:        true,
		AdminTLS:         true,
		Sessions:         session.NewStore(time.Hour),
	}

	wPublic := httptest.NewRecorder()
	publicToken, err := app.issueCSRFCookie(wPublic)
	if err != nil {
		t.Fatalf("issue public csrf: %v", err)
	}
	reqAdmin := httptest.NewRequest(http.MethodPost, "/admin/login", nil)
	reqAdmin.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqAdmin.Form = map[string][]string{"csrf_token": {publicToken}}
	for _, c := range wPublic.Result().Cookies() {
		reqAdmin.AddCookie(c)
	}
	if app.verifyAdminCSRF(reqAdmin) {
		t.Fatal("admin csrf verification must fail with public csrf cookie")
	}
}
