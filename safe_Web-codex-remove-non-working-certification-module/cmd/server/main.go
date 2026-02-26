package main

import (
	"bufio"
	"crypto/rand"
	"crypto/tls"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"safe_web/internal/auth"
	"safe_web/internal/icmprepo"
	"safe_web/internal/ratelimit"
	"safe_web/internal/session"
	"safe_web/internal/store"
	"safe_web/internal/web"
)

const (
	defaultPublicAddr = ":8443"
	defaultAdminAddr  = "127.0.0.1:9443"
	defaultLocalAddr  = ""

	defaultPublicCertPath = "config/cert.pem"
	defaultPublicKeyPath  = "config/key.pem"
	defaultAdminCertPath  = "config/admin_cert.pem"
	defaultAdminKeyPath   = "config/admin_key.pem"

	loginWindowMinutes = 10
	banTTLMinutes      = 60
	maxLoginBodyBytes  = 1 << 20
	passwordMaxAge     = 90 * 24 * time.Hour
	publicSessionTTL   = 8 * time.Hour
	adminSessionTTL    = 2 * time.Hour
	icmpHostsCacheTTL  = 2 * time.Second
)

type App struct {
	Store         store.Store
	Limiter       *ratelimit.Limiter
	AdminLimiter  *ratelimit.Limiter
	Sessions      *session.Store
	AdminSessions *session.Store
	DummyHash     string
	CookieName    string
	AdminCookie   string
	Settings      *Settings
	ICMPRepo      *icmprepo.Repo
	PublicTLS     bool
	AdminTLS      bool

	icmpHostsCacheMu    sync.Mutex
	icmpHostsCacheUntil time.Time
	icmpHostsCacheJSON  []byte
}

type Settings struct {
	requireLogin atomic.Bool
}

type SettingsView struct {
	RequireLogin bool
}

func NewSettings(requireLogin bool) *Settings {
	s := &Settings{}
	s.requireLogin.Store(requireLogin)
	return s
}

func (s *Settings) RequireLogin() bool {
	return s.requireLogin.Load()
}

func (s *Settings) SetRequireLogin(value bool) {
	s.requireLogin.Store(value)
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type templateData struct {
	CSRFToken         string
	Error             string
	Username          string
	PasswordChangedAt string
	Clients           []store.Client
	Client            *store.Client
	WhitelistEntries  []store.WhitelistEntry
	AdminAudit        []store.AuditEntry
	UserAudit         []store.UserAuditEntry
	Settings          *SettingsView
	Users             []store.User
	UserIPs           map[int64]string
}

func main() {
	publicAddr, publicEnabled, err := promptPublicListenAddr()
	if err != nil {
		log.Fatalf("public interface selection failed: %v", err)
	}

	adminAddr := defaultAdminAddr
	if requested := strings.TrimSpace(os.Getenv("LISTEN_ADMIN_ADDR")); requested != "" && requested != defaultAdminAddr {
		log.Printf("LISTEN_ADMIN_ADDR is ignored; admin is fixed to %s", defaultAdminAddr)
	}
	localAddr := getenv("LISTEN_LOCAL_ADDR", defaultLocalAddr)
	publicCertPath := getenv("PUBLIC_CERT_PATH", defaultPublicCertPath)
	publicKeyPath := getenv("PUBLIC_KEY_PATH", defaultPublicKeyPath)
	adminCertPath := getenv("ADMIN_CERT_PATH", defaultAdminCertPath)
	adminKeyPath := getenv("ADMIN_KEY_PATH", defaultAdminKeyPath)
	publicTLSEnabled := getenvBool("PUBLIC_TLS_ENABLED", false)
	adminTLSEnabled := getenvBool("ADMIN_TLS_ENABLED", false)
	requireLogin := getenvBool("REQUIRE_LOGIN", true)

	if publicEnabled {
		validateListenAddr(publicAddr)
	}
	validateLoopbackAddr(adminAddr)

	st, err := store.NewStore()
	if err != nil {
		log.Fatalf("store init: %v", err)
	}
	icmpDBPath := getenv("ICMPMON_DB_PATH", "icmpmon/icmpmon.db")
	icmpRepo, icmpErr := icmprepo.New(icmpDBPath)
	if icmpErr != nil {
		log.Printf("icmp repo disabled (%s): %v", icmpDBPath, icmpErr)
	}

	dummyHash, err := auth.HashPassword("dummy-password")
	if err != nil {
		log.Fatalf("dummy hash: %v", err)
	}

	settings := NewSettings(requireLogin)

	app := &App{
		Store:         st,
		Limiter:       ratelimit.New(5, time.Minute),
		AdminLimiter:  ratelimit.New(5, time.Minute),
		Sessions:      session.NewStore(publicSessionTTL),
		AdminSessions: session.NewStore(adminSessionTTL),
		DummyHash:     dummyHash,
		CookieName:    "session_id",
		AdminCookie:   "admin_session",
		Settings:      settings,
		ICMPRepo:      icmpRepo,
		PublicTLS:     publicTLSEnabled,
		AdminTLS:      adminTLSEnabled,
	}

	bootstrapAdminUser(app)

	var publicServer *http.Server
	if publicEnabled {
		var publicTLS *tls.Config
		if publicTLSEnabled {
			publicTLS, err = buildPublicTLSConfig()
			if err != nil {
				log.Fatalf("tls config: %v", err)
			}
		}

		publicMux := http.NewServeMux()
		publicMux.Handle("/", app.ipGuard(app.securityHeaders(http.HandlerFunc(app.indexHandler))))
		publicMux.Handle("/favicon.ico", app.ipGuard(app.securityHeaders(http.HandlerFunc(app.faviconHandler))))
		publicMux.Handle("/login", app.ipGuard(app.securityHeaders(http.HandlerFunc(app.loginHandler))))
		publicMux.Handle("/app", app.ipGuard(app.securityHeaders(http.HandlerFunc(app.appHandler))))
		publicMux.Handle("/app/host", app.ipGuard(app.securityHeaders(http.HandlerFunc(app.appHostHandler))))
		publicMux.Handle("/change-password", app.ipGuard(app.securityHeaders(http.HandlerFunc(app.changePasswordHandler))))
		publicMux.Handle("/app/api/icmp/hosts", app.ipGuard(app.securityHeaders(app.publicAppAuth(http.HandlerFunc(app.icmpHostsHandler)))))
		publicMux.Handle("/app/api/icmp/host", app.ipGuard(app.securityHeaders(app.publicAppAuth(http.HandlerFunc(app.icmpHostHandler)))))
		publicMux.Handle("/app/api/icmp/host/samples", app.ipGuard(app.securityHeaders(app.publicAppAuth(http.HandlerFunc(app.icmpHostSamplesHandler)))))
		publicMux.Handle("/app/api/icmp/host/events", app.ipGuard(app.securityHeaders(app.publicAppAuth(http.HandlerFunc(app.icmpHostEventsHandler)))))
		publicMux.Handle("/app/api/icmp/host/add", app.ipGuard(app.securityHeaders(app.publicAppAuth(http.HandlerFunc(app.icmpHostAddHandler)))))
		publicMux.Handle("/app/api/icmp/host/edit", app.ipGuard(app.securityHeaders(app.publicAppAuth(http.HandlerFunc(app.icmpHostEditHandler)))))
		publicMux.Handle("/app/api/icmp/host/delete", app.ipGuard(app.securityHeaders(app.publicAppAuth(http.HandlerFunc(app.icmpHostDeleteHandler)))))
		publicMux.Handle("/app/api/icmp/export.csv", app.ipGuard(app.securityHeaders(app.publicAppAuth(http.HandlerFunc(app.icmpExportCSVHandler)))))
		publicMux.Handle("/app/api/icmp/import/preview.csv", app.ipGuard(app.securityHeaders(app.publicAppAuth(http.HandlerFunc(app.icmpImportPreviewCSVHandler)))))
		publicMux.Handle("/app/api/icmp/import.csv", app.ipGuard(app.securityHeaders(app.publicAppAuth(http.HandlerFunc(app.icmpImportCSVHandler)))))

		publicServer = &http.Server{
			Addr:              publicAddr,
			Handler:           publicMux,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      10 * time.Second,
			IdleTimeout:       60 * time.Second,
			TLSConfig:         publicTLS,
		}
	}

	adminMux := http.NewServeMux()
	adminMux.Handle("/", app.adminIPGuard(app.securityHeaders(http.HandlerFunc(app.adminRootHandler))))
	adminMux.Handle("/admin/login", app.adminIPGuard(app.securityHeaders(http.HandlerFunc(app.adminLoginHandler))))
	adminMux.Handle("/admin/logout", app.adminIPGuard(app.securityHeaders(http.HandlerFunc(app.adminLogoutHandler))))
	adminMux.Handle("/admin/dashboard", app.adminAuth(app.securityHeaders(http.HandlerFunc(app.adminDashboardHandler))))
	adminMux.Handle("/admin/clients", app.adminAuth(app.securityHeaders(http.HandlerFunc(app.adminClientsHandler))))
	adminMux.Handle("/admin/clients/", app.adminAuth(app.securityHeaders(http.HandlerFunc(app.adminClientDetailHandler))))
	adminMux.Handle("/admin/whitelist", app.adminAuth(app.securityHeaders(http.HandlerFunc(app.adminWhitelistHandler))))
	adminMux.Handle("/admin/settings", app.adminAuth(app.securityHeaders(http.HandlerFunc(app.adminSettingsHandler))))
	adminMux.Handle("/admin/audit", app.adminAuth(app.securityHeaders(http.HandlerFunc(app.adminAuditHandler))))
	adminMux.Handle("/admin/audit/admin", app.adminAuth(app.securityHeaders(http.HandlerFunc(app.adminAuditAdminHandler))))
	adminMux.Handle("/admin/audit/users", app.adminAuth(app.securityHeaders(http.HandlerFunc(app.adminAuditUsersHandler))))

	adminServer := &http.Server{
		Addr:              adminAddr,
		Handler:           adminMux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	if localAddr != "" {
		localMux := http.NewServeMux()
		localMux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		localServer := &http.Server{
			Addr:              localAddr,
			Handler:           localMux,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      10 * time.Second,
			IdleTimeout:       60 * time.Second,
		}

		go func() {
			log.Printf("local http listening on %s", localAddr)
			if err := localServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Fatalf("local server error: %v", err)
			}
		}()
	}

	if !publicEnabled {
		log.Printf("public client interface disabled")
		log.Printf("admin listening on %s", adminAddr)
		if adminTLSEnabled {
			if err := adminServer.ListenAndServeTLS(adminCertPath, adminKeyPath); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Fatalf("admin server error: %v", err)
			}
			return
		}
		if err := adminServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("admin server error: %v", err)
		}
		return
	}

	go func() {
		log.Printf("admin listening on %s", adminAddr)
		if adminTLSEnabled {
			if err := adminServer.ListenAndServeTLS(adminCertPath, adminKeyPath); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Fatalf("admin server error: %v", err)
			}
			return
		}
		if err := adminServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("admin server error: %v", err)
		}
	}()

	if publicTLSEnabled {
		log.Printf("public https listening on %s", publicAddr)
		if err := publicServer.ListenAndServeTLS(publicCertPath, publicKeyPath); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("public server error: %v", err)
		}
		return
	}

	log.Printf("public http listening on %s", publicAddr)
	if err := publicServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("public server error: %v", err)
	}
}

func buildPublicTLSConfig() (*tls.Config, error) {
	cfg := &tls.Config{
		MinVersion:               tls.VersionTLS12,
		PreferServerCipherSuites: true,
	}
	return cfg, nil
}

func (a *App) auditUserEvent(r *http.Request, eventType, actor string, details map[string]any) {
	payload := "{}"
	if len(details) > 0 {
		encoded, err := json.Marshal(details)
		if err == nil {
			payload = string(encoded)
		}
	}
	_ = a.Store.InsertAudit(eventType, actor, requestIP(r), payload, time.Now().Round(0))
}

func requestIP(r *http.Request) string {
	ip := clientIP(r)
	if ip != nil {
		return ip.String()
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return strings.TrimSpace(r.RemoteAddr)
}

func (a *App) ipGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)
		if ip == nil {
			a.auditUserEvent(r, "request_denied_invalid_ip", "", map[string]any{
				"path":   r.URL.Path,
				"method": r.Method,
			})
			minimalResponse(w)
			return
		}
		allowed, err := a.isWhitelisted(ip.String())
		if err != nil {
			a.auditUserEvent(r, "request_denied_whitelist_error", "", map[string]any{
				"path":   r.URL.Path,
				"method": r.Method,
			})
			minimalResponse(w)
			return
		}
		if !allowed {
			a.auditUserEvent(r, "request_denied_not_whitelisted", "", map[string]any{
				"path":   r.URL.Path,
				"method": r.Method,
			})
			minimalResponse(w)
			return
		}

		banned, err := a.Store.IsBanned(ip.String(), time.Now())
		if err == nil && banned {
			a.auditUserEvent(r, "request_denied_ip_banned", "", map[string]any{
				"path":   r.URL.Path,
				"method": r.Method,
			})
			minimalResponse(w)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (a *App) adminIPGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)
		if ip == nil || !ip.IsLoopback() {
			minimalResponse(w)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *App) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		csp := "default-src 'self'; frame-ancestors 'none'"
		if strings.HasPrefix(r.URL.Path, "/app") {
			csp = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'"
		}
		w.Header().Set("Content-Security-Policy", csp)
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "geolocation=(), camera=(), microphone=()")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Del("Server")
		next.ServeHTTP(w, r)
	})
}

func (a *App) publicAppAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !a.Settings.RequireLogin() {
			next.ServeHTTP(w, r)
			return
		}
		if _, ok := a.optionalPublicSession(r); !ok {
			minimalResponse(w)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *App) optionalPublicSession(r *http.Request) (*session.Session, bool) {
	cookie, err := r.Cookie(a.CookieName)
	if err != nil || cookie.Value == "" {
		return nil, false
	}
	sess, ok := a.Sessions.Get(cookie.Value, time.Now())
	if !ok {
		return nil, false
	}
	return sess, true
}

func (a *App) publicActor(r *http.Request) string {
	if sess, ok := a.optionalPublicSession(r); ok && strings.TrimSpace(sess.Username) != "" {
		return sess.Username
	}
	return "anonymous"
}

func (a *App) verifyPublicWriteCSRF(r *http.Request) bool {
	if a.Settings.RequireLogin() {
		sess, ok := a.optionalPublicSession(r)
		if !ok {
			return false
		}
		return a.verifySessionCSRF(r, sess.CSRFToken)
	}
	return a.verifyCSRF(r)
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeJSONBytes(w http.ResponseWriter, status int, payload []byte) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(payload)
}

func writeText(w http.ResponseWriter, status int, text string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(text))
}

func parseIntParam(r *http.Request, key string, fallback int) int {
	value := strings.TrimSpace(r.URL.Query().Get(key))
	if value == "" {
		return fallback
	}
	n, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return n
}

func parseOptionalInt64Param(r *http.Request, key string) *int64 {
	value := strings.TrimSpace(r.URL.Query().Get(key))
	if value == "" {
		return nil
	}
	n, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return nil
	}
	return &n
}

func (a *App) getICMPHostsCache(now time.Time) ([]byte, bool) {
	a.icmpHostsCacheMu.Lock()
	defer a.icmpHostsCacheMu.Unlock()
	if now.Before(a.icmpHostsCacheUntil) && len(a.icmpHostsCacheJSON) > 0 {
		out := make([]byte, len(a.icmpHostsCacheJSON))
		copy(out, a.icmpHostsCacheJSON)
		return out, true
	}
	return nil, false
}

func (a *App) setICMPHostsCache(now time.Time, payload []byte) {
	a.icmpHostsCacheMu.Lock()
	defer a.icmpHostsCacheMu.Unlock()
	a.icmpHostsCacheJSON = make([]byte, len(payload))
	copy(a.icmpHostsCacheJSON, payload)
	a.icmpHostsCacheUntil = now.Add(icmpHostsCacheTTL)
}

func (a *App) invalidateICMPHostsCache() {
	a.icmpHostsCacheMu.Lock()
	defer a.icmpHostsCacheMu.Unlock()
	a.icmpHostsCacheUntil = time.Time{}
	a.icmpHostsCacheJSON = nil
}

func (a *App) indexHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet || r.URL.Path != "/" {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	csrfToken, err := a.issueCSRFCookie(w)
	if err != nil {
		minimalResponse(w)
		return
	}

	a.auditUserEvent(r, "index_view", "", map[string]any{"path": r.URL.Path})
	web.Render(w, "index.html", templateData{CSRFToken: csrfToken})
}

func (a *App) faviconHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet || r.URL.Path != "/favicon.ico" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *App) loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	ip := clientIP(r)
	if ip == nil {
		minimalResponse(w)
		return
	}
	ipStr := ip.String()

	if !a.Limiter.Allow(ipStr, time.Now()) {
		a.auditUserEvent(r, "login_rate_limited", "", map[string]any{"path": r.URL.Path})
		minimalResponse(w)
		return
	}

	if !a.verifyCSRF(r) {
		a.auditUserEvent(r, "login_csrf_failed", "", map[string]any{"path": r.URL.Path})
		minimalResponse(w)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodyBytes)
	payload, err := parseLoginRequest(r)
	if err != nil {
		a.auditUserEvent(r, "login_bad_payload", "", map[string]any{"path": r.URL.Path})
		a.renderLoginError(w)
		return
	}

	username := strings.TrimSpace(payload.Username)
	password := payload.Password
	if username == "" || password == "" {
		a.auditUserEvent(r, "login_bad_payload", username, map[string]any{
			"path":   r.URL.Path,
			"reason": "empty_username_or_password",
		})
		a.renderLoginError(w)
		return
	}

	banned, err := a.Store.IsBanned(ipStr, time.Now())
	if err == nil && banned {
		a.auditUserEvent(r, "login_blocked", username, map[string]any{"reason": "ip_banned"})
		minimalResponse(w)
		return
	}

	user, err := a.Store.GetUser(username)
	userActive := err == nil && user != nil && user.IsActive
	storedHash := a.DummyHash
	if userActive {
		storedHash = user.PasswordHash
	}

	passwordOK, verifyErr := auth.VerifyPassword(password, storedHash)
	if verifyErr != nil || err != nil || !userActive || !passwordOK {
		_ = a.Store.InsertAttempt(ipStr, username, false, time.Now())
		a.auditUserEvent(r, "login_failed", username, map[string]any{"reason": "invalid_credentials"})

		shouldBan, checkErr := a.Store.CheckConsecutiveFailures(
			ipStr,
			time.Duration(loginWindowMinutes)*time.Minute,
			3,
			time.Now(),
		)
		if checkErr == nil && shouldBan {
			_ = a.Store.UpsertBan(ipStr, time.Duration(banTTLMinutes)*time.Minute, "3_failed_logins_in_10m", time.Now())
			a.auditUserEvent(r, "ip_banned", username, map[string]any{"reason": "3_failed_logins"})
		}

		a.renderLoginError(w)
		return
	}

	_ = a.Store.InsertAttempt(ipStr, username, true, time.Now())
	a.auditUserEvent(r, "login_success", username, map[string]any{})

	mustChange := time.Since(user.PasswordChangedAt) > passwordMaxAge
	sess, err := a.Sessions.Create(username, mustChange, time.Now())
	if err != nil {
		a.auditUserEvent(r, "login_session_create_error", username, map[string]any{"path": r.URL.Path})
		minimalResponse(w)
		return
	}

	setSessionCookie(w, a.CookieName, sess.ID, a.PublicTLS)
	setCSRFCookie(w, sess.CSRFToken, a.PublicTLS)

	if mustChange {
		a.auditUserEvent(r, "login_requires_password_change", username, map[string]any{})
		http.Redirect(w, r, "/change-password", http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/app", http.StatusSeeOther)
}

func (a *App) appHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	sess, ok := a.optionalPublicSession(r)
	if !ok {
		if a.Settings.RequireLogin() {
			a.auditUserEvent(r, "app_denied_no_session", "", map[string]any{"path": r.URL.Path})
			minimalResponse(w)
			return
		}
		csrfToken, err := a.issueCSRFCookie(w)
		if err != nil {
			minimalResponse(w)
			return
		}
		a.auditUserEvent(r, "app_view_guest_mode", "device", map[string]any{"path": r.URL.Path})
		web.Render(w, "app.html", templateData{
			Username:  "device",
			CSRFToken: csrfToken,
		})
		return
	}

	if sess.MustChange {
		a.auditUserEvent(r, "app_redirect_change_password", sess.Username, map[string]any{"path": r.URL.Path})
		http.Redirect(w, r, "/change-password", http.StatusSeeOther)
		return
	}

	user, err := a.Store.GetUser(sess.Username)
	if err != nil {
		a.auditUserEvent(r, "app_user_lookup_error", sess.Username, map[string]any{"path": r.URL.Path})
		minimalResponse(w)
		return
	}

	setCSRFCookie(w, sess.CSRFToken, a.PublicTLS)
	a.auditUserEvent(r, "app_view", user.Username, map[string]any{"path": r.URL.Path})
	web.Render(w, "app.html", templateData{
		Username:          user.Username,
		PasswordChangedAt: user.PasswordChangedAt.Format(time.RFC3339),
		CSRFToken:         sess.CSRFToken,
	})
}

func (a *App) appHostHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	sess, ok := a.optionalPublicSession(r)
	if !ok {
		if a.Settings.RequireLogin() {
			a.auditUserEvent(r, "app_host_denied_no_session", "", map[string]any{"path": r.URL.Path})
			minimalResponse(w)
			return
		}
		csrfToken, err := a.issueCSRFCookie(w)
		if err != nil {
			minimalResponse(w)
			return
		}
		web.Render(w, "app_host.html", templateData{
			Username:  "device",
			CSRFToken: csrfToken,
		})
		return
	}

	if sess.MustChange {
		http.Redirect(w, r, "/change-password", http.StatusSeeOther)
		return
	}

	user, err := a.Store.GetUser(sess.Username)
	if err != nil {
		minimalResponse(w)
		return
	}

	setCSRFCookie(w, sess.CSRFToken, a.PublicTLS)
	web.Render(w, "app_host.html", templateData{
		Username:          user.Username,
		PasswordChangedAt: user.PasswordChangedAt.Format(time.RFC3339),
		CSRFToken:         sess.CSRFToken,
	})
}

func (a *App) icmpHostsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if a.ICMPRepo == nil {
		writeText(w, http.StatusServiceUnavailable, "icmp repo is not available")
		return
	}

	now := time.Now()
	if cached, ok := a.getICMPHostsCache(now); ok {
		writeJSONBytes(w, http.StatusOK, cached)
		return
	}

	list, err := a.ICMPRepo.ListHosts()
	if err != nil {
		writeText(w, http.StatusInternalServerError, "db query failed")
		return
	}
	var up, down, unk int
	for _, host := range list {
		switch host.Status {
		case "UP":
			up++
		case "DOWN":
			down++
		default:
			unk++
		}
	}
	payload := map[string]any{
		"hosts": len(list),
		"up":    up,
		"down":  down,
		"unk":   unk,
		"list":  list,
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		writeText(w, http.StatusInternalServerError, "json encode failed")
		return
	}
	a.setICMPHostsCache(now, encoded)
	writeJSONBytes(w, http.StatusOK, encoded)
}

func (a *App) icmpHostHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if a.ICMPRepo == nil {
		writeText(w, http.StatusServiceUnavailable, "icmp repo is not available")
		return
	}

	id, err := strconv.ParseInt(strings.TrimSpace(r.URL.Query().Get("id")), 10, 64)
	if err != nil || id <= 0 {
		writeText(w, http.StatusBadRequest, "id required")
		return
	}
	limit := parseIntParam(r, "limit", 2000)
	detail, err := a.ICMPRepo.GetHost(id, limit)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeText(w, http.StatusNotFound, "not found")
			return
		}
		writeText(w, http.StatusInternalServerError, "db query failed")
		return
	}
	writeJSON(w, http.StatusOK, detail)
}

func (a *App) icmpHostSamplesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if a.ICMPRepo == nil {
		writeText(w, http.StatusServiceUnavailable, "icmp repo is not available")
		return
	}
	id, err := strconv.ParseInt(strings.TrimSpace(r.URL.Query().Get("id")), 10, 64)
	if err != nil || id <= 0 {
		writeText(w, http.StatusBadRequest, "id required")
		return
	}
	fromTS := parseOptionalInt64Param(r, "from")
	toTS := parseOptionalInt64Param(r, "to")
	limit := parseIntParam(r, "limit", 5000)
	items, err := a.ICMPRepo.ListSamples(id, fromTS, toTS, limit)
	if err != nil {
		writeText(w, http.StatusInternalServerError, "db query failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"host_id": id,
		"items":   items,
	})
}

func (a *App) icmpHostEventsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if a.ICMPRepo == nil {
		writeText(w, http.StatusServiceUnavailable, "icmp repo is not available")
		return
	}
	id, err := strconv.ParseInt(strings.TrimSpace(r.URL.Query().Get("id")), 10, 64)
	if err != nil || id <= 0 {
		writeText(w, http.StatusBadRequest, "id required")
		return
	}
	fromTS := parseOptionalInt64Param(r, "from")
	toTS := parseOptionalInt64Param(r, "to")
	limit := parseIntParam(r, "limit", 500)
	items, err := a.ICMPRepo.ListEvents(id, fromTS, toTS, limit)
	if err != nil {
		writeText(w, http.StatusInternalServerError, "db query failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"host_id": id,
		"items":   items,
	})
}

func (a *App) icmpHostAddHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if a.ICMPRepo == nil {
		writeText(w, http.StatusServiceUnavailable, "icmp repo is not available")
		return
	}
	if !a.verifyPublicWriteCSRF(r) {
		a.auditUserEvent(r, "icmp_csrf_failed", a.publicActor(r), map[string]any{
			"path":   r.URL.Path,
			"method": r.Method,
		})
		minimalResponse(w)
		return
	}
	if err := r.ParseForm(); err != nil {
		writeText(w, http.StatusBadRequest, "bad form")
		return
	}
	input, err := parseICMPHostInput(r)
	if err != nil {
		writeText(w, http.StatusBadRequest, err.Error())
		return
	}
	id, err := a.ICMPRepo.AddHost(input)
	if err != nil {
		writeText(w, http.StatusBadRequest, err.Error())
		return
	}
	a.invalidateICMPHostsCache()
	a.auditUserEvent(r, "icmp_host_add", a.publicActor(r), map[string]any{
		"host_id": id,
		"name":    input.Name,
		"ip":      input.IP,
	})
	writeText(w, http.StatusOK, "OK")
}

func (a *App) icmpHostEditHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if a.ICMPRepo == nil {
		writeText(w, http.StatusServiceUnavailable, "icmp repo is not available")
		return
	}
	if !a.verifyPublicWriteCSRF(r) {
		a.auditUserEvent(r, "icmp_csrf_failed", a.publicActor(r), map[string]any{
			"path":   r.URL.Path,
			"method": r.Method,
		})
		minimalResponse(w)
		return
	}
	id, err := strconv.ParseInt(strings.TrimSpace(r.URL.Query().Get("id")), 10, 64)
	if err != nil || id <= 0 {
		writeText(w, http.StatusBadRequest, "id required")
		return
	}
	if err := r.ParseForm(); err != nil {
		writeText(w, http.StatusBadRequest, "bad form")
		return
	}
	input, err := parseICMPHostInput(r)
	if err != nil {
		writeText(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := a.ICMPRepo.UpdateHost(id, input); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeText(w, http.StatusNotFound, "not found")
			return
		}
		writeText(w, http.StatusBadRequest, err.Error())
		return
	}
	a.invalidateICMPHostsCache()
	a.auditUserEvent(r, "icmp_host_edit", a.publicActor(r), map[string]any{
		"host_id": id,
		"name":    input.Name,
		"ip":      input.IP,
	})
	writeText(w, http.StatusOK, "OK")
}

func (a *App) icmpHostDeleteHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if a.ICMPRepo == nil {
		writeText(w, http.StatusServiceUnavailable, "icmp repo is not available")
		return
	}
	if !a.verifyPublicWriteCSRF(r) {
		a.auditUserEvent(r, "icmp_csrf_failed", a.publicActor(r), map[string]any{
			"path":   r.URL.Path,
			"method": r.Method,
		})
		minimalResponse(w)
		return
	}
	id, err := strconv.ParseInt(strings.TrimSpace(r.URL.Query().Get("id")), 10, 64)
	if err != nil || id <= 0 {
		writeText(w, http.StatusBadRequest, "id required")
		return
	}
	if err := a.ICMPRepo.DeleteHost(id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeText(w, http.StatusNotFound, "not found")
			return
		}
		writeText(w, http.StatusBadRequest, err.Error())
		return
	}
	a.invalidateICMPHostsCache()
	a.auditUserEvent(r, "icmp_host_delete", a.publicActor(r), map[string]any{
		"host_id": id,
	})
	writeText(w, http.StatusOK, "OK")
}

func (a *App) icmpExportCSVHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if a.ICMPRepo == nil {
		writeText(w, http.StatusServiceUnavailable, "icmp repo is not available")
		return
	}

	data, err := a.ICMPRepo.ExportHostsCSV()
	if err != nil {
		writeText(w, http.StatusInternalServerError, "db query failed")
		return
	}

	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="icmp_hosts.csv"`)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (a *App) icmpImportPreviewCSVHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if a.ICMPRepo == nil {
		writeText(w, http.StatusServiceUnavailable, "icmp repo is not available")
		return
	}
	if !a.verifyPublicWriteCSRF(r) {
		a.auditUserEvent(r, "icmp_csrf_failed", a.publicActor(r), map[string]any{
			"path":   r.URL.Path,
			"method": r.Method,
		})
		minimalResponse(w)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 4<<20)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeText(w, http.StatusBadRequest, "bad csv body")
		return
	}
	stats, err := a.ICMPRepo.PreviewImportCSV(string(body))
	if err != nil {
		writeText(w, http.StatusBadRequest, "csv preview failed")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"preview_can_import":  stats.Added + stats.Updated,
		"updated":             stats.Updated,
		"bad":                 stats.Bad,
		"duplicates_existing": stats.DuplicatesExisting,
		"duplicates_file":     stats.DuplicatesFile,
		"details":             stats.Details,
	})
}

func (a *App) icmpImportCSVHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if a.ICMPRepo == nil {
		writeText(w, http.StatusServiceUnavailable, "icmp repo is not available")
		return
	}
	if !a.verifyPublicWriteCSRF(r) {
		a.auditUserEvent(r, "icmp_csrf_failed", a.publicActor(r), map[string]any{
			"path":   r.URL.Path,
			"method": r.Method,
		})
		minimalResponse(w)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 4<<20)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeText(w, http.StatusBadRequest, "bad csv body")
		return
	}
	stats, err := a.ICMPRepo.ImportCSV(string(body))
	if err != nil {
		writeText(w, http.StatusBadRequest, "csv import failed")
		return
	}

	if stats.Added > 0 || stats.Updated > 0 {
		a.invalidateICMPHostsCache()
	}
	a.auditUserEvent(r, "icmp_host_import_csv", a.publicActor(r), map[string]any{
		"imported":     stats.Added,
		"updated":      stats.Updated,
		"bad":          stats.Bad,
		"dup_existing": stats.DuplicatesExisting,
		"dup_in_file":  stats.DuplicatesFile,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"imported":            stats.Added,
		"updated":             stats.Updated,
		"bad":                 stats.Bad,
		"duplicates_existing": stats.DuplicatesExisting,
		"duplicates_file":     stats.DuplicatesFile,
		"details":             stats.Details,
	})
}

func parseICMPHostInput(r *http.Request) (icmprepo.HostInput, error) {
	in := icmprepo.HostInput{
		Name:     strings.TrimSpace(r.FormValue("name")),
		IP:       strings.TrimSpace(r.FormValue("ip")),
		Group:    strings.TrimSpace(r.FormValue("group")),
		Subgroup: strings.TrimSpace(r.FormValue("subgroup")),
		Enabled:  parseEnabledForm(r.FormValue("enabled"), true),
	}

	if v := strings.TrimSpace(r.FormValue("interval_ms")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return in, errors.New("invalid interval_ms")
		}
		in.IntervalMS = n
	}
	if v := strings.TrimSpace(r.FormValue("timeout_ms")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return in, errors.New("invalid timeout_ms")
		}
		in.TimeoutMS = n
	}
	if v := strings.TrimSpace(r.FormValue("down_threshold")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return in, errors.New("invalid down_threshold")
		}
		in.DownThreshold = n
	}

	return in, nil
}

func parseEnabledForm(value string, fallback bool) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	case "":
		return fallback
	default:
		return fallback
	}
}

func (a *App) changePasswordHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		sess, ok := a.requireSession(w, r)
		if !ok {
			a.auditUserEvent(r, "change_password_denied_no_session", "", map[string]any{"path": r.URL.Path})
			return
		}
		a.auditUserEvent(r, "change_password_form_view", sess.Username, map[string]any{"path": r.URL.Path})
		web.Render(w, "change_password.html", templateData{CSRFToken: sess.CSRFToken})
		return
	}

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	sess, ok := a.requireSession(w, r)
	if !ok {
		a.auditUserEvent(r, "change_password_denied_no_session", "", map[string]any{"path": r.URL.Path})
		return
	}

	if !a.verifySessionCSRF(r, sess.CSRFToken) {
		a.auditUserEvent(r, "change_password_csrf_failed", sess.Username, map[string]any{"path": r.URL.Path})
		minimalResponse(w)
		return
	}

	if err := r.ParseForm(); err != nil {
		a.auditUserEvent(r, "change_password_parse_error", sess.Username, map[string]any{"path": r.URL.Path})
		minimalResponse(w)
		return
	}

	current := r.FormValue("current_password")
	newPassword := r.FormValue("new_password")
	confirm := r.FormValue("confirm_password")

	if newPassword == "" || current == "" || confirm == "" {
		a.auditUserEvent(r, "change_password_failed", sess.Username, map[string]any{"reason": "empty_fields"})
		web.Render(w, "change_password.html", templateData{CSRFToken: sess.CSRFToken, Error: "All fields are required."})
		return
	}
	if newPassword != confirm {
		a.auditUserEvent(r, "change_password_failed", sess.Username, map[string]any{"reason": "confirm_mismatch"})
		web.Render(w, "change_password.html", templateData{CSRFToken: sess.CSRFToken, Error: "Passwords do not match."})
		return
	}

	user, err := a.Store.GetUser(sess.Username)
	if err != nil {
		a.auditUserEvent(r, "change_password_failed", sess.Username, map[string]any{"reason": "user_not_found"})
		minimalResponse(w)
		return
	}

	okPassword, err := auth.VerifyPassword(current, user.PasswordHash)
	if err != nil || !okPassword {
		a.auditUserEvent(r, "change_password_failed", sess.Username, map[string]any{"reason": "invalid_current_password"})
		web.Render(w, "change_password.html", templateData{CSRFToken: sess.CSRFToken, Error: "Invalid current password."})
		return
	}

	if !checkPasswordComplexity(newPassword) {
		a.auditUserEvent(r, "change_password_failed", sess.Username, map[string]any{"reason": "weak_password"})
		web.Render(w, "change_password.html", templateData{CSRFToken: sess.CSRFToken, Error: "Password does not meet complexity requirements."})
		return
	}

	if same, err := auth.VerifyPassword(newPassword, user.PasswordHash); err == nil && same {
		a.auditUserEvent(r, "change_password_failed", sess.Username, map[string]any{"reason": "same_password"})
		web.Render(w, "change_password.html", templateData{CSRFToken: sess.CSRFToken, Error: "New password must differ from old password."})
		return
	}

	newHash, err := auth.HashPassword(newPassword)
	if err != nil {
		a.auditUserEvent(r, "change_password_failed", sess.Username, map[string]any{"reason": "hash_error"})
		minimalResponse(w)
		return
	}

	now := time.Now()
	if err := a.Store.UpdatePassword(user.Username, newHash, now); err != nil {
		a.auditUserEvent(r, "change_password_failed", sess.Username, map[string]any{"reason": "store_update_error"})
		minimalResponse(w)
		return
	}

	a.Sessions.Update(sess.ID, func(s *session.Session) {
		s.MustChange = false
		s.ExpiresAt = now.Add(publicSessionTTL)
	})

	a.auditUserEvent(r, "change_password_success", sess.Username, map[string]any{"path": r.URL.Path})
	http.Redirect(w, r, "/app", http.StatusSeeOther)
}

func (a *App) adminLoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		csrf, err := a.issueAdminCSRFCookie(w)
		if err != nil {
			minimalResponse(w)
			return
		}
		web.Render(w, "admin_login.html", templateData{CSRFToken: csrf})
		return
	}

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	ip := clientIP(r)
	if ip == nil {
		minimalResponse(w)
		return
	}

	if !a.AdminLimiter.Allow(ip.String(), time.Now()) {
		minimalResponse(w)
		return
	}

	if !a.verifyAdminCSRF(r) {
		minimalResponse(w)
		return
	}

	if err := r.ParseForm(); err != nil {
		minimalResponse(w)
		return
	}

	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	if username == "" || password == "" {
		web.Render(w, "admin_login.html", templateData{CSRFToken: a.rotateAdminCSRF(w), Error: "Invalid credentials."})
		return
	}

	admin, err := a.Store.GetAdminUser(username)
	storedHash := a.DummyHash
	if err == nil {
		storedHash = admin.PasswordHash
	}
	ok, verifyErr := auth.VerifyPassword(password, storedHash)
	if verifyErr != nil || err != nil || !ok {
		web.Render(w, "admin_login.html", templateData{CSRFToken: a.rotateAdminCSRF(w), Error: "Invalid credentials."})
		return
	}

	_ = a.Store.UpdateAdminLogin(username, time.Now())
	sess, err := a.AdminSessions.Create(username, false, time.Now())
	if err != nil {
		minimalResponse(w)
		return
	}

	setSessionCookie(w, a.AdminCookie, sess.ID, a.AdminTLS)
	setCSRFCookie(w, sess.CSRFToken, a.AdminTLS)
	_ = a.Store.InsertAuditEntry(store.AuditEntry{Actor: username, Action: "admin_login", TargetType: "admin", TargetID: username, Metadata: "{}", CreatedAt: time.Now()})
	http.Redirect(w, r, "/admin/dashboard", http.StatusSeeOther)
}

func (a *App) adminRootHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
}

func (a *App) adminLogoutHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(a.AdminCookie)
	if err == nil {
		a.AdminSessions.Delete(cookie.Value)
	}
	setSessionCookie(w, a.AdminCookie, "", a.AdminTLS)
	http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
}

func (a *App) adminDashboardHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	web.Render(w, "admin_dashboard.html", templateData{})
}

func (a *App) adminClientsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		if !a.verifyAdminCSRF(r) {
			minimalResponse(w)
			return
		}
		if err := r.ParseForm(); err != nil {
			minimalResponse(w)
			return
		}
		name := strings.TrimSpace(r.FormValue("name"))
		if name != "" {
			client, err := a.Store.CreateClient(name, time.Now())
			if err == nil {
				_ = a.Store.InsertAuditEntry(store.AuditEntry{Actor: a.adminActor(r), Action: "client_create", TargetType: "client", TargetID: fmt.Sprintf("%d", client.ID), Metadata: "{}", CreatedAt: time.Now()})
			}
		}
		http.Redirect(w, r, "/admin/clients", http.StatusSeeOther)
		return
	}

	clients, _ := a.Store.ListClients()
	csrf := a.rotateAdminCSRF(w)
	web.Render(w, "admin_clients.html", templateData{Clients: clients, CSRFToken: csrf})
}

func (a *App) adminClientDetailHandler(w http.ResponseWriter, r *http.Request) {
	id, err := parseID(strings.TrimPrefix(r.URL.Path, "/admin/clients/"))
	if err != nil {
		minimalResponse(w)
		return
	}

	client, err := a.Store.GetClient(id)
	if err != nil {
		minimalResponse(w)
		return
	}

	if r.Method == http.MethodPost {
		if !a.verifyAdminCSRF(r) {
			minimalResponse(w)
			return
		}
		if err := r.ParseForm(); err != nil {
			minimalResponse(w)
			return
		}
		action := r.FormValue("action")
		switch action {
		case "disable":
			_ = a.Store.SetClientStatus(id, "disabled", time.Now())
			_ = a.Store.InsertAuditEntry(store.AuditEntry{Actor: a.adminActor(r), Action: "client_disable", TargetType: "client", TargetID: fmt.Sprintf("%d", id), Metadata: "{}", CreatedAt: time.Now()})
		case "enable":
			_ = a.Store.SetClientStatus(id, "active", time.Now())
			_ = a.Store.InsertAuditEntry(store.AuditEntry{Actor: a.adminActor(r), Action: "client_enable", TargetType: "client", TargetID: fmt.Sprintf("%d", id), Metadata: "{}", CreatedAt: time.Now()})
		case "create_user":
			username := strings.TrimSpace(r.FormValue("username"))
			password := r.FormValue("password")
			ip := strings.TrimSpace(r.FormValue("ip"))
			if username == "" || password == "" || !validateWhitelistValue(ip) {
				http.Redirect(w, r, fmt.Sprintf("/admin/clients/%d", id), http.StatusSeeOther)
				return
			}
			hash, err := auth.HashPassword(password)
			if err == nil {
				if user, err := a.Store.CreateUser(id, username, hash, time.Now()); err == nil {
					_ = a.Store.AddWhitelist(store.WhitelistEntry{
						Value:     ip,
						OwnerType: "user",
						OwnerID:   user.ID,
						Label:     username,
						CreatedAt: time.Now(),
					})
					_ = a.Store.InsertAuditEntry(store.AuditEntry{Actor: a.adminActor(r), Action: "user_create", TargetType: "user", TargetID: fmt.Sprintf("%d", user.ID), Metadata: "{}", CreatedAt: time.Now()})
				}
			}
		}
		http.Redirect(w, r, fmt.Sprintf("/admin/clients/%d", id), http.StatusSeeOther)
		return
	}

	users, _ := a.Store.ListUsersByClient(id)
	userIPs := map[int64]string{}
	entries, _ := a.Store.ListWhitelist()
	byUser := map[int64][]string{}
	for _, entry := range entries {
		if entry.OwnerType != "user" {
			continue
		}
		byUser[entry.OwnerID] = append(byUser[entry.OwnerID], entry.Value)
	}
	for _, user := range users {
		values := byUser[user.ID]
		if len(values) == 0 {
			continue
		}
		sort.Strings(values)
		userIPs[user.ID] = strings.Join(values, ", ")
	}
	csrf := a.rotateAdminCSRF(w)
	web.Render(w, "admin_client_detail.html", templateData{
		Client:    client,
		Users:     users,
		UserIPs:   userIPs,
		CSRFToken: csrf,
	})
}

func (a *App) adminWhitelistHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		if !a.verifyAdminCSRF(r) {
			minimalResponse(w)
			return
		}
		if err := r.ParseForm(); err != nil {
			minimalResponse(w)
			return
		}
		entry := strings.TrimSpace(r.FormValue("entry"))
		label := strings.TrimSpace(r.FormValue("label"))
		if entry != "" && validateWhitelistValue(entry) {
			_ = a.Store.AddWhitelist(store.WhitelistEntry{
				Value:     entry,
				OwnerType: "manual",
				OwnerID:   0,
				Label:     label,
				CreatedAt: time.Now(),
			})
			_ = a.Store.InsertAuditEntry(store.AuditEntry{Actor: a.adminActor(r), Action: "whitelist_add", TargetType: "whitelist", TargetID: entry, Metadata: "{}", CreatedAt: time.Now()})
		}
		if deleteID := r.FormValue("delete_id"); deleteID != "" {
			if id, err := strconv.ParseInt(deleteID, 10, 64); err == nil {
				_ = a.Store.DeleteWhitelist(id)
				_ = a.Store.InsertAuditEntry(store.AuditEntry{Actor: a.adminActor(r), Action: "whitelist_delete", TargetType: "whitelist", TargetID: deleteID, Metadata: "{}", CreatedAt: time.Now()})
			}
		}
		http.Redirect(w, r, "/admin/whitelist", http.StatusSeeOther)
		return
	}

	entries, _ := a.Store.ListWhitelist()
	csrf := a.rotateAdminCSRF(w)
	web.Render(w, "admin_whitelist.html", templateData{WhitelistEntries: entries, CSRFToken: csrf})
}

func (a *App) adminSettingsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		if !a.verifyAdminCSRF(r) {
			minimalResponse(w)
			return
		}
		if err := r.ParseForm(); err != nil {
			minimalResponse(w)
			return
		}
		a.Settings.SetRequireLogin(r.FormValue("require_login") == "on")
		_ = a.Store.InsertAuditEntry(store.AuditEntry{Actor: a.adminActor(r), Action: "settings_update", TargetType: "settings", TargetID: "global", Metadata: "{}", CreatedAt: time.Now()})
		http.Redirect(w, r, "/admin/settings", http.StatusSeeOther)
		return
	}

	csrf := a.rotateAdminCSRF(w)
	web.Render(w, "admin_settings.html", templateData{
		Settings: &SettingsView{RequireLogin: a.Settings.RequireLogin()},
		CSRFToken: csrf,
	})
}

func (a *App) adminAuditHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	web.Render(w, "admin_audit.html", templateData{})
}

func (a *App) adminAuditAdminHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	adminEntries, _ := a.Store.ListAudit(100)
	web.Render(w, "admin_audit_admin.html", templateData{
		AdminAudit: adminEntries,
	})
}

func (a *App) adminAuditUsersHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	userEntries, _ := a.Store.ListUserAudit(200)
	web.Render(w, "admin_audit_users.html", templateData{
		UserAudit: filterUserAuditEntries(userEntries),
	})
}

func filterUserAuditEntries(entries []store.UserAuditEntry) []store.UserAuditEntry {
	out := make([]store.UserAuditEntry, 0, len(entries))
	for _, entry := range entries {
		if entry.EventType == "index_view" && strings.Contains(entry.Details, "\"path\":\"/favicon.ico\"") {
			continue
		}
		out = append(out, entry)
	}
	return out
}

func (a *App) adminAuth(next http.Handler) http.Handler {
	return a.adminIPGuard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/admin/login") {
			next.ServeHTTP(w, r)
			return
		}
		cookie, err := r.Cookie(a.AdminCookie)
		if err != nil || cookie.Value == "" {
			http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
			return
		}
		sess, ok := a.AdminSessions.Get(cookie.Value, time.Now())
		if !ok {
			http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
			return
		}
		_ = sess
		next.ServeHTTP(w, r)
	}))
}

func (a *App) requireSession(w http.ResponseWriter, r *http.Request) (*session.Session, bool) {
	cookie, err := r.Cookie(a.CookieName)
	if err != nil || cookie.Value == "" {
		minimalResponse(w)
		return nil, false
	}

	sess, ok := a.Sessions.Get(cookie.Value, time.Now())
	if !ok {
		minimalResponse(w)
		return nil, false
	}

	return sess, true
}

func (a *App) renderLoginError(w http.ResponseWriter) {
	csrfToken, err := a.issueCSRFCookie(w)
	if err != nil {
		minimalResponse(w)
		return
	}
	web.Render(w, "index.html", templateData{CSRFToken: csrfToken, Error: "invalid"})
}

func (a *App) issueCSRFCookie(w http.ResponseWriter) (string, error) {
	token, err := randomToken(32)
	if err != nil {
		return "", err
	}
	setCSRFCookie(w, token, a.PublicTLS)
	return token, nil
}

func (a *App) issueAdminCSRFCookie(w http.ResponseWriter) (string, error) {
	token, err := randomToken(32)
	if err != nil {
		return "", err
	}
	setCSRFCookie(w, token, a.AdminTLS)
	return token, nil
}

func (a *App) rotateAdminCSRF(w http.ResponseWriter) string {
	token, err := randomToken(32)
	if err != nil {
		return ""
	}
	setCSRFCookie(w, token, a.AdminTLS)
	return token
}

func (a *App) verifyCSRF(r *http.Request) bool {
	formToken := r.FormValue("csrf_token")
	if formToken == "" {
		formToken = r.Header.Get("X-CSRF-Token")
	}
	cookie, err := r.Cookie("csrf_token")
	if err != nil || cookie.Value == "" {
		return false
	}
	return cookie.Value == formToken
}

func (a *App) verifyAdminCSRF(r *http.Request) bool {
	if err := r.ParseForm(); err != nil {
		return false
	}
	formToken := r.FormValue("csrf_token")
	cookie, err := r.Cookie("csrf_token")
	if err != nil || cookie.Value == "" {
		return false
	}
	return cookie.Value == formToken
}

func (a *App) verifySessionCSRF(r *http.Request, token string) bool {
	if token == "" {
		return false
	}
	formToken := r.FormValue("csrf_token")
	if formToken == "" {
		formToken = r.Header.Get("X-CSRF-Token")
	}
	cookie, err := r.Cookie("csrf_token")
	if err != nil || cookie.Value == "" {
		return false
	}
	return cookie.Value == formToken && token == formToken
}

func (a *App) isWhitelisted(ip string) (bool, error) {
	if parsed := net.ParseIP(ip); parsed == nil {
		return false, errors.New("invalid ip")
	}

	allowed, err := a.Store.IsWhitelisted(ip)
	if err != nil || allowed {
		return allowed, err
	}

	entries, err := a.Store.ListWhitelist()
	if err != nil {
		return false, err
	}

	target := net.ParseIP(ip)
	for _, entry := range entries {
		_, ipNet, parseErr := net.ParseCIDR(strings.TrimSpace(entry.Value))
		if parseErr == nil && ipNet.Contains(target) {
			return true, nil
		}
	}

	return false, nil
}

func (a *App) adminActor(r *http.Request) string {
	cookie, err := r.Cookie(a.AdminCookie)
	if err != nil || cookie.Value == "" {
		return "admin"
	}

	sess, ok := a.AdminSessions.Get(cookie.Value, time.Now())
	if !ok || strings.TrimSpace(sess.Username) == "" {
		return "admin"
	}

	return sess.Username
}

func parseID(value string) (int64, error) {
	value = strings.Trim(value, "/")
	if value == "" {
		return 0, errors.New("missing id")
	}
	id, err := strconv.ParseInt(value, 10, 64)
	if err != nil || id <= 0 {
		return 0, errors.New("invalid id")
	}
	return id, nil
}

func validateWhitelistValue(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	if net.ParseIP(value) != nil {
		return true
	}
	_, _, err := net.ParseCIDR(value)
	return err == nil
}

func parseLoginRequest(r *http.Request) (*loginRequest, error) {
	contentType := r.Header.Get("Content-Type")
	if strings.HasPrefix(contentType, "application/json") {
		var payload loginRequest
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			return nil, err
		}
		return &payload, nil
	}

	if err := r.ParseForm(); err != nil {
		return nil, err
	}
	return &loginRequest{
		Username: r.FormValue("username"),
		Password: r.FormValue("password"),
	}, nil
}

func checkPasswordComplexity(password string) bool {
	if len(password) < 12 {
		return false
	}

	var hasUpper, hasLower, hasDigit, hasSymbol bool
	for _, r := range password {
		switch {
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r >= 'a' && r <= 'z':
			hasLower = true
		case r >= '0' && r <= '9':
			hasDigit = true
		default:
			hasSymbol = true
		}
	}

	return hasUpper && hasLower && hasDigit && hasSymbol
}

func bootstrapMemoryUser(app *App) {
	memory, ok := app.Store.(*store.MemoryStore)
	if !ok {
		return
	}

	username := strings.TrimSpace(os.Getenv("BOOTSTRAP_USER"))
	if username == "" {
		return
	}

	var hash string
	if rawHash := strings.TrimSpace(os.Getenv("BOOTSTRAP_HASH")); rawHash != "" {
		hash = rawHash
	} else if password := os.Getenv("BOOTSTRAP_PASSWORD"); password != "" {
		generated, err := auth.HashPassword(password)
		if err != nil {
			log.Printf("bootstrap hash error: %v", err)
			return
		}
		hash = generated
	}

	if hash == "" {
		log.Printf("bootstrap user set without password/hash")
		return
	}

	memory.AddUser(username, hash, true, time.Now().UTC())
}

func bootstrapAdminUser(app *App) {
	type adminBootstrapper interface {
		AddAdminUser(username, passwordHash, role string, now time.Time)
	}

	bootstrapper, ok := app.Store.(adminBootstrapper)
	if !ok {
		return
	}
	username := strings.TrimSpace(os.Getenv("BOOTSTRAP_ADMIN_USER"))
	password := os.Getenv("BOOTSTRAP_ADMIN_PASSWORD")
	if username == "" || password == "" {
		return
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return
	}
	bootstrapper.AddAdminUser(username, hash, "admin", time.Now())
}

func clientIP(r *http.Request) net.IP {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return nil
	}
	return net.ParseIP(host)
}

func minimalResponse(w http.ResponseWriter) {
	w.Header().Del("Server")
	w.WriteHeader(http.StatusNotFound)
}

func randomToken(size int) (string, error) {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func setSessionCookie(w http.ResponseWriter, name, value string, secure bool) {
	cookie := &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		Secure:   secure,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}
	if value == "" {
		cookie.MaxAge = -1
	}
	http.SetCookie(w, cookie)
}

func setCSRFCookie(w http.ResponseWriter, value string, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    value,
		Path:     "/",
		Secure:   secure,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

func getenv(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func getenvBool(key string, fallback bool) bool {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	switch strings.ToLower(value) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
}

func promptPublicListenAddr() (string, bool, error) {
	hosts, labels, err := listPublicBindOptions()
	if err != nil {
		return "", false, err
	}

	reader := bufio.NewReader(os.Stdin)
	fmt.Fprintln(os.Stdout, "Select client interface:")
	fmt.Fprintln(os.Stdout, "  0) do not start client interface")
	for i, label := range labels {
		fmt.Fprintf(os.Stdout, "  %d) %s\n", i+1, label)
	}

	choice, err := readChoice(reader, len(labels))
	if err != nil {
		return "", false, err
	}
	if choice == 0 {
		return "", false, nil
	}

	_, defaultPort, err := net.SplitHostPort(defaultPublicAddr)
	if err != nil {
		return "", false, err
	}
	port, err := readPort(reader, defaultPort)
	if err != nil {
		return "", false, err
	}

	host := hosts[choice-1]
	if host == "" {
		return ":" + port, true, nil
	}
	return net.JoinHostPort(host, port), true, nil
}

func listPublicBindOptions() ([]string, []string, error) {
	hosts := []string{"", "127.0.0.1"}
	labels := []string{
		"0.0.0.0 (all interfaces)",
		"127.0.0.1 (loopback)",
	}
	seen := map[string]struct{}{
		"":          {},
		"127.0.0.1": {},
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, nil, err
	}
	sort.Slice(ifaces, func(i, j int) bool {
		return ifaces[i].Name < ifaces[j].Name
	})

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			default:
				continue
			}

			ip4 := ip.To4()
			if ip4 == nil {
				continue
			}
			host := ip4.String()
			if _, ok := seen[host]; ok {
				continue
			}
			seen[host] = struct{}{}
			hosts = append(hosts, host)
			labels = append(labels, fmt.Sprintf("%s (%s)", host, iface.Name))
		}
	}

	return hosts, labels, nil
}

func readChoice(reader *bufio.Reader, max int) (int, error) {
	for {
		fmt.Fprint(os.Stdout, "Enter number [1]: ")
		line, err := readLine(reader)
		if err != nil {
			return 0, err
		}
		if line == "" {
			return 1, nil
		}

		n, err := strconv.Atoi(line)
		if err == nil && n >= 0 && n <= max {
			return n, nil
		}
		fmt.Fprintln(os.Stdout, "Invalid choice. Use a number from the list.")
	}
}

func readPort(reader *bufio.Reader, defaultPort string) (string, error) {
	for {
		fmt.Fprintf(os.Stdout, "Enter client port [%s]: ", defaultPort)
		line, err := readLine(reader)
		if err != nil {
			return "", err
		}
		if line == "" {
			return defaultPort, nil
		}
		port, err := strconv.Atoi(line)
		if err == nil && port >= 1 && port <= 65535 {
			return strconv.Itoa(port), nil
		}
		fmt.Fprintln(os.Stdout, "Invalid port. Use 1..65535.")
	}
}

func readLine(reader *bufio.Reader) (string, error) {
	line, err := reader.ReadString('\n')
	if err != nil {
		if errors.Is(err, io.EOF) {
			return strings.TrimSpace(line), nil
		}
		return "", err
	}
	return strings.TrimSpace(line), nil
}

func validateListenAddr(addr string) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		log.Fatalf("invalid LISTEN_PUBLIC_ADDR: %v", err)
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		return
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		log.Fatalf("interfaces: %v", err)
	}
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && ipNet.IP.String() == host {
			return
		}
	}
	log.Fatalf("LISTEN_PUBLIC_ADDR host %s not found on any interface", host)
}

func validateLoopbackAddr(addr string) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		log.Fatalf("invalid LISTEN_ADMIN_ADDR: %v", err)
	}
	if host == "" {
		return
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		log.Fatalf("LISTEN_ADMIN_ADDR must be loopback (127.0.0.1 or ::1)")
	}
}
