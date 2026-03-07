package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// -----------------------------------------------------------------------
// Configuration types
// -----------------------------------------------------------------------

// Config represents the global server configuration.
type Config struct {
	Port       int      `json:"port"`        // Default port (used when a vhost omits port)
	DefaultSSL bool     `json:"default_ssl"` // Enable SSL on default port
	DefaultCrt string   `json:"default_crt"`
	DefaultKey string   `json:"default_key"`
	AllowedIPs []string `json:"allowed_ips"` // Global IP allow-list (empty = allow all)
	DeniedIPs  []string `json:"denied_ips"`  // Global IP deny-list
	VHosts     []VHost  `json:"vhosts"`
}

// VHost represents a virtual host configuration.
type VHost struct {
	// Routing
	Hostname string `json:"hostname"`  // Hostname to match ("*" = catch-all for this port)
	Port     int    `json:"port"`      // 0 = inherit Config.Port
	BindAddr string `json:"bind_addr"` // Optional bind address, default "0.0.0.0"

	// Proxy mode
	UpstreamURL    string            `json:"upstream_url"`
	InsecureTLS    bool              `json:"insecure_tls"`
	CustomeHeaders map[string]string `json:"custom_headers"`

	// Static file mode (takes priority over proxy when set)
	StaticDir       string `json:"static_dir"`        // Root directory to serve
	StaticIndex     string `json:"static_index"`      // Index file (default: index.html)
	StaticFallback  string `json:"static_fallback"`   // SPA fallback (e.g. "index.html")
	StaticStripPath string `json:"static_strip_path"` // Strip URL prefix before resolving

	// Auth — three mutually exclusive modes:
	//   • jwt_secret set              → HS256 (shared secret)
	//   • jwt_key + jwt_pub set       → RS256 (file paths to PEM keys)
	//   • all empty                   → authentication disabled
	JWTSecret  string `json:"jwt_secret"` // HS256 shared secret
	JWTKeyFile string `json:"jwt_key"`    // RS256: path to PEM private-key file (optional for proxy/verify-only)
	JWTPubFile string `json:"jwt_pub"`    // RS256: path to PEM public-key file  (required for RS256)

	// TLS (per-vhost / per-port)
	SSLEnabled bool   `json:"ssl_enabled"`
	SSLCert    string `json:"ssl_cert"`
	SSLKey     string `json:"ssl_key"`
}

// -----------------------------------------------------------------------
// Runtime handler types
// -----------------------------------------------------------------------

// authMode describes which JWT algorithm a vhost uses.
type authMode int

const (
	authNone  authMode = iota // no authentication
	authHS256                 // HMAC-SHA256 shared secret
	authRS256                 // RSA-SHA256 public/private key pair
)

// vhostHandler holds the fully-initialised handler for one vhost.
type vhostHandler struct {
	vhost        VHost
	proxy        *httputil.ReverseProxy // proxy mode; nil in static mode
	staticFS     http.Handler           // static mode; nil in proxy mode
	requiresAuth bool
	auth         authMode
	rsaPub       *rsa.PublicKey // pre-parsed at startup; nil for HS256/none
}

// portGroup bundles all vhosts that share the same listen address:port.
// One http.Server is created per portGroup — this is the key RAM-saving
// design: N vhosts on the same port share a single listener, read buffer,
// and goroutine pool instead of each paying the overhead of their own server.
type portGroup struct {
	addr           string // e.g. "0.0.0.0:9000"
	sslEnabled     bool
	tlsCfg         *tls.Config
	handlers       map[string]*vhostHandler // keyed by lowercase hostname
	defaultHandler *vhostHandler            // catch-all ("*")
}

// -----------------------------------------------------------------------
// Global state (CLI flags + loaded config)
// -----------------------------------------------------------------------

var (
	configFile  string
	upstreamURL string
	port        int
	sslEnabled  bool
	sslCert     string
	sslKey      string
	insecureTLS bool
	jwtSecret   string
	DEBUG       bool

	config Config
)

func init() {
	flag.StringVar(&configFile, "config", "config.json", "Path to configuration file")
	flag.StringVar(&upstreamURL, "upstream", "", "Upstream server URL (CLI-only mode)")
	flag.IntVar(&port, "port", 8080, "Default port to listen on")
	flag.BoolVar(&sslEnabled, "ssl", false, "Enable SSL on default port")
	flag.StringVar(&sslCert, "cert", "", "SSL certificate file")
	flag.StringVar(&sslKey, "key", "", "SSL key file")
	flag.BoolVar(&insecureTLS, "insecure", false, "Skip upstream certificate verification")
	flag.StringVar(&jwtSecret, "jwt-secret", "", "JWT secret for token validation")
	flag.BoolVar(&DEBUG, "debug", false, "Enable debug mode")
}

// -----------------------------------------------------------------------
// main
// -----------------------------------------------------------------------

func main() {
	flag.Parse()

	if DEBUG {
		log.Println("Debug mode enabled")
	}

	if jwtSecret == "" {
		if v := os.Getenv("JWT_SECRET"); v != "" {
			jwtSecret = v
			log.Println("Loaded JWT_SECRET from environment")
		}
	}

	loadConfig()

	// ---- Group vhosts by (bindAddr:port) --------------------------------
	// Vhosts that share a port are served by one http.Server → minimal RAM.
	groups := make(map[string]*portGroup)

	for i := range config.VHosts {
		vh := config.VHosts[i]

		effectivePort := vh.Port
		if effectivePort == 0 {
			effectivePort = config.Port
		}
		bindAddr := vh.BindAddr
		if bindAddr == "" {
			bindAddr = "0.0.0.0"
		}
		addr := fmt.Sprintf("%s:%d", bindAddr, effectivePort)

		grp, exists := groups[addr]
		if !exists {
			grp = &portGroup{
				addr:     addr,
				handlers: make(map[string]*vhostHandler),
			}
			groups[addr] = grp
		}

		if vh.SSLEnabled {
			grp.sslEnabled = true
		}

		h, err := createVHostHandler(vh)
		if err != nil {
			log.Printf("[ERROR] vhost %s: %v — skipping", vh.Hostname, err)
			continue
		}

		key := strings.ToLower(vh.Hostname)
		grp.handlers[key] = h
		if vh.Hostname == "*" {
			grp.defaultHandler = h
		}

		mode := "proxy"
		if vh.StaticDir != "" {
			mode = "static"
		}
		log.Printf("Registered vhost %-30s [%-6s] auth=%-5v ssl=%-5v addr=%s",
			vh.Hostname, mode, h.requiresAuth, vh.SSLEnabled, addr)
	}

	// CLI-only mode: one wildcard vhost on the default port
	defaultAddr := fmt.Sprintf("0.0.0.0:%d", config.Port)
	if _, exists := groups[defaultAddr]; !exists && upstreamURL != "" {
		grp := &portGroup{
			addr:       defaultAddr,
			sslEnabled: config.DefaultSSL,
			handlers:   make(map[string]*vhostHandler),
		}
		vh := VHost{
			Hostname:    "*",
			UpstreamURL: upstreamURL,
			JWTSecret:   jwtSecret,
			SSLEnabled:  config.DefaultSSL,
			SSLCert:     config.DefaultCrt,
			SSLKey:      config.DefaultKey,
			InsecureTLS: insecureTLS,
		}
		h, err := createVHostHandler(vh)
		if err != nil {
			log.Fatalf("Failed to create default handler: %v", err)
		}
		grp.handlers["*"] = h
		grp.defaultHandler = h
		groups[defaultAddr] = grp
	}

	if len(groups) == 0 {
		log.Fatal("No vhosts configured. Provide a config file or --upstream flag.")
	}

	// ---- Build TLS config for each group that needs it ------------------
	for _, grp := range groups {
		if !grp.sslEnabled {
			continue
		}
		tc, err := buildTLSConfig(grp)
		if err != nil {
			log.Fatalf("TLS error for %s: %v", grp.addr, err)
		}
		grp.tlsCfg = tc
	}

	// ---- Start one lightweight http.Server per port group ---------------
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var wg sync.WaitGroup
	for _, grp := range groups {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runServer(ctx, grp)
		}()
	}

	wg.Wait()
	log.Println("All listeners stopped.")
}

// runServer starts an http.Server for one portGroup and shuts it down
// gracefully when ctx is cancelled.
func runServer(ctx context.Context, grp *portGroup) {
	srv := &http.Server{
		Addr:    grp.addr,
		Handler: http.HandlerFunc(grp.route),
		// Tight timeouts keep goroutine/buffer pressure low.
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// Graceful shutdown when the root context is cancelled.
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutCtx); err != nil {
			log.Printf("[WARN] shutdown %s: %v", grp.addr, err)
		}
	}()

	var err error
	if grp.tlsCfg != nil {
		srv.TLSConfig = grp.tlsCfg
		log.Printf("TLS listener ready on %s", grp.addr)
		err = srv.ListenAndServeTLS("", "")
	} else {
		log.Printf("Listener ready on %s", grp.addr)
		err = srv.ListenAndServe()
	}

	if err != nil && err != http.ErrServerClosed {
		log.Printf("[ERROR] %s: %v", grp.addr, err)
	}
}

// -----------------------------------------------------------------------
// Request routing (one per portGroup — shared across all its vhosts)
// -----------------------------------------------------------------------

func (grp *portGroup) route(w http.ResponseWriter, r *http.Request) {
	remoteIP := ipFromRequest(r)

	if DEBUG {
		log.Printf("[%s] %s %s%s from %s", grp.addr, r.Method, r.Host, r.URL.Path, remoteIP)
	}

	// Global IP checks
	if isIPDenied(remoteIP) {
		http.Error(w, "Access denied", http.StatusForbidden)
		return
	}
	if !isIPAllowed(remoteIP) {
		http.Error(w, "Access denied", http.StatusForbidden)
		return
	}

	// Hostname-based vhost selection
	host, _, _ := net.SplitHostPort(r.Host)
	if host == "" {
		host = r.Host
	}
	h := grp.handlerFor(strings.ToLower(host))
	if h == nil {
		http.Error(w, fmt.Sprintf("No vhost for '%s'", host), http.StatusNotFound)
		return
	}

	// JWT auth (localhost requests bypass auth)
	if h.requiresAuth && !isLocalhost(remoteIP) {
		res, err := validateJWT(r, h)
		if err != nil {
			log.Printf("JWT [%s]: %v", h.vhost.Hostname, err)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		// On first auth (token arrived via header / query param, not cookie),
		// set a session cookie so subsequent browser requests work seamlessly.
		// Errors from Set-Cookie are silently ignored — API clients that don't
		// support cookies continue working via their existing token source.
		if _, cookieErr := r.Cookie(jwtCookieName); cookieErr != nil {
			setSessionCookie(w, r, res, h.vhost)
		}
	}

	// Dispatch to static file server or reverse proxy
	if h.staticFS != nil {
		h.staticFS.ServeHTTP(w, r)
	} else {
		h.proxy.ServeHTTP(w, r)
	}
}

func (grp *portGroup) handlerFor(hostname string) *vhostHandler {
	if h, ok := grp.handlers[hostname]; ok {
		return h
	}
	return grp.defaultHandler // may be nil
}

// -----------------------------------------------------------------------
// Handler construction
// -----------------------------------------------------------------------

// resolveAuth determines the auth mode for a vhost, pre-parses the RSA
// public key from disk when RS256 is configured, and emits startup warnings
// for ambiguous or incomplete configurations.
func resolveAuth(vhost VHost) (authMode, *rsa.PublicKey, error) {
	hasSecret := vhost.JWTSecret != ""
	hasPub := vhost.JWTPubFile != ""
	hasKey := vhost.JWTKeyFile != ""

	switch {
	case hasSecret && !hasPub && !hasKey:
		// HS256 — shared secret only
		return authHS256, nil, nil

	case !hasSecret && hasPub:
		// RS256 — public key file required; private key file is optional
		// (proxy/static servers only need to verify, not sign)
		if hasSecret {
			log.Printf("[WARN] vhost %s: jwt_secret is set alongside jwt_pub — jwt_secret is ignored for RS256", vhost.Hostname)
		}
		pemBytes, err := os.ReadFile(vhost.JWTPubFile)
		if err != nil {
			return authNone, nil, fmt.Errorf("jwt_pub %q: %v", vhost.JWTPubFile, err)
		}
		pub, err := parseRSAPublicKey(string(pemBytes))
		if err != nil {
			return authNone, nil, fmt.Errorf("jwt_pub %q: %v", vhost.JWTPubFile, err)
		}
		if hasKey {
			// Validate the private key file is readable at startup even though
			// this process only uses it for verification (future signing support).
			if _, err := os.Stat(vhost.JWTKeyFile); err != nil {
				log.Printf("[WARN] vhost %s: jwt_key %q not accessible: %v", vhost.Hostname, vhost.JWTKeyFile, err)
			}
		}
		return authRS256, pub, nil

	case !hasSecret && !hasPub && !hasKey:
		// No auth config — disable authentication
		log.Printf("[WARN] vhost %s: no jwt_secret or jwt_pub set — authentication disabled", vhost.Hostname)
		return authNone, nil, nil

	default:
		// Ambiguous: both jwt_secret and jwt_pub/jwt_key provided
		return authNone, nil, fmt.Errorf(
			"vhost %s: ambiguous auth config — set either jwt_secret (HS256) or jwt_pub+jwt_key (RS256), not both",
			vhost.Hostname,
		)
	}
}

func createVHostHandler(vhost VHost) (*vhostHandler, error) {
	mode, rsaPub, err := resolveAuth(vhost)
	if err != nil {
		return nil, err
	}

	var h *vhostHandler
	if vhost.StaticDir != "" {
		h, err = createStaticHandler(vhost)
	} else {
		h, err = createProxyHandler(vhost)
	}
	if err != nil {
		return nil, err
	}

	h.auth = mode
	h.rsaPub = rsaPub
	h.requiresAuth = mode != authNone
	return h, nil
}

func createProxyHandler(vhost VHost) (*vhostHandler, error) {
	if vhost.UpstreamURL == "" {
		return nil, fmt.Errorf("upstream_url required for proxy mode")
	}
	targetURL, err := url.Parse(vhost.UpstreamURL)
	if err != nil {
		return nil, fmt.Errorf("invalid upstream URL: %v", err)
	}

	tr := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	if vhost.InsecureTLS {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	}

	// Use Rewrite instead of the deprecated Director.
	// Rewrite runs on the outbound copy of the request, so:
	//   - hop-by-hop headers are already stripped before Rewrite is called
	//   - inbound X-Forwarded-* headers are NOT copied to preq.Out by default,
	//     preventing client IP-spoofing; we reconstruct them explicitly via
	//     SetXForwarded() and then add our own accurate X-Real-IP.
	proxy := &httputil.ReverseProxy{
		Transport: tr,
		Rewrite: func(preq *httputil.ProxyRequest) {
			// Point the outbound request at the upstream.
			preq.SetURL(targetURL)
			// Rewrite() clears Host; restore it to the upstream host so that
			// virtual hosting on the upstream side works correctly.
			preq.Out.Host = targetURL.Host

			// Populate X-Forwarded-For / X-Forwarded-Host / X-Forwarded-Proto
			// from the verified inbound connection data (not from client headers).
			preq.SetXForwarded()

			// Overwrite X-Forwarded-Host with the original Host header value
			// (SetXForwarded uses req.Host which may already be correct, but
			// being explicit avoids any ambiguity).
			preq.Out.Header.Set("X-Forwarded-Host", preq.In.Host)

			// X-Real-IP derived from the actual TCP remote address — immune to
			// spoofing because we never read it from an inbound header.
			preq.Out.Header.Set("X-Real-IP", ipFromRequest(preq.In))

			// Custom headers defined in the vhost config.
			for k, v := range vhost.CustomeHeaders {
				preq.Out.Header.Set(k, v)
			}

			if DEBUG {
				log.Printf("Rewrite [%s] → %s%s", vhost.Hostname, targetURL.Host, preq.Out.URL.Path)
			}
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("Proxy error [%s]: %v", vhost.Hostname, err)
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
		},
	}

	return &vhostHandler{
		vhost: vhost,
		proxy: proxy,
		// requiresAuth / auth / rsaPub are set by createVHostHandler
	}, nil
}

func createStaticHandler(vhost VHost) (*vhostHandler, error) {
	info, err := os.Stat(vhost.StaticDir)
	if err != nil {
		return nil, fmt.Errorf("static_dir %q: %v", vhost.StaticDir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("static_dir %q is not a directory", vhost.StaticDir)
	}

	fs := http.FileServer(http.Dir(vhost.StaticDir))

	var h http.Handler = fs
	if vhost.StaticStripPath != "" {
		h = http.StripPrefix(vhost.StaticStripPath, fs)
	}

	if vhost.StaticFallback != "" {
		staticDir := vhost.StaticDir
		fallback := strings.TrimPrefix(vhost.StaticFallback, "/")
		strip := vhost.StaticStripPath
		inner := h
		h = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := r.URL.Path
			if strip != "" {
				p = strings.TrimPrefix(p, strip)
			}
			if !strings.HasPrefix(p, "/") {
				p = "/" + p
			}
			if _, serr := os.Stat(staticDir + p); os.IsNotExist(serr) {
				http.ServeFile(w, r, staticDir+"/"+fallback)
				return
			}
			inner.ServeHTTP(w, r)
		})
	}

	return &vhostHandler{
		vhost:    vhost,
		staticFS: h,
		// requiresAuth / auth / rsaPub are set by createVHostHandler
	}, nil
}

// -----------------------------------------------------------------------
// TLS — one config per portGroup
// -----------------------------------------------------------------------

func buildTLSConfig(grp *portGroup) (*tls.Config, error) {
	var certs []tls.Certificate
	sniMap := make(map[string]*tls.Certificate)

	// Global default cert
	if config.DefaultCrt != "" && config.DefaultKey != "" {
		if c, err := tls.LoadX509KeyPair(config.DefaultCrt, config.DefaultKey); err == nil {
			certs = append(certs, c)
		} else {
			log.Printf("[WARN] default cert: %v", err)
		}
	}

	// Per-vhost certs
	for _, h := range grp.handlers {
		vh := h.vhost
		if !vh.SSLEnabled || vh.SSLCert == "" || vh.SSLKey == "" {
			continue
		}
		c, err := tls.LoadX509KeyPair(vh.SSLCert, vh.SSLKey)
		if err != nil {
			log.Printf("[WARN] cert for %s: %v", vh.Hostname, err)
			continue
		}
		certs = append(certs, c)
		cc := c
		sniMap[strings.ToLower(vh.Hostname)] = &cc
	}

	// Self-signed fallback
	if len(certs) == 0 {
		log.Printf("[INFO] No certs on %s — generating self-signed", grp.addr)
		c, err := generateSelfSignedCert(config.DefaultCrt, config.DefaultKey)
		if err != nil {
			return nil, err
		}
		certs = append(certs, c)
	}

	defaultCert := &certs[0]
	return &tls.Config{
		Certificates: certs,
		GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if info.ServerName != "" {
				if c, ok := sniMap[strings.ToLower(info.ServerName)]; ok {
					return c, nil
				}
			}
			return defaultCert, nil
		},
	}, nil
}

func generateSelfSignedCert(certFile, keyFile string) (tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{Organization: []string{"Self-Signed"}, CommonName: "localhost"},
		NotBefore:             now,
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if certFile != "" && keyFile != "" {
		_ = os.WriteFile(certFile, certPEM, 0644)
		_ = os.WriteFile(keyFile, keyPEM, 0600)
	}
	return tls.X509KeyPair(certPEM, keyPEM)
}

// -----------------------------------------------------------------------
// Config loading
// -----------------------------------------------------------------------

func loadConfig() {
	config.Port = port
	config.DefaultSSL = sslEnabled
	config.DefaultCrt = sslCert
	config.DefaultKey = sslKey

	data, err := os.ReadFile(configFile)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("[WARN] config file: %v", err)
		}
		return
	}
	if err := json.Unmarshal(data, &config); err != nil {
		log.Fatalf("Failed to parse config: %v", err)
	}
	if DEBUG {
		log.Printf("Loaded config: %+v", config)
	}
	if port != 8080 {
		config.Port = port
	}
	if sslEnabled {
		config.DefaultSSL = true
		if sslCert != "" {
			config.DefaultCrt = sslCert
		}
		if sslKey != "" {
			config.DefaultKey = sslKey
		}
	}
}

// -----------------------------------------------------------------------
// JWT validation
// -----------------------------------------------------------------------

const jwtCookieName = "jwt_session"

// jwtResult carries the validated token string, its parsed form, and the
// expiry time extracted from the mandatory "exp" claim.
type jwtResult struct {
	raw    string
	token  *jwt.Token
	expiry time.Time
}

// extractTokenString looks for a JWT in (priority order):
//  1. Cookie "jwt_session"
//  2. Authorization: Bearer <token>
//  3. ?access_token= query parameter
func extractTokenString(r *http.Request) string {
	if c, err := r.Cookie(jwtCookieName); err == nil && c.Value != "" {
		return c.Value
	}
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}
	return r.URL.Query().Get("access_token")
}

// parseRSAPublicKey parses a PEM-encoded RSA public key (PKIX or PKCS#1).
func parseRSAPublicKey(pemStr string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	switch block.Type {
	case "PUBLIC KEY": // PKIX / SubjectPublicKeyInfo
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("ParsePKIXPublicKey: %v", err)
		}
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("not an RSA public key")
		}
		return rsaPub, nil
	case "RSA PUBLIC KEY": // PKCS#1
		return x509.ParsePKCS1PublicKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported PEM block type %q", block.Type)
	}
}

// validateJWT validates the JWT from the request and returns a jwtResult.
// It enforces:
//   - correct signing method (HS256 or RS256 based on resolved authMode)
//   - presence and validity of the "exp" claim
func validateJWT(r *http.Request, h *vhostHandler) (*jwtResult, error) {
	raw := extractTokenString(r)
	if raw == "" {
		return nil, fmt.Errorf("no token provided")
	}

	// Choose the key-func based on the pre-resolved auth mode.
	var keyFunc jwt.Keyfunc
	switch h.auth {
	case authHS256:
		keyFunc = func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("expected HS256, got %v", t.Header["alg"])
			}
			return []byte(h.vhost.JWTSecret), nil
		}
	case authRS256:
		// rsaPub was parsed from disk at startup — zero allocation per request.
		pub := h.rsaPub
		keyFunc = func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("expected RS256, got %v", t.Header["alg"])
			}
			return pub, nil
		}
	default:
		// authNone should never reach here (route() guards on requiresAuth),
		// but be defensive.
		return nil, fmt.Errorf("auth not configured for this vhost")
	}

	parsed, err := jwt.Parse(raw,
		keyFunc,
		jwt.WithExpirationRequired(), // "exp" claim is mandatory
		jwt.WithIssuedAt(),           // reject tokens with future iat
	)
	if err != nil {
		return nil, err
	}
	if !parsed.Valid {
		return nil, fmt.Errorf("token invalid")
	}

	// Extract expiry from the validated claims.
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("unexpected claims type")
	}
	expVal, ok := claims["exp"]
	if !ok {
		return nil, fmt.Errorf("missing exp claim")
	}
	expFloat, ok := expVal.(float64)
	if !ok {
		return nil, fmt.Errorf("exp claim is not a number")
	}
	expiry := time.Unix(int64(expFloat), 0)
	if time.Now().After(expiry) {
		return nil, fmt.Errorf("token expired")
	}

	if DEBUG {
		log.Printf("JWT valid [%s] exp=%s claims=%+v", h.vhost.Hostname, expiry.UTC(), claims)
	}

	return &jwtResult{raw: raw, token: parsed, expiry: expiry}, nil
}

// setSessionCookie writes the JWT as an HttpOnly session cookie whose Max-Age
// matches the token's exp claim. Errors are intentionally swallowed — clients
// that do not support cookies (e.g. API callers) must keep using the
// Authorization header or ?access_token= on every request.
func setSessionCookie(w http.ResponseWriter, r *http.Request, res *jwtResult, vhost VHost) {
	ttl := time.Until(res.expiry)
	if ttl <= 0 {
		return // already expired; do not bother setting
	}
	cookie := &http.Cookie{
		Name:     jwtCookieName,
		Value:    res.raw,
		Path:     "/",
		MaxAge:   int(ttl.Seconds()),
		HttpOnly: true,                 // not accessible via JS
		SameSite: http.SameSiteLaxMode, // sensible CSRF default
		Secure:   vhost.SSLEnabled,     // Secure flag only when the vhost uses TLS
	}
	// Best-effort: if the client ignores Set-Cookie we simply fall through.
	// http.SetCookie itself never returns an error; we just guard against
	// any future-proof concern by discarding implicitly.
	http.SetCookie(w, cookie)
	if DEBUG {
		log.Printf("Set-Cookie %s for %s (ttl=%s secure=%v)",
			jwtCookieName, vhost.Hostname, ttl.Round(time.Second), vhost.SSLEnabled)
	}
}

// -----------------------------------------------------------------------
// IP helpers
// -----------------------------------------------------------------------

func ipFromRequest(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

func isLocalhost(ip string) bool {
	return ip == "127.0.0.1" || ip == "::1" || ip == "localhost"
}

func isIPDenied(ip string) bool {
	for _, p := range config.DeniedIPs {
		if matchIP(ip, p) {
			return true
		}
	}
	return false
}

func isIPAllowed(ip string) bool {
	if len(config.AllowedIPs) == 0 {
		return true
	}
	for _, p := range config.AllowedIPs {
		if matchIP(ip, p) {
			return true
		}
	}
	return false
}

func matchIP(ip, pattern string) bool {
	if ip == pattern {
		return true
	}
	_, ipNet, err := net.ParseCIDR(pattern)
	if err != nil {
		return false
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	return ipNet.Contains(parsed)
}
