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
	"path/filepath"
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

	// Path base — strip this prefix from all incoming URLs before routing.
	// Useful in Kubernetes when an ingress forwards /myapp/... without
	// rewriting to / so the app sees the full path including the prefix.
	// The login page and cookie path are also scoped under this prefix.
	// Example: "/myapp"  (no trailing slash; empty = disabled)
	PathBase string `json:"path_base"`

	// Session cookie name for this vhost (default "jwt_session").
	SessionCookieName string `json:"session_cookie_name"`

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
		grp := grp
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

	// Built-in login page — serves before auth so unauthenticated browsers
	// can reach it. Matches the full path including PathBase (e.g. /myapp/__auth).
	if h.requiresAuth && r.URL.Path == loginPath(h.vhost) {
		serveLoginPage(w, r, h.vhost)
		return
	}

	// JWT auth (localhost requests bypass auth)
	if h.requiresAuth && !isLocalhost(remoteIP) {
		res, err := validateJWT(r, h)
		if err != nil {
			log.Printf("JWT [%s]: %v", h.vhost.Hostname, err)
			// API clients (non-browser or explicit token requests) get a plain 401.
			// Browser requests get a redirect to the built-in login page instead.
			if isBrowserRequest(r) {
				redirectToLogin(w, r, h.vhost)
			} else {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
			}
			return
		}
		// On first auth (token arrived via header / query param, not cookie),
		// set a session cookie so subsequent browser requests work seamlessly.
		// Errors from Set-Cookie are silently ignored — API clients that don't
		// support cookies continue working via their existing token source.
		if _, cookieErr := r.Cookie(cookieName(h.vhost)); cookieErr != nil {
			setSessionCookie(w, r, res, h.vhost)
		}
	}

	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "same-origin")
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
	// Normalise PathBase once at startup so all comparisons are consistent.
	vhost.PathBase = normPathBase(vhost.PathBase)

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

			// Strip PathBase so the upstream sees a clean "/" root.
			// (Static mode handles this via StripPrefix instead.)
			if pb := vhost.PathBase; pb != "" {
				stripped := strings.TrimPrefix(preq.Out.URL.Path, pb)
				if stripped == "" {
					stripped = "/"
				}
				preq.Out.URL.Path = stripped
				if preq.Out.URL.RawPath != "" {
					raw := strings.TrimPrefix(preq.Out.URL.RawPath, pb)
					if raw == "" {
						raw = "/"
					}
					preq.Out.URL.RawPath = raw
				}
			}

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

	// Use a per-vhost ServeMux registered at the full route path (pathBase+"/").
	// This mirrors the reference implementation exactly:
	//   mux.Handle(routePath, http.StripPrefix(stripPrefix, fileServer))
	//
	// Because the mux pattern includes PathBase, http.ServeMux sets r.URL.Path
	// correctly before FileServer sees it, so all generated hrefs and redirects
	// already include PathBase — no response rewriting needed.
	routePath := vhost.PathBase + "/"
	stripPrefix := vhost.PathBase
	if vhost.StaticStripPath != "" {
		// Explicit override takes full control.
		routePath = vhost.StaticStripPath + "/"
		stripPrefix = vhost.StaticStripPath
	}

	if DEBUG {
		log.Printf("Static [%s] routePath=%q stripPrefix=%q dir=%q",
			vhost.Hostname, routePath, stripPrefix, vhost.StaticDir)
	}

	fileHandler := http.StripPrefix(stripPrefix, fs)

	if vhost.StaticFallback != "" {
		staticDir := vhost.StaticDir
		fallback := strings.TrimPrefix(vhost.StaticFallback, "/")
		inner := fileHandler
		fileHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := strings.TrimPrefix(r.URL.Path, stripPrefix)
			if !strings.HasPrefix(p, "/") {
				p = "/" + p
			}

			full := filepath.Join(staticDir, p)

			f, err := os.Open(full)
			if err == nil {
				info, _ := f.Stat()
				f.Close()

				if !info.IsDir() {
					inner.ServeHTTP(w, r)
					return
				}
			}

			http.ServeFile(w, r, filepath.Join(staticDir, fallback))
		})
		// fileHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 	// Derive on-disk path from the already-stripped URL.
		// 	p := strings.TrimPrefix(r.URL.Path, stripPrefix)
		// 	if !strings.HasPrefix(p, "/") {
		// 		p = "/" + p
		// 	}
		// 	if _, serr := os.Stat(staticDir + p); os.IsNotExist(serr) {
		// 		http.ServeFile(w, r, staticDir+"/"+fallback)
		// 		return
		// 	}
		// 	inner.ServeHTTP(w, r)
		// })
	}

	return &vhostHandler{
		vhost:    vhost,
		staticFS: http.StripPrefix(stripPrefix, fs),
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
		MinVersion:               tls.VersionTLS12,
		PreferServerCipherSuites: true,
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
		},
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
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

	// return &tls.Config{
	// 	Certificates: certs,
	// 	GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
	// 		if info.ServerName != "" {
	// 			if c, ok := sniMap[strings.ToLower(info.ServerName)]; ok {
	// 				return c, nil
	// 			}
	// 		}
	// 		return defaultCert, nil
	// 	},
	// }, nil
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
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
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

// cookieName returns the session cookie name for a vhost,
// falling back to "jwt_session" when not configured.
func cookieName(vhost VHost) string {
	if vhost.SessionCookieName != "" {
		return vhost.SessionCookieName
	}
	return "jwt_session"
}

// normPathBase ensures PathBase has a leading slash and no trailing slash,
// e.g. "" → "", "myapp" → "/myapp", "/myapp/" → "/myapp".
// Called once at startup so every path comparison is consistent.
func normPathBase(s string) string {
	if s == "" {
		return ""
	}
	s = strings.TrimRight(s, "/")
	if !strings.HasPrefix(s, "/") {
		s = "/" + s
	}
	return s
}

// loginPath returns the absolute path of the built-in login page for a vhost,
// respecting the vhost's PathBase prefix.
func loginPath(vhost VHost) string {
	return vhost.PathBase + "/__auth"
}

// jwtResult carries the validated token string, its parsed form, and the
// expiry time extracted from the mandatory "exp" claim.
type jwtResult struct {
	raw    string
	token  *jwt.Token
	expiry time.Time
}

// extractTokenString looks for a JWT in (priority order):
//  1. Session cookie (name configured per-vhost, default "jwt_session")
//  2. Authorization: Bearer <token>
//  3. ?access_token= query parameter
func extractTokenString(r *http.Request, vhost VHost) string {
	if c, err := r.Cookie(cookieName(vhost)); err == nil && c.Value != "" {
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
	raw := extractTokenString(r, h.vhost)
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
	// Scope the cookie to PathBase so it does not bleed into sibling apps.
	cookiePath := vhost.PathBase
	if cookiePath == "" {
		cookiePath = "/"
	}
	cookie := &http.Cookie{
		Name:     cookieName(vhost),
		Value:    res.raw,
		Path:     cookiePath,
		MaxAge:   int(ttl.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   vhost.SSLEnabled,
	}
	// Best-effort: if the client ignores Set-Cookie we simply fall through.
	// http.SetCookie itself never returns an error; we just guard against
	// any future-proof concern by discarding implicitly.
	http.SetCookie(w, cookie)
	if DEBUG {
		log.Printf("Set-Cookie %s for %s (ttl=%s secure=%v)",
			cookieName(vhost), vhost.Hostname, ttl.Round(time.Second), vhost.SSLEnabled)
	}
}

// -----------------------------------------------------------------------
// Login page (built-in, served at /__auth)
// -----------------------------------------------------------------------

// isBrowserRequest returns true when the client is likely a browser —
// it accepts HTML and is not sending an explicit Authorization header.
// API clients that carry a Bearer token never see the login page.
func isBrowserRequest(r *http.Request) bool {
	if r.Header.Get("Authorization") != "" {
		return false
	}
	accept := r.Header.Get("Accept")
	return strings.Contains(accept, "text/html") || strings.Contains(accept, "*/*")
}

// redirectToLogin sends a 302 to the built-in login page, encoding the
// original URL as a ?next= query parameter so the page can redirect back.
// The login path is prefixed with vhost.PathBase when set.
func redirectToLogin(w http.ResponseWriter, r *http.Request, vhost VHost) {
	next := r.URL.RequestURI()
	http.Redirect(w, r, loginPath(vhost)+"?next="+url.QueryEscape(next), http.StatusFound)
}

// serveLoginPage handles GET (show form) and POST (accept token) for /__auth.
func serveLoginPage(w http.ResponseWriter, r *http.Request, vhost VHost) {
	next := r.URL.Query().Get("next")
	if next == "" {
		base := vhost.PathBase
		if base == "" {
			base = "/"
		}
		next = base
	}
	// Sanitise the redirect target — only allow same-origin relative paths.
	if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") {
		next = vhost.PathBase + "/"
		if next == "/" {
			next = "/"
		}
	}

	switch r.Method {
	case http.MethodPost:
		serveLoginPost(w, r, vhost, next)
	default:
		serveLoginGet(w, r, next, vhost)
	}
}

// serveLoginGet renders the token-entry form.
func serveLoginGet(w http.ResponseWriter, r *http.Request, next string, vhost VHost) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusUnauthorized)
	_ = loginPageTmpl(w, next, "", vhost.PathBase)
}

// serveLoginPost validates the submitted token, sets the session cookie on
// success, and redirects to next. On failure it re-renders the form with an
// error message — never a bare 401 so the user can try again.
func serveLoginPost(w http.ResponseWriter, r *http.Request, vhost VHost, next string) {
	if err := r.ParseForm(); err != nil {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = loginPageTmpl(w, next, "Could not parse form.", vhost.PathBase)
		return
	}

	tokenStr := strings.TrimSpace(r.FormValue("token"))
	if tokenStr == "" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		_ = loginPageTmpl(w, next, "Please enter a token.", vhost.PathBase)
		return
	}

	// Build a synthetic request so we can reuse validateJWT unchanged.
	synthReq := r.Clone(r.Context())
	synthReq.Header.Set("Authorization", "Bearer "+tokenStr)

	// We need a vhostHandler to call validateJWT; build a minimal one.
	// resolveAuth already ran at startup — we just need the cached pub key.
	// Find the real handler from the portGroup via the host header.
	// Simpler: call validateJWT directly with a temporary handler shell that
	// carries only what the function needs (auth mode + key material).
	//
	// Because we cannot cheaply look up the portGroup here, we rely on the
	// vhost value passed in (which was captured from the real handler above).
	mode, rsaPub, err := resolveAuth(vhost)
	if err != nil {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		_ = loginPageTmpl(w, next, "Server auth configuration error.", vhost.PathBase)
		return
	}
	tmpHandler := &vhostHandler{vhost: vhost, auth: mode, rsaPub: rsaPub, requiresAuth: true}

	res, err := validateJWT(synthReq, tmpHandler)
	if err != nil {
		if DEBUG {
			log.Printf("Login page token rejected for %s: %v", vhost.Hostname, err)
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		_ = loginPageTmpl(w, next, "Invalid or expired token.", vhost.PathBase)
		return
	}

	// Token is good — set the session cookie and redirect.
	setSessionCookie(w, r, res, vhost)
	http.Redirect(w, r, next, http.StatusFound)
}

// loginPageTmpl writes the HTML login form to w and returns any write error.
// Uses strings.NewReplacer instead of fmt.Fprintf so that the % characters
// inside the CSS rules (e.g. width:100%) are never misread as format verbs.
// pathBase is the vhost's PathBase (already normalised, may be "").
func loginPageTmpl(w http.ResponseWriter, next, errMsg, pathBase string) error {
	errHTML := ""
	if errMsg != "" {
		errHTML = `<p class="err">` + htmlEscape(errMsg) + `</p>`
	}
	// The form action must include PathBase so the browser POSTs to the full
	// ingress path. The stripped "/__auth" alone would 404 through the ingress.
	loginAction := pathBase + "/__auth"
	replacer := strings.NewReplacer(
		"{{.Next}}", htmlEscape(next),
		"{{.Error}}", errHTML,
		"{{.LoginPath}}", htmlEscape(loginAction),
	)
	_, err := replacer.WriteString(w, loginHTML)
	return err
}

// htmlEscape escapes the five characters that are significant in HTML/attribute context.
func htmlEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, `"`, "&#34;")
	s = strings.ReplaceAll(s, "'", "&#39;")
	return s
}

// loginHTML is the self-contained login page template.
// %s args: next (URL-safe, already escaped), optional error paragraph HTML.
const loginHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Authentication required</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0 }
  body {
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    background: #0f1117;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    color: #e2e8f0;
  }
  .card {
    background: #1a1d27;
    border: 1px solid #2d3148;
    border-radius: 12px;
    padding: 2.5rem 2rem;
    width: 100%;
    max-width: 420px;
    box-shadow: 0 8px 32px rgba(0,0,0,.4);
  }
  .icon {
    width: 48px; height: 48px;
    background: linear-gradient(135deg, #6366f1, #8b5cf6);
    border-radius: 12px;
    display: flex; align-items: center; justify-content: center;
    margin-bottom: 1.25rem;
    font-size: 1.5rem;
  }
  h1 { font-size: 1.25rem; font-weight: 600; margin-bottom: .35rem }
  .sub { font-size: .875rem; color: #94a3b8; margin-bottom: 1.75rem }
  label { display: block; font-size: .8rem; font-weight: 500;
          color: #94a3b8; margin-bottom: .4rem; letter-spacing: .03em }
  textarea {
    width: 100%; min-height: 120px;
    background: #0f1117;
    border: 1px solid #2d3148;
    border-radius: 8px;
    color: #e2e8f0;
    font-family: "SFMono-Regular", Consolas, monospace;
    font-size: .78rem;
    line-height: 1.5;
    padding: .65rem .75rem;
    resize: vertical;
    outline: none;
    transition: border-color .15s;
  }
  textarea:focus { border-color: #6366f1 }
  .err {
    margin-top: .9rem;
    background: rgba(239,68,68,.12);
    border: 1px solid rgba(239,68,68,.35);
    color: #fca5a5;
    border-radius: 6px;
    padding: .55rem .75rem;
    font-size: .825rem;
  }
  button {
    margin-top: 1.25rem;
    width: 100%;
    padding: .7rem;
    background: linear-gradient(135deg, #6366f1, #8b5cf6);
    border: none;
    border-radius: 8px;
    color: #fff;
    font-size: .95rem;
    font-weight: 600;
    cursor: pointer;
    transition: opacity .15s;
  }
  button:hover { opacity: .88 }
  .hint { margin-top: 1rem; font-size: .775rem; color: #475569; text-align: center }
</style>
</head>
<body>
<div class="card">
  <div class="icon">&#128274;</div>
  <h1>Authentication required</h1>
  <p class="sub">Paste your JWT token below to continue.</p>
  <form method="POST" action="{{.LoginPath}}?next={{.Next}}">
    <label for="token">JWT Token</label>
    <textarea id="token" name="token" placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." autofocus spellcheck="false" autocomplete="off"></textarea>
    {{.Error}}
    <button type="submit">Sign in &#8594;</button>
  </form>
  <p class="hint">Token is stored as a secure session cookie and expires with the token.</p>
<p class="hint"><a href="https://note.kaykraft.org/assets/media/html/jwt-tool.html" target="_blank">JWT Tool</a></p>
</div>
</body>
</html>`

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
