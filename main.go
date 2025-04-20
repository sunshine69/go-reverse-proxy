package main

import (
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
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Config represents the server configuration
type Config struct {
	Port       int      `json:"port"`
	DefaultSSL bool     `json:"default_ssl"`
	DefaultCrt string   `json:"default_crt"`
	DefaultKey string   `json:"default_key"`
	AllowedIPs []string `json:"allowed_ips"`
	DeniedIPs  []string `json:"denied_ips"`
	VHosts     []VHost  `json:"vhosts"`
}

// VHost represents a virtual host configuration
type VHost struct {
	Hostname       string            `json:"hostname"`
	UpstreamURL    string            `json:"upstream_url"`
	JWTSecret      string            `json:"jwt_secret"`
	SSLEnabled     bool              `json:"ssl_enabled"`
	SSLCert        string            `json:"ssl_cert"`
	SSLKey         string            `json:"ssl_key"`
	InsecureTLS    bool              `json:"insecure_tls"`
	JWTPublicKey   string            `json:"jwt_public_key"`
	CustomeHeaders map[string]string `json:"custom_headers"`
}

// ProxyHandler contains the pre-configured proxy handler for a vhost
type ProxyHandler struct {
	vhost        VHost
	proxy        *httputil.ReverseProxy
	requiresAuth bool
}

var (
	configFile     string
	upstreamURL    string
	port           int
	sslEnabled     bool
	sslCert        string
	sslKey         string
	insecureTLS    bool
	jwtSecret      string
	config         Config
	vhostConfigs   map[string]VHost
	proxyHandlers  map[string]*ProxyHandler
	defaultHandler *ProxyHandler
	handlerMutex   sync.RWMutex
	DEBUG          bool
)

func init() {
	flag.StringVar(&configFile, "config", "config.json", "Path to configuration file")
	flag.StringVar(&upstreamURL, "upstream", "", "Upstream server URL")
	flag.IntVar(&port, "port", 8080, "Port to listen on")
	flag.BoolVar(&sslEnabled, "ssl", false, "Enable SSL")
	flag.StringVar(&sslCert, "cert", "", "SSL certificate file")
	flag.StringVar(&sslKey, "key", "", "SSL key file")
	flag.BoolVar(&insecureTLS, "insecure", false, "Skip verification of upstream certificate")
	flag.StringVar(&jwtSecret, "jwt-secret", "", "JWT secret for token validation")
	flag.BoolVar(&DEBUG, "debug", false, "Enable debug mode")
}

func main() {
	flag.Parse()

	if DEBUG {
		log.Println("Debug mode enabled")
	}

	if jwtSecret == "" {
		jwtSecret = os.Getenv("JWT_SECRET")
		if jwtSecret != "" {
			log.Println("Loaded jwtSecret from env var JWT_SECRET")
		}
	}

	// Load configuration file
	loadConfig()

	// Initialize vhost map and pre-create proxy handlers
	vhostConfigs = make(map[string]VHost)
	proxyHandlers = make(map[string]*ProxyHandler)

	// Create handlers for each vhost
	for _, vhost := range config.VHosts {
		log.Println("Creating handler for vhost " + vhost.Hostname)
		if DEBUG {
			log.Printf("VHost config: %+v", vhost)
		}
		vhostConfigs[vhost.Hostname] = vhost
		handler, err := createProxyHandler(vhost)
		if err != nil {
			log.Printf("Error creating proxy handler for %s: %v", vhost.Hostname, err)
			continue
		}

		proxyHandlers[vhost.Hostname] = handler

		// Set default handler if this is a wildcard host
		if vhost.Hostname == "*" {
			defaultHandler = handler
		}
	}
	// Create server
	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", config.Port),
		Handler: http.HandlerFunc(routeRequest),
	}

	// Configure TLS
	tlsConfig := configureTLS()
	if tlsConfig != nil {
		server.TLSConfig = tlsConfig
		log.Printf("Starting reverse proxy with SSL on port %d", config.Port)
		log.Fatal(server.ListenAndServeTLS("", ""))
	} else {
		log.Printf("Starting reverse proxy on port %d", config.Port)
		log.Fatal(server.ListenAndServe())
	}
}

func loadConfig() {
	// Set defaults from flags
	config.Port = port
	config.DefaultSSL = sslEnabled
	config.DefaultCrt = sslCert
	config.DefaultKey = sslKey

	// Try to load config file
	data, err := os.ReadFile(configFile)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("Warning: Could not read config file: %v", err)
		}
		// If no config file, create a default vhost using command line flags
		if upstreamURL != "" {
			config.VHosts = []VHost{
				{
					Hostname:    "*",
					UpstreamURL: upstreamURL,
					JWTSecret:   jwtSecret,
					SSLEnabled:  sslEnabled,
					SSLCert:     sslCert,
					SSLKey:      sslKey,
					InsecureTLS: insecureTLS,
				},
			}
		}
		return
	}

	// Parse config file
	if err := json.Unmarshal(data, &config); err != nil {
		log.Fatalf("Failed to parse config file: %v", err)
	}
	if DEBUG {
		log.Printf("Config loaded: %+v", config)
	}

	// Override with flags if specified
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

// createProxyHandler creates a reverse proxy handler for a vhost
func createProxyHandler(vhost VHost) (*ProxyHandler, error) {
	targetURL, err := url.Parse(vhost.UpstreamURL)
	if err != nil {
		return nil, fmt.Errorf("invalid upstream URL: %v", err)
	}

	// Create a new reverse proxy
	proxy := httputil.NewSingleHostReverseProxy(targetURL)

	// Configure transport for upstream connection
	transport := &http.Transport{
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

	// Handle insecure TLS (self-signed certificate) for upstream
	if vhost.InsecureTLS {
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
		}
		if DEBUG {
			log.Println("Insecure TLS enabled for upstream connection")
		}
	}

	proxy.Transport = transport

	// Set up the director function
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		req.Header.Set("X-Forwarded-Host", req.Host)
		req.Header.Set("X-Real-IP", getIPFromRequest(req))
		req.Host = targetURL.Host
		// Add custom headers
		for kheader, vheader := range vhost.CustomeHeaders {
			req.Header.Add(kheader, vheader)
			if DEBUG {
				log.Printf("Adding custom header %s: %s", kheader, vheader)
			}
		}
	}

	// Configure error handler
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("Proxy error: %v", err)
		http.Error(w, "Proxy Error", http.StatusBadGateway)
	}

	// Create handler
	handler := &ProxyHandler{
		vhost:        vhost,
		proxy:        proxy,
		requiresAuth: vhost.JWTSecret != "",
	}
	if DEBUG {
		log.Printf("Proxy handler created for %s", vhost.Hostname)
	}
	return handler, nil
}

// configureTLS sets up the TLS configuration with all certificates
func configureTLS() *tls.Config {
	if !config.DefaultSSL {
		if DEBUG {
			log.Println("SSL not enabled")
		}
		return nil
	}

	certs := []tls.Certificate{}

	// Add default certificate
	if config.DefaultCrt != "" && config.DefaultKey != "" {
		defaultCert, err := tls.LoadX509KeyPair(config.DefaultCrt, config.DefaultKey)
		if err != nil {
			log.Printf("Failed to load default SSL certificate: %v", err)
		} else {
			certs = append(certs, defaultCert)
			if DEBUG {
				log.Println("Default SSL certificate loaded")
			}
		}
	}

	// Add vhost certificates
	for _, vhost := range config.VHosts {
		log.Printf("VHOST %s => '%s - SSLEnabled: %v\n", vhost.Hostname, vhost.UpstreamURL, vhost.SSLEnabled)
		if vhost.JWTSecret == "" {
			log.Printf("[WARN] VHOST %s JWTSecret is empty, disabling authentication\n", vhost.Hostname)
		}
		if vhost.SSLEnabled && vhost.SSLCert != "" && vhost.SSLKey != "" {
			cert, err := tls.LoadX509KeyPair(vhost.SSLCert, vhost.SSLKey)
			if err != nil {
				log.Printf("Failed to load SSL certificate for %s: %v", vhost.Hostname, err)
				continue
			}
			certs = append(certs, cert)
			if DEBUG {
				log.Printf("SSL certificate loaded for %s", vhost.Hostname)
			}
		}
	}

	// Generate self-signed certificate if no certificates are available
	if len(certs) == 0 {
		log.Println("No certificates found or loaded, generating self-signed certificate")
		cert, err := generateSelfSignedCert()
		if err != nil {
			log.Fatalf("Failed to generate self-signed certificate: %v", err)
		}
		certs = append(certs, cert)
		if DEBUG {
			log.Println("Self-signed certificate generated")
		}
	}

	return &tls.Config{
		Certificates: certs,
		GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			// Find certificate for the requested server name
			if info.ServerName != "" {
				// Try exact match
				if vhost, ok := vhostConfigs[info.ServerName]; ok && vhost.SSLEnabled {
					cert, err := tls.LoadX509KeyPair(vhost.SSLCert, vhost.SSLKey)
					if err == nil {
						if DEBUG {
							log.Printf("Serving certificate for %s", info.ServerName)
						}
						return &cert, nil
					}
				}
			}
			// Return the first certificate as default
			if len(certs) > 0 {
				if DEBUG {
					log.Println("Serving default certificate")
				}
				return &certs[0], nil
			}
			return nil, fmt.Errorf("no certificate available for %s", info.ServerName)
		},
	}
}

// generateSelfSignedCert creates a new self-signed certificate
func generateSelfSignedCert() (tls.Certificate, error) {
	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	// Create certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}

	now := time.Now()
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Reverse Proxy Self Signed Certificate"},
			CommonName:   "localhost",
		},
		NotBefore:             now,
		NotAfter:              now.Add(365 * 24 * time.Hour), // 1 year
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	// Create certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return tls.Certificate{}, err
	}

	// Encode certificate and private key to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	// Save the certificate and key to files if needed
	if config.DefaultCrt != "" && config.DefaultKey != "" {
		if err := os.WriteFile(config.DefaultCrt, certPEM, 0644); err != nil {
			log.Printf("Failed to write certificate to file: %v", err)
		}
		if err := os.WriteFile(config.DefaultKey, keyPEM, 0600); err != nil {
			log.Printf("Failed to write private key to file: %v", err)
		}
		if DEBUG {
			log.Println("Self-signed certificate and key saved to file")
		}
	}

	// Parse the certificate
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, err
	}

	return cert, nil
}

// routeRequest is the main request handler that routes requests to the appropriate vhost handler
func routeRequest(w http.ResponseWriter, r *http.Request) {
	// Get remote IP directly from the connection
	remoteIP := getIPFromRequest(r)
	log.Printf("Request from IP: %s to vhost '%s' path '%s'", remoteIP, r.Host, r.URL.Path)
	if DEBUG {
		log.Printf("Request details: %+v", r)
	}

	// Check if IP is in denied list
	if isIPDenied(remoteIP) {
		log.Printf("Access denied from IP: %s", remoteIP)
		http.Error(w, "Access denied", http.StatusForbidden)
		return
	}

	// Check if IP is not in allowed list (when allowed list is not empty)
	if !isIPAllowed(remoteIP) {
		log.Printf("Access denied from IP: %s", remoteIP)
		http.Error(w, "Access denied", http.StatusForbidden)
		return
	}

	// Get the appropriate handler for this host
	handlerMutex.RLock()
	_host, _, _ := net.SplitHostPort(r.Host)
	handler := getProxyHandler(_host)
	handlerMutex.RUnlock()

	if handler == nil {
		msg := fmt.Sprintf("No handler configured for this host '%s'", _host)
		log.Println(msg)
		http.Error(w, msg, http.StatusNotFound)
		return
	}

	// Skip auth if request is from localhost or the vhost has no JWT secret
	isLocalhost := isLocalRequest(remoteIP)
	if handler.requiresAuth && !isLocalhost {
		// Validate JWT token
		authorized, err := validateJWT(r, handler)
		if err != nil || !authorized {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			if err != nil {
				log.Printf("JWT validation error: %v", err)
			}
			return
		}
		if DEBUG {
			log.Println("JWT token validated successfully")
		}
	} else {
		if DEBUG {
			log.Println("Skipping JWT validation")
		}
	}
	// Forward the request to the upstream server
	// log.Printf("Send request to upstream %v\n", r)
	handler.proxy.ServeHTTP(w, r)
}

// getProxyHandler returns the appropriate proxy handler for the given hostname
func getProxyHandler(hostname string) *ProxyHandler {
	// Try exact match
	if handler, ok := proxyHandlers[hostname]; ok {
		return handler
	}

	// Try wildcard match
	if defaultHandler != nil {
		return defaultHandler
	}

	return nil
}

// validateJWT validates the JWT token from the request
func validateJWT(r *http.Request, handler *ProxyHandler) (bool, error) {
	var tokenString string

	// Check Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
		tokenString = strings.TrimPrefix(authHeader, "Bearer ")
	}

	// If not in header, check URL parameter
	if tokenString == "" {
		tokenString = r.URL.Query().Get("access_token")
	}

	if tokenString == "" {
		return false, fmt.Errorf("no token provided")
	}

	// Parse and validate token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Validate algorithm
		if handler.vhost.JWTPublicKey == "" {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(handler.vhost.JWTSecret), nil
		} else { // RS256
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return handler.vhost.JWTPublicKey, nil
		}
	})

	if err != nil {
		return false, err
	}
	if DEBUG {
		log.Printf("JWT claims: %+v", token.Claims)
	}
	return token.Valid, nil
}

// getIPFromRequest gets the IP address from the request safely
func getIPFromRequest(r *http.Request) string {
	// Get IP from RemoteAddr
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// If SplitHostPort fails, use RemoteAddr as is
		return r.RemoteAddr
	}
	return ip
}

// isLocalRequest checks if the request is coming from localhost
func isLocalRequest(ip string) bool {
	return ip == "127.0.0.1" || ip == "::1" || ip == "localhost"
}

// isIPDenied checks if the IP is in the denied list
func isIPDenied(ip string) bool {
	for _, deniedIP := range config.DeniedIPs {
		if matchIP(ip, deniedIP) {
			log.Println("Denied IP " + deniedIP)
			return true
		}
	}
	return false
}

// isIPAllowed checks if the IP is in the allowed list
func isIPAllowed(ip string) bool {
	// If no allowed IPs are specified, allow all
	if len(config.AllowedIPs) == 0 {
		log.Println("AllowedIPs not set thus allow all IPs")
		return true
	}

	for _, allowedIP := range config.AllowedIPs {
		if matchIP(ip, allowedIP) {
			log.Println("AllowedIP IP " + allowedIP)
			return true
		}
	}
	return false
}

// matchIP checks if an IP matches a pattern (exact match or CIDR)
func matchIP(ip, pattern string) bool {
	// Exact match
	if ip == pattern {
		return true
	}

	// CIDR match
	_, ipNet, err := net.ParseCIDR(pattern)
	if err != nil {
		return false
	}

	ipParsed := net.ParseIP(ip)
	if ipParsed == nil {
		return false
	}

	return ipNet.Contains(ipParsed)
}
