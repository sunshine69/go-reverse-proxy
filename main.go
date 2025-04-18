package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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
	"time"

	"github.com/golang-jwt/jwt"
)

// Configuration structs
type Config struct {
	Port             int                    `json:"port"`
	SSLEnabled       bool                   `json:"ssl_enabled"`
	CertFile         string                 `json:"cert_file"`
	KeyFile          string                 `json:"key_file"`
	DefaultUpstream  string                 `json:"default_upstream"`
	IPAllowList      []string               `json:"ip_allow_list"`
	IPDenyList       []string               `json:"ip_deny_list"`
	TrustSelfSigned  bool                   `json:"trust_self_signed"`
	VirtualHosts     map[string]VirtualHost `json:"virtual_hosts"`
	DefaultJWTSecret string                 `json:"default_jwt_secret"`
}

type VirtualHost struct {
	Upstream        string `json:"upstream"`
	JWTSecret       string `json:"jwt_secret"`
	JWTCertFile     string `json:"jwt_cert_file"`               // For RS256
	TrustSelfSigned *bool  `json:"trust_self_signed,omitempty"` // Per-vhost SSL trust setting
}

// JWTClaims defines the structure of our JWT claims
type JWTClaims struct {
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.StandardClaims
}

func main() {
	// Parse command line flags
	upstreamURL := flag.String("upstream", "", "Default upstream server URL")
	port := flag.Int("port", 8080, "Port to listen on")
	sslEnabled := flag.Bool("ssl", false, "Enable SSL")
	certFile := flag.String("cert", "server.crt", "SSL certificate file")
	keyFile := flag.String("key", "server.key", "SSL key file")
	configFile := flag.String("config", "config.json", "Configuration file")
	trustSelfSigned := flag.Bool("trust-self-signed", false, "Trust self-signed certificates on upstream")
	generateCert := flag.Bool("generate-cert", false, "Generate self-signed certificate if not exists")
	defaultJWTSecret := flag.String("jwt-secret", "", "Default JWT secret for authentication")
	flag.Parse()

	// Load configuration
	config := loadConfig(*configFile)

	// Override config with command line flags if provided
	if *upstreamURL != "" {
		config.DefaultUpstream = *upstreamURL
	}
	if *port != 8080 {
		config.Port = *port
	}
	if *sslEnabled {
		config.SSLEnabled = true
	}
	if *certFile != "server.crt" {
		config.CertFile = *certFile
	}
	if *keyFile != "server.key" {
		config.KeyFile = *keyFile
	}
	if *trustSelfSigned {
		config.TrustSelfSigned = true
	}
	if *defaultJWTSecret != "" {
		config.DefaultJWTSecret = *defaultJWTSecret
	}

	// Check if SSL is enabled and certificates need to be generated
	if config.SSLEnabled {
		certExists := fileExists(config.CertFile)
		keyExists := fileExists(config.KeyFile)

		if (!certExists || !keyExists) && *generateCert {
			// Generate self-signed certificate
			err := GenerateSelfSignedCert(config.CertFile, config.KeyFile)
			if err != nil {
				log.Fatalf("Failed to generate self-signed certificate: %v", err)
			}
		} else if !certExists || !keyExists {
			log.Fatalf("SSL certificate or key file not found. Use --generate-cert to generate them automatically.")
		}
	}

	// Set up the default transport with global SSL settings
	defaultTransport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: config.TrustSelfSigned,
		},
	}

	// Create default upstream target
	defaultTargetURL, err := url.Parse(config.DefaultUpstream)
	if err != nil {
		log.Fatalf("Error parsing default upstream URL: %v", err)
	}

	// Create reverse proxy handler with default transport
	proxy := httputil.NewSingleHostReverseProxy(defaultTargetURL)
	proxy.Transport = defaultTransport

	// Create maps for virtual host configuration
	vhostProxies := make(map[string]*httputil.ReverseProxy)
	vhostSecrets := make(map[string]string)
	vhostAuthEnabled := make(map[string]bool)

	for hostname, vhost := range config.VirtualHosts {
		targetURL, err := url.Parse(vhost.Upstream)
		if err != nil {
			log.Printf("Error parsing upstream URL for %s: %v", hostname, err)
			continue
		}

		// Create a custom transport for this vhost if it has specific SSL trust settings
		vhostProxy := httputil.NewSingleHostReverseProxy(targetURL)

		// Check if this vhost has specific SSL trust settings
		if vhost.TrustSelfSigned != nil {
			// Create a custom transport with vhost-specific SSL settings
			vhostTransport := &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: *vhost.TrustSelfSigned,
				},
			}
			vhostProxy.Transport = vhostTransport
			log.Printf("Virtual host %s => upstream '%s' - SSL trust setting: %v", vhost.Upstream, hostname, *vhost.TrustSelfSigned)
		} else {
			// Use the default transport
			vhostProxy.Transport = defaultTransport
		}

		vhostProxies[hostname] = vhostProxy
		vhostSecrets[hostname] = vhost.JWTSecret

		// Enable authentication only if JWT secret is not empty
		vhostAuthEnabled[hostname] = vhost.JWTSecret != ""
		if !vhostAuthEnabled[hostname] {
			log.Printf("[WARN] Authentication disabled for virtual host %s (no JWT secret provided)", hostname)
		}
	}

	// Create HTTP server
	server := &http.Server{
		Addr: fmt.Sprintf(":%d", config.Port),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Log remote IP
			ip, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				ip = r.RemoteAddr
			}
			log.Printf("Request from IP: %s to Host: %s", ip, r.Host)

			// Check if IP is in deny list
			for _, deniedIP := range config.IPDenyList {
				if ip == deniedIP {
					http.Error(w, "Access denied", http.StatusForbidden)
					return
				}
			}

			// Check if IP allow list is configured and not empty
			if len(config.IPAllowList) > 0 {
				allowed := false
				for _, allowedIP := range config.IPAllowList {
					if ip == allowedIP {
						allowed = true
						break
					}
				}
				// Check if localhost (special case - always allowed)
				if ip == "127.0.0.1" || ip == "::1" || ip == "localhost" {
					allowed = true
				}
				if !allowed {
					http.Error(w, "IP not in allow list", http.StatusForbidden)
					return
				}
			}

			// Check if request is from localhost
			isLocalhost := ip == "127.0.0.1" || ip == "::1" || ip == "localhost"

			// Get hostname for virtual host routing
			hostname := r.Host
			if strings.Contains(hostname, ":") {
				hostname, _, _ = net.SplitHostPort(hostname)
			}

			// Select the appropriate proxy and JWT secret based on the hostname
			currentProxy := proxy
			jwtSecret := config.DefaultJWTSecret // Default secret
			authEnabled := config.DefaultJWTSecret != ""

			if vhostProxy, exists := vhostProxies[hostname]; exists {
				currentProxy = vhostProxy
				jwtSecret = vhostSecrets[hostname]
				authEnabled = vhostAuthEnabled[hostname]
			}

			// Skip authentication for localhost or if auth is disabled for this vhost
			if !isLocalhost && authEnabled {
				// First try to extract token from query parameters
				tokenString := r.URL.Query().Get("access_token")

				// If no token in query, check Authorization header
				if tokenString == "" {
					authHeader := r.Header.Get("Authorization")
					if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
						tokenString = strings.TrimPrefix(authHeader, "Bearer ")
					}
				}

				// If still no token found, return unauthorized
				if tokenString == "" {
					http.Error(w, "Authentication token required", http.StatusUnauthorized)
					return
				}

				// Parse and validate JWT token
				token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
					// Validate the algorithm
					if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
						return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
					}
					return []byte(jwtSecret), nil
				})

				if err != nil || !token.Valid {
					http.Error(w, "Invalid token", http.StatusUnauthorized)
					return
				}

				// Access token claims if needed
				// if claims, ok := token.Claims.(*JWTClaims); ok {
				//     log.Printf("User: %s, Role: %s", claims.Username, claims.Role)
				// }
			}

			// Remove the access_token parameter from the URL if present
			if r.URL.Query().Get("access_token") != "" {
				q := r.URL.Query()
				q.Del("access_token")
				r.URL.RawQuery = q.Encode()
			}

			// Serve the request through the proxy
			currentProxy.ServeHTTP(w, r)
		}),
	}

	// Start the server
	if config.SSLEnabled {
		log.Printf("Starting HTTPS server on port %d", config.Port)
		log.Fatal(server.ListenAndServeTLS(config.CertFile, config.KeyFile))
	} else {
		log.Printf("Starting HTTP server on port %d", config.Port)
		log.Fatal(server.ListenAndServe())
	}
}

func loadConfig(configFile string) Config {
	// Default configuration
	config := Config{
		Port:             8080,
		SSLEnabled:       false,
		CertFile:         "server.crt",
		KeyFile:          "server.key",
		DefaultUpstream:  "http://localhost:8081",
		IPAllowList:      []string{},
		IPDenyList:       []string{},
		TrustSelfSigned:  false,
		VirtualHosts:     make(map[string]VirtualHost),
		DefaultJWTSecret: "",
	}

	// Try to load from file
	if _, err := os.Stat(configFile); err == nil {
		// Read the file
		data, err := os.ReadFile(configFile)
		if err == nil {
			// Parse JSON
			err = json.Unmarshal(data, &config)
			if err != nil {
				log.Printf("Error parsing config file: %v", err)
			} else {
				log.Printf("Loaded configuration from %s", configFile)
			}
		} else {
			log.Printf("Error reading config file: %v", err)
		}
	} else {
		log.Printf("Config file %s not found, using defaults", configFile)
	}

	return config
}

// GenerateSelfSignedCert creates a self-signed certificate and saves it to the specified files
func GenerateSelfSignedCert(certFile, keyFile string) error {
	// Create a new private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %v", err)
	}

	// Create a certificate template
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Reverse Proxy Self Signed"},
			CommonName:   "localhost",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // Valid for 1 year
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
	}

	// Create the certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %v", err)
	}

	// Write the certificate to file
	certOut, err := os.Create(certFile)
	if err != nil {
		return fmt.Errorf("failed to open %s for writing: %v", certFile, err)
	}
	defer certOut.Close()

	err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	if err != nil {
		return fmt.Errorf("failed to write certificate to file: %v", err)
	}
	log.Printf("Certificate written to %s", certFile)

	// Write the private key to file
	keyOut, err := os.OpenFile(keyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to open %s for writing: %v", keyFile, err)
	}
	defer keyOut.Close()

	privBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %v", err)
	}

	err = pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})
	if err != nil {
		return fmt.Errorf("failed to write private key to file: %v", err)
	}
	log.Printf("Private key written to %s", keyFile)

	return nil
}

// Helper function to check if a file exists
func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil
}
