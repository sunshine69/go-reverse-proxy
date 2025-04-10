package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
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

	jwt "github.com/golang-jwt/jwt"
)

var (
	// Command line flags
	upstreamURLFlag      = flag.String("upstream", "", "URL of the upstream server to proxy to")
	listenPortFlag       = flag.Int("port", 3000, "Port to listen on")
	enableSSLFlag        = flag.Bool("ssl", false, "Enable SSL with self-signed certificate")
	certFileFlag         = flag.String("cert", "", "Path to SSL certificate file (if empty, generates self-signed)")
	keyFileFlag          = flag.String("key", "", "Path to SSL private key file (if empty, generates self-signed)")
	insecureUpstreamFlag = flag.Bool("insecure-upstream", false, "Skip verification of upstream server's certificate (use with caution)")

	// JWT signing key - should be stored securely in production
	signingKey = []byte(getEnvOrDefault("JWT_SECRET", "your-secret-key"))

	// Target upstream server - flag takes precedence over env var
	upstreamURL string

	// IP access control lists (fixed at startup)
	allowedIPs = parseIPList(getEnvOrDefault("ALLOWED_IPS", ""))
	deniedIPs  = parseIPList(getEnvOrDefault("DENIED_IPS", ""))
)

// IPList stores IPs with O(1) lookup
type IPList map[string]struct{}

func getEnvOrDefault(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

func parseIPList(ipListStr string) IPList {
	list := make(IPList)
	if ipListStr == "" {
		return list
	}

	ips := strings.Split(ipListStr, ",")
	for _, ip := range ips {
		list[strings.TrimSpace(ip)] = struct{}{}
	}
	return list
}

func getClientIP(r *http.Request) string {
	// Check for X-Forwarded-For header first
	// xForwardedFor := r.Header.Get("X-Forwarded-For")
	// if xForwardedFor != "" {
	// 	log.Println("Found X-Forwarded-For will get clict IP from it")
	// 	// Take the first IP in the list
	// 	ips := strings.Split(xForwardedFor, ",")
	// 	return strings.TrimSpace(ips[0])
	// }

	// Get IP from RemoteAddr
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		log.Println("SplitHostPort error " + err.Error())
		// If error in splitting, just return the RemoteAddr
		return r.RemoteAddr
	}
	log.Println("Get client IP using r.RemoteAddr " + ip)
	return ip
}

func isLocalhost(ip string) bool {
	return ip == "127.0.0.1" || ip == "::1" || ip == "localhost"
}

// Generate a self-signed certificate and key
func generateSelfSignedCert() ([]byte, []byte, error) {
	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	// Prepare certificate template
	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour) // Valid for 1 year

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Reverse Proxy Self-Signed"},
			CommonName:   "localhost",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		DNSNames:              []string{"localhost"},
	}

	// Create certificate
	derBytes, err := x509.CreateCertificate(
		rand.Reader,
		&template,
		&template,
		&privateKey.PublicKey,
		privateKey,
	)
	if err != nil {
		return nil, nil, err
	}

	// Encode certificate to PEM
	certBuffer := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})

	// Encode private key to PEM
	keyBuffer := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	return certBuffer, keyBuffer, nil
}

// Create a TLS configuration with certificate
func createTLSConfig() (*tls.Config, error) {
	var cert tls.Certificate
	var err error

	// If certificate and key files are provided, use them
	if *certFileFlag != "" && *keyFileFlag != "" {
		cert, err = tls.LoadX509KeyPair(*certFileFlag, *keyFileFlag)
		if err != nil {
			return nil, fmt.Errorf("failed to load certificate: %v", err)
		}
	} else {
		// Otherwise, generate a self-signed certificate
		log.Println("Generating self-signed certificate...")
		certPEM, keyPEM, err := generateSelfSignedCert()
		if err != nil {
			return nil, fmt.Errorf("failed to generate self-signed certificate: %v", err)
		}

		// Save the generated certificate and key to files for future use
		os.WriteFile("server.crt", certPEM, 0644)
		os.WriteFile("server.key", keyPEM, 0600)
		log.Println("Self-signed certificate and key saved to server.crt and server.key")

		// Load the generated certificate
		cert, err = tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			return nil, fmt.Errorf("failed to load generated certificate: %v", err)
		}
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// Create custom transport for the reverse proxy
func createTransport() *http.Transport {
	// Create transport with default settings
	transport := http.DefaultTransport.(*http.Transport).Clone()

	// If insecure flag is set, skip certificate verification
	if *insecureUpstreamFlag {
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
		}
		log.Println("Warning: Upstream certificate verification disabled")
	}

	return transport
}

func main() {
	// Parse command line flags
	flag.Parse()

	// Determine upstream URL - flag takes precedence over env var
	if *upstreamURLFlag != "" {
		upstreamURL = *upstreamURLFlag
	} else {
		upstreamURL = getEnvOrDefault("UPSTREAM_URL", "http://localhost:8080")
	}

	// Parse the upstream URL
	upstream, err := url.Parse(upstreamURL)
	if err != nil {
		log.Fatalf("Error parsing upstream URL: %v", err)
	}

	// Create the reverse proxy with custom transport
	proxy := httputil.NewSingleHostReverseProxy(upstream)

	// Replace the default transport with our custom one
	proxy.Transport = createTransport()

	// Create handler chain with middlewares
	handler := ipAccessControlMiddleware(authMiddleware(proxy))

	// Configure server
	addr := fmt.Sprintf(":%d", *listenPortFlag)

	// Print startup information
	protocol := "http"
	if *enableSSLFlag {
		protocol = "https"
	}

	upstreamProtocol := "http"
	if upstream.Scheme == "https" {
		upstreamProtocol = "https"
	}

	fmt.Printf("Starting reverse proxy server on %s://%s to %s://%s\n",
		protocol, addr, upstreamProtocol, upstream.Host)

	if len(allowedIPs) > 0 {
		fmt.Println("IP Allow List active:", allowedIPs)
	}

	if len(deniedIPs) > 0 {
		fmt.Println("IP Deny List active:", deniedIPs)
	}

	fmt.Println("Localhost requests will bypass authentication")

	// Start the server with or without SSL
	if *enableSSLFlag {
		tlsConfig, err := createTLSConfig()
		if err != nil {
			log.Fatalf("Failed to create TLS config: %v", err)
		}

		server := &http.Server{
			Addr:      addr,
			Handler:   handler,
			TLSConfig: tlsConfig,
		}

		log.Fatal(server.ListenAndServeTLS("", ""))
	} else {
		log.Fatal(http.ListenAndServe(addr, handler))
	}
}

// ipAccessControlMiddleware checks if client IP is allowed or denied
func ipAccessControlMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get client IP
		clientIP := getClientIP(r)

		// Log the incoming request with IP
		log.Printf("Incoming request from IP: %s, Path: %s", clientIP, r.URL.Path)

		// Check if IP is denied
		_, isDenied := deniedIPs[clientIP]

		// If allow list is not empty, check if IP is allowed
		isAllowListActive := len(allowedIPs) > 0
		_, isAllowed := allowedIPs[clientIP]

		if isDenied {
			log.Printf("Access denied for IP: %s (in deny list)", clientIP)
			http.Error(w, "Access denied", http.StatusForbidden)
			return
		}

		if isAllowListActive && !isAllowed {
			log.Printf("Access denied for IP: %s (not in allow list)", clientIP)
			http.Error(w, "Access denied", http.StatusForbidden)
			return
		}

		// Proceed to next middleware
		next.ServeHTTP(w, r)
	})
}

// authMiddleware validates JWT tokens before proxying requests
func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get client IP
		clientIP := getClientIP(r)
		log.Printf("Client IP is: '%s'\n", clientIP)
		// Bypass authentication for localhost requests
		if isLocalhost(clientIP) {
			log.Printf("Bypassing authentication for localhost request: %s", clientIP)
			next.ServeHTTP(w, r)
			return
		}

		var tokenString string

		// First try to get token from URL query parameter
		tokenString = r.URL.Query().Get("access_token")

		// If not in URL, try Authorization header as fallback
		if tokenString == "" {
			authHeader := r.Header.Get("Authorization")
			if authHeader != "" {
				// Token should be in format: "Bearer <token>"
				tokenParts := strings.Split(authHeader, " ")
				if len(tokenParts) == 2 && tokenParts[0] == "Bearer" {
					tokenString = tokenParts[1]
				}
			}
		}

		// No token found in either location
		if tokenString == "" {
			http.Error(w, "Access token required (use ?access_token=<token> or Authorization header)", http.StatusUnauthorized)
			return
		}

		// Parse and validate the token
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// Validate the algorithm
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}

			// Ensure we're using HS256
			if token.Method != jwt.SigningMethodHS256 {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}

			return signingKey, nil
		})

		if err != nil {
			log.Printf("Invalid token: %v", err)
			http.Error(w, "Invalid token: "+err.Error(), http.StatusUnauthorized)
			return
		}

		// Check if token is valid
		if !token.Valid {
			log.Printf("Invalid token")
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// Extract claims if needed
		if claims, ok := token.Claims.(jwt.MapClaims); ok {
			// Log user info
			log.Printf("Authenticated request from user: %v", claims["sub"])
		}

		// To keep URL clean (remove token from query params)
		if tokenString == r.URL.Query().Get("access_token") {
			// Make a copy of the request to modify
			newQuery := r.URL.Query()
			newQuery.Del("access_token")

			// Create new URL with updated query string
			r2 := new(http.Request)
			*r2 = *r
			r2.URL = new(url.URL)
			*r2.URL = *r.URL
			r2.URL.RawQuery = newQuery.Encode()

			// Proxy the clean request
			next.ServeHTTP(w, r2)
			return
		}

		// Proxy the original request
		next.ServeHTTP(w, r)
	})
}
