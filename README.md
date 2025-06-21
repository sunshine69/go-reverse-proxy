# Reverse Proxy Server with SSL and JWT Authentication

A flexible reverse proxy server built in Go that supports:
- Multiple virtual hosts (vhosts)
- SSL/TLS termination
- JWT-based authentication
- IP access control
- Custom headers forwarding
- Self-signed certificate generation

---

## 📦 Installation

1. **Install Go** (version 1.20+ required)
2. **Clone the repository**
3. **Build or run directly**:
   ```bash
   go run main.go
   ```

---

## 🗂️ Configuration

### ✅ Required: `config.json`
```json
{
  "port": 8080,
  "default_ssl": false,
  "default_crt": "",
  "default_key": "",
  "allowed_ips": ["192.168.1.0/24"],
  "denied_ips": [],
  "vhosts": [
    {
      "hostname": "example.com",
      "upstream_url": "https://backend.example.com",
      "jwt_secret": "your-secret-key",
      "ssl_enabled": true,
      "ssl_cert": "cert.pem",
      "ssl_key": "key.pem",
      "insecure_tls": false
    }
  ]
}
```

### 🚀 Command Line Flags (overrides config file)
```bash
--config="path/to/config.json"     # Default: config.json
--upstream="http://backend"        # Default: none
--port=8080                        # Default: 8080
--ssl                              # Enable SSL
--cert="cert.pem"                  # SSL certificate file
--key="key.pem"                    # SSL private key file
--insecure                         # Skip upstream TLS verification
--jwt-secret="your-secret-key"     # JWT secret for authentication
--debug                            # Enable debug logging
```

---

## 🔐 Security Features

### 🛡️ SSL/TLS
- Supports both default and vhost-specific certificates
- Auto-generates self-signed certificates if none are provided
- Configurable certificate file permissions (0644 for certs, 0600 for keys)

### 🔒 Authentication
- JWT validation with:
  - HMAC (symmetric) or RSA (asymmetric)
  - Token verification from `Authorization` header
  - Optional IP-based access control

### 🧩 Access Control
- Allow/deny IPs via CIDR notation
- Localhost bypasses authentication

---

## 🚀 Usage Examples

### Basic Start
```bash
go run main.go --upstream="https://api.example.com" --port=8081
```

### With SSL
```bash
go run main.go --upstream="https://backend" --ssl --cert="server.pem" --key="server.key"
```

### Debug Mode
```bash
go run main.go --debug --config="dev-config.json"
```

---

## ⚠️ Security Notes

1. **Never use `--insecure` in production**
2. **Avoid exposing JWT secrets in URLs** (only use `Authorization` header)
3. **Regularly rotate SSL certificates**
4. **Validate all input data** in configuration files
5. **Restrict allowed IPs** in production environments

---

## 📝 License

MIT License
Copyright (c) 2023 Steve Kieu

---

For more details, see the [source code documentation](https://github.com/sunshine69/go-reverse-proxy).