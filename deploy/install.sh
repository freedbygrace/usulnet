#!/bin/bash
# =============================================================================
# usulnet - Quick Install Script
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/fr4nsys/usulnet/main/deploy/install.sh | sudo bash
#
# Or download and run manually:
#   chmod +x install.sh && ./install.sh
#
# =============================================================================
set -euo pipefail

INSTALL_DIR="${USULNET_DIR:-/opt/usulnet}"
REPO_BASE="https://raw.githubusercontent.com/fr4nsys/usulnet/main/deploy"

echo "============================================"
echo " usulnet Docker Management Platform"
echo " Installation Script"
echo "============================================"
echo ""

# --- Prerequisites ---

if ! command -v docker &>/dev/null; then
    echo "ERROR: Docker is not installed."
    echo "Install Docker: https://docs.docker.com/engine/install/"
    exit 1
fi

if ! docker compose version &>/dev/null 2>&1; then
    echo "ERROR: Docker Compose v2 is not available."
    echo "Install: https://docs.docker.com/compose/install/"
    exit 1
fi

if ! command -v openssl &>/dev/null; then
    echo "WARNING: openssl not found. Secrets will use /dev/urandom fallback."
fi

if ! command -v curl &>/dev/null; then
    echo "ERROR: curl is required."
    exit 1
fi

# --- Create directory ---

echo "Install directory: ${INSTALL_DIR}"
if [ ! -w "$(dirname "${INSTALL_DIR}")" ] && [ "$(id -u)" -ne 0 ]; then
    echo ""
    echo "ERROR: Cannot write to $(dirname "${INSTALL_DIR}"). Run with sudo or set USULNET_DIR to a writable path."
    echo "  sudo bash <(curl -fsSL https://raw.githubusercontent.com/fr4nsys/usulnet/main/deploy/install.sh)"
    echo "  Or: USULNET_DIR=~/usulnet bash <(curl -fsSL ...)"
    exit 1
fi
mkdir -p "${INSTALL_DIR}"
cd "${INSTALL_DIR}"

# --- Download docker-compose ---

echo "Downloading docker-compose.yml..."
curl -fsSL "${REPO_BASE}/docker-compose.prod.yml" -o docker-compose.yml
curl -fsSL "${REPO_BASE}/.env.example" -o .env
curl -fsSL "${REPO_BASE}/nats-server.conf" -o nats-server.conf

# --- Generate secrets ---

echo "Generating secure secrets..."

generate_hex() {
    if command -v openssl &>/dev/null; then
        openssl rand -hex 32
    else
        head -c 32 /dev/urandom | xxd -p -c 64
    fi
}

generate_password() {
    if command -v openssl &>/dev/null; then
        openssl rand -base64 24 | tr -dc 'a-zA-Z0-9' | head -c 32
    else
        head -c 24 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | head -c 32
    fi
}

DB_PASSWORD=$(generate_password)
JWT_SECRET=$(generate_hex)
ENCRYPTION_KEY=$(generate_hex)

# Replace DB_PASSWORD placeholder in .env (for PostgreSQL service)
sed -i "s|CHANGE_ME_GENERATE_RANDOM_PASSWORD|${DB_PASSWORD}|" .env

# --- Generate TLS certificates for PostgreSQL, Redis, and NATS ---
# These are generated on the host (which has internet + openssl) and mounted
# into the containers. The backend network uses internal:true (no internet)
# so containers cannot install openssl at runtime.

echo "Generating TLS certificates..."
mkdir -p "${INSTALL_DIR}/certs"

if command -v openssl &>/dev/null; then
    # PostgreSQL self-signed ECDSA P-256 cert (10 years)
    if [ ! -f "${INSTALL_DIR}/certs/postgres-server.crt" ]; then
        openssl req -new -x509 -days 3650 -nodes \
            -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
            -subj "/CN=postgres/O=usulnet" \
            -addext "subjectAltName=DNS:postgres,DNS:localhost,IP:127.0.0.1" \
            -keyout "${INSTALL_DIR}/certs/postgres-server.key" \
            -out "${INSTALL_DIR}/certs/postgres-server.crt" 2>/dev/null
        chmod 600 "${INSTALL_DIR}/certs/postgres-server.key"
        chmod 644 "${INSTALL_DIR}/certs/postgres-server.crt"
    fi

    # Redis self-signed ECDSA P-256 cert (10 years)
    if [ ! -f "${INSTALL_DIR}/certs/redis-server.crt" ]; then
        openssl req -new -x509 -days 3650 -nodes \
            -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
            -subj "/CN=redis/O=usulnet" \
            -addext "subjectAltName=DNS:redis,DNS:localhost,IP:127.0.0.1" \
            -keyout "${INSTALL_DIR}/certs/redis-server.key" \
            -out "${INSTALL_DIR}/certs/redis-server.crt" 2>/dev/null
        chmod 600 "${INSTALL_DIR}/certs/redis-server.key"
        chmod 644 "${INSTALL_DIR}/certs/redis-server.crt"
    fi

    # NATS self-signed ECDSA P-256 cert (10 years)
    if [ ! -f "${INSTALL_DIR}/certs/nats-server.crt" ]; then
        openssl req -new -x509 -days 3650 -nodes \
            -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
            -subj "/CN=nats/O=usulnet" \
            -addext "subjectAltName=DNS:nats,DNS:localhost,IP:127.0.0.1" \
            -keyout "${INSTALL_DIR}/certs/nats-server.key" \
            -out "${INSTALL_DIR}/certs/nats-server.crt" 2>/dev/null
        chmod 600 "${INSTALL_DIR}/certs/nats-server.key"
        chmod 644 "${INSTALL_DIR}/certs/nats-server.crt"
    fi
else
    echo "WARNING: openssl not found. TLS certificates will be generated inside containers."
    echo "         If containers fail to start, install openssl and re-run this script."
fi

# --- Generate config.yaml ---

echo "Generating config.yaml..."
cat > config.yaml <<YAML
# usulnet Configuration
# Generated by install.sh — edit as needed
# Structure must match Go Config struct in internal/app/config.go

# Operation mode: master | agent
mode: "master"

# Server settings
server:
  host: "0.0.0.0"
  port: 8080
  https_port: 7443
  read_timeout: "30s"
  write_timeout: "30s"
  idle_timeout: "120s"
  shutdown_timeout: "10s"
  # TLS / HTTPS configuration
  # When enabled, the server listens on both :8080 (HTTP) and :7443 (HTTPS)
  tls:
    enabled: true               # HTTPS enabled on port 7443 (auto-generates self-signed cert)
    auto_tls: true              # Auto-generate self-signed cert from internal CA
    # cert_file: ""             # Custom certificate path (overrides auto-generated)
    # key_file: ""              # Custom private key path
    # data_dir: ""              # PKI data directory (default: <storage.path>/pki)

# Database (PostgreSQL)
database:
  # sslmode=require: encrypted by default (postgres self-generates a cert).
  # Change to verify-full and mount your CA cert for full certificate verification.
  url: "postgres://usulnet:${DB_PASSWORD}@postgres:5432/usulnet?sslmode=require"
  max_open_conns: 25
  max_idle_conns: 10
  conn_max_lifetime: "30m"
  conn_max_idle_time: "5m"

# Redis (caching and sessions) — TLS encrypted by default
redis:
  url: "rediss://redis:6379"
  # tls_enabled: true           # Auto-enabled when using rediss:// URL scheme
  # tls_skip_verify: true       # Skip CA verification (default for self-signed)
  # tls_ca_file: ""             # CA certificate for server verification
  # tls_cert_file: ""           # Client certificate (optional, for mTLS)
  # tls_key_file: ""            # Client private key (optional, for mTLS)

# NATS (messaging) — TLS encrypted by default (self-signed cert)
nats:
  url: "natss://nats:4222"
  name: "usulnet"
  # token: ""              # NATS auth token (if server requires it)
  # username: ""           # NATS username (alternative to token)
  # password: ""           # NATS password
  jetstream:
    enabled: true
  # tls:                   # TLS is auto-enabled by natss:// URL scheme
  #   cert_file: ""        # Client certificate path (for mutual TLS)
  #   key_file: ""         # Client private key path
  #   ca_file: ""          # CA certificate path (for server verification)
  #   skip_verify: true    # Default: true (self-signed CA)

# Security (JWT, encryption, passwords)
# This is the section the app validates - NOT "auth"
security:
  # Generate with: openssl rand -hex 32
  jwt_secret: "${JWT_SECRET}"
  jwt_expiry: "24h"
  refresh_expiry: "168h"
  # Generate with: openssl rand -hex 32 (must be 64 hex chars = 32 bytes)
  config_encryption_key: "${ENCRYPTION_KEY}"
  cookie_secure: false
  cookie_samesite: "lax"
  password_min_length: 8

# Storage (backups)
storage:
  type: "local"
  path: "/app/data"
  backup:
    compression: "gzip"
    default_retention_days: 30

# Trivy (security scanning)
trivy:
  enabled: true
  cache_dir: "/var/lib/usulnet/trivy"
  timeout: "5m"
  severity: "CRITICAL,HIGH,MEDIUM"
  ignore_unfixed: false
  update_db_on_start: true

# Reverse proxy (nginx backend, always enabled when encryption key is set)
nginx:
  acme_email: ""                    # Required for Let's Encrypt certificates (or env USULNET_NGINX_ACME_EMAIL)
  config_dir: "/etc/nginx/conf.d/usulnet"
  cert_dir: "/etc/usulnet/certs"
  acme_web_root: "/var/lib/usulnet/acme"
  acme_account_dir: "/var/lib/usulnet/acme/account"
  listen_http: ":80"
  listen_https: ":443"

# MinIO/S3 storage (connect via Settings UI)
minio:
  enabled: false

# Docker settings (passed via socket mount, not config)
# docker:
#   socket: "/var/run/docker.sock"

# Logging
logging:
  level: "info"
  format: "json"
YAML

# --- Start ---

echo ""
echo "Starting usulnet..."
docker compose up -d

echo ""
echo "============================================"
echo " usulnet installed successfully!"
echo "============================================"
echo ""
echo " Access usulnet:"
echo "   HTTPS: https://$(hostname -I 2>/dev/null | awk '{print $1}' || echo 'localhost'):7443"
echo "   HTTP:  http://$(hostname -I 2>/dev/null | awk '{print $1}' || echo 'localhost'):8080"
echo "   NATS:  natss://$(hostname -I 2>/dev/null | awk '{print $1}' || echo 'localhost'):4222 (agent communication, TLS)"
echo ""
echo " Files: ${INSTALL_DIR}/"
echo "   config.yaml        # Application configuration"
echo "   .env                # Docker Compose variables"
echo "   nats-server.conf    # NATS server configuration"
echo "   docker-compose.yml"
echo ""
echo " Useful commands:"
echo "   cd ${INSTALL_DIR}"
echo "   docker compose logs -f          # View logs"
echo "   docker compose restart          # Restart"
echo "   docker compose down             # Stop"
echo "   docker compose pull && docker compose up -d  # Update"
echo ""
