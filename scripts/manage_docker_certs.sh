#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# -------- CONFIGURABLE PATHS --------
BASE_DIR="/opt/docker_conf_m8"
CONF_DIR="${BASE_DIR}/ssl_conf"
SCRIPTS_DIR="${BASE_DIR}/scripts"
SERVER_CONF_TEMPLATE="${CONF_DIR}/ssl_docker_server.conf"
SERVER_CONF="${CONF_DIR}/ssl_docker_server.dynamic.conf"
CLIENT_CONF_TEMPLATE="${CONF_DIR}/ssl_docker_client.conf"
CLIENT_CONF="${CONF_DIR}/ssl_docker_client.dynamic.conf"
SERVER_CERT_DIR="/etc/docker/certs"
CLIENT_CERT_DIR="${BASE_DIR}/certs"
SUBUID_FILE="/etc/subuid"

# -------- HELPERS --------
err()  { echo "ERROR: $*" >&2; exit 1; }
info() { echo " * $*"; }

# -------- ROOT CHECK --------
[[ $EUID -eq 0 ]] || err "Must be run as root."

# -------- DOCKER INSTALLED CHECK --------
if ! command -v docker &>/dev/null; then
  err "Docker CLI not found; please install Docker."
fi
info "Docker is installed."

# -------- MODE SWITCH --------
mode="${1:-}"
case "$mode" in
  generate)
    ;;
  remove)
    ;;
  *)
    cat <<EOF
Usage: $0 {generate|remove}
  generate   Create CA, server, and client certificates
  remove     Delete both server and client cert dirs
EOF
    exit 1
    ;;
esac

# -------- REMOVE MODE --------
if [[ "$mode" == "remove" ]]; then
  info "Attempting to stop Docker daemon before removing certificates..."
  # Stopping Docker is important to prevent errors when its certs are deleted.
  # '|| true' allows the script to continue if Docker is not running.
  sudo systemctl stop docker || true
  for d in "$SERVER_CERT_DIR" "$CLIENT_CERT_DIR"; do
    if [[ -d "$d" ]]; then
      info "Removing $d"
      rm -rf "$d" || err "Failed deleting $d"
    else
      info "Directory not found, skipping: $d"
    fi
  done
  info "Removal complete. You may need to manually restart Docker daemon (sudo systemctl start docker)."
  exit 0
fi

# -------- GENERATE MODE --------
info "Starting certificate generation..."

# Ensure DOCKER_HOST_IP env is set and is valid
if ! "$SCRIPTS_DIR"/validate_docker_host_ip.sh; then
    err "Invalid or missing DOCKER_HOST_IP—aborting."
fi

info "Using dynamic IP: ${DOCKER_HOST_IP}"

# Validate template conf files
[[ -r "$SERVER_CONF_TEMPLATE" ]] || err "Cannot read $SERVER_CONF_TEMPLATE"
[[ -r "$CLIENT_CONF_TEMPLATE" ]] || err "Cannot read $CLIENT_CONF_TEMPLATE"
info "Found OpenSSL template config files."

# Set dynamic SSL configuration files.
info "Building dynamic OpenSSL configuration files."

# Build dynamic server conf
info "Building dynamic server conf."
# Copy the static part of your template (everything BEFORE the [alt_names] section)
sed '/^\[alt_names\]/,$d' "$SERVER_CONF_TEMPLATE" > "$SERVER_CONF"
# Append the dynamic alt_names entries, including the [alt_names] header
{
  echo "[alt_names]"
  echo "DNS.1 = docker-host.local"
  echo "IP.1  = 127.0.0.1"
  echo "IP.2  = ${DOCKER_HOST_IP}"
} >> "$SERVER_CONF"

# Build dynamic client conf
info "Building dynamic client conf."
# Copy the static part of your template (everything BEFORE the [alt_names] section)
sed '/^\[alt_names\]/,$d' "$CLIENT_CONF_TEMPLATE" > "$CLIENT_CONF"
# Append the dynamic alt_names entries, including the [alt_names] header
{
  echo "[alt_names]"
  echo "DNS.1 = docker-client.local"
  echo "IP.1  = 127.0.0.1"
  echo "IP.2  = ${DOCKER_HOST_IP}" # Client also needs to know the server's IP
} >> "$CLIENT_CONF"

# Validate dynamic conf files
[[ -r "$SERVER_CONF" ]] || err "Cannot read $SERVER_CONF"
[[ -r "$CLIENT_CONF" ]] || err "Cannot read $CLIENT_CONF"
info "Found OpenSSL dynamic config files."

# 2) Ensure /etc/docker exists
[[ -d /etc/docker ]] || err "/etc/docker missing; is Docker installed correctly?"
info "/etc/docker exists."

# 3) Prepare server cert dir
info "Preparing $SERVER_CERT_DIR"
mkdir -p "$SERVER_CERT_DIR"
chmod 700 "$SERVER_CERT_DIR"
chown root:root "$SERVER_CERT_DIR"

# 4) Generate CA key & cert
info "Generating CA key (4096-bit) and certificate..."
openssl genrsa -out "$SERVER_CERT_DIR/ca-key.pem" 4096
openssl req -new -x509 -days 3650 \
  -key "$SERVER_CERT_DIR/ca-key.pem" \
  -out "$SERVER_CERT_DIR/ca.pem" \
  -config "$SERVER_CONF" \
  -subj "/CN=Docker-CA" # Explicit Common Name for the CA

# 5) Generate server key, CSR, cert
info "Generating server key (4096-bit), CSR, and certificate..."
openssl genrsa -out "$SERVER_CERT_DIR/server-key.pem" 4096
openssl req -new \
  -key "$SERVER_CERT_DIR/server-key.pem" \
  -out "$SERVER_CERT_DIR/server.csr" \
  -config "$SERVER_CONF" \
  -subj "/CN=docker-host.local" # Explicit Common Name for server, aligned with template DNS.1

openssl x509 -req -in "$SERVER_CERT_DIR/server.csr" \
  -CA "$SERVER_CERT_DIR/ca.pem" -CAkey "$SERVER_CERT_DIR/ca-key.pem" \
  -CAcreateserial \
  -out "$SERVER_CERT_DIR/server-cert.pem" \
  -days 3650 \
  -extensions req_ext -extfile "$SERVER_CONF"

# 6) Fix server perms & ownership
info "Setting permissions for server certificates..."
chown -R root:docker "$SERVER_CERT_DIR" # Ensure Docker group can read certs
chmod 700 "$SERVER_CERT_DIR" # Directory access for owner only
chmod 600 "$SERVER_CERT_DIR"/{ca-key.pem,server-key.pem} # Private keys: owner read/write only
chmod 644 "$SERVER_CERT_DIR"/{ca.pem,server-cert.pem} # Public certs: owner read/write, group/others read only

# 7) Prepare client cert dir
info "Preparing $CLIENT_CERT_DIR"
mkdir -p "$CLIENT_CERT_DIR"
chmod 700 "$CLIENT_CERT_DIR"
chown root:root "$CLIENT_CERT_DIR"

# 8) Generate client key, CSR, cert
info "Copying CA certificate to client certificate directory..."
cp /etc/docker/certs/ca.pem "$CLIENT_CERT_DIR/ca.pem"
chmod 644 "$CLIENT_CERT_DIR/ca.pem"

info "Generating client key (4096-bit), CSR, and certificate..."
openssl genrsa -out "$CLIENT_CERT_DIR/client-key.pem" 4096
openssl req -new \
  -key "$CLIENT_CERT_DIR/client-key.pem" \
  -out "$CLIENT_CERT_DIR/client.csr" \
  -config "$CLIENT_CONF" \
  -subj "/CN=docker-client.local" # Explicit Common Name for client, aligned with template DNS.1

openssl x509 -req -in "$CLIENT_CERT_DIR/client.csr" \
  -CA "$CLIENT_CERT_DIR/ca.pem" -CAkey "$SERVER_CERT_DIR/ca-key.pem" \
  -CAcreateserial \
  -out "$CLIENT_CERT_DIR/client-cert.pem" \
  -days 3650 \
  -extensions req_ext -extfile "$CLIENT_CONF"

# 9) Fix client perms
info "Setting permissions for client certificates..."
chmod 600 "$CLIENT_CERT_DIR/client-key.pem" # Private key: owner read/write only
chmod 644 "$CLIENT_CERT_DIR"/client-cert.pem # Public cert: owner read/write, group/others read only
# The CA cert was already copied and chmod'd to 644 in step 8

# 10) Chown client dir to dockremap UID for user namespace remapping compatibility
dockuid=$(awk -F: '/^dockremap:/ {print $2; exit}' "$SUBUID_FILE")
[[ -n "$dockuid" ]] || err "Cannot find dockremap UID in $SUBUID_FILE. Ensure userns-remap is enabled and Docker restarted."
info "Chowning client certificates directory to UID:GID $dockuid:$dockuid for userns-remap compatibility."
chown -R "${dockuid}:${dockuid}" "$CLIENT_CERT_DIR"

info "Certificate generation completed successfully."
exit 0