#!/usr/bin/env bash
#
# HPX Node (multi-backend) container entrypoint.
# Turnkey: generates the node's TLS certificate on first run, prepares the host
# for VPN traffic, prints the Server CA to paste into the panel, then runs the node.
#
set -e

: "${API_KEY:?API_KEY is required - set it in docker-compose.yml (any UUID)}"

DATA="${HPX_NODE_DATA:-/var/lib/hpx-node}"
export SSL_CERT_FILE="${SSL_CERT_FILE:-$DATA/certs/ssl_cert.pem}"
export SSL_KEY_FILE="${SSL_KEY_FILE:-$DATA/certs/ssl_key.pem}"
export GENERATED_CONFIG_PATH="${GENERATED_CONFIG_PATH:-$DATA/generated/}"

mkdir -p "$(dirname "$SSL_CERT_FILE")" "$GENERATED_CONFIG_PATH"

# Self-signed cert for the panel<->node gRPC channel (SAN carries the public IP),
# generated once and kept in the data volume.
if [ ! -s "$SSL_CERT_FILE" ]; then
  PUBLIC_IP="$(curl -fsS4 --max-time 5 https://api.ipify.org 2>/dev/null || true)"
  [ -n "$PUBLIC_IP" ] || PUBLIC_IP="$(ip -4 route get 1.1.1.1 2>/dev/null | grep -oP 'src \K\S+' || echo 127.0.0.1)"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
    -keyout "$SSL_KEY_FILE" -out "$SSL_CERT_FILE" -days 3650 -nodes \
    -subj "/CN=${PUBLIC_IP}" \
    -addext "subjectAltName = IP:${PUBLIC_IP},IP:127.0.0.1,DNS:localhost"
  chmod 600 "$SSL_KEY_FILE"
  echo "[hpx-node] generated TLS certificate for ${PUBLIC_IP}"
fi

# Best-effort host prep (needs cap NET_ADMIN + SYS_MODULE and network_mode: host).
# The node also installs its own per-backend NAT; this just ensures the basics.
modprobe wireguard 2>/dev/null || true
sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true

echo "================= HPX Node - Server CA ================="
echo "Paste the block below into the node's \"Server CA\" field in the panel:"
echo
cat "$SSL_CERT_FILE"
echo "==============================================================="

exec /app/main
