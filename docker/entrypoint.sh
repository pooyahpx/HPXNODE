#!/usr/bin/env bash
#
# HPX Node (multi-backend) container entrypoint.
# Turnkey: generates the node's TLS certificate on first run, prepares the host
# for VPN traffic, prints the Server CA to paste into the panel, then runs the node.
# Also starts in-container hpx-node-serviced on PANEL_API_PORT when docker.sock is mounted
# so Panel "Update Node" works without a separate host systemd unit.
#
set -e

: "${API_KEY:?API_KEY is required - set it in docker-compose.yml (any UUID)}"

DATA="${HPX_NODE_DATA:-/var/lib/hpx-node}"
export SSL_CERT_FILE="${SSL_CERT_FILE:-$DATA/certs/ssl_cert.pem}"
export SSL_KEY_FILE="${SSL_KEY_FILE:-$DATA/certs/ssl_key.pem}"
export GENERATED_CONFIG_PATH="${GENERATED_CONFIG_PATH:-$DATA/generated/}"

mkdir -p "$(dirname "$SSL_CERT_FILE")" "$GENERATED_CONFIG_PATH"

# Detect the IP the panel should dial. Prefer explicit NODE_PUBLIC_IP / PUBLIC_IP.
detect_public_ip() {
  if [ -n "${NODE_PUBLIC_IP:-}" ]; then
    echo "$NODE_PUBLIC_IP"
    return
  fi
  if [ -n "${PUBLIC_IP:-}" ]; then
    echo "$PUBLIC_IP"
    return
  fi
  local ip=""
  ip="$(curl -fsS4 --max-time 5 https://api.ipify.org 2>/dev/null || true)"
  [ -n "$ip" ] || ip="$(curl -fsS4 --max-time 5 https://ifconfig.io 2>/dev/null || true)"
  [ -n "$ip" ] || ip="$(ip -4 route get 1.1.1.1 2>/dev/null | grep -oP 'src \K\S+' || true)"
  echo "${ip:-127.0.0.1}"
}

# All non-loopback IPv4s (network_mode: host → visible inside the container).
list_host_ipv4s() {
  ip -4 -o addr show scope global 2>/dev/null \
    | awk '{print $4}' \
    | cut -d/ -f1 \
    | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' \
    | sort -u || true
}

build_san() {
  local primary="$1"
  local san="IP:${primary},IP:127.0.0.1,DNS:localhost"
  local ip
  while IFS= read -r ip; do
    [ -z "$ip" ] && continue
    [ "$ip" = "$primary" ] && continue
    [ "$ip" = "127.0.0.1" ] && continue
    case ",${san}," in
      *,IP:${ip},*) ;;
      *) san="${san},IP:${ip}" ;;
    esac
  done < <(list_host_ipv4s)
  echo "$san"
}

cert_covers_ip() {
  local want="$1"
  [ -s "$SSL_CERT_FILE" ] || return 1
  local text cn
  text="$(openssl x509 -in "$SSL_CERT_FILE" -noout -text 2>/dev/null || true)"
  echo "$text" | grep -F "IP Address:${want}" >/dev/null 2>&1 && return 0
  cn="$(openssl x509 -in "$SSL_CERT_FILE" -noout -subject -nameopt RFC2253 2>/dev/null \
    | sed -n 's/.*CN=\([^,]*\).*/\1/p' | tr -d '[:space:]')"
  [ "$cn" = "$want" ]
}

PUBLIC_IP="$(detect_public_ip)"
export PUBLIC_IP

NEED_CERT=0
if [ "${HPX_NODE_REGENERATE_CERT:-0}" = "1" ] || [ "${FORCE_REGEN_CERT:-0}" = "1" ]; then
  NEED_CERT=1
  echo "[hpx-node] FORCE_REGEN_CERT set — regenerating TLS certificate"
elif ! cert_covers_ip "$PUBLIC_IP"; then
  NEED_CERT=1
  if [ -s "$SSL_CERT_FILE" ]; then
    echo "[hpx-node] TLS cert does not cover ${PUBLIC_IP} (dual-IP / route change) — regenerating"
  fi
fi

if [ "$NEED_CERT" = "1" ]; then
  SAN="$(build_san "$PUBLIC_IP")"
  rm -f "$SSL_CERT_FILE" "$SSL_KEY_FILE"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
    -keyout "$SSL_KEY_FILE" -out "$SSL_CERT_FILE" -days 3650 -nodes \
    -subj "/CN=${PUBLIC_IP}" \
    -addext "subjectAltName = ${SAN}"
  chmod 600 "$SSL_KEY_FILE"
  echo "[hpx-node] generated TLS certificate for ${PUBLIC_IP} (SAN: ${SAN})"
fi

# Best-effort host prep (needs cap NET_ADMIN + SYS_MODULE and network_mode: host).
modprobe wireguard 2>/dev/null || true
sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true

echo "================= HPX Node - Server CA ================="
echo "Paste the block below into the node's \"Server CA\" field in the panel:"
echo
cat "$SSL_CERT_FILE"
echo "==============================================================="

start_incontainer_serviced() {
  local api_port="${PANEL_API_PORT:-}"
  if [ -z "$api_port" ]; then
    echo "[hpx-node] PANEL_API_PORT unset — skipping in-container management API"
    return 0
  fi
  if [ ! -S /var/run/docker.sock ]; then
    echo "[hpx-node] /var/run/docker.sock missing — Panel Update Node needs docker.sock mount"
    return 0
  fi
  if [ ! -x /usr/local/bin/hpx-node-serviced ]; then
    echo "[hpx-node] hpx-node-serviced binary missing in image"
    return 0
  fi

  export API_PORT="$api_port"
  export APP_NAME="${APP_NAME:-hpx-node}"
  cat > /tmp/hpx-serviced.env <<EOF
API_KEY=${API_KEY}
API_PORT=${API_PORT}
SSL_CERT_FILE=${SSL_CERT_FILE}
SSL_KEY_FILE=${SSL_KEY_FILE}
APP_NAME=${APP_NAME}
EOF
  ENV_FILE=/tmp/hpx-serviced.env /usr/local/bin/hpx-node-serviced >>/tmp/hpx-serviced.log 2>&1 &
  echo "[hpx-node] management API (Update Node) listening on :${API_PORT}"
}

start_incontainer_serviced

exec /app/main
