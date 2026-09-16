#!/usr/bin/env bash
# In-container CLI used by hpx-node-serviced (Update Node from panel).
# Speaks the same subcommands the host installer advertises for probeCLISubcommand.
set -euo pipefail

INSTALL_DIR="${HPX_INSTALL_DIR:-/opt/hpx-node}"
SERVICE="${HPX_SERVICE_NAME:-hpx-node}"
COMPOSE_FILE="${HPX_COMPOSE_FILE:-$INSTALL_DIR/docker-compose.yml}"

usage() {
  cat <<EOF
Usage: hpx-node <command>

Commands:
  update       Pull latest image and recreate the container
  core-update  Placeholder (core binary updates)
  geofiles     Placeholder (geo asset updates)
  -h, --help   Show this help
EOF
}

dc() {
  if [ ! -f "$COMPOSE_FILE" ]; then
    echo "compose file not found: $COMPOSE_FILE" >&2
    exit 1
  fi
  if ! command -v docker >/dev/null 2>&1; then
    echo "docker CLI missing inside container (docker.sock mount required)" >&2
    exit 1
  fi
  docker compose -p "$SERVICE" -f "$COMPOSE_FILE" "$@"
}

cmd="${1:-}"
shift || true

# Ignore flags the host CLI accepts.
filtered=()
for arg in "$@"; do
  case "$arg" in
    --no-update-service|-y|--yes) ;;
    *) filtered+=("$arg") ;;
  esac
done
set -- ${filtered[@]+"${filtered[@]}"}

case "$cmd" in
  update)
    dc pull
    dc up -d
    echo "updated $SERVICE"
    ;;
  core-update)
    echo "core-update is not supported in-container yet" >&2
    exit 1
    ;;
  geofiles)
    echo "geofiles is not supported in-container yet" >&2
    exit 1
    ;;
  -h|--help|help|"")
    usage
    ;;
  *)
    echo "unknown command: $cmd" >&2
    usage >&2
    exit 1
    ;;
esac
