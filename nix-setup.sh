#!/usr/bin/env bash
# nix-setup.sh — Nix + Podman alternative to the docker compose workflow.
#
# Replaces:
#   ./setup.sh                                  -> ./nix-setup.sh build
#   docker compose -f env/docker-compose.yml up -> ./nix-setup.sh start
#
# Requires: nix (flakes enabled), podman
set -euo pipefail

IMAGE="nginx-rift:vulnerable"
CONTAINER="nginx-rift-poc"
PORT=19321

# ── build ──────────────────────────────────────────────────────────────────
# Compiles nginx from commit 98fc3bb78 via Nix and loads the OCI image into
# Podman.  Equivalent to `docker compose build` in the original workflow.
build() {
    echo "[*] Generating flake.lock (first run only)..."
    [[ -f flake.lock ]] || nix flake update

    echo "[*] Building vulnerable nginx (98fc3bb78) from source via Nix..."
    echo "    (this compiles nginx — takes a few minutes on first run)"
    nix build .#dockerImage --out-link result-docker

    echo "[*] Loading OCI image into Podman..."
    podman load < result-docker
    echo "[+] Image ready: ${IMAGE}"
}

# ── start ──────────────────────────────────────────────────────────────────
# Starts the container with ASLR disabled.
# Equivalent to `docker compose -f env/docker-compose.yml up`.
start() {
    echo "[*] Starting vulnerable nginx container (ASLR disabled)..."
    podman rm -f "${CONTAINER}" 2>/dev/null || true
    podman run -d \
        --name "${CONTAINER}" \
        -p "${PORT}:19321" \
        --cap-add SYS_PTRACE \
        --security-opt seccomp=unconfined \
        "${IMAGE}"

    echo "[*] Waiting for nginx..."
    for i in $(seq 1 15); do
        if python3 -c "
import socket, sys
try:
    s = socket.create_connection(('127.0.0.1', ${PORT}), timeout=1)
    s.sendall(b'GET / HTTP/1.1\r\nHost:l\r\nConnection:close\r\n\r\n')
    s.recv(10); s.close(); sys.exit(0)
except: sys.exit(1)
" 2>/dev/null; then
            echo "[+] nginx is up on 127.0.0.1:${PORT}"
            return
        fi
        sleep 0.5
    done
    echo "[!] nginx did not respond in time"
    podman logs "${CONTAINER}" 2>&1 | tail -20
    exit 1
}

# ── stop ───────────────────────────────────────────────────────────────────
stop() {
    echo "[*] Stopping container..."
    podman stop "${CONTAINER}" 2>/dev/null || true
    podman rm   "${CONTAINER}" 2>/dev/null || true
    echo "[+] Done"
}

# ── logs ───────────────────────────────────────────────────────────────────
logs() { podman logs -f "${CONTAINER}"; }

# ── exec ───────────────────────────────────────────────────────────────────
# Equivalent to `docker compose exec nginx <cmd>`.
exec_cmd() { podman exec "${CONTAINER}" "$@"; }

# ── poc ────────────────────────────────────────────────────────────────────
poc() {
    echo "[*] Running Nginx-Rift PoC..."
    python3 poc.py "$@"
}

# ── dispatch ───────────────────────────────────────────────────────────────
case "${1:-help}" in
    build)  build ;;
    start)  start ;;
    stop)   stop  ;;
    logs)   logs  ;;
    exec)   shift; exec_cmd "$@" ;;
    poc)    shift; poc "$@" ;;
    all)
        build
        start
        echo ""
        echo "  # Terminal 1 — server is running.  In another terminal:"
        echo "  ./nix-setup.sh poc --cmd 'id > /tmp/pwned'"
        echo ""
        echo "  # Verify:"
        echo "  ./nix-setup.sh exec cat /tmp/pwned"
        ;;
    *)
        cat <<EOF
Usage: $0 <command> [args]

  build          Compile nginx ${COMMIT:-98fc3bb78} via Nix and load into Podman
  start          Start vulnerable nginx (port ${PORT}, ASLR disabled)
  stop           Stop and remove the container
  logs           Tail container logs
  exec <cmd>     Run command inside the running container
  poc  [args]    Run poc.py (pass extra args directly, e.g. --cmd 'id > /tmp/pwned')
  all            build + start, then print usage hint

Original docker compose workflow:
  ./setup.sh                               ->  ./nix-setup.sh build
  docker compose -f env/docker-compose.yml up  ->  ./nix-setup.sh start
EOF
        ;;
esac
