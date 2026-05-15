#!/bin/bash
set -e
cd "$(dirname "$0")"

echo "[*] Stopping vulnerable nginx..."
docker compose -f env/docker-compose.yml down
echo "[+] Done"
