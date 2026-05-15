#!/bin/bash
set -e
cd "$(dirname "$0")"

COMPOSE="docker compose -f env/docker-compose.yml"

# ビルド済みイメージがなければ自動でビルド
if ! docker images | grep -q "env-nginx\|nginx-rift"; then
    echo "[*] Image not found. Running setup.sh first..."
    ./setup.sh
fi

# RCE 出力ディレクトリをリセット
rm -rf env/poc-output && mkdir -p env/poc-output

echo "[*] Starting vulnerable nginx (port 19321, ASLR disabled)..."
$COMPOSE up -d

echo "[*] Waiting for nginx..."
for i in $(seq 1 15); do
    if python3 -c "
import socket, sys
try:
    s = socket.create_connection(('127.0.0.1', 19321), timeout=1)
    s.sendall(b'GET / HTTP/1.1\r\nHost:l\r\nConnection:close\r\n\r\n')
    s.recv(10); s.close(); sys.exit(0)
except: sys.exit(1)
" 2>/dev/null; then
        echo "[+] nginx is up on 127.0.0.1:19321"
        echo ""
        echo "  コマンド実行 (RCE):"
        echo "    python3 poc.py --cmd 'id > /tmp/pwned'"
        echo ""
        echo "  RCE 確認 (コンテナが停止していても OK):"
        echo "    cat env/poc-output/pwned"
        echo ""
        echo "  インタラクティブシェル:"
        echo "    python3 poc.py --shell"
        exit 0
    fi
    sleep 0.5
done

echo "[!] nginx did not respond in time"
$COMPOSE logs --tail=20
exit 1
