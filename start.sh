#!/bin/bash
set -e
cd "$(dirname "$0")"

if ! podman image exists nginx-rift:vulnerable 2>/dev/null; then
    echo "[*] Image not found. Building..."
    ./nix-setup.sh build
fi

./nix-setup.sh start
