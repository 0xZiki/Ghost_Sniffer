#!/usr/bin/env bash
set -e
echo "[*] Installing GhostSniffer v2.1 (Hardened Engine)..."
pip install -e . --break-system-packages
echo "[+] Successfully installed! You can now run 'ghostsniffer' or 'sudo ghostsniffer' from anywhere."
