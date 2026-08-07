#!/bin/bash

GREEN="\e[32m"
BLUE="\e[34m"
RED="\e[31m"
RESET="\e[0m"

echo -e "${BLUE}[*] Deploying GhostSniffer v2.0...${RESET}"

if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}[!] Please run as root (sudo ./install.sh)${RESET}"
  exit 1
fi

INSTALL_DIR="/opt/GhostSniffer"
echo -e "${BLUE}[*] Copying files to ${INSTALL_DIR}...${RESET}"
mkdir -p "$INSTALL_DIR"

cp ghost_sniffer "$INSTALL_DIR/ghost_sniffer.py" 2>/dev/null || cp ghost_sniffer.py "$INSTALL_DIR/"
cp .env "$INSTALL_DIR/" 2>/dev/null
cp .env.example "$INSTALL_DIR/" 2>/dev/null

BIN_PATH="/usr/local/bin/ghostSniffer"
echo -e "${BLUE}[*] Creating global command '${GREEN}ghostSniffer${BLUE}'...${RESET}"

cat << 'EOF' > "$BIN_PATH"
#!/bin/bash
# Always run the tool with `sudo`, as raw sockets require root privileges.
# Using the system's Python directly, as there are no dependencies.
sudo python3 /opt/GhostSniffer/ghost_sniffer.py "$@"
EOF

chmod +x "$BIN_PATH"

echo -e "${GREEN}[👻] Deployment Complete!${RESET}"
echo -e "Type ${GREEN}ghostSniffer --help${RESET} from anywhere to start hunting."