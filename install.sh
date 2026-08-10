#!/bin/bash
#
#  ╔═══════════════════════════════════════════════════╗
#  ║   GhostSniffer v2.0 — Installation Script        ║
#  ║   Advanced Network Reconnaissance Tool            ║
#  ╚═══════════════════════════════════════════════════╝
#

set -e

VERSION="2.0"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/ghost_sniffer"
TOOL_NAME="ghostSniffer"
SOURCE_FILE="ghost_sniffer.py"

# ── Colors (for installer output only) ──
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

echo ""
echo -e "${BOLD}${CYAN}  GhostSniffer v${VERSION} — Installer${NC}"
echo "  ======================================="
echo ""

# ── 1. Check root privileges ──
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[!]${NC} This installer requires root privileges."
    echo "    Run: ${BOLD}sudo bash install.sh${NC}"
    exit 1
fi
echo -e "${GREEN}[+]${NC} Root privileges verified"

# ── 2. Check Python 3 ──
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}[!]${NC} Python 3 is required but not installed."
    echo ""
    echo "    Install it first:"
    echo "      Debian/Ubuntu : sudo apt install python3"
    echo "      CentOS/RHEL   : sudo yum install python3"
    echo "      Arch Linux    : sudo pacman -S python"
    echo "      macOS         : brew install python3"
    exit 1
fi

PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
echo -e "${GREEN}[+]${NC} Python 3 found: v${PYTHON_VERSION}"

# ── 3. Locate source files ──
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ ! -f "${SCRIPT_DIR}/${SOURCE_FILE}" ]; then
    echo -e "${RED}[!]${NC} ${SOURCE_FILE} not found in ${SCRIPT_DIR}"
    echo "    Make sure you run this script from the GhostSniffer directory."
    exit 1
fi
echo -e "${GREEN}[+]${NC} Source found: ${SCRIPT_DIR}/${SOURCE_FILE}"

# ── 4. Install main tool ──
echo -e "${GREEN}[+]${NC} Installing ${BOLD}${TOOL_NAME}${NC} to ${INSTALL_DIR}/ ..."
cp "${SCRIPT_DIR}/${SOURCE_FILE}" "${INSTALL_DIR}/${TOOL_NAME}"
chmod +x "${INSTALL_DIR}/${TOOL_NAME}"

# ── 5. Install configuration ──
echo -e "${GREEN}[+]${NC} Setting up configuration in ${CONFIG_DIR}/ ..."
mkdir -p "${CONFIG_DIR}"

if [ -f "${SCRIPT_DIR}/.env" ]; then
    cp "${SCRIPT_DIR}/.env" "${CONFIG_DIR}/.env"
    chmod 600 "${CONFIG_DIR}/.env"
    echo -e "${GREEN}[+]${NC} Configuration file installed: ${CONFIG_DIR}/.env"
fi

if [ -f "${SCRIPT_DIR}/.env.example" ]; then
    cp "${SCRIPT_DIR}/.env.example" "${CONFIG_DIR}/.env.example"
    echo -e "${GREEN}[+]${NC} Example config installed: ${CONFIG_DIR}/.env.example"
fi

# ── 6. Verify installation ──
echo ""
if command -v "${TOOL_NAME}" &> /dev/null; then
    INSTALLED_PATH=$(command -v "${TOOL_NAME}")
    echo -e "${GREEN}${BOLD}  ✓ Installation successful!${NC}"
    echo ""
    echo -e "  ${BOLD}Installed to:${NC}  ${INSTALLED_PATH}"
    echo -e "  ${BOLD}Config dir:${NC}    ${CONFIG_DIR}/"
    echo ""
    echo -e "  ${BOLD}${CYAN}Quick Start:${NC}"
    echo ""
    echo "    # Show help"
    echo "    ${TOOL_NAME} --help"
    echo ""
    echo "    # Passive host discovery"
    echo "    ${TOOL_NAME} --mode passive --subnet 192.168.1.0/24"
    echo ""
    echo "    # UDP scan (default)"
    echo "    ${TOOL_NAME} --target 192.168.1.0/24"
    echo ""
    echo "    # TCP SYN stealth scan"
    echo "    ${TOOL_NAME} --target 192.168.1.0/24 --scan-type tcp_syn -p 22,80,443"
    echo ""
    echo "    # TCP SYN scan + service detection"
    echo "    ${TOOL_NAME} --target 192.168.1.0/24 --scan-type tcp_syn -p 1-1024 -sV"
    echo ""
    echo "    # ARP discovery (Layer 2)"
    echo "    ${TOOL_NAME} --target 192.168.1.0/24 --scan-type arp"
    echo ""
    echo "    # Port knocking listener"
    echo "    ${TOOL_NAME} --mode listen --knock-seq 1000,2000,3000 --action \"command\""
    echo ""
    echo "    # Full stealth + decoys + JSON output"
    echo "    ${TOOL_NAME} --target 10.0.0.0/24 --stealth --decoys 10.0.0.1,10.0.0.254 -o results.json"
    echo ""
    echo -e "  ${BOLD}Uninstall:${NC}"
    echo "    sudo rm ${INSTALL_DIR}/${TOOL_NAME}"
    echo "    sudo rm -rf ${CONFIG_DIR}"
    echo ""
else
    echo -e "${YELLOW}[!]${NC} Installation completed but '${TOOL_NAME}' not found in PATH."
    echo "    Ensure ${INSTALL_DIR} is in your PATH variable:"
    echo "    export PATH=\"${INSTALL_DIR}:\$PATH\""
fi