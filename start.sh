#!/usr/bin/env bash
# =============================================================================
# WiFi Deauth Defender — Startup Script
# =============================================================================
# Pre-flight checks and launch for production deployment.
#
# Usage:
#   sudo ./start.sh                     # default config.yaml
#   sudo ./start.sh -c /etc/deauth.yaml # custom config path
#
# Requirements:
#   - Root or sudo privileges (required for raw packet capture)
#   - A wireless interface in monitor mode
#   - Python 3.9+ with dependencies installed
# =============================================================================

set -euo pipefail
IFS=$'\n\t'

# --- Colours for terminal output -------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Colour

# --- Defaults ---------------------------------------------------------------
CONFIG_FILE="config.yaml"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# --- Parse CLI arguments ----------------------------------------------------
while getopts "c:h" opt; do
    case "$opt" in
        c) CONFIG_FILE="$OPTARG" ;;
        h)
            echo "Usage: $0 [-c config.yaml]"
            exit 0
            ;;
        *)
            echo "Usage: $0 [-c config.yaml]"
            exit 1
            ;;
    esac
done

# =============================================================================
# Pre-flight checks
# =============================================================================

echo -e "${CYAN}╔══════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║      WiFi Deauth Defender — Startup         ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════╝${NC}"
echo ""

# 1. Root / sudo check -------------------------------------------------------
echo -n "[1/5] Checking privileges … "
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}FAIL${NC}"
    echo -e "${RED}ERROR: This script must be run as root (or with sudo).${NC}"
    echo "       Raw packet capture requires CAP_NET_RAW + CAP_NET_ADMIN."
    exit 1
fi
echo -e "${GREEN}OK${NC} (running as root)"

# 2. Python check -------------------------------------------------------------
PYTHON_CMD="python3"
PIP_CMD="pip3"
if [ -d "${SCRIPT_DIR}/.venv" ]; then
    PYTHON_CMD="${SCRIPT_DIR}/.venv/bin/python"
    PIP_CMD="${SCRIPT_DIR}/.venv/bin/pip"
fi

echo -n "[2/5] Checking Python 3.9+ … "
if ! command -v "$PYTHON_CMD" &>/dev/null; then
    echo -e "${RED}FAIL${NC}"
    echo -e "${RED}ERROR: python3 not found in PATH.${NC}"
    exit 1
fi
PY_VERSION=$("$PYTHON_CMD" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
PY_MAJOR=$(echo "$PY_VERSION" | cut -d. -f1)
PY_MINOR=$(echo "$PY_VERSION" | cut -d. -f2)
if [ "$PY_MAJOR" -lt 3 ] || { [ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 9 ]; }; then
    echo -e "${RED}FAIL${NC}"
    echo -e "${RED}ERROR: Python 3.9+ required (found $PY_VERSION).${NC}"
    exit 1
fi
echo -e "${GREEN}OK${NC} (Python $PY_VERSION)"

# 3. Dependencies check -------------------------------------------------------
echo -n "[3/5] Checking Python dependencies … "
MISSING=()
for pkg in scapy httpx yaml; do
    "$PYTHON_CMD" -c "import $pkg" 2>/dev/null || MISSING+=("$pkg")
done
if [ ${#MISSING[@]} -gt 0 ]; then
    echo -e "${YELLOW}INSTALLING${NC}"
    echo "    Missing packages: ${MISSING[*]}"
    "$PIP_CMD" install -r "${SCRIPT_DIR}/requirements.txt" --quiet
    echo -e "    ${GREEN}Dependencies installed.${NC}"
else
    echo -e "${GREEN}OK${NC}"
fi

# 4. Configuration check ------------------------------------------------------
echo -n "[4/5] Checking configuration … "
if [ ! -f "$CONFIG_FILE" ]; then
    # Try relative to script directory.
    CONFIG_FILE="${SCRIPT_DIR}/${CONFIG_FILE}"
fi
if [ ! -f "$CONFIG_FILE" ]; then
    echo -e "${RED}FAIL${NC}"
    echo -e "${RED}ERROR: Config file not found: ${CONFIG_FILE}${NC}"
    exit 1
fi
echo -e "${GREEN}OK${NC} ($CONFIG_FILE)"

# 5. Interface check -----------------------------------------------------------
echo -n "[5/5] Checking monitor interface … "
IFACE=$("$PYTHON_CMD" -c "
import yaml, sys
with open('$CONFIG_FILE') as f:
    cfg = yaml.safe_load(f)
print(cfg.get('capture', {}).get('interface', 'wlan0mon'))
" 2>/dev/null || echo "wlan0mon")

if ip link show "$IFACE" &>/dev/null; then
    echo -e "${GREEN}OK${NC} ($IFACE is up)"
else
    echo -e "${YELLOW}WARNING${NC} (interface '$IFACE' not found — capture will fail)"
    echo -e "    ${YELLOW}Tip: Put your adapter in monitor mode:${NC}"
    echo "      sudo ip link set wlan0 down"
    echo "      sudo iw dev wlan0 set type monitor"
    echo "      sudo ip link set wlan0 up"
    echo "      (or use airmon-ng start wlan0)"
fi

# --- Set channel (if configured and interface exists) -------------------------
CHANNEL=$("$PYTHON_CMD" -c "
import yaml
with open('$CONFIG_FILE') as f:
    cfg = yaml.safe_load(f)
print(cfg.get('capture', {}).get('channel', 0))
" 2>/dev/null || echo "0")

if [ "$CHANNEL" -gt 0 ] 2>/dev/null && ip link show "$IFACE" &>/dev/null; then
    echo -e "    Setting channel to ${CYAN}${CHANNEL}${NC} on ${IFACE} …"
    iw dev "$IFACE" set channel "$CHANNEL" 2>/dev/null || \
        echo -e "    ${YELLOW}Could not set channel (non-fatal).${NC}"
fi

# =============================================================================
# Launch
# =============================================================================
echo ""
echo -e "${GREEN}Starting WiFi Deauth Defender …${NC}"
echo "─────────────────────────────────────────────"
echo ""

cd "$SCRIPT_DIR"
exec "$PYTHON_CMD" main.py -c "$CONFIG_FILE"
