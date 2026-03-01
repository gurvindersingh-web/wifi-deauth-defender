#!/bin/bash

# WiFi Deauth Defender Startup Script
# Starts n8n container and the Python detector

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

PROJECT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
N8N_DIR="${PROJECT_DIR}/../n8n/n8n"

echo -e "${GREEN}================================${NC}"
echo -e "${GREEN}WiFi Deauth Defender${NC}"
echo -e "${GREEN}================================${NC}"
echo ""

# Check if running as root (for packet capture)
if [[ $EUID -ne 0 ]]; then
   echo -e "${YELLOW}⚠  Running without root privileges. Packet capture may fail.${NC}"
   echo -e "${YELLOW}   Consider running with: sudo -E bash start_defender.sh${NC}"
   echo ""
fi

# 1. Start n8n container
echo -e "${GREEN}[1/3] Starting n8n automation engine...${NC}"

cd "$N8N_DIR"

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo -e "${RED}✗ Docker is not installed. Please install Docker.${NC}"
    exit 1
fi

# Check if Docker daemon is running
if ! docker info &> /dev/null; then
    echo -e "${RED}✗ Docker daemon is not running. Please start Docker.${NC}"
    exit 1
fi

# Start n8n container
docker compose up -d

# Wait for n8n to be ready
echo -e "${YELLOW}  Waiting for n8n to be ready...${NC}"
for i in {1..30}; do
    if curl -s http://localhost:5678/healthz > /dev/null 2>&1; then
        echo -e "${GREEN}✓ n8n is ready${NC}"
        break
    fi
    if [ $i -eq 30 ]; then
        echo -e "${YELLOW}⚠ n8n health check timed out. It may still be starting...${NC}"
    fi
    sleep 1
done

echo ""

# 2. Setup Python environment
echo -e "${GREEN}[2/3] Setting up Python environment...${NC}"

cd "$PROJECT_DIR"

# Check Python version
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}✗ Python3 is not installed.${NC}"
    exit 1
fi

PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
echo -e "${YELLOW}  Python version: ${PYTHON_VERSION}${NC}"

# Check/install required packages
echo -e "${YELLOW}  Checking required packages...${NC}"
MISSING_PKGS=""
python3 -c "import scapy" 2>/dev/null || MISSING_PKGS="scapy"
python3 -c "import requests" 2>/dev/null || MISSING_PKGS="$MISSING_PKGS requests"

if [ -n "$MISSING_PKGS" ]; then
    echo -e "${YELLOW}  Installing: ${MISSING_PKGS}...${NC}"
    python3 -m pip install --break-system-packages -q $MISSING_PKGS 2>/dev/null || \
    python3 -m pip install -q $MISSING_PKGS 2>/dev/null || {
        echo -e "${RED}✗ Failed to install packages. Try: pip install ${MISSING_PKGS}${NC}"
        exit 1
    }
fi

echo -e "${GREEN}✓ Python environment ready${NC}"
echo ""

# 3. Start the detector
echo -e "${GREEN}[3/3] Starting WiFi deauth detector...${NC}"

# Create log directory
mkdir -p "${PROJECT_DIR}/.n8n/alerts"

# Export environment variables
export N8N_WEBHOOK_URL="${N8N_WEBHOOK_URL:-http://localhost:5678/webhook-test/8a37cb06-dc42-46e7-946a-0521f48f7ca8}"
export WEBHOOK_ENABLED="true"
export FILE_LOGGING_ENABLED="true"

# Set network interface (can be overridden)
INTERFACE="${WIFI_INTERFACE:-}"

echo -e "${YELLOW}  Starting packet detector...${NC}"
echo -e "${YELLOW}  Webhook URL: ${N8N_WEBHOOK_URL}${NC}"
echo -e "${YELLOW}  Log Directory: ${PROJECT_DIR}/.n8n/alerts${NC}"
echo ""

# Start detector in background
if [ -z "$INTERFACE" ]; then
    echo -e "${YELLOW}  No interface specified. Auto-detecting...${NC}"
    sudo python3 "${PROJECT_DIR}/fast_detector.py" -f ip &
else
    echo -e "${YELLOW}  Using interface: ${INTERFACE}${NC}"
    sudo python3 "${PROJECT_DIR}/fast_detector.py" -i "$INTERFACE" -f ip &
fi

DETECTOR_PID=$!
echo -e "${GREEN}✓ Detector started (PID: ${DETECTOR_PID})${NC}"

echo ""
echo -e "${GREEN}================================${NC}"
echo -e "${GREEN}System Ready${NC}"
echo -e "${GREEN}================================${NC}"
echo ""
echo -e "n8n Dashboard:     ${YELLOW}http://localhost:5678${NC}"
echo -e "Alert Logs:        ${YELLOW}${PROJECT_DIR}/.n8n/alerts${NC}"
echo -e "Detector PID:      ${YELLOW}${DETECTOR_PID}${NC}"
echo ""
echo -e "${YELLOW}To stop the system:${NC}"
echo -e "  1. Stop detector: kill ${DETECTOR_PID}"
echo -e "  2. Stop n8n:      cd ${N8N_DIR} && docker compose down"
echo ""
echo -e "${YELLOW}View detector logs:${NC}"
echo -e "  tail -f ${PROJECT_DIR}/.n8n/alerts/alerts_*.jsonl"
echo ""

# Keep script running
wait $DETECTOR_PID
