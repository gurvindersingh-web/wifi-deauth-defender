#!/bin/bash

# WiFi Deauth Defense Pipeline - Automated Test Script
# Tests the complete alert flow through n8n

set -e

# Colors
GREEN='\033[92m'
RED='\033[91m'
YELLOW='\033[93m'
BLUE='\033[94m'
RESET='\033[0m'

echo -e "${BLUE}============================================${RESET}"
echo -e "${BLUE}WiFi Deauth Defense Pipeline Test${RESET}"
echo -e "${BLUE}============================================${RESET}"
echo ""

# Check if n8n is running
echo -e "${YELLOW}[1/5] Checking n8n health...${RESET}"
if ! curl -s http://localhost:5678/healthz > /dev/null; then
    echo -e "${RED}❌ n8n is not running${RESET}"
    echo -e "${YELLOW}Start it with: sudo -E bash /home/thunder/start_defender.sh${RESET}"
    exit 1
fi
echo -e "${GREEN}✓ n8n is running${RESET}"
echo ""

# Check if workflow is active
echo -e "${YELLOW}[2/5] Checking webhook endpoint...${RESET}"
WEBHOOK_RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:5678/webhook-test/8a37cb06-dc42-46e7-946a-0521f48f7ca8 -X POST \
  -H "Content-Type: application/json" \
  -d '{"test": true}' 2>/dev/null || echo "000")

if [ "$WEBHOOK_RESPONSE" = "200" ] || [ "$WEBHOOK_RESPONSE" = "201" ] || [ "$WEBHOOK_RESPONSE" = "202" ]; then
    echo -e "${GREEN}✓ Webhook endpoint is active${RESET}"
elif [ "$WEBHOOK_RESPONSE" = "404" ]; then
    echo -e "${YELLOW}⚠ Workflow not imported yet (404)${RESET}"
    echo -e "${YELLOW}   But test will continue - workflow may auto-activate${RESET}"
else
    echo -e "${YELLOW}⚠ Webhook status: $WEBHOOK_RESPONSE (continuing anyway)${RESET}"
fi
echo ""

# Create log directory if not exists
mkdir -p /home/thunder/.n8n/alerts

# Function to send alert
send_alert() {
    local severity=$1
    local attack=$2
    local source=$3
    local packet_count=$4
    
    python3 << EOF
from webhook_alerter import get_alerter
alerter = get_alerter()
alerter.send_alert(
    severity='$severity',
    attack='$attack',
    source='$source',
    details={'packet_count': $packet_count, 'test': True}
)
EOF
}

# Send test alerts
echo -e "${YELLOW}[3/5] Sending test alerts...${RESET}"
echo ""

echo -e "  ${BLUE}→ LOW severity${RESET}"
send_alert "LOW" "SYN Probe" "192.168.1.50" "5"
sleep 1

echo -e "  ${BLUE}→ MEDIUM severity${RESET}"
send_alert "MEDIUM" "Port Scan Detected" "192.168.1.100" "25"
sleep 1

echo -e "  ${BLUE}→ HIGH severity${RESET}"
send_alert "HIGH" "Traffic Flood" "192.168.1.75" "500"
sleep 1

echo -e "  ${BLUE}→ CRITICAL severity${RESET}"
send_alert "CRITICAL" "Potential DDoS Attack" "192.168.1.200" "2000"
sleep 1

echo -e "${GREEN}✓ All test alerts sent${RESET}"
echo ""

# Check if alerts were logged
echo -e "${YELLOW}[4/5] Checking alert logs...${RESET}"
ALERT_COUNT=$(wc -l < /home/thunder/.n8n/alerts/alerts_*.jsonl 2>/dev/null || echo "0")

if [ "$ALERT_COUNT" -gt 0 ]; then
    echo -e "${GREEN}✓ Alerts logged: $ALERT_COUNT${RESET}"
else
    echo -e "${YELLOW}⚠ No alerts found in log file (may take a moment)${RESET}"
fi
echo ""

# Show alert summary
echo -e "${YELLOW}[5/5] Alert Summary...${RESET}"
python3 << 'EOF'
from alert_logger import get_logger

try:
    logger = get_logger()
    summary = logger.get_alert_summary()
    
    print()
    print(f"  Total Alerts: {summary['total_alerts']}")
    
    if summary['by_severity']:
        print(f"  By Severity:")
        for severity, count in sorted(summary['by_severity'].items()):
            print(f"    - {severity}: {count}")
    
    if summary['by_attack_type']:
        print(f"  By Type:")
        for attack, count in sorted(summary['by_attack_type'].items()):
            print(f"    - {attack}: {count}")
    
    print(f"  Unique Sources: {summary['unique_sources']}")
    print()
except Exception as e:
    print(f"  Error: {e}")
    print()
EOF

echo -e "${GREEN}============================================${RESET}"
echo -e "${GREEN}✓ Test Complete!${RESET}"
echo -e "${GREEN}============================================${RESET}"
echo ""
echo -e "View alerts in real-time:"
echo -e "  ${YELLOW}tail -f /home/thunder/.n8n/alerts/alerts_*.jsonl | jq .${RESET}"
echo ""
echo -e "View n8n executions:"
echo -e "  ${YELLOW}Open: http://localhost:5678${RESET}"
echo -e "  ${YELLOW}Then: Workflows → WiFi Deauth Defense Alert Handler → Executions${RESET}"
echo ""
