# WiFi Deauth Defense Pipeline - Testing Guide

## Quick Test (5 minutes)

### 1. Start the System

```bash
# Open a terminal and run
cd /home/thunder
sudo -E bash start_defender.sh
```

This will:
- Start n8n container (port 5678)
- Start the packet detector
- Show you the dashboard URL

**Wait for**: "System Ready" message

---

## 2. Import the Workflow into n8n

In a **new terminal**:

```bash
# Open n8n dashboard
open http://localhost:5678
# or if using SSH
curl http://localhost:5678
```

**Steps in n8n UI:**

1. Click the **three-line menu** (top left)
2. Select **"Workflows"**
3. Click **"Import"** button
4. Click **"Upload JSON file"**
5. Select: `/home/thunder/n8n/wifi_deauth_workflow.json`
6. Click **"Import"** 
7. Click **"Activate"** to enable the workflow

---

## 3. Send Test Alerts

In a **third terminal**, send test alerts to trigger the pipeline:

```bash
# Send a LOW severity test alert
python3 -c "
from webhook_alerter import get_alerter
alerter = get_alerter()
alerter.send_alert(
    severity='LOW',
    attack='Test Alert (Low)',
    source='192.168.1.50',
    details={'test': True, 'severity_level': 'low'}
)
print('✓ LOW severity alert sent')
"

# Wait 2 seconds
sleep 2

# Send a MEDIUM severity alert
python3 -c "
from webhook_alerter import get_alerter
alerter = get_alerter()
alerter.send_alert(
    severity='MEDIUM',
    attack='Port Scan Detected (Medium)',
    source='192.168.1.100',
    details={'unique_ports': 25, 'severity_level': 'medium'}
)
print('✓ MEDIUM severity alert sent')
"

# Wait 2 seconds
sleep 2

# Send a HIGH severity alert (triggers special handling)
python3 -c "
from webhook_alerter import get_alerter
alerter = get_alerter()
alerter.send_alert(
    severity='HIGH',
    attack='Traffic Flood Detected (High)',
    source='192.168.1.75',
    details={'packet_count': 500, 'pps': 750, 'severity_level': 'high'}
)
print('✓ HIGH severity alert sent')
"
```

---

## 4. Monitor Alert Flow

In a **fourth terminal**, watch the alerts being logged:

```bash
# View alerts in real-time
tail -f /home/thunder/.n8n/alerts/alerts_*.jsonl | jq .
```

You should see:
- Alerts logged with timestamps
- Details from the detector
- Status from n8n processing

---

## Complete Test Script

Run this all-in-one script instead:

```bash
#!/bin/bash

echo "🚀 WiFi Deauth Defense Pipeline Test"
echo "======================================"
echo ""

# Check if n8n is running
if ! curl -s http://localhost:5678/healthz > /dev/null; then
    echo "❌ n8n is not running"
    echo "Start it with: sudo -E bash /home/thunder/start_defender.sh"
    exit 1
fi

echo "✓ n8n is running"
echo ""

# Function to send alert
send_alert() {
    local severity=$1
    local attack=$2
    local source=$3
    local details=$4
    
    python3 -c "
from webhook_alerter import get_alerter
import json

alerter = get_alerter()
details = $details
alerter.send_alert('$severity', '$attack', '$source', details)
print(f'✓ Sent: {severity} - {attack}')
"
}

echo "📤 Sending test alerts..."
echo ""

# Test 1: LOW severity
send_alert "LOW" "Test Alert - SYN Probe" "192.168.1.50" '{"syn_packets": 5}'
sleep 1

# Test 2: MEDIUM severity  
send_alert "MEDIUM" "Port Scan Detected" "192.168.1.100" '{"unique_ports": 25, "protocol": "TCP"}'
sleep 1

# Test 3: HIGH severity
send_alert "HIGH" "Traffic Flood Detected" "192.168.1.75" '{"packet_count": 500, "pps": 750}'
sleep 1

# Test 4: CRITICAL severity
send_alert "CRITICAL" "Potential DDoS Attack" "192.168.1.200" '{"packet_rate": 2000, "duration_seconds": 10}'
sleep 1

echo ""
echo "✅ All test alerts sent!"
echo ""
echo "Monitoring alerts (Ctrl+C to stop):"
echo "------------------------------------"
tail -f /home/thunder/.n8n/alerts/alerts_*.jsonl | jq .
```

Save as `/home/thunder/run_test.sh` and run:

```bash
chmod +x /home/thunder/run_test.sh
/home/thunder/run_test.sh
```

---

## 5. Verify Workflow Processing

Check n8n dashboard to see workflow execution:

1. Open http://localhost:5678
2. Click **"Workflows"**
3. Click **"WiFi Deauth Defense Alert Handler"**
4. Click **"Executions"** tab
5. You should see 4 completed executions (one for each test alert)

---

## 6. Check Alert Logs

View all alerts logged:

```bash
# View all alerts
cat /home/thunder/.n8n/alerts/alerts_2026-02-05.jsonl | jq .

# Count alerts by severity
grep -c '"severity": "LOW"' /home/thunder/.n8n/alerts/alerts_*.jsonl
grep -c '"severity": "MEDIUM"' /home/thunder/.n8n/alerts/alerts_*.jsonl
grep -c '"severity": "HIGH"' /home/thunder/.n8n/alerts/alerts_*.jsonl

# Filter HIGH severity only
cat /home/thunder/.n8n/alerts/alerts_*.jsonl | jq 'select(.severity=="HIGH")'

# Get summary
python3 -c "
from alert_logger import get_logger
logger = get_logger()
summary = logger.get_alert_summary()
print('Alert Summary:')
print(f'  Total: {summary[\"total_alerts\"]}')
print(f'  By Severity: {summary[\"by_severity\"]}')
print(f'  By Type: {summary[\"by_attack_type\"]}')
print(f'  Unique Sources: {summary[\"unique_sources\"]}')
"
```

---

## 7. Test Detector Integration (Real Packets)

Instead of sending fake alerts, test with real packet capture:

```bash
# Start detector in foreground (shows all traffic)
sudo python3 /home/thunder/fast_detector.py -f ip -w 5

# In another terminal, generate traffic to trigger detection
ping -c 100 8.8.8.8        # Generate flood
nmap -sV localhost         # Generate port scan (if nmap installed)
```

---

## Pipeline Flow Diagram

```
Manual Test Alert
      ↓
webhook_alerter.send_alert()
      ↓
HTTP POST to http://localhost:5678/webhook/wifi-deauth-alerts
      ↓
n8n Webhook Node receives
      ↓
Enrich Alert Data (add timestamp, hostname, etc)
      ↓
Check: Is High Severity?
      ├─→ YES (HIGH/CRITICAL)
      │   ├─→ Log High Severity Alert
      │   └─→ Send Response
      │
      └─→ NO (LOW/MEDIUM)
          ├─→ Log Alert Event
          ├─→ Store Alert in DB
          └─→ Send Response
      ↓
Response sent back to detector
      ↓
alert_logger.log_alert() saves to /home/thunder/.n8n/alerts/
      ↓
Queryable via get_logger().get_recent_alerts()
```

---

## Expected Test Results

### Alert Received in n8n
- ✅ Webhook endpoint receives JSON payload
- ✅ Alert enriched with metadata
- ✅ Routed based on severity
- ✅ Processing logged
- ✅ Response sent back

### Alert Logged to File
- ✅ JSON file created: `/home/thunder/.n8n/alerts/alerts_YYYY-MM-DD.jsonl`
- ✅ One line per alert
- ✅ Includes timestamp, source, severity, attack type
- ✅ Includes logging timestamp and alert ID

### n8n Dashboard Shows
- ✅ Workflow listed as "Active"
- ✅ Executions tab shows completed runs
- ✅ Each execution shows 200/201 status
- ✅ Processing took < 1 second per alert

---

## Troubleshooting

### "Cannot connect to n8n"
```bash
# Check if n8n is running
curl http://localhost:5678/healthz

# Restart if needed
cd /home/thunder/n8n/n8n && docker-compose restart
```

### "Webhook returns 404"
```bash
# Workflow not imported yet
# Import from UI or:
curl -X POST http://localhost:5678/api/workflows \
  --data-binary @/home/thunder/n8n/wifi_deauth_workflow.json
```

### "Alerts not appearing in file"
```bash
# Check if logger has permission
ls -la /home/thunder/.n8n/alerts/

# Check if detector is running
ps aux | grep fast_detector

# Check if webhook_alerter can reach n8n
python3 -c "
from webhook_alerter import WebhookAlerter
alerter = WebhookAlerter()
print(f'Webhook URL: {alerter.webhook_url}')
print(f'Reachable: {alerter.is_webhook_reachable()}')
"
```

### "Permission Denied"
```bash
# Fix alert directory permissions
sudo chmod 777 /home/thunder/.n8n/alerts

# Run detector with sudo
sudo python3 /home/thunder/fast_detector.py
```

---

## Performance Test

Test alert throughput:

```python
#!/usr/bin/env python3
import time
from webhook_alerter import get_alerter

alerter = get_alerter()

print("Testing alert throughput...")
start = time.time()

for i in range(100):
    alerter.send_alert(
        f"Alert {i}",
        f"Test Alert #{i}",
        f"192.168.1.{i % 254}",
        {"test": True, "iteration": i}
    )

elapsed = time.time() - start
print(f"Sent 100 alerts in {elapsed:.2f}s")
print(f"Rate: {100/elapsed:.1f} alerts/sec")
```

---

## Full Integration Test Workflow

Complete end-to-end test:

```bash
# 1. Start system
echo "Starting system..."
sudo -E bash /home/thunder/start_defender.sh &
SYSTEM_PID=$!
sleep 10

# 2. Import workflow (one-time)
echo "Importing workflow..."
# Manually do this via UI

# 3. Run test alerts
echo "Sending test alerts..."
/home/thunder/run_test.sh &
TEST_PID=$!

# 4. Monitor alerts
sleep 5
echo "Monitoring alerts..."
tail -f /home/thunder/.n8n/alerts/alerts_*.jsonl | head -20

# 5. Show summary
python3 -c "
from alert_logger import get_logger
logger = get_logger()
print('\n=== Alert Summary ===')
summary = logger.get_alert_summary()
for severity, count in summary['by_severity'].items():
    print(f'{severity}: {count}')
"

# 6. Cleanup
kill $SYSTEM_PID $TEST_PID 2>/dev/null
echo "Test complete!"
```

---

## Next: Advanced Testing

After basic tests pass, try:

1. **Add Slack notifications** - Add Slack node to workflow
2. **Add database storage** - Connect to MySQL/PostgreSQL
3. **Real packet capture** - Run on actual network with traffic
4. **Load testing** - Send 1000s of alerts
5. **Custom rules** - Modify detection thresholds

See `README_SETUP.md` for advanced configuration.

---

**Test Duration**: 5-10 minutes  
**Success Indicator**: Alerts visible in `/home/thunder/.n8n/alerts/` and n8n dashboard
