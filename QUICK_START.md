# WiFi Deauth Defense System - Quick Start Guide

## 30-Second Setup

```bash
# 1. Test your system
python3 /home/thunder/test_system.py

# 2. Start the system
cd /home/thunder
sudo -E bash start_defender.sh

# 3. Open browser to http://localhost:5678
```

## 5-Minute Verification

```bash
# Terminal 1: Monitor real-time alerts
tail -f /home/thunder/.n8n/alerts/alerts_*.jsonl | jq .

# Terminal 2: Check n8n health
curl http://localhost:5678/healthz

# Terminal 3: View detector logs
ps aux | grep fast_detector
```

## Component Files

| File | Purpose | Type |
|------|---------|------|
| `fast_detector.py` | Network anomaly detector | Python |
| `webhook_alerter.py` | n8n webhook client | Python |
| `alert_logger.py` | Alert persistence | Python |
| `detector_config.py` | Configuration module | Python |
| `start_defender.sh` | System startup | Bash |
| `test_system.py` | System diagnostics | Python |
| `n8n/docker-compose.yml` | n8n container config | Docker |

## Quick Commands

### Start/Stop System

```bash
# Start
sudo -E bash /home/thunder/start_defender.sh

# Stop detector
pkill -f fast_detector.py

# Stop n8n
cd /home/thunder/n8n/n8n && docker-compose down
```

### Monitor System

```bash
# View all alerts
tail -20 /home/thunder/.n8n/alerts/alerts_*.jsonl | jq .

# Filter by severity
grep "HIGH\|CRITICAL" /home/thunder/.n8n/alerts/alerts_*.jsonl

# Check detector process
ps aux | grep -E "fast_detector|python3"

# Check n8n container
docker ps | grep n8n
```

### Test Webhook

```bash
# Send test alert
python3 -c "
from webhook_alerter import get_alerter
alerter = get_alerter()
alerter.send_alert('HIGH', 'Test', '192.168.1.1')
"

# Verify webhook reachable
curl -I http://localhost:5678/webhook/wifi-deauth-alerts
```

### View Configuration

```bash
# Print current config
python3 -c "
import detector_config as cfg
cfg.print_config()
"
```

### Query Alerts Programmatically

```python
from alert_logger import get_logger

logger = get_logger()

# Get recent alerts
alerts = logger.get_recent_alerts(limit=10)
print(f"Recent: {len(alerts)} alerts")

# Get summary
summary = logger.get_alert_summary()
print(f"Total: {summary['total_alerts']}")
print(f"By severity: {summary['by_severity']}")

# Export for analysis
logger.export_alerts("/tmp/alerts.json")
```

## Environment Variables

Set before starting:

```bash
# Network
export WIFI_INTERFACE="wlan0"

# Webhook
export N8N_WEBHOOK_URL="http://localhost:5678/webhook/wifi-deauth-alerts"
export WEBHOOK_TIMEOUT="5"
export WEBHOOK_MAX_RETRIES="3"

# Logging
export FILE_LOGGING_ENABLED="true"
export ALERT_LOG_DIR="/home/thunder/.n8n/alerts"

# Detection thresholds
export FLOOD_THRESHOLD="100"
export PORT_SCAN_THRESHOLD="20"
export UDP_RATIO_THRESHOLD="0.85"

# Then start
sudo -E bash start_defender.sh
```

## Common Issues

| Issue | Solution |
|-------|----------|
| **Port 5678 in use** | `sudo lsof -i :5678 && sudo kill -9 <PID>` |
| **Docker not running** | `sudo systemctl start docker` |
| **Permission denied** | Run with `sudo -E` |
| **Webhook not reachable** | Check `curl http://localhost:5678/healthz` |
| **No alerts being logged** | Check `ps aux \| grep fast_detector` |

## Alert Payload Format

Detector sends to n8n:

```json
{
  "timestamp": "2026-02-05T18:51:16Z",
  "severity": "HIGH",
  "attack_type": "Port Scan",
  "source": "192.168.1.100",
  "details": {"unique_ports": 25},
  "alert_id": "uuid-string",
  "system": "wifi_deauth_defender"
}
```

## File Locations

```
/home/thunder/
├── fast_detector.py                 (Enhanced detector with webhook)
├── webhook_alerter.py               (Webhook client)
├── alert_logger.py                  (Alert storage)
├── detector_config.py               (Config module)
├── start_defender.sh                (Startup script)
├── test_system.py                   (Diagnostics)
├── README_SETUP.md                  (Full documentation)
├── QUICK_START.md                   (This file)
├── sniffer.py                       (Original sniffer)
├── n8n/
│   ├── docker-compose.yml
│   ├── wifi_deauth_workflow.json    (Example workflow)
│   └── n8n/
│       └── docker-compose.yml       (Main n8n config)
└── .n8n/                            (n8n data & alerts)
    ├── database.sqlite
    └── alerts/
        └── alerts_YYYY-MM-DD.jsonl  (Alert logs)
```

## Performance Tips

- **High traffic network?** Increase `AGGREGATION_WINDOW` to reduce alerts
- **Reduce latency?** Decrease `AGGREGATION_WINDOW` (watch for more alerts)
- **Large alert volume?** Increase `MAX_LOG_FILE_SIZE_MB` for less rotation

## Integration Examples

### Slack Notifications (in n8n workflow)

Add a Slack node after the severity check to send notifications on HIGH/CRITICAL alerts.

### Database Storage

Add HTTP node pointing to your database API endpoint for persistent storage.

### Grafana Dashboard

Export alerts as JSON and import into Grafana for visualization:

```bash
python3 /home/thunder/alert_logger.py
logger.export_alerts("/tmp/alerts.json")
```

## Debugging

Enable detector debug mode (run in foreground):

```bash
sudo python3 /home/thunder/fast_detector.py -i eth0 -f ip -w 10
```

View n8n workflow execution logs:

```bash
cd /home/thunder/n8n/n8n && docker-compose logs -f
```

Check webhook connectivity:

```bash
curl -v -X POST http://localhost:5678/webhook/wifi-deauth-alerts \
  -H "Content-Type: application/json" \
  -d '{"test": true}'
```

## Next Steps

1. ✓ Start the system (`start_defender.sh`)
2. ✓ Verify n8n is running (`curl http://localhost:5678/healthz`)
3. ✓ Check alerts are being logged (`tail -f .n8n/alerts/alerts_*.jsonl`)
4. → Customize n8n workflow with your own nodes
5. → Add Slack/email notifications
6. → Integrate with your monitoring system

---

See `README_SETUP.md` for complete documentation.
