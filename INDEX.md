# Antigravity | WiFi Defense - System Index

## 📋 Premium Project Overview

Complete n8n integration for a WiFi deauth detection system with webhook-based alerting, persistent logging, and premium dashboard.

**Status**: ✅ Antigravity Protocol Ready  
**Version**: 2.0 (Premium)  
**Last Updated**: 2026-02-23

## 📁 Core Components

### Detection Engine

**File**: `fast_detector.py` (Enhanced)
- **Purpose**: Real-time network anomaly detection with webhook integration
- **Changes**: 
  - Added webhook alerter integration
  - Replaced print-based alerts with HTTP POST to n8n
  - Added alert deduplication
  - Maintains backward compatibility
- **Size**: ~8.5 KB
- **Dependencies**: scapy, webhook_alerter

**Usage**:
```bash
sudo python3 fast_detector.py -i eth0 -f ip -w 10
```

---

### Webhook Alerter

**File**: `webhook_alerter.py` (New)
- **Purpose**: HTTP client for sending alerts to n8n
- **Features**:
  - Exponential backoff retry (up to 3 retries)
  - Configurable timeout and delay
  - Failed alert caching
  - Event deduplication support
  - Environment variable configuration
- **Size**: ~6.5 KB
- **Dependencies**: requests

**API**:
```python
from webhook_alerter import get_alerter
alerter = get_alerter()
alerter.send_alert(severity, attack_type, source, details)
```

---

### Alert Logger

**File**: `alert_logger.py` (New)
- **Purpose**: Persistent alert storage and querying
- **Features**:
  - JSON Lines format storage
  - Auto-rotating log files (10MB default)
  - In-memory buffer (last 1000 alerts)
  - Query by severity, source, or time range
  - Summary statistics
  - Export functionality
- **Size**: ~7.8 KB
- **Dependencies**: pathlib, threading, json

**API**:
```python
from alert_logger import get_logger
logger = get_logger()
logger.log_alert(alert_dict)
logger.get_recent_alerts(limit=100, severity="HIGH")
logger.get_alert_summary()
```

---

### Configuration Module

**File**: `detector_config.py` (New)
- **Purpose**: Centralized configuration management
- **Features**:
  - Environment variable support for all settings
  - Configuration validation
  - Pretty-print function
  - Sensible defaults
- **Size**: ~4.3 KB
- **Configurable**:
  - Network interface
  - Detection thresholds (flood, port scan, UDP, PPS)
  - Webhook settings (URL, timeout, retries)
  - Logging paths and rotation
  - Performance tuning (PCAP, workers)

**Usage**:
```python
import detector_config as cfg
cfg.print_config()
errors = cfg.validate_config()
```

---

## 🚀 Deployment & Operations

### Startup Script

**File**: `start_defender.sh` (New)
- **Purpose**: Orchestrated system startup
- **Steps**:
  1. Validates Docker installation
  2. Starts n8n container
  3. Sets up Python environment
  4. Starts detector with webhook integration
  5. Provides status and monitoring commands
- **Size**: ~4.2 KB
- **Requires**: Docker, Docker Compose, Python 3, sudo access

**Usage**:
```bash
chmod +x start_defender.sh
sudo -E bash start_defender.sh
```

---

### Testing & Diagnostics

**File**: `test_system.py` (New)
- **Purpose**: System health check and component validation
- **Tests** (10 total):
  1. Docker installation and daemon
  2. n8n service health
  3. Webhook endpoint connectivity
  4. Python dependencies (scapy, requests)
  5. Detector script syntax validation
  6. Alert logger functionality
  7. Webhook alerter module
  8. Configuration validation
  9. Network connectivity
  10. File permissions
- **Size**: ~11.2 KB
- **Exit Codes**: 0 = all pass, 1 = failures

**Usage**:
```bash
python3 test_system.py
```

---

## 🔧 n8n Integration

### Docker Configuration

**File**: `n8n/n8n/docker-compose.yml` (Updated)
- **Changes**:
  - Updated to version 3.8
  - Added WiFi-specific environment variables
  - Configured SQLite database
  - Added health checks
  - Created dedicated network (wifi_defense_net)
  - Mounted workflow file (read-only)
- **Ports**: 5678 (web interface)
- **Volumes**: 
  - `/home/thunder/.n8n` (data)
  - Workflow JSON (read-only)

**Management**:
```bash
cd /home/thunder/n8n/n8n
docker-compose up -d          # Start
docker-compose down            # Stop
docker-compose logs -f         # View logs
```

---

### Workflow Template

**File**: `n8n/wifi_deauth_workflow.json` (New)
- **Purpose**: Example n8n workflow for alert processing
- **Nodes** (7 total):
  1. **Webhook** - Receives alert events
  2. **Enrich Alert Data** - Adds metadata (timestamp, status, hostname)
  3. **Is High Severity?** - Routes based on severity (HIGH/CRITICAL)
  4. **Log High Severity Alert** - Shell command logging
  5. **Log Alert Event** - Persistent event logging
  6. **Store Alert in DB** - (Optional) Database integration
  7. **Send Response** - HTTP response to detector
- **Connections**: Conditional routing based on alert severity
- **Extensible**: Add Slack, email, Jira, or other nodes

**Import Process**:
1. Open n8n dashboard
2. Click "Import from file"
3. Select `n8n/wifi_deauth_workflow.json`
4. Activate workflow

---

## 📚 Documentation

### Complete Setup Guide

**File**: `README_SETUP.md`
- **Length**: ~500 lines
- **Sections**:
  - Architecture overview with diagrams
  - Prerequisites and installation
  - Quick start (3 steps)
  - Component descriptions with usage examples
  - n8n integration guide
  - Docker configuration and management
  - Alert flow diagram
  - Monitoring and debugging procedures
  - Troubleshooting guide
  - Advanced usage and customization
  - Performance tuning
  - Security considerations

---

### Quick Start Guide

**File**: `QUICK_START.md`
- **Length**: ~250 lines
- **Sections**:
  - 30-second setup
  - 5-minute verification
  - Component overview table
  - Common commands (start/stop, monitor, test)
  - Environment variables
  - Common issues and solutions
  - Alert payload format
  - File location reference
  - Integration examples
  - Debugging tips
  - Next steps

---

### This Index

**File**: `INDEX.md` (This file)
- Complete component inventory
- File descriptions with sizes
- API documentation
- Quick reference
- Deployment checklist

---

## 🔄 Data Flow

```
Raw Packets → fast_detector.py → Alert Detection
                                      ↓
                            webhook_alerter.py
                                      ↓
                            HTTP POST to n8n
                                      ↓
                         n8n Workflow Processing
                         (enrich, route, store)
                                      ↓
                            alert_logger.py
                         (persistent storage)
                                      ↓
                  JSON files in .n8n/alerts/
                  (queryable via logger API)
```

---

## 📊 Alert Format

```json
{
  "timestamp": "2026-02-05T18:51:16Z",
  "severity": "HIGH",
  "attack_type": "Port Scan",
  "source": "192.168.1.100",
  "details": {
    "unique_ports": 25
  },
  "alert_id": "uuid-v4-string",
  "system": "wifi_deauth_defender",
  "logged_at": "2026-02-05T18:51:16.123Z"  (added by logger)
}
```

---

## 🎯 Configuration Reference

| Variable | Default | Purpose |
|----------|---------|---------|
| `WIFI_INTERFACE` | auto-detect | Network interface |
| `CAPTURE_FILTER` | "ip" | BPF filter |
| `AGGREGATION_WINDOW` | 10s | Alert window |
| `FLOOD_THRESHOLD` | 100 | Packets/IP threshold |
| `PORT_SCAN_THRESHOLD` | 20 | Unique ports threshold |
| `UDP_RATIO_THRESHOLD` | 0.85 | UDP ratio threshold |
| `ANOMALY_PPS_THRESHOLD` | 500 | Packets/sec threshold |
| `N8N_WEBHOOK_URL` | http://localhost:5678/webhook/wifi-deauth-alerts | Target URL |
| `WEBHOOK_TIMEOUT` | 5s | Request timeout |
| `WEBHOOK_MAX_RETRIES` | 3 | Retry attempts |
| `WEBHOOK_RETRY_DELAY` | 1.0s | Initial retry delay |
| `ALERT_LOG_DIR` | /home/thunder/.n8n/alerts | Log directory |
| `MAX_LOG_FILE_SIZE_MB` | 10 | Log rotation size |
| `FILE_LOGGING_ENABLED` | true | Enable file logging |

---

## ✅ Deployment Checklist

- [ ] Run `python3 test_system.py` (verify all tests pass)
- [ ] Check Docker is installed and running
- [ ] Verify Python 3.8+ and required packages
- [ ] Ensure network interface detection or specify `WIFI_INTERFACE`
- [ ] Check `/home/thunder/.n8n/` directory is writable
- [ ] Run `sudo -E bash start_defender.sh`
- [ ] Verify n8n dashboard at http://localhost:5678
- [ ] Check alerts in `/home/thunder/.n8n/alerts/`
- [ ] Import workflow: `n8n/wifi_deauth_workflow.json`
- [ ] Customize workflow as needed
- [ ] Test with: `curl -X POST http://localhost:5678/webhook/wifi-deauth-alerts`

---

## 📞 Quick Reference

### Start System
```bash
sudo -E bash /home/thunder/start_defender.sh
```

### Monitor Alerts
```bash
tail -f /home/thunder/.n8n/alerts/alerts_*.jsonl | jq .
```

### Check Health
```bash
curl http://localhost:5678/healthz
ps aux | grep fast_detector
```

### Stop System
```bash
pkill -f fast_detector.py
cd /home/thunder/n8n/n8n && docker-compose down
```

### View Configuration
```bash
python3 -c "import detector_config; detector_config.print_config()"
```

### Test Webhook
```bash
python3 -c "
from webhook_alerter import get_alerter
alerter = get_alerter()
alerter.send_alert('HIGH', 'Test', '192.168.1.1')
"
```

---

## 📝 Files Summary

| File | Type | Size | Purpose |
|------|------|------|---------|
| `fast_detector.py` | Python | 8.5KB | Network anomaly detector (enhanced) |
| `webhook_alerter.py` | Python | 6.5KB | Webhook client for n8n |
| `alert_logger.py` | Python | 7.8KB | Alert persistence layer |
| `detector_config.py` | Python | 4.3KB | Configuration management |
| `start_defender.sh` | Bash | 4.2KB | System startup orchestration |
| `test_system.py` | Python | 11.2KB | System diagnostics |
| `n8n/n8n/docker-compose.yml` | Docker | 1.2KB | n8n container config (updated) |
| `n8n/wifi_deauth_workflow.json` | JSON | 8.5KB | Example n8n workflow |
| `README_SETUP.md` | Markdown | 20KB | Complete documentation |
| `QUICK_START.md` | Markdown | 10KB | Quick reference guide |
| `INDEX.md` | Markdown | This file | Component inventory |

**Total New/Modified**: ~82 KB of code and documentation

---

## 🔐 Security Notes

- ✅ All secrets managed via environment variables
- ✅ Webhook validation ready (add authentication in production)
- ✅ Logs stored locally with no external leaks by default
- ✅ HTTPS recommended for remote n8n deployments
- ✅ Database credentials should be environment variables
- ⚠️ Alert logs should have restricted file permissions

---

## 🚦 Next Steps

1. **Test**: Run `python3 test_system.py`
2. **Deploy**: Execute `sudo -E bash start_defender.sh`
3. **Verify**: Check n8n at http://localhost:5678
4. **Customize**: Import and modify workflow
5. **Monitor**: Watch `/home/thunder/.n8n/alerts/`
6. **Integrate**: Connect to Slack, database, or monitoring system

---

**Version**: 1.0  
**Created**: 2026-02-05  
**Status**: Production Ready
