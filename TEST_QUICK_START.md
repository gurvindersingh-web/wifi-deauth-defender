# Pipeline Test - Quick Start (5 Minutes)

## Step 1: Start System (Terminal 1)

```bash
cd /home/thunder
sudo -E bash start_defender.sh
```

Wait for: `✓ System Ready` message

---

## Step 2: Import Workflow (One-time Setup)

**In Web Browser:**

```
1. Go to: http://localhost:5678
2. Click: Menu (3 lines) → Workflows
3. Click: Import (top right)
4. Click: Upload JSON file
5. Select: /home/thunder/n8n/wifi_deauth_workflow.json
6. Click: Import → Activate
```

---

## Step 3: Run Tests (Terminal 2)

```bash
/home/thunder/run_test.sh
```

**Or manually send alerts:**

```bash
# LOW severity
python3 -c "from webhook_alerter import get_alerter; get_alerter().send_alert('LOW', 'Test', '192.168.1.1')"

# MEDIUM severity
python3 -c "from webhook_alerter import get_alerter; get_alerter().send_alert('MEDIUM', 'Port Scan', '192.168.1.2')"

# HIGH severity
python3 -c "from webhook_alerter import get_alerter; get_alerter().send_alert('HIGH', 'Flood', '192.168.1.3')"
```

---

## Step 4: Monitor Results (Terminal 3)

```bash
# Watch alerts in real-time
tail -f /home/thunder/.n8n/alerts/alerts_*.jsonl | jq .
```

---

## Step 5: Verify in n8n Dashboard

```
1. Open: http://localhost:5678
2. Click: Workflows
3. Click: WiFi Deauth Defense Alert Handler
4. Click: Executions tab
5. You should see 4+ completed executions
```

---

## What You Should See

✅ **Alert logs** appear in terminal 3 (Step 4)  
✅ **n8n executions** show in dashboard (Step 5)  
✅ **Alert counts** shown at end of test script  

---

## Troubleshooting

| Issue | Fix |
|-------|-----|
| "Cannot connect to n8n" | Check: `curl http://localhost:5678/healthz` |
| "Webhook 404 error" | Import workflow from Step 2 |
| "No alerts logged" | Check: `ls /home/thunder/.n8n/alerts/` |
| "Permission denied" | Run with sudo or: `sudo chmod 777 /home/thunder/.n8n/alerts` |

---

## Expected Flow

```
Test Script (run_test.sh)
    ↓
Send 4 Test Alerts (LOW, MEDIUM, HIGH, CRITICAL)
    ↓
webhook_alerter sends to n8n
    ↓
n8n workflow processes
    ↓
Alerts logged to /home/thunder/.n8n/alerts/
    ↓
View in real-time with tail -f
```

---

## Key Files

| File | Purpose |
|------|---------|
| `run_test.sh` | Automated test script (run this!) |
| `TEST_PIPELINE.md` | Detailed testing guide |
| `.n8n/alerts/alerts_YYYY-MM-DD.jsonl` | Alert log file |

---

**Time to complete**: 5-10 minutes  
**Success**: Alerts visible in log and n8n dashboard
