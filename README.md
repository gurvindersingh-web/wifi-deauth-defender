# WiFi Deauth Defender

Real-time WiFi deauthentication attack detection and alerting system with kernel-level BPF filtering, statistical anomaly detection, incident correlation, and n8n webhook delivery.

---

## Architecture

```
┌─────────────┐     ┌──────────────┐     ┌──────────────┐     ┌───────────┐
│  wlan0mon   │────▶│  capture.py  │────▶│ detector.py  │────▶│alerter.py │
│ (Monitor)   │ BPF │   Batching   │ pkt │  3-σ Anomaly │alert│Correlation│──▶ n8n Webhook
│             │     │  50pkt / 5s  │batch│  Detection   │     │ & Webhook │    HTTP POST
└─────────────┘     └──────────────┘     └──────────────┘     └───────────┘
                           ▲                    ▲                    ▲
                           │                    │                    │
                    ┌──────┴────────────────────┴────────────────────┴──────┐
                    │                     main.py                          │
                    │           Orchestrator + Health Monitor               │
                    │                   config.yaml                        │
                    └──────────────────────────────────────────────────────┘
```

### Data Flow

1. **Capture** (`capture.py`): Scapy sniffs 802.11 deauthentication frames using a kernel-level BPF filter (`subtype deauth`). Packets are batched in a thread-safe deque — flushed on 50 packets OR 5 seconds.

2. **Detection** (`detector.py`): Per-source rolling baselines (1-hour window) with 3-sigma anomaly detection. Produces threat scores (0–10) based on z-score magnitude, burst density, and target diversity.

3. **Alerting** (`alerter.py`): Correlates alerts from the same source MAC within a 60-second window into incidents. Enriches with metadata and delivers via HTTP POST to an n8n webhook with retry logic.

4. **Orchestration** (`main.py`): Wires up the pipeline, manages lifecycle, signal handlers (SIGINT/SIGTERM), and health logging.

---

## Prerequisites

- **Linux** with a wireless adapter supporting monitor mode
- **Python 3.9+**
- **Root or sudo** privileges (required for raw packet capture)

### Supported Adapters

Any adapter that supports monitor mode via `iw` or `airmon-ng`:
- Alfa AWUS036ACH/ACM
- TP-Link TL-WN722N (v1)
- Any adapter with ath9k/ath10k/rtl88xx drivers

---

## Quick Start

### 1. Clone and Install

```bash
git clone <repository-url>
cd piplineflow
pip install -r requirements.txt
```

### 2. Set Up Monitor Mode

```bash
# Option A: Manual
sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up

# Option B: airmon-ng
sudo airmon-ng start wlan0
```

### 3. Configure

Edit `config.yaml`:

```yaml
capture:
  interface: wlan0mon    # your monitor-mode interface
  channel: 6             # channel to monitor

alerting:
  webhook_url: "https://your-n8n.com/webhook/deauth-alerts"
```

### 4. Run

```bash
# Using the startup script (recommended)
sudo ./start.sh

# Or directly
sudo python3 main.py -c config.yaml
```

---

## Docker Deployment

```bash
# Build
docker build -t deauth-defender .

# Run
docker run --rm -it \
  --cap-add=NET_RAW --cap-add=NET_ADMIN \
  --network=host \
  -v /path/to/config.yaml:/app/config.yaml:ro \
  deauth-defender
```

> **Note**: `--network=host` and `--cap-add` flags are required for raw wireless frame capture.

---

## Configuration Reference

### `config.yaml`

| Section | Key | Default | Description |
|---------|-----|---------|-------------|
| `capture` | `interface` | `wlan0mon` | Monitor-mode wireless interface |
| | `channel` | `6` | WiFi channel to lock onto (0 = no change) |
| | `bpf_filter` | `subtype deauth` | BPF expression for kernel filtering |
| | `batch_size` | `50` | Max packets per batch |
| | `batch_timeout` | `5.0` | Seconds before partial batch flush |
| `detection` | `baseline_window` | `3600` | Rolling baseline duration (seconds) |
| | `sigma_threshold` | `3.0` | Standard deviations for anomaly flag |
| | `min_baseline_samples` | `10` | Minimum buckets before detection activates |
| | `bucket_size` | `10` | Rate computation bucket duration (seconds) |
| | `eviction_timeout` | `7200` | Seconds before stale baselines are purged |
| `alerting` | `webhook_url` | *(required)* | n8n webhook endpoint URL |
| | `batch_interval` | `30` | Seconds between webhook deliveries |
| | `max_batch_size` | `100` | Max alerts per payload |
| | `retry_attempts` | `3` | Retry count on delivery failure |
| | `retry_delay` | `5` | Base retry delay (exponential backoff) |
| | `correlation_window` | `60` | Seconds to group alerts into incidents |
| `logging` | `level` | `INFO` | Log level |
| | `file` | `deauth_defender.log` | Log file path |
| `security` | `hash_macs` | `false` | SHA-256 hash MACs in payloads |
| | `allowed_interfaces` | `[wlan0mon, wlan1mon]` | Whitelisted interfaces |

---

## Webhook Payload Format

The system sends HTTP POST requests with the following JSON structure:

```json
{
  "batch_metadata": {
    "timestamp": "2026-03-29T23:45:00",
    "alert_count": 15,
    "severity_distribution": {"critical": 3, "high": 8, "medium": 4},
    "unique_sources": 2,
    "unique_targets": 5,
    "total_deauth_frames": 347,
    "incident_count": 2
  },
  "incidents": [
    {
      "incident_id": "aa:bb:cc:dd:ee:ff_1711754700",
      "source_mac": "aa:bb:cc:dd:ee:ff",
      "alert_count": 10,
      "duration": 45.3,
      "severity": "critical",
      "target_macs": ["11:22:33:44:55:66", "..."],
      "alerts": [
        {
          "alert_id": "a1b2c3d4e5f6",
          "source_mac": "aa:bb:cc:dd:ee:ff",
          "target_mac": "11:22:33:44:55:66",
          "bssid": "aa:bb:cc:dd:ee:ff",
          "reason": 7,
          "signal": -45,
          "timestamp": 1711754700.1234,
          "severity": "critical",
          "score": 9.2,
          "channel": 6,
          "deauth_count": 50,
          "z_score": 4.5
        }
      ]
    }
  ],
  "raw_alerts": [ ]
}
```

---

## Threat Scoring

The threat score (0–10) is a weighted composite:

| Component | Weight | Description | Normalization |
|-----------|--------|-------------|---------------|
| Z-score magnitude | 50% | How far above baseline | Capped at 10σ |
| Burst density | 30% | Absolute packet count | Capped at 200 pkts |
| Target diversity | 20% | Distinct target MACs | Capped at 20 targets |

### Severity Mapping

| Score | Severity |
|-------|----------|
| ≥ 8.0 | `critical` |
| ≥ 6.0 | `high` |
| ≥ 4.0 | `medium` |
| < 4.0 | `low` |

---

## Testing

### Unit Tests

```bash
# Run all tests
python -m pytest tests/ -v

# Run specific test module
python -m pytest tests/test_detector.py -v
```

### End-to-End Simulation

```bash
# Runs synthetic traffic through the full pipeline
python tests/simulate_attack.py

# Verbose mode (prints full JSON payload)
python tests/simulate_attack.py --loud
```

The simulation:
1. Feeds 20 buckets of normal traffic (baseline learning)
2. Injects a 150-packet attack burst from attacker A
3. Injects an 80-packet burst from attacker B
4. Correlates alerts into incidents
5. Validates the webhook JSON against the schema
6. Prints a detailed summary

---

## File Structure

```
piplineflow/
├── main.py              # Orchestrator — CLI entry point
├── capture.py           # Packet capture with BPF + batching
├── detector.py          # 3-sigma anomaly detection engine
├── alerter.py           # Alert correlation + webhook delivery
├── models.py            # Data models (DeauthPacket, Alert, Incident, etc.)
├── config.yaml          # Configuration file
├── requirements.txt     # Python dependencies
├── start.sh             # Production startup script
├── Dockerfile           # Container deployment
├── README.md            # This file
└── tests/
    ├── test_models.py       # Model serialization tests
    ├── test_detector.py     # Detection logic tests
    ├── test_alerter.py      # Correlation + webhook tests
    ├── test_capture.py      # Batching logic tests
    └── simulate_attack.py   # End-to-end simulation
```

---

## Security Considerations

- **Monitor mode only**: The system captures on a dedicated monitor-mode interface — it does not transmit or inject frames.
- **Minimal data**: Only MAC addresses, timestamps, signal strength, and reason codes are captured. No payload data.
- **MAC hashing**: Enable `security.hash_macs: true` in config to SHA-256 hash all MAC addresses before they leave the system.
- **Interface whitelist**: Only interfaces listed in `security.allowed_interfaces` are accepted.
- **Root scope**: The startup script validates root privileges are present (required for `CAP_NET_RAW`).

---

## Performance

- **Memory target**: ~200 MB under sustained high frame rates
- **Bounded data structures**: `deque` with `maxlen` for baselines and packet buffers
- **Kernel filtering**: BPF runs in kernel space — only deauth frames are copied to userspace
- **Stale eviction**: Baselines for inactive sources are automatically purged after 2 hours

---

## License

MIT
