import httpx
import json

URL = "https://thunder0123.app.n8n.cloud/webhook-test/8a37cb06-dc42-46e7-946a-0521f48f7ca8"

payload = {
    "batch_metadata": {
        "timestamp": "2026-03-30T10:00:00",
        "alert_count": 1,
        "severity_distribution": {"high": 1},
        "unique_sources": 1,
        "unique_targets": 1,
        "total_deauth_frames": 150,
        "incident_count": 1
    },
    "incidents": [
        {
            "incident_id": "aa:bb:cc:dd:ee:ff_1234567890",
            "source_mac": "aa:bb:cc:dd:ee:ff",
            "alert_count": 1,
            "duration": 0.0,
            "severity": "high",
            "target_macs": ["11:22:33:44:55:66"],
            "alerts": []
        }
    ],
    "raw_alerts": []
}

def test(data, desc):
    print(f"Testing {desc}...")
    try:
        r = httpx.post(URL, json=data)
        print(f"Status: {r.status_code}")
        print(f"Response: {r.text}")
    except Exception as e:
        print(f"Error: {e}")

test(payload, "Dict Payload")
test([payload], "List Payload")
test({"data": payload}, "Nested Dict Payload")
test({"incidents": payload["incidents"]}, "Only Incidents")

