"""
WiFi Deauth Defender — End-to-End Attack Simulation
=====================================================
Generates synthetic deauth traffic (normal baseline + attack burst),
pipes it through the full detection → alerting pipeline, and validates
the final webhook payload against the expected JSON schema.

This script does NOT require a wireless interface — it operates
entirely in-memory using fabricated packet data.

Usage::

    python tests/simulate_attack.py          # default scenario
    python tests/simulate_attack.py --loud   # verbose output
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

# Ensure the project root is on the path.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from alerter import AlertProcessor
from detector import AnomalyDetector
from models import Alert, BatchMetadata, DeauthPacket, Incident, WebhookPayload


# ---------------------------------------------------------------------------
# Synthetic traffic generators
# ---------------------------------------------------------------------------

def generate_normal_traffic(
    source_mac: str = "aa:bb:cc:dd:ee:ff",
    target_mac: str = "11:22:33:44:55:66",
    buckets: int = 20,
    packets_per_bucket: int = 5,
    bucket_interval: float = 11.0,
    base_ts: float = 1000.0,
) -> List[List[DeauthPacket]]:
    """Generate steady-state deauth traffic (baseline learning phase).

    Returns a list of batches, one per time bucket.
    """
    batches: List[List[DeauthPacket]] = []
    for b in range(buckets):
        ts = base_ts + b * bucket_interval
        batch = [
            DeauthPacket(
                source_mac=source_mac,
                target_mac=target_mac,
                bssid=source_mac,
                reason=7,
                signal=-50,
                timestamp=ts + i * 0.1,
                channel=6,
            )
            for i in range(packets_per_bucket)
        ]
        batches.append(batch)
    return batches


def generate_attack_burst(
    source_mac: str = "aa:bb:cc:dd:ee:ff",
    num_targets: int = 10,
    packet_count: int = 150,
    base_ts: float = 2000.0,
) -> List[DeauthPacket]:
    """Generate a high-volume deauth attack burst targeting many MACs."""
    return [
        DeauthPacket(
            source_mac=source_mac,
            target_mac=f"de:ad:be:ef:{(i % num_targets):02x}:{i % 256:02x}",
            bssid=source_mac,
            reason=7,
            signal=-35,  # strong signal — nearby attacker
            timestamp=base_ts + i * 0.01,
            channel=6,
        )
        for i in range(packet_count)
    ]


def generate_second_attacker_burst(
    base_ts: float = 2100.0,
) -> List[DeauthPacket]:
    """Generate a smaller burst from a second attacker source."""
    return [
        DeauthPacket(
            source_mac="dd:ee:ff:00:11:22",
            target_mac=f"ca:fe:ba:be:00:{i:02x}",
            bssid="dd:ee:ff:00:11:22",
            reason=3,
            signal=-60,
            timestamp=base_ts + i * 0.05,
            channel=11,
        )
        for i in range(80)
    ]


# ---------------------------------------------------------------------------
# Schema validator
# ---------------------------------------------------------------------------

REQUIRED_BATCH_META_KEYS = {
    "timestamp", "alert_count", "severity_distribution",
    "unique_sources", "unique_targets", "total_deauth_frames",
    "incident_count",
}

REQUIRED_INCIDENT_KEYS = {
    "incident_id", "alert_count", "duration", "severity", "alerts",
}

REQUIRED_ALERT_KEYS = {
    "source_mac", "target_mac", "bssid", "reason",
    "signal", "timestamp", "severity", "score",
}


def validate_payload(payload_dict: Dict[str, Any]) -> List[str]:
    """Validate the webhook payload against the expected schema.

    Returns a list of validation error strings (empty = valid).
    """
    errors: List[str] = []

    # Top-level keys.
    for key in ("batch_metadata", "incidents", "raw_alerts"):
        if key not in payload_dict:
            errors.append(f"Missing top-level key: '{key}'")

    if errors:
        return errors  # can't continue without top-level keys

    # Batch metadata.
    bm = payload_dict["batch_metadata"]
    for key in REQUIRED_BATCH_META_KEYS:
        if key not in bm:
            errors.append(f"batch_metadata missing key: '{key}'")

    if bm.get("alert_count", 0) < 1:
        errors.append("batch_metadata.alert_count should be >= 1")

    # Incidents.
    incidents = payload_dict["incidents"]
    if not isinstance(incidents, list):
        errors.append("'incidents' should be a list")
    else:
        for idx, inc in enumerate(incidents):
            for key in REQUIRED_INCIDENT_KEYS:
                if key not in inc:
                    errors.append(f"incidents[{idx}] missing key: '{key}'")

    # Raw alerts.
    raw_alerts = payload_dict["raw_alerts"]
    if not isinstance(raw_alerts, list):
        errors.append("'raw_alerts' should be a list")
    else:
        for idx, alert in enumerate(raw_alerts):
            for key in REQUIRED_ALERT_KEYS:
                if key not in alert:
                    errors.append(f"raw_alerts[{idx}] missing key: '{key}'")

    return errors


# ---------------------------------------------------------------------------
# Simulation runner
# ---------------------------------------------------------------------------

def run_simulation(verbose: bool = False) -> bool:
    """Execute the full end-to-end simulation.

    Returns True if all validations pass.
    """
    print("=" * 60)
    print("  WiFi Deauth Defender — End-to-End Simulation")
    print("=" * 60)
    print()

    # --- Set up the pipeline ------------------------------------------------
    detector = AnomalyDetector(
        baseline_window=3600,
        sigma_threshold=3.0,
        min_baseline_samples=5,   # lower for simulation
        bucket_size=10,
        eviction_timeout=7200,
    )

    all_alerts: List[Alert] = []

    # --- Phase 1: Normal traffic (baseline learning) -----------------------
    print("[Phase 1] Feeding normal traffic (20 buckets × 5 packets) …")
    normal_batches = generate_normal_traffic(
        buckets=20, packets_per_bucket=5, bucket_interval=11.0, base_ts=1000.0,
    )
    for batch in normal_batches:
        alerts = detector.process_batch(batch)
        all_alerts.extend(alerts)

    normal_alert_count = len(all_alerts)
    print(f"  → Alerts during baseline: {normal_alert_count}")
    if normal_alert_count == 0:
        print("  ✓ No false positives during baseline learning")
    else:
        print("  ⚠ False positives detected during baseline — investigate thresholds")

    # --- Phase 2: Attack burst (primary attacker) ---------------------------
    print()
    print("[Phase 2] Injecting attack burst (150 packets, 10 targets) …")
    attack_pkts = generate_attack_burst(
        packet_count=150, num_targets=10, base_ts=20 * 11.0 + 1000.0,
    )
    alerts = detector.process_batch(attack_pkts)
    all_alerts.extend(alerts)
    print(f"  → Alerts from primary attack: {len(alerts)}")

    # --- Phase 3: Second attacker -------------------------------------------
    print()
    print("[Phase 3] Injecting second attacker burst (80 packets) …")
    attack2_pkts = generate_second_attacker_burst(
        base_ts=20 * 11.0 + 1200.0,
    )
    # Feed it through the detector — need baseline for second source first.
    # Build a quick baseline for the second source.
    for i in range(10):
        baseline_batch = [
            DeauthPacket(
                source_mac="dd:ee:ff:00:11:22",
                target_mac="ca:fe:ba:be:00:00",
                bssid="dd:ee:ff:00:11:22",
                reason=3, signal=-60,
                timestamp=500.0 + i * 11.0,
                channel=11,
            )
            for _ in range(3)
        ]
        detector.process_batch(baseline_batch)

    alerts2 = detector.process_batch(attack2_pkts)
    all_alerts.extend(alerts2)
    print(f"  → Alerts from second attacker: {len(alerts2)}")

    # --- Phase 4: Correlation & payload assembly ----------------------------
    print()
    print("[Phase 4] Correlating alerts and assembling payload …")

    # Use AlertProcessor's correlation engine (without webhook delivery).
    processor = AlertProcessor(
        webhook_url="",  # no actual delivery
        correlation_window=120.0,
        batch_interval=3600,
    )
    incidents = processor._correlate_alerts(all_alerts)

    metadata = BatchMetadata.from_alerts(all_alerts, incidents)
    payload = WebhookPayload(
        batch_metadata=metadata,
        incidents=incidents,
        raw_alerts=all_alerts,
    )
    payload_dict = payload.to_dict()

    # --- Phase 5: Validate schema -------------------------------------------
    print()
    print("[Phase 5] Validating webhook payload schema …")
    errors = validate_payload(payload_dict)

    if errors:
        print("  ✗ VALIDATION FAILED:")
        for err in errors:
            print(f"    - {err}")
        return False
    else:
        print("  ✓ Payload schema is valid!")

    # --- Phase 6: Webhook Delivery ------------------------------------------
    print()
    print("[Phase 6] Testing Webhook Delivery …")
    import yaml
    try:
        with open("config.yaml") as f:
            config = yaml.safe_load(f)
            webhook_url = config.get("alerting", {}).get("webhook_url", "")
    except Exception as e:
        print(f"  ⚠ Could not load config.yaml: {e}")
        webhook_url = ""
        
    if webhook_url:
        processor.webhook_url = webhook_url
        print(f"  → Sending test payload to webhook: {webhook_url}")
        delivery_success = processor._deliver(payload)
        if delivery_success:
            print("  ✓ Webhook delivery successful!")
        else:
            print("  ✗ Webhook delivery failed.")
            # We don't return early here to allow printing the JSON payload for debugging
    else:
        print("  → No webhook URL found in config.yaml — skipping delivery testing.")

    # --- Summary ------------------------------------------------------------
    print()
    print("─" * 60)
    print(" SIMULATION RESULTS")
    print("─" * 60)
    bm = payload_dict["batch_metadata"]
    print(f"  Total alerts:          {bm['alert_count']}")
    print(f"  Severity distribution: {bm['severity_distribution']}")
    print(f"  Unique sources:        {bm['unique_sources']}")
    print(f"  Unique targets:        {bm['unique_targets']}")
    print(f"  Total deauth frames:   {bm['total_deauth_frames']}")
    print(f"  Incidents:             {bm['incident_count']}")

    for inc in payload_dict["incidents"]:
        print(f"\n  Incident: {inc['incident_id']}")
        print(f"    Severity:    {inc['severity']}")
        print(f"    Alerts:      {inc['alert_count']}")
        print(f"    Duration:    {inc['duration']}s")
        print(f"    Targets:     {inc.get('target_macs', 'N/A')}")

    if verbose:
        print()
        print("─" * 60)
        print(" FULL PAYLOAD JSON")
        print("─" * 60)
        print(json.dumps(payload_dict, indent=2, default=str))

    print()
    print("─" * 60)

    # Detector diagnostics.
    det_stats = detector.get_stats()
    print(f"  Detector stats: {det_stats}")
    print("─" * 60)

    # Final assertions.
    assert bm["alert_count"] >= 1, "Should have at least 1 alert"
    assert bm["incident_count"] >= 1, "Should have at least 1 incident"
    assert len(payload_dict["raw_alerts"]) == bm["alert_count"]

    print()
    print("  ✓ ALL CHECKS PASSED — simulation successful!")
    print()
    return True


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    verbose = "--loud" in sys.argv or "-v" in sys.argv
    success = run_simulation(verbose=verbose)
    sys.exit(0 if success else 1)
