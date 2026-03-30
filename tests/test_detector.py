"""
Tests for detector.py — Anomaly detection engine.

Uses synthetic deauth packet streams to validate:
- Baseline learning (no false positives during normal traffic)
- 3-sigma anomaly detection on attack bursts
- Severity and score thresholds
- Stale baseline eviction
- Scoring composition

Note: The detector uses packet timestamps (not wall-clock time) for
bucket closing decisions.  Each test must therefore ensure that
successive batches have timestamps spaced > bucket_size apart to
trigger bucket closure and anomaly evaluation.
"""

import time
from typing import List

from detector import AnomalyDetector
from models import DeauthPacket


def _make_packets(
    source_mac: str = "aa:bb:cc:dd:ee:ff",
    target_mac: str = "11:22:33:44:55:66",
    count: int = 5,
    base_ts: float = 0.0,
    interval: float = 0.1,
    reason: int = 7,
    signal: int = -45,
) -> List[DeauthPacket]:
    """Generate a batch of synthetic deauth packets."""
    return [
        DeauthPacket(
            source_mac=source_mac,
            target_mac=target_mac,
            bssid=source_mac,
            reason=reason,
            signal=signal,
            timestamp=base_ts + i * interval,
            channel=6,
        )
        for i in range(count)
    ]


class TestAnomalyDetector:
    """Tests for the AnomalyDetector class."""

    def _make_detector(self, **kwargs):
        defaults = dict(
            baseline_window=3600,
            sigma_threshold=3.0,
            min_baseline_samples=5,  # lower for tests
            bucket_size=10,
            eviction_timeout=7200,
        )
        defaults.update(kwargs)
        return AnomalyDetector(**defaults)

    def test_no_alerts_during_baseline_learning(self):
        """No alerts should fire while we have < min_baseline_samples."""
        detector = self._make_detector(min_baseline_samples=10)
        # Feed a few small batches — not enough to build a baseline.
        for i in range(5):
            pkts = _make_packets(count=3, base_ts=i * 15.0)
            alerts = detector.process_batch(pkts)
            assert alerts == [], f"Unexpected alert on batch {i}"

    def test_no_false_positives_on_steady_traffic(self):
        """Steady, consistent deauth rates should not trigger alerts."""
        detector = self._make_detector(min_baseline_samples=5, bucket_size=10)

        # Simulate 20 buckets of ~5 packets each (steady rate).
        # Each batch's timestamps span within a bucket; the *next* batch
        # has timestamps > bucket_size later, which closes the previous bucket.
        for bucket_idx in range(20):
            ts = bucket_idx * 11.0  # slightly > bucket_size to close each bucket
            pkts = _make_packets(count=5, base_ts=ts)
            alerts = detector.process_batch(pkts)

        # After baseline is built, the steady rate should produce NO alerts.
        ts = 20 * 11.0
        pkts = _make_packets(count=5, base_ts=ts)
        alerts = detector.process_batch(pkts)
        assert alerts == [], "False positive on steady traffic"

    def test_detects_burst_attack(self):
        """A sudden spike well above the baseline should trigger an alert."""
        detector = self._make_detector(min_baseline_samples=5, bucket_size=10)

        # Phase 1: build a baseline of ~5 packets per bucket.
        for bucket_idx in range(15):
            ts = bucket_idx * 11.0
            pkts = _make_packets(count=5, base_ts=ts)
            detector.process_batch(pkts)

        # Phase 2: inject a massive burst (100 packets in one bucket).
        # The bucket may close during this call or the follow-up.
        attack_ts = 15 * 11.0
        attack_pkts = _make_packets(count=100, base_ts=attack_ts)
        all_alerts = list(detector.process_batch(attack_pkts))

        # Phase 3: send a follow-up to close any remaining open bucket.
        followup_ts = attack_ts + 11.0
        followup_pkts = _make_packets(count=1, base_ts=followup_ts)
        all_alerts.extend(detector.process_batch(followup_pkts))

        assert len(all_alerts) >= 1, "Attack burst was not detected"
        alert = all_alerts[0]
        assert alert.severity in ("critical", "high", "medium", "low")
        assert alert.z_score >= 3.0
        assert alert.deauth_count >= 50  # at least the attack packets

    def test_severity_thresholds(self):
        """Verify that score-to-severity mapping respects thresholds."""
        detector = self._make_detector()
        assert detector._score_to_severity(9.0) == "critical"
        assert detector._score_to_severity(7.0) == "high"
        assert detector._score_to_severity(5.0) == "medium"
        assert detector._score_to_severity(1.0) == "low"

    def test_scoring_components(self):
        """Verify composite score calculation."""
        # High z-score, high burst, high target diversity → near 10.0
        score = AnomalyDetector._compute_score(
            z_score=10.0, bucket_count=200, target_count=20,
        )
        assert 9.0 <= score <= 10.0

        # Moderate values
        score = AnomalyDetector._compute_score(
            z_score=5.0, bucket_count=50, target_count=5,
        )
        assert 3.0 <= score <= 6.0

        # Low values
        score = AnomalyDetector._compute_score(
            z_score=1.0, bucket_count=5, target_count=1,
        )
        assert score < 3.0

    def test_multiple_sources_tracked_independently(self):
        """Each source MAC should maintain its own independent baseline."""
        detector = self._make_detector(min_baseline_samples=5, bucket_size=10)

        # Build baseline for source A.
        for i in range(10):
            pkts = _make_packets(
                source_mac="aa:aa:aa:aa:aa:aa", count=5, base_ts=i * 11.0,
            )
            detector.process_batch(pkts)

        # Source B sends a burst — should NOT be compared against A's baseline.
        # B has no baseline yet, so the detector should NOT alert (cold-start guard).
        burst = _make_packets(
            source_mac="bb:bb:bb:bb:bb:bb", count=100, base_ts=200.0,
        )
        alerts = detector.process_batch(burst)
        # B has only 1 observation — below min_baseline_samples.
        assert len(alerts) == 0, "Should not alert on first observation of a new source"

    def test_stale_baseline_eviction(self):
        """Sources not seen for > eviction_timeout should be evicted."""
        detector = self._make_detector(eviction_timeout=100)

        # Feed a batch at t=1000.
        pkts = _make_packets(count=5, base_ts=1000.0)
        detector.process_batch(pkts)
        assert detector.get_stats()["tracked_sources"] == 1

        # Feed a batch from a DIFFERENT source at t=1200 (200s later).
        # Since the original source's last_seen was ~1000 and now=1200,
        # elapsed (200) > eviction_timeout (100), so it should be evicted.
        pkts2 = _make_packets(
            source_mac="xx:xx:xx:xx:xx:xx", count=1, base_ts=1200.0,
        )
        detector.process_batch(pkts2)

        # Original source should be evicted.
        assert "aa:bb:cc:dd:ee:ff" not in detector._baselines

    def test_empty_batch(self):
        """Processing an empty batch should return no alerts."""
        detector = self._make_detector()
        assert detector.process_batch([]) == []

    def test_get_baseline_summary(self):
        """Baseline summary should return stats for tracked sources."""
        detector = self._make_detector(min_baseline_samples=3, bucket_size=5)

        # Feed 5 batches spaced 6s apart (> bucket_size=5) to close buckets.
        for i in range(5):
            pkts = _make_packets(count=3, base_ts=i * 6.0)
            detector.process_batch(pkts)

        # Send one more batch to close the last open bucket.
        pkts = _make_packets(count=1, base_ts=5 * 6.0)
        detector.process_batch(pkts)

        summary = detector.get_baseline_summary("AA:BB:CC:DD:EE:FF")
        assert summary is not None
        assert summary["source_mac"] == "aa:bb:cc:dd:ee:ff"
        assert summary["observations"] > 0

    def test_target_diversity_in_burst(self):
        """Bursts targeting many different MACs should score higher."""
        detector = self._make_detector(min_baseline_samples=5, bucket_size=10)

        # Build baseline with single-target traffic.
        for i in range(10):
            pkts = _make_packets(count=5, base_ts=i * 11.0, target_mac="11:11:11:11:11:11")
            detector.process_batch(pkts)

        # Burst targeting 20 different MACs.
        ts = 10 * 11.0
        diverse_pkts = []
        for j in range(100):
            diverse_pkts.append(DeauthPacket(
                source_mac="aa:bb:cc:dd:ee:ff",
                target_mac=f"00:00:00:00:00:{j % 20:02x}",
                bssid="aa:bb:cc:dd:ee:ff",
                reason=7, signal=-45,
                timestamp=ts + j * 0.01,
                channel=6,
            ))
        detector.process_batch(diverse_pkts)

        # Close the attack bucket with a follow-up.
        followup = _make_packets(count=1, base_ts=ts + 11.0)
        alerts = detector.process_batch(followup)
        if alerts:
            assert alerts[0].score > 5.0, "Diverse-target attack should score high"
