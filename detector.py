"""
WiFi Deauth Defender — Anomaly Detection Engine
=================================================
Maintains per-source rolling baselines and applies statistical anomaly
detection (3-sigma rule) to identify deauthentication flood attacks
in real-time.

Detection Strategy
------------------
1. **Rate bucketing**: Incoming deauth packets are counted per source MAC
   in fixed-duration time buckets (default 10 s).
2. **Rolling baseline**: For each source, a ``deque`` stores up to 1 hour
   of rate observations.  Mean and standard deviation are computed
   incrementally.
3. **Anomaly flagging**: A new bucket whose rate exceeds ``mean + σ * k``
   (where *k* is the configurable sigma threshold, default 3.0) is
   flagged as anomalous.
4. **Threat scoring**: A composite score (0-10) blends:
   - z-score magnitude (how far above baseline)
   - burst density (packets per second within the bucket)
   - target diversity (number of distinct target MACs)
5. **Severity mapping**: score ≥ 8 → critical, ≥ 6 → high, ≥ 4 → medium,
   else → low.

Memory Management
-----------------
* Baselines for sources inactive longer than ``eviction_timeout`` (2 h)
  are automatically purged.
* Maximum stored observations are bounded by ``baseline_window / bucket_size``.
"""

from __future__ import annotations

import logging
import math
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Deque, Dict, List, Optional, Set, Tuple

from models import Alert, DeauthPacket

logger = logging.getLogger("deauth_defender.detector")


# ---------------------------------------------------------------------------
# Internal data structures
# ---------------------------------------------------------------------------

@dataclass
class SourceBaseline:
    """Rolling baseline state for a single transmitter MAC.

    Attributes:
        rates:        Deque of ``(bucket_epoch, count)`` tuples.
        current_count: Packets accumulated in the *current* (open) bucket.
        bucket_start:  Start epoch of the current bucket.
        targets_seen:  Distinct target MACs observed in the current bucket.
        last_seen:     Epoch of the most-recent packet from this source.
    """

    rates: Deque[Tuple[float, int]] = field(
        default_factory=lambda: deque(maxlen=360)  # 1 h @ 10 s buckets
    )
    current_count: int = 0
    bucket_start: float = 0.0
    targets_seen: Set[str] = field(default_factory=set)
    last_seen: float = 0.0

    # Incremental statistics -----------------------------------------------
    _sum: float = 0.0
    _sum_sq: float = 0.0

    @property
    def n(self) -> int:
        return len(self.rates)

    @property
    def mean(self) -> float:
        return self._sum / self.n if self.n > 0 else 0.0

    @property
    def std(self) -> float:
        if self.n < 2:
            return 0.0
        variance = (self._sum_sq / self.n) - (self.mean ** 2)
        return math.sqrt(max(variance, 0.0))

    def push_rate(self, epoch: float, count: int) -> None:
        """Add a closed bucket and update running statistics."""
        # If the deque is full, evict the oldest and adjust sums.
        if len(self.rates) == self.rates.maxlen:
            _, old_count = self.rates[0]
            self._sum -= old_count
            self._sum_sq -= old_count ** 2

        self.rates.append((epoch, count))
        self._sum += count
        self._sum_sq += count ** 2


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------

class AnomalyDetector:
    """Statistical anomaly detector for deauth flood attacks.

    Args:
        baseline_window:     Seconds of history to keep (default 3600).
        sigma_threshold:     Sigma multiplier for anomaly flagging (default 3.0).
        min_baseline_samples: Minimum buckets before detection activates (default 10).
        bucket_size:         Duration of each rate bucket in seconds (default 10).
        eviction_timeout:    Seconds of inactivity before a source baseline is purged (default 7200).
        severity_thresholds: Dict mapping severity name → minimum score.
    """

    def __init__(
        self,
        baseline_window: int = 3600,
        sigma_threshold: float = 3.0,
        min_baseline_samples: int = 10,
        bucket_size: int = 10,
        eviction_timeout: int = 7200,
        severity_thresholds: Optional[Dict[str, float]] = None,
    ) -> None:
        self.baseline_window = baseline_window
        self.sigma_threshold = sigma_threshold
        self.min_baseline_samples = min_baseline_samples
        self.bucket_size = bucket_size
        self.eviction_timeout = eviction_timeout

        # Severity thresholds (score → label), evaluated high-to-low.
        self.severity_thresholds: List[Tuple[float, str]] = sorted(
            (severity_thresholds or {
                "critical": 8.0,
                "high": 6.0,
                "medium": 4.0,
                "low": 2.0,
            }).items(),
            key=lambda x: x[1],
            reverse=True,
        )

        # Per-source baselines keyed by lowercase MAC.
        self._baselines: Dict[str, SourceBaseline] = defaultdict(SourceBaseline)

        # Diagnostic counters.
        self.total_packets_processed: int = 0
        self.total_alerts_generated: int = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def process_batch(self, packets: List[DeauthPacket]) -> List[Alert]:
        """Ingest a batch of deauth packets and return any generated alerts.

        This is the primary entry point called by the orchestrator for
        each flushed capture batch.

        Args:
            packets: List of :class:`DeauthPacket` objects from the capturer.

        Returns:
            A (possibly empty) list of :class:`Alert` objects for anomalous
            sources detected within the batch.
        """
        if not packets:
            return []

        self.total_packets_processed += len(packets)

        # Use the latest packet timestamp as the reference time for bucket
        # closing decisions.  This makes the detector deterministic and
        # testable with synthetic timestamps.
        now = max(pkt.timestamp for pkt in packets)

        # --- Step 1: Aggregate counts per source in this batch -------------
        source_agg: Dict[str, List[DeauthPacket]] = defaultdict(list)
        for pkt in packets:
            source_agg[pkt.source_mac.lower()].append(pkt)

        alerts: List[Alert] = []

        # --- Step 2: Update baselines and detect anomalies -----------------
        for source_mac, pkts in source_agg.items():
            baseline = self._baselines[source_mac]
            new_alerts = self._update_and_detect(source_mac, baseline, pkts, now)
            alerts.extend(new_alerts)

        # --- Step 3: Evict stale baselines ---------------------------------
        self._evict_stale(now)

        self.total_alerts_generated += len(alerts)
        return alerts

    # ------------------------------------------------------------------
    # Internal detection logic
    # ------------------------------------------------------------------

    def _update_and_detect(
        self,
        source_mac: str,
        baseline: SourceBaseline,
        pkts: List[DeauthPacket],
        now: float,
    ) -> List[Alert]:
        """Update the baseline for *source_mac* and detect anomalies.

        Buckets are closed when the current time exceeds
        ``bucket_start + bucket_size``.
        """
        alerts: List[Alert] = []

        # Initialise the first bucket if needed.
        if baseline.bucket_start == 0.0:
            baseline.bucket_start = now

        # Accumulate new packets into the current bucket.
        for pkt in pkts:
            baseline.current_count += 1
            baseline.targets_seen.add(pkt.target_mac.lower())
            baseline.last_seen = pkt.timestamp

        # Check if the current bucket should be closed.
        elapsed = now - baseline.bucket_start
        if elapsed >= self.bucket_size:
            # Close the bucket -------------------------------------------------
            closed_count = baseline.current_count
            closed_targets = set(baseline.targets_seen)

            # Push rate into the rolling baseline.
            baseline.push_rate(baseline.bucket_start, closed_count)

            # Detect anomalies only if we have sufficient history.
            if baseline.n >= self.min_baseline_samples:
                alert = self._evaluate_anomaly(
                    source_mac=source_mac,
                    baseline=baseline,
                    bucket_count=closed_count,
                    target_set=closed_targets,
                    representative_pkt=pkts[-1],
                )
                if alert is not None:
                    alerts.append(alert)

            # Reset the bucket for the next window.
            baseline.current_count = 0
            baseline.bucket_start = now
            baseline.targets_seen.clear()

        return alerts

    def _evaluate_anomaly(
        self,
        source_mac: str,
        baseline: SourceBaseline,
        bucket_count: int,
        target_set: Set[str],
        representative_pkt: DeauthPacket,
    ) -> Optional[Alert]:
        """Apply the 3-sigma rule and score the anomaly.

        Returns an :class:`Alert` if the current bucket is anomalous,
        otherwise ``None``.
        """
        mean = baseline.mean
        std = baseline.std

        # Avoid division by zero — if std is 0, any deviation is anomalous
        # provided the count is above the mean.
        if std == 0.0:
            if bucket_count <= mean:
                return None
            z_score = float(bucket_count - mean)  # treat as raw deviation
        else:
            z_score = (bucket_count - mean) / std

        # --- Gate: must exceed sigma threshold ----------------------------
        if z_score < self.sigma_threshold:
            return None

        # --- Compute composite threat score (0-10) -------------------------
        score = self._compute_score(
            z_score=z_score,
            bucket_count=bucket_count,
            target_count=len(target_set),
        )
        severity = self._score_to_severity(score)

        logger.warning(
            "ANOMALY  src=%s  z=%.2f  count=%d  mean=%.1f  std=%.1f  "
            "targets=%d  score=%.1f  severity=%s",
            source_mac,
            z_score,
            bucket_count,
            mean,
            std,
            len(target_set),
            score,
            severity,
        )

        return Alert(
            source_mac=source_mac,
            target_mac=representative_pkt.target_mac,
            bssid=representative_pkt.bssid,
            reason=representative_pkt.reason,
            signal=representative_pkt.signal,
            timestamp=representative_pkt.timestamp,
            severity=severity,
            score=score,
            channel=representative_pkt.channel,
            deauth_count=bucket_count,
            z_score=z_score,
        )

    # ------------------------------------------------------------------
    # Scoring
    # ------------------------------------------------------------------

    @staticmethod
    def _compute_score(
        z_score: float,
        bucket_count: int,
        target_count: int,
    ) -> float:
        """Composite threat score combining multiple signals.

        Formula (each component normalised to [0, 1], then weighted):
            score = 10 * (w_z * norm_z + w_burst * norm_burst + w_div * norm_div)

        Components:
            - **z-score magnitude** (weight 0.50): How far above the baseline.
            - **burst density** (weight 0.30): Absolute packet count in the bucket.
            - **target diversity** (weight 0.20): Number of distinct targets.
        """
        # Normalise z-score: cap at ~10 sigmas → 1.0
        norm_z = min(z_score / 10.0, 1.0)

        # Normalise burst density: cap at 200 packets/bucket → 1.0
        norm_burst = min(bucket_count / 200.0, 1.0)

        # Normalise target diversity: cap at 20 unique targets → 1.0
        norm_div = min(target_count / 20.0, 1.0)

        raw = 0.50 * norm_z + 0.30 * norm_burst + 0.20 * norm_div
        return round(min(raw * 10.0, 10.0), 2)

    def _score_to_severity(self, score: float) -> str:
        """Map a numerical score to a severity label."""
        for label, threshold in self.severity_thresholds:
            if score >= threshold:
                return label
        return "low"

    # ------------------------------------------------------------------
    # Maintenance
    # ------------------------------------------------------------------

    def _evict_stale(self, now: float) -> None:
        """Remove baselines for sources not seen within the eviction window."""
        stale_keys = [
            mac
            for mac, bl in self._baselines.items()
            if bl.last_seen > 0 and (now - bl.last_seen) > self.eviction_timeout
        ]
        for key in stale_keys:
            logger.debug("Evicting stale baseline for %s", key)
            del self._baselines[key]

    def get_stats(self) -> Dict[str, Any]:
        """Return detector diagnostics."""
        return {
            "tracked_sources": len(self._baselines),
            "total_packets_processed": self.total_packets_processed,
            "total_alerts_generated": self.total_alerts_generated,
        }

    def get_baseline_summary(self, source_mac: str) -> Optional[Dict[str, Any]]:
        """Return baseline statistics for a specific source (debugging)."""
        key = source_mac.lower()
        if key not in self._baselines:
            return None
        bl = self._baselines[key]
        return {
            "source_mac": key,
            "observations": bl.n,
            "mean": round(bl.mean, 2),
            "std": round(bl.std, 2),
            "current_bucket_count": bl.current_count,
            "last_seen": bl.last_seen,
        }
