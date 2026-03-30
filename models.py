"""
WiFi Deauth Defender — Data Models
===================================
Defines all data structures used across the pipeline:
  - DeauthPacket: raw captured frame metadata
  - Alert: scored anomaly event produced by the detector
  - Incident: correlated group of related alerts
  - BatchMetadata: aggregate statistics for a webhook batch
  - WebhookPayload: final JSON envelope sent to n8n

All models use dataclasses with explicit type hints and provide
`to_dict()` helpers for deterministic JSON serialization.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Packet-level model
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class DeauthPacket:
    """Represents a single captured 802.11 deauthentication frame.

    Attributes:
        source_mac:  Transmitter MAC address (TA).
        target_mac:  Receiver / destination MAC address (RA).
        bssid:       Basic Service Set Identifier (access-point MAC).
        reason:      IEEE 802.11 reason code (uint16).
        signal:      Received signal strength in dBm (from RadioTap header).
        timestamp:   Unix epoch time when the frame was captured.
        channel:     WiFi channel number the frame was observed on.
    """

    source_mac: str
    target_mac: str
    bssid: str
    reason: int
    signal: int
    timestamp: float
    channel: int = 0

    def to_dict(self, hash_macs: bool = False) -> Dict[str, Any]:
        """Serialize to a plain dictionary.

        Args:
            hash_macs: If True, SHA-256 hash all MAC address fields for privacy.
        """
        def _mac(addr: str) -> str:
            if hash_macs:
                return hashlib.sha256(addr.lower().encode()).hexdigest()[:16]
            return addr.lower()

        return {
            "source_mac": _mac(self.source_mac),
            "target_mac": _mac(self.target_mac),
            "bssid": _mac(self.bssid),
            "reason": self.reason,
            "signal": self.signal,
            "timestamp": self.timestamp,
            "channel": self.channel,
        }


# ---------------------------------------------------------------------------
# Alert-level model
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class Alert:
    """An anomaly alert produced by the detection engine.

    Extends packet metadata with a severity classification and a
    numerical threat score (0-10 scale).

    Attributes:
        source_mac:  Transmitter MAC.
        target_mac:  Target MAC.
        bssid:       BSSID.
        reason:      802.11 reason code.
        signal:      Signal strength in dBm.
        timestamp:   Epoch time of the triggering packet.
        severity:    Categorical severity: critical / high / medium / low.
        score:       Numerical threat score in [0, 10].
        alert_id:    Unique identifier for this alert.
        channel:     WiFi channel.
        deauth_count: Number of deauth frames in the detection window.
        z_score:     Statistical z-score that triggered the alert.
    """

    source_mac: str
    target_mac: str
    bssid: str
    reason: int
    signal: int
    timestamp: float
    severity: str
    score: float
    alert_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    channel: int = 0
    deauth_count: int = 0
    z_score: float = 0.0

    def to_dict(self, hash_macs: bool = False) -> Dict[str, Any]:
        """Serialize to the webhook-compatible alert object format."""
        def _mac(addr: str) -> str:
            if hash_macs:
                return hashlib.sha256(addr.lower().encode()).hexdigest()[:16]
            return addr.lower()

        return {
            "alert_id": self.alert_id,
            "source_mac": _mac(self.source_mac),
            "target_mac": _mac(self.target_mac),
            "bssid": _mac(self.bssid),
            "reason": self.reason,
            "signal": self.signal,
            "timestamp": self.timestamp,
            "severity": self.severity,
            "score": round(self.score, 2),
            "channel": self.channel,
            "deauth_count": self.deauth_count,
            "z_score": round(self.z_score, 2),
        }


# ---------------------------------------------------------------------------
# Incident model (correlated group of alerts)
# ---------------------------------------------------------------------------

@dataclass
class Incident:
    """A correlated incident grouping related alerts from the same source.

    Attributes:
        incident_id:  Deterministic ID: ``{source_mac}_{epoch_int}``.
        source_mac:   Common attacker MAC for all child alerts.
        alerts:       Ordered list of child :class:`Alert` objects.
        severity:     Highest severity among child alerts.
        created_at:   Epoch time when the incident was first opened.
    """

    incident_id: str
    source_mac: str
    alerts: List[Alert] = field(default_factory=list)
    severity: str = "low"
    created_at: float = 0.0

    # -- derived properties ---------------------------------------------------

    @property
    def alert_count(self) -> int:
        return len(self.alerts)

    @property
    def duration(self) -> float:
        """Duration in seconds from first to last alert."""
        if len(self.alerts) < 2:
            return 0.0
        timestamps = [a.timestamp for a in self.alerts]
        return round(max(timestamps) - min(timestamps), 2)

    @property
    def target_macs(self) -> List[str]:
        """Unique target MACs across all alerts in this incident."""
        return list({a.target_mac.lower() for a in self.alerts})

    def to_dict(self, hash_macs: bool = False) -> Dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "source_mac": (
                hashlib.sha256(self.source_mac.lower().encode()).hexdigest()[:16]
                if hash_macs
                else self.source_mac.lower()
            ),
            "alert_count": self.alert_count,
            "duration": self.duration,
            "severity": self.severity,
            "target_macs": self.target_macs,
            "alerts": [a.to_dict(hash_macs=hash_macs) for a in self.alerts],
        }


# ---------------------------------------------------------------------------
# Batch metadata model
# ---------------------------------------------------------------------------

@dataclass
class BatchMetadata:
    """Aggregate statistics for a webhook batch.

    Computed from the full set of raw alerts in the batch.
    """

    timestamp: str = ""
    alert_count: int = 0
    severity_distribution: Dict[str, int] = field(default_factory=dict)
    unique_sources: int = 0
    unique_targets: int = 0
    total_deauth_frames: int = 0
    incident_count: int = 0

    @classmethod
    def from_alerts(
        cls,
        alerts: List[Alert],
        incidents: List[Incident],
    ) -> "BatchMetadata":
        """Factory: compute metadata from a list of alerts and incidents."""
        severity_dist: Dict[str, int] = {}
        sources: set[str] = set()
        targets: set[str] = set()
        total_frames = 0

        for alert in alerts:
            severity_dist[alert.severity] = severity_dist.get(alert.severity, 0) + 1
            sources.add(alert.source_mac.lower())
            targets.add(alert.target_mac.lower())
            total_frames += max(alert.deauth_count, 1)

        return cls(
            timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            alert_count=len(alerts),
            severity_distribution=severity_dist,
            unique_sources=len(sources),
            unique_targets=len(targets),
            total_deauth_frames=total_frames,
            incident_count=len(incidents),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "alert_count": self.alert_count,
            "severity_distribution": self.severity_distribution,
            "unique_sources": self.unique_sources,
            "unique_targets": self.unique_targets,
            "total_deauth_frames": self.total_deauth_frames,
            "incident_count": self.incident_count,
        }


# ---------------------------------------------------------------------------
# Webhook payload envelope
# ---------------------------------------------------------------------------

@dataclass
class WebhookPayload:
    """Top-level JSON envelope sent to the n8n webhook.

    Structure:
        {
            "batch_metadata": { ... },
            "incidents": [ ... ],
            "raw_alerts": [ ... ]
        }
    """

    batch_metadata: BatchMetadata
    incidents: List[Incident]
    raw_alerts: List[Alert]

    def to_dict(self, hash_macs: bool = False) -> Dict[str, Any]:
        return {
            "batch_metadata": self.batch_metadata.to_dict(),
            "incidents": [i.to_dict(hash_macs=hash_macs) for i in self.incidents],
            "raw_alerts": [a.to_dict(hash_macs=hash_macs) for a in self.raw_alerts],
        }
