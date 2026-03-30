"""
Tests for models.py — Data model serialization and validation.
"""

import time
from models import Alert, BatchMetadata, DeauthPacket, Incident, WebhookPayload


class TestDeauthPacket:
    """Tests for the DeauthPacket dataclass."""

    def _make_packet(self, **kwargs):
        defaults = dict(
            source_mac="AA:BB:CC:DD:EE:FF",
            target_mac="11:22:33:44:55:66",
            bssid="AA:BB:CC:DD:EE:FF",
            reason=7,
            signal=-45,
            timestamp=1711754700.1234,
            channel=6,
        )
        defaults.update(kwargs)
        return DeauthPacket(**defaults)

    def test_to_dict_basic(self):
        pkt = self._make_packet()
        d = pkt.to_dict()
        assert d["source_mac"] == "aa:bb:cc:dd:ee:ff"
        assert d["target_mac"] == "11:22:33:44:55:66"
        assert d["bssid"] == "aa:bb:cc:dd:ee:ff"
        assert d["reason"] == 7
        assert d["signal"] == -45
        assert d["timestamp"] == 1711754700.1234
        assert d["channel"] == 6

    def test_to_dict_hashed_macs(self):
        pkt = self._make_packet()
        d = pkt.to_dict(hash_macs=True)
        # Hashed MACs should be 16-char hex strings, not raw addresses.
        assert len(d["source_mac"]) == 16
        assert ":" not in d["source_mac"]
        assert d["source_mac"] == d["bssid"]  # same input → same hash

    def test_to_dict_preserves_all_fields(self):
        pkt = self._make_packet()
        d = pkt.to_dict()
        expected_keys = {"source_mac", "target_mac", "bssid", "reason",
                         "signal", "timestamp", "channel"}
        assert set(d.keys()) == expected_keys


class TestAlert:
    """Tests for the Alert dataclass."""

    def _make_alert(self, **kwargs):
        defaults = dict(
            source_mac="AA:BB:CC:DD:EE:FF",
            target_mac="11:22:33:44:55:66",
            bssid="AA:BB:CC:DD:EE:FF",
            reason=7,
            signal=-45,
            timestamp=1711754700.1234,
            severity="critical",
            score=9.2,
            channel=6,
            deauth_count=50,
            z_score=4.5,
        )
        defaults.update(kwargs)
        return Alert(**defaults)

    def test_to_dict_format(self):
        alert = self._make_alert()
        d = alert.to_dict()
        assert d["severity"] == "critical"
        assert d["score"] == 9.2
        assert d["z_score"] == 4.5
        assert d["deauth_count"] == 50
        assert "alert_id" in d

    def test_alert_id_uniqueness(self):
        a1 = self._make_alert()
        a2 = self._make_alert()
        assert a1.alert_id != a2.alert_id


class TestIncident:
    """Tests for the Incident dataclass."""

    def _make_alerts(self, count=3, base_ts=1711754700.0, interval=10.0):
        alerts = []
        for i in range(count):
            alerts.append(Alert(
                source_mac="AA:BB:CC:DD:EE:FF",
                target_mac=f"11:22:33:44:55:{i:02x}",
                bssid="AA:BB:CC:DD:EE:FF",
                reason=7,
                signal=-45,
                timestamp=base_ts + i * interval,
                severity="high" if i < count - 1 else "critical",
                score=7.0 + i * 0.5,
            ))
        return alerts

    def test_incident_properties(self):
        alerts = self._make_alerts(count=5, interval=10.0)
        inc = Incident(
            incident_id="test_inc_1",
            source_mac="AA:BB:CC:DD:EE:FF",
            alerts=alerts,
            severity="critical",
            created_at=alerts[0].timestamp,
        )
        assert inc.alert_count == 5
        assert inc.duration == 40.0  # 4 intervals × 10s
        assert len(inc.target_macs) == 5

    def test_incident_single_alert(self):
        alerts = self._make_alerts(count=1)
        inc = Incident(
            incident_id="single",
            source_mac="AA:BB:CC:DD:EE:FF",
            alerts=alerts,
            severity="high",
        )
        assert inc.duration == 0.0
        assert inc.alert_count == 1

    def test_to_dict_structure(self):
        alerts = self._make_alerts(count=3)
        inc = Incident(
            incident_id="aa:bb:cc:dd:ee:ff_1711754700",
            source_mac="AA:BB:CC:DD:EE:FF",
            alerts=alerts,
            severity="critical",
        )
        d = inc.to_dict()
        assert d["incident_id"] == "aa:bb:cc:dd:ee:ff_1711754700"
        assert d["alert_count"] == 3
        assert isinstance(d["alerts"], list)
        assert len(d["alerts"]) == 3


class TestBatchMetadata:
    """Tests for BatchMetadata computation."""

    def test_from_alerts(self):
        alerts = [
            Alert(source_mac="AA:BB:CC:DD:EE:FF", target_mac="11:22:33:44:55:66",
                  bssid="AA:BB:CC:DD:EE:FF", reason=7, signal=-45,
                  timestamp=time.time(), severity="critical", score=9.0,
                  deauth_count=100),
            Alert(source_mac="AA:BB:CC:DD:EE:FF", target_mac="77:88:99:AA:BB:CC",
                  bssid="AA:BB:CC:DD:EE:FF", reason=7, signal=-50,
                  timestamp=time.time(), severity="high", score=7.0,
                  deauth_count=50),
            Alert(source_mac="DD:EE:FF:00:11:22", target_mac="11:22:33:44:55:66",
                  bssid="DD:EE:FF:00:11:22", reason=3, signal=-60,
                  timestamp=time.time(), severity="medium", score=5.0,
                  deauth_count=30),
        ]
        incidents = [
            Incident(incident_id="inc1", source_mac="AA:BB:CC:DD:EE:FF",
                     alerts=alerts[:2], severity="critical"),
        ]
        meta = BatchMetadata.from_alerts(alerts, incidents)
        d = meta.to_dict()

        assert d["alert_count"] == 3
        assert d["severity_distribution"]["critical"] == 1
        assert d["severity_distribution"]["high"] == 1
        assert d["severity_distribution"]["medium"] == 1
        assert d["unique_sources"] == 2
        assert d["unique_targets"] == 2  # two distinct targets
        assert d["total_deauth_frames"] == 180  # 100 + 50 + 30
        assert d["incident_count"] == 1


class TestWebhookPayload:
    """Tests for the complete payload structure."""

    def test_payload_schema(self):
        alerts = [
            Alert(source_mac="AA:BB:CC:DD:EE:FF", target_mac="11:22:33:44:55:66",
                  bssid="AA:BB:CC:DD:EE:FF", reason=7, signal=-45,
                  timestamp=1711754700.1234, severity="critical", score=9.2,
                  deauth_count=100),
        ]
        incidents = [
            Incident(
                incident_id="aa:bb:cc:dd:ee:ff_1711754700",
                source_mac="AA:BB:CC:DD:EE:FF",
                alerts=alerts,
                severity="critical",
                created_at=1711754700.0,
            ),
        ]
        meta = BatchMetadata.from_alerts(alerts, incidents)
        payload = WebhookPayload(
            batch_metadata=meta,
            incidents=incidents,
            raw_alerts=alerts,
        )
        d = payload.to_dict()

        # Top-level keys must match the spec.
        assert "batch_metadata" in d
        assert "incidents" in d
        assert "raw_alerts" in d

        # Batch metadata fields.
        bm = d["batch_metadata"]
        assert "timestamp" in bm
        assert "alert_count" in bm
        assert "severity_distribution" in bm
        assert "unique_sources" in bm
        assert "unique_targets" in bm
        assert "total_deauth_frames" in bm
        assert "incident_count" in bm

        # Incident fields.
        inc = d["incidents"][0]
        assert "incident_id" in inc
        assert "alert_count" in inc
        assert "duration" in inc
        assert "severity" in inc
        assert "alerts" in inc

        # Alert fields.
        alert = d["raw_alerts"][0]
        for key in ("source_mac", "target_mac", "bssid", "reason",
                     "signal", "timestamp", "severity", "score"):
            assert key in alert, f"Missing key: {key}"
