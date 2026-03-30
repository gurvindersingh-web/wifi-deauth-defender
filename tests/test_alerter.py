"""
Tests for alerter.py — Alert correlation, incident building, and webhook delivery.

Uses mock HTTP responses to validate:
- Alert correlation by source MAC and time window
- Incident metadata enrichment
- Batch metadata computation
- Webhook JSON payload schema compliance
- Retry logic on delivery failures
"""

import json
import time
from typing import List
from unittest.mock import MagicMock, patch

from alerter import AlertProcessor
from models import Alert, Incident


def _make_alerts(
    count: int = 5,
    source_mac: str = "aa:bb:cc:dd:ee:ff",
    base_ts: float = 1711754700.0,
    interval: float = 5.0,
    severity: str = "high",
    score: float = 7.0,
) -> List[Alert]:
    """Generate synthetic alerts for testing."""
    return [
        Alert(
            source_mac=source_mac,
            target_mac=f"11:22:33:44:55:{i:02x}",
            bssid=source_mac,
            reason=7,
            signal=-45 - i,
            timestamp=base_ts + i * interval,
            severity=severity,
            score=score + i * 0.1,
            deauth_count=50 + i * 10,
        )
        for i in range(count)
    ]


class TestAlertCorrelation:
    """Tests for the correlation engine."""

    def _make_processor(self, **kwargs):
        defaults = dict(
            webhook_url="",  # no actual delivery in correlation tests
            correlation_window=60.0,
            batch_interval=3600,  # don't auto-flush
        )
        defaults.update(kwargs)
        return AlertProcessor(**defaults)

    def test_same_source_within_window_grouped(self):
        """Alerts from the same source within the correlation window
        should be grouped into one incident."""
        proc = self._make_processor(correlation_window=60.0)

        alerts = _make_alerts(count=5, interval=10.0)  # 0, 10, 20, 30, 40s apart
        incidents = proc._correlate_alerts(alerts)

        assert len(incidents) == 1
        assert incidents[0].alert_count == 5
        assert incidents[0].source_mac == "aa:bb:cc:dd:ee:ff"

    def test_same_source_split_across_windows(self):
        """Alerts from the same source with a gap > correlation_window
        should produce separate incidents."""
        proc = self._make_processor(correlation_window=30.0)

        # Group 1: t=0, 5, 10
        # Gap: 100s (>> 30s window)
        # Group 2: t=110, 115
        alerts = _make_alerts(count=3, base_ts=100.0, interval=5.0)
        alerts += _make_alerts(count=2, base_ts=300.0, interval=5.0)

        incidents = proc._correlate_alerts(alerts)
        assert len(incidents) == 2

    def test_different_sources_separate_incidents(self):
        """Alerts from different source MACs are always separate incidents."""
        proc = self._make_processor()

        alerts_a = _make_alerts(count=3, source_mac="aa:aa:aa:aa:aa:aa")
        alerts_b = _make_alerts(count=2, source_mac="bb:bb:bb:bb:bb:bb")

        incidents = proc._correlate_alerts(alerts_a + alerts_b)
        assert len(incidents) == 2

        sources = {inc.source_mac for inc in incidents}
        assert "aa:aa:aa:aa:aa:aa" in sources
        assert "bb:bb:bb:bb:bb:bb" in sources

    def test_incident_severity_is_max(self):
        """Incident severity should be the highest severity among its alerts."""
        proc = self._make_processor()

        alerts = [
            Alert(source_mac="aa:bb:cc:dd:ee:ff", target_mac="11:22:33:44:55:66",
                  bssid="aa:bb:cc:dd:ee:ff", reason=7, signal=-45,
                  timestamp=100.0, severity="medium", score=5.0),
            Alert(source_mac="aa:bb:cc:dd:ee:ff", target_mac="11:22:33:44:55:77",
                  bssid="aa:bb:cc:dd:ee:ff", reason=7, signal=-50,
                  timestamp=110.0, severity="critical", score=9.0),
            Alert(source_mac="aa:bb:cc:dd:ee:ff", target_mac="11:22:33:44:55:88",
                  bssid="aa:bb:cc:dd:ee:ff", reason=7, signal=-55,
                  timestamp=120.0, severity="high", score=7.0),
        ]
        incidents = proc._correlate_alerts(alerts)
        assert len(incidents) == 1
        assert incidents[0].severity == "critical"

    def test_incident_id_format(self):
        """Incident ID should be '{source_mac}_{epoch_int}'."""
        proc = self._make_processor()
        alerts = _make_alerts(count=1, base_ts=1711754700.0)
        incidents = proc._correlate_alerts(alerts)
        assert incidents[0].incident_id == "aa:bb:cc:dd:ee:ff_1711754700"

    def test_incident_duration(self):
        """Duration should be last_ts - first_ts."""
        proc = self._make_processor()
        alerts = _make_alerts(count=5, base_ts=100.0, interval=10.0)
        incidents = proc._correlate_alerts(alerts)
        assert incidents[0].duration == 40.0  # (100+40) - 100


class TestWebhookDelivery:
    """Tests for webhook payload formatting and delivery."""

    def test_payload_matches_spec(self):
        """The final JSON payload must match the specified structure."""
        proc = AlertProcessor(
            webhook_url="http://localhost:9999/webhook/test",
            correlation_window=60.0,
            batch_interval=3600,
        )

        alerts = _make_alerts(count=10, source_mac="aa:bb:cc:dd:ee:ff")
        alerts += _make_alerts(count=5, source_mac="dd:ee:ff:00:11:22")

        # Build incidents and metadata using the internal method.
        incidents = proc._correlate_alerts(alerts)
        from models import BatchMetadata, WebhookPayload
        meta = BatchMetadata.from_alerts(alerts, incidents)
        payload = WebhookPayload(batch_metadata=meta, incidents=incidents, raw_alerts=alerts)
        d = payload.to_dict()

        # Top-level structure.
        assert set(d.keys()) == {"batch_metadata", "incidents", "raw_alerts"}

        # Batch metadata fields.
        bm = d["batch_metadata"]
        assert bm["alert_count"] == 15
        assert bm["unique_sources"] == 2
        assert bm["incident_count"] == 2
        assert isinstance(bm["severity_distribution"], dict)

        # Each incident has the required fields.
        for inc in d["incidents"]:
            assert "incident_id" in inc
            assert "alert_count" in inc
            assert "duration" in inc
            assert "severity" in inc
            assert "alerts" in inc

        # Each raw alert has the required fields.
        for alert in d["raw_alerts"]:
            for key in ("source_mac", "target_mac", "bssid", "reason",
                        "signal", "timestamp", "severity", "score"):
                assert key in alert, f"Missing key '{key}' in alert"

    @patch("alerter.httpx.Client")
    def test_successful_delivery(self, MockClient):
        """Verify that a 200 response is treated as success."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "OK"

        mock_client_instance = MagicMock()
        mock_client_instance.post.return_value = mock_response
        MockClient.return_value = mock_client_instance

        proc = AlertProcessor(
            webhook_url="http://localhost:9999/webhook/test",
            batch_interval=3600,
        )
        proc._client = mock_client_instance

        alerts = _make_alerts(count=3)
        proc._alert_buffer = list(alerts)
        proc.total_alerts_received = len(alerts)
        proc._flush_batch(reason="test")

        mock_client_instance.post.assert_called_once()
        assert proc.total_webhooks_sent == 1
        assert proc.total_webhooks_failed == 0

    @patch("alerter.httpx.Client")
    def test_retry_on_failure(self, MockClient):
        """Verify retry logic on server errors."""
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.text = "Internal Server Error"

        mock_client_instance = MagicMock()
        mock_client_instance.post.return_value = mock_response
        MockClient.return_value = mock_client_instance

        proc = AlertProcessor(
            webhook_url="http://localhost:9999/webhook/test",
            retry_attempts=3,
            retry_delay=0.01,  # fast retries for test
            batch_interval=3600,
        )
        proc._client = mock_client_instance

        alerts = _make_alerts(count=2)
        proc._alert_buffer = list(alerts)
        proc.total_alerts_received = len(alerts)
        proc._flush_batch(reason="test")

        assert mock_client_instance.post.call_count == 3  # 3 attempts
        assert proc.total_webhooks_failed == 1

    def test_no_delivery_without_url(self):
        """If webhook_url is empty, delivery should be skipped gracefully."""
        proc = AlertProcessor(webhook_url="", batch_interval=3600)
        alerts = _make_alerts(count=2)
        proc._alert_buffer = list(alerts)
        proc._flush_batch(reason="test")
        assert proc.total_webhooks_sent == 0
        assert proc.total_webhooks_failed == 0


class TestBatchFlushTriggers:
    """Tests for count-based and time-based batch flushing."""

    def test_count_based_flush(self):
        """Buffer exceeding max_batch_size should trigger immediate flush."""
        delivered = []

        proc = AlertProcessor(
            webhook_url="",  # won't actually POST
            max_batch_size=5,
            batch_interval=3600,
        )
        # Monkey-patch _flush_batch to capture calls.
        original_flush = proc._flush_batch
        def tracking_flush(reason="timer"):
            delivered.append(reason)
            original_flush(reason)
        proc._flush_batch = tracking_flush

        alerts = _make_alerts(count=10)
        proc.ingest(alerts)  # 10 > max_batch_size=5 → should trigger

        assert "count" in delivered

    def test_ingestion_accumulates(self):
        """Alerts below the threshold should accumulate in the buffer."""
        proc = AlertProcessor(
            webhook_url="",
            max_batch_size=100,
            batch_interval=3600,
        )
        alerts = _make_alerts(count=3)
        proc.ingest(alerts)
        assert len(proc._alert_buffer) == 3
