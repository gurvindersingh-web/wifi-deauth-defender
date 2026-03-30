"""
WiFi Deauth Defender — Alert Processing & Webhook Delivery
============================================================
Collects alerts produced by the anomaly detector, correlates them
into incidents (groups by source MAC within a time window), enriches
each incident with metadata, assembles a batch payload, and delivers
it to the configured n8n webhook endpoint via HTTP POST.

Delivery Strategy
-----------------
* **Batch timer**: alerts are accumulated and flushed every
  ``batch_interval`` seconds (default 30 s) OR when the batch reaches
  ``max_batch_size`` alerts.
* **Retry with back-off**: failed webhook POSTs are retried up to
  ``retry_attempts`` times with exponential delay.
* **Thread-safe**: a background daemon thread handles the periodic
  flush; alert ingestion from the detector thread is lock-protected.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from collections import defaultdict
from typing import Any, Dict, List, Optional

import httpx

from models import Alert, BatchMetadata, Incident, WebhookPayload

logger = logging.getLogger("deauth_defender.alerter")


class AlertProcessor:
    """Correlates alerts into incidents and delivers them via webhook.

    Args:
        webhook_url:        Target URL for the HTTP POST.
        batch_interval:     Seconds between automatic batch flushes.
        max_batch_size:     Maximum alerts before a forced flush.
        retry_attempts:     Number of retry attempts on delivery failure.
        retry_delay:        Base delay (seconds) between retries (exponential).
        correlation_window: Seconds within which alerts from the same source
                            are grouped into a single incident.
        request_timeout:    HTTP request timeout in seconds.
        hash_macs:          If True, SHA-256 hash MAC addresses in payloads.
    """

    def __init__(
        self,
        webhook_url: str = "",
        batch_interval: float = 30.0,
        max_batch_size: int = 100,
        retry_attempts: int = 3,
        retry_delay: float = 5.0,
        correlation_window: float = 60.0,
        request_timeout: float = 15.0,
        hash_macs: bool = False,
    ) -> None:
        self.webhook_url = webhook_url
        self.batch_interval = batch_interval
        self.max_batch_size = max_batch_size
        self.retry_attempts = retry_attempts
        self.retry_delay = retry_delay
        self.correlation_window = correlation_window
        self.request_timeout = request_timeout
        self.hash_macs = hash_macs

        # Internal state -------------------------------------------------------
        self._alert_buffer: List[Alert] = []
        self._lock = threading.RLock()  # Reentrant to allow nested acquire
        self._flush_timer: Optional[threading.Timer] = None
        self._running = False

        # HTTP client (reusable connection pool) --------------------------------
        self._client = httpx.Client(
            timeout=httpx.Timeout(request_timeout),
            follow_redirects=True,
        )

        # Diagnostics -----------------------------------------------------------
        self.total_alerts_received: int = 0
        self.total_incidents_created: int = 0
        self.total_webhooks_sent: int = 0
        self.total_webhooks_failed: int = 0
        self.last_webhook_status: Optional[int] = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the periodic batch-flush timer."""
        if self._running:
            return

        self._running = True
        logger.info(
            "AlertProcessor started  |  webhook=%s  |  interval=%.0fs  "
            "|  correlation_window=%.0fs",
            self.webhook_url[:60] + "…" if len(self.webhook_url) > 60 else self.webhook_url,
            self.batch_interval,
            self.correlation_window,
        )
        self._schedule_flush()

    def stop(self) -> None:
        """Stop the timer, flush remaining alerts, and close the HTTP client."""
        if not self._running:
            return

        self._running = False

        if self._flush_timer is not None:
            self._flush_timer.cancel()
            self._flush_timer = None

        # Final flush -----------------------------------------------------------
        self._flush_batch(reason="shutdown")

        self._client.close()
        logger.info(
            "AlertProcessor stopped.  alerts=%d  incidents=%d  "
            "webhooks_sent=%d  webhooks_failed=%d",
            self.total_alerts_received,
            self.total_incidents_created,
            self.total_webhooks_sent,
            self.total_webhooks_failed,
        )

    # ------------------------------------------------------------------
    # Alert ingestion
    # ------------------------------------------------------------------

    def ingest(self, alerts: List[Alert]) -> None:
        """Add alerts to the buffer.  If the buffer exceeds
        ``max_batch_size``, a flush is triggered immediately.

        Args:
            alerts: List of :class:`Alert` objects from the detector.
        """
        if not alerts:
            return

        should_flush = False
        with self._lock:
            self._alert_buffer.extend(alerts)
            self.total_alerts_received += len(alerts)

            logger.debug(
                "Ingested %d alerts (buffer=%d)",
                len(alerts),
                len(self._alert_buffer),
            )

            should_flush = len(self._alert_buffer) >= self.max_batch_size

        # Flush OUTSIDE the lock to avoid deadlock with _flush_batch's
        # own lock acquisition and to keep webhook I/O off the lock path.
        if should_flush:
            self._flush_batch(reason="count")

    # ------------------------------------------------------------------
    # Correlation engine
    # ------------------------------------------------------------------

    def _correlate_alerts(self, alerts: List[Alert]) -> List[Incident]:
        """Group alerts into incidents by source MAC and time proximity.

        Alerts from the same source MAC whose timestamps fall within the
        ``correlation_window`` are merged into one :class:`Incident`.
        If a gap between consecutive alerts exceeds the window, a new
        incident is started for that source.

        Returns:
            List of :class:`Incident` objects, sorted by severity (desc).
        """
        # Group by source MAC --------------------------------------------------
        by_source: Dict[str, List[Alert]] = defaultdict(list)
        for alert in alerts:
            by_source[alert.source_mac.lower()].append(alert)

        incidents: List[Incident] = []

        for source_mac, source_alerts in by_source.items():
            # Sort by timestamp within each source group.
            source_alerts.sort(key=lambda a: a.timestamp)

            # Split into temporal clusters (incidents).
            cluster: List[Alert] = [source_alerts[0]]
            for alert in source_alerts[1:]:
                if alert.timestamp - cluster[-1].timestamp <= self.correlation_window:
                    cluster.append(alert)
                else:
                    incidents.append(self._build_incident(source_mac, cluster))
                    cluster = [alert]

            # Don't forget the last cluster.
            incidents.append(self._build_incident(source_mac, cluster))

        # Sort incidents: critical first, then by alert count descending.
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        incidents.sort(
            key=lambda inc: (severity_order.get(inc.severity, 9), -inc.alert_count)
        )

        self.total_incidents_created += len(incidents)
        return incidents

    @staticmethod
    def _build_incident(source_mac: str, alerts: List[Alert]) -> Incident:
        """Create an :class:`Incident` from a cluster of related alerts.

        The incident ID is deterministic: ``{source_mac}_{epoch_int}``
        using the timestamp of the first alert.
        """
        first_ts = alerts[0].timestamp
        incident_id = f"{source_mac}_{int(first_ts)}"

        # Severity = highest severity among child alerts.
        severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        max_severity = max(alerts, key=lambda a: severity_rank.get(a.severity, 0))

        return Incident(
            incident_id=incident_id,
            source_mac=source_mac,
            alerts=list(alerts),
            severity=max_severity.severity,
            created_at=first_ts,
        )

    # ------------------------------------------------------------------
    # Batch assembly & delivery
    # ------------------------------------------------------------------

    def _flush_batch(self, reason: str = "timer") -> None:
        """Drain the alert buffer, correlate, and deliver via webhook.

        Args:
            reason: Why the flush was triggered (``timer`` | ``count`` | ``shutdown``).
        """
        with self._lock:
            if not self._alert_buffer:
                return
            alerts = list(self._alert_buffer)
            self._alert_buffer.clear()

        logger.info("Flushing %d alerts (reason=%s)", len(alerts), reason)

        # Correlate alerts into incidents.
        incidents = self._correlate_alerts(alerts)

        # Build the batch metadata envelope.
        metadata = BatchMetadata.from_alerts(alerts, incidents)

        # Assemble the complete payload.
        payload = WebhookPayload(
            batch_metadata=metadata,
            incidents=incidents,
            raw_alerts=alerts,
        )

        # Deliver to the webhook endpoint.
        self._deliver(payload)

    def _deliver(self, payload: WebhookPayload) -> bool:
        """Send the payload to the webhook URL with retry logic.

        Args:
            payload: The complete :class:`WebhookPayload` to deliver.

        Returns:
            ``True`` if delivery succeeded, ``False`` otherwise.
        """
        if not self.webhook_url:
            logger.warning("No webhook URL configured — skipping delivery")
            return False

        json_body = payload.to_dict(hash_macs=self.hash_macs)
        json_str = json.dumps(json_body, default=str)

        logger.debug(
            "Webhook payload: %d alerts, %d incidents, %d bytes",
            payload.batch_metadata.alert_count,
            payload.batch_metadata.incident_count,
            len(json_str),
        )

        for attempt in range(1, self.retry_attempts + 1):
            try:
                response = self._client.post(
                    self.webhook_url,
                    json=json_body,
                )
                self.last_webhook_status = response.status_code

                if 200 <= response.status_code < 300:
                    self.total_webhooks_sent += 1
                    logger.info(
                        "Webhook delivered  status=%d  attempt=%d/%d",
                        response.status_code,
                        attempt,
                        self.retry_attempts,
                    )
                    return True

                logger.warning(
                    "Webhook returned %d on attempt %d/%d: %s",
                    response.status_code,
                    attempt,
                    self.retry_attempts,
                    response.text[:200],
                )

            except httpx.TimeoutException:
                logger.warning(
                    "Webhook timed out on attempt %d/%d",
                    attempt,
                    self.retry_attempts,
                )
            except httpx.HTTPError as exc:
                logger.warning(
                    "Webhook HTTP error on attempt %d/%d: %s",
                    attempt,
                    self.retry_attempts,
                    exc,
                )
            except Exception:
                logger.error(
                    "Unexpected error delivering webhook (attempt %d/%d)",
                    attempt,
                    self.retry_attempts,
                    exc_info=True,
                )

            # Exponential back-off before the next retry.
            if attempt < self.retry_attempts:
                delay = self.retry_delay * (2 ** (attempt - 1))
                logger.info("Retrying in %.1f seconds …", delay)
                time.sleep(delay)

        self.total_webhooks_failed += 1
        logger.error(
            "Webhook delivery FAILED after %d attempts", self.retry_attempts
        )
        return False

    # ------------------------------------------------------------------
    # Timer management
    # ------------------------------------------------------------------

    def _schedule_flush(self) -> None:
        """Schedule the next periodic batch flush."""
        if not self._running:
            return

        self._flush_timer = threading.Timer(
            self.batch_interval,
            self._timer_flush,
        )
        self._flush_timer.daemon = True
        self._flush_timer.start()

    def _timer_flush(self) -> None:
        """Handler for the periodic timer event."""
        if not self._running:
            return
        self._flush_batch(reason="timer")
        self._schedule_flush()

    # ------------------------------------------------------------------
    # Diagnostics
    # ------------------------------------------------------------------

    def get_stats(self) -> Dict[str, Any]:
        """Return alerter diagnostics."""
        return {
            "total_alerts_received": self.total_alerts_received,
            "total_incidents_created": self.total_incidents_created,
            "total_webhooks_sent": self.total_webhooks_sent,
            "total_webhooks_failed": self.total_webhooks_failed,
            "last_webhook_status": self.last_webhook_status,
            "buffer_size": len(self._alert_buffer),
        }
