"""
WiFi Deauth Defender — Main Orchestrator
==========================================
Wires up the three pipeline stages — capture → detection → alerting —
and manages the application lifecycle, configuration loading, signal
handling, and health reporting.

Usage::

    python main.py                     # uses default config.yaml
    python main.py -c /etc/deauth.yaml # custom config path

The orchestrator:
1. Loads and validates ``config.yaml``.
2. Instantiates :class:`PacketCapture`, :class:`AnomalyDetector`,
   and :class:`AlertProcessor`.
3. Connects them via the ``on_batch`` callback chain.
4. Installs ``SIGINT`` / ``SIGTERM`` handlers for graceful shutdown.
5. Logs health diagnostics every 60 seconds.
"""

from __future__ import annotations

import argparse
import logging
import logging.handlers
import os
import signal
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import yaml

from alerter import AlertProcessor
from capture import PacketCapture
from detector import AnomalyDetector
from models import DeauthPacket

# ---------------------------------------------------------------------------
# Version
# ---------------------------------------------------------------------------
__version__ = "1.0.0"

logger = logging.getLogger("deauth_defender")


# ---------------------------------------------------------------------------
# Configuration loader & validator
# ---------------------------------------------------------------------------

def load_config(path: str) -> Dict[str, Any]:
    """Load and validate the YAML configuration file.

    Args:
        path: Filesystem path to the YAML config.

    Returns:
        Parsed configuration dictionary.

    Raises:
        FileNotFoundError: If the config file does not exist.
        ValueError: If required keys are missing or values are invalid.
    """
    config_path = Path(path)
    if not config_path.is_file():
        raise FileNotFoundError(f"Configuration file not found: {path}")

    with open(config_path, "r", encoding="utf-8") as fh:
        config: Dict[str, Any] = yaml.safe_load(fh)

    if not isinstance(config, dict):
        raise ValueError("Config file must be a YAML mapping")

    # --- Validate top-level sections ------------------------------------
    for section in ("capture", "detection", "alerting"):
        if section not in config:
            raise ValueError(f"Missing required config section: '{section}'")

    # --- Validate capture -----------------------------------------------
    cap = config["capture"]
    iface = cap.get("interface", "")
    allowed = config.get("security", {}).get("allowed_interfaces", [])
    if allowed and iface not in allowed:
        raise ValueError(
            f"Interface '{iface}' is not in the allowed list: {allowed}"
        )

    # --- Validate webhook URL -------------------------------------------
    webhook_url = config["alerting"].get("webhook_url", "")
    if webhook_url:
        parsed = urlparse(webhook_url)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(
                f"Webhook URL must use http or https scheme, got: {parsed.scheme}"
            )

    return config


# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

def setup_logging(config: Dict[str, Any]) -> None:
    """Configure rotating file + console logging.

    Args:
        config: The ``logging`` section of the config file.
    """
    log_cfg = config.get("logging", {})
    level_name = log_cfg.get("level", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)

    fmt = logging.Formatter(
        "%(asctime)s  %(levelname)-8s  [%(name)s]  %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Console handler -------------------------------------------------------
    console = logging.StreamHandler(sys.stdout)
    console.setLevel(level)
    console.setFormatter(fmt)

    # Rotating file handler -------------------------------------------------
    log_file = log_cfg.get("file", "deauth_defender.log")
    max_bytes = int(log_cfg.get("max_bytes", 10_485_760))
    backup_count = int(log_cfg.get("backup_count", 3))

    file_handler = logging.handlers.RotatingFileHandler(
        log_file, maxBytes=max_bytes, backupCount=backup_count
    )
    file_handler.setLevel(level)
    file_handler.setFormatter(fmt)

    root = logging.getLogger()
    root.setLevel(level)
    root.addHandler(console)
    root.addHandler(file_handler)


# ---------------------------------------------------------------------------
# DeauthDefender — the main application class
# ---------------------------------------------------------------------------

class DeauthDefender:
    """Top-level orchestrator for the WiFi Deauth Defender pipeline.

    Attributes:
        config:   Parsed YAML configuration.
        capture:  Packet capture engine.
        detector: Anomaly detection engine.
        alerter:  Alert processor and webhook sender.
    """

    def __init__(self, config: Dict[str, Any]) -> None:
        self.config = config
        self._shutdown_event = threading.Event()
        self._health_timer: Optional[threading.Timer] = None

        # --- Detection engine ---------------------------------------------
        det_cfg = config["detection"]
        severity_thresholds = det_cfg.get("severity_thresholds", {})
        self.detector = AnomalyDetector(
            baseline_window=int(det_cfg.get("baseline_window", 3600)),
            sigma_threshold=float(det_cfg.get("sigma_threshold", 3.0)),
            min_baseline_samples=int(det_cfg.get("min_baseline_samples", 10)),
            bucket_size=int(det_cfg.get("bucket_size", 10)),
            eviction_timeout=int(det_cfg.get("eviction_timeout", 7200)),
            severity_thresholds=severity_thresholds if severity_thresholds else None,
        )

        # --- Alert processor -----------------------------------------------
        alert_cfg = config["alerting"]
        sec_cfg = config.get("security", {})
        self.alerter = AlertProcessor(
            webhook_url=alert_cfg.get("webhook_url", ""),
            batch_interval=float(alert_cfg.get("batch_interval", 30)),
            max_batch_size=int(alert_cfg.get("max_batch_size", 100)),
            retry_attempts=int(alert_cfg.get("retry_attempts", 3)),
            retry_delay=float(alert_cfg.get("retry_delay", 5)),
            correlation_window=float(alert_cfg.get("correlation_window", 60)),
            request_timeout=float(alert_cfg.get("request_timeout", 15)),
            hash_macs=bool(sec_cfg.get("hash_macs", False)),
        )

        # --- Packet capture ------------------------------------------------
        cap_cfg = config["capture"]
        self.capture = PacketCapture(
            interface=cap_cfg.get("interface", "wlan0mon"),
            bpf_filter=cap_cfg.get("bpf_filter", "subtype deauth"),
            batch_size=int(cap_cfg.get("batch_size", 50)),
            batch_timeout=float(cap_cfg.get("batch_timeout", 5.0)),
            channel=int(cap_cfg.get("channel", 0)),
            on_batch=self._on_batch,  # wire capture → detection → alerting
        )

    # ------------------------------------------------------------------
    # Pipeline callback
    # ------------------------------------------------------------------

    def _on_batch(self, packets: List[DeauthPacket]) -> None:
        """Callback invoked by the capture engine for each flushed batch.

        Routes packets through detection and alert processing.
        """
        try:
            # Step 1: Run anomaly detection on the batch.
            alerts = self.detector.process_batch(packets)

            # Step 2: Feed detected alerts into the alerter.
            if alerts:
                logger.info(
                    "Detected %d anomalous alert(s) from batch of %d packets",
                    len(alerts),
                    len(packets),
                )
                self.alerter.ingest(alerts)
            else:
                logger.debug(
                    "Batch of %d packets processed — no anomalies", len(packets)
                )

        except Exception:
            logger.error("Error processing batch", exc_info=True)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start all pipeline components and block until shutdown."""
        logger.info("=" * 60)
        logger.info(
            "WiFi Deauth Defender v%s starting …", __version__
        )
        logger.info("=" * 60)

        # Install signal handlers -------------------------------------------
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

        # Start components in dependency order.
        self.alerter.start()
        self.capture.start()

        # Start health reporter.
        self._schedule_health()

        logger.info("All components started.  Monitoring for deauth attacks …")

        # Block the main thread until a shutdown signal is received.
        self._shutdown_event.wait()

        # Shutdown sequence.
        self._shutdown()

    def _shutdown(self) -> None:
        """Gracefully stop all components."""
        logger.info("Initiating graceful shutdown …")

        if self._health_timer:
            self._health_timer.cancel()

        self.capture.stop()
        self.alerter.stop()

        logger.info("Shutdown complete.")

    def _signal_handler(self, signum: int, frame: Any) -> None:
        """Handle SIGINT / SIGTERM for graceful shutdown."""
        sig_name = signal.Signals(signum).name
        logger.info("Received %s — shutting down …", sig_name)
        self._shutdown_event.set()

    # ------------------------------------------------------------------
    # Health monitoring
    # ------------------------------------------------------------------

    def _schedule_health(self) -> None:
        """Schedule the next health report (every 60 s)."""
        if self._shutdown_event.is_set():
            return

        self._health_timer = threading.Timer(60.0, self._report_health)
        self._health_timer.daemon = True
        self._health_timer.start()

    def _report_health(self) -> None:
        """Log aggregated diagnostics from all pipeline components."""
        if self._shutdown_event.is_set():
            return

        cap_stats = self.capture.get_stats()
        det_stats = self.detector.get_stats()
        alt_stats = self.alerter.get_stats()

        # Estimate memory usage (rough, but useful for ops).
        try:
            import resource
            mem_mb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
        except Exception:
            mem_mb = 0

        logger.info(
            "HEALTH  |  capture: %s  |  detector: %s  |  alerter: %s  |  mem=%.1f MB",
            cap_stats,
            det_stats,
            alt_stats,
            mem_mb,
        )

        self._schedule_health()


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    """Parse CLI arguments and launch the defender."""
    parser = argparse.ArgumentParser(
        description="WiFi Deauth Defender — Real-time deauthentication attack detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-c", "--config",
        default="config.yaml",
        help="Path to the configuration file (default: config.yaml)",
    )
    parser.add_argument(
        "-v", "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    args = parser.parse_args()

    # Load configuration ------------------------------------------------------
    try:
        config = load_config(args.config)
    except (FileNotFoundError, ValueError) as exc:
        print(f"[ERROR] Configuration error: {exc}", file=sys.stderr)
        sys.exit(1)

    # Configure logging -------------------------------------------------------
    setup_logging(config)

    # Launch the defender -----------------------------------------------------
    defender = DeauthDefender(config)

    try:
        defender.start()
    except KeyboardInterrupt:
        pass  # already handled by signal handler


if __name__ == "__main__":
    main()
