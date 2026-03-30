"""
WiFi Deauth Defender — Packet Capture Engine
==============================================
Captures 802.11 deauthentication frames using Scapy's AsyncSniffer
with a kernel-level BPF filter for efficiency.  Packets are buffered
in memory and flushed as batches (count-based or time-based, whichever
triggers first).

Key design choices
------------------
* **BPF filter ``subtype deauth``** runs in kernel space, ensuring only
  deauth management frames are copied to user space — critical for
  handling high-frame-rate environments without saturating memory.
* **Thread-safe deque** with a ``threading.Lock`` protects the batch
  buffer from concurrent access by the sniffer callback thread and
  the batch-consumer thread.
* **Graceful lifecycle** — ``start()`` / ``stop()`` manage the sniffer
  and a periodic flush timer cleanly.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from typing import Any, Callable, Deque, Dict, List, Optional

from models import DeauthPacket

logger = logging.getLogger("deauth_defender.capture")


class PacketCapture:
    """Non-blocking 802.11 deauth frame capturer with in-memory batching.

    Args:
        interface:     Monitor-mode wireless interface (e.g. ``wlan0mon``).
        bpf_filter:    BPF expression for kernel-level filtering.
        batch_size:    Maximum packets per batch before flush.
        batch_timeout: Maximum seconds before a partial batch is flushed.
        channel:       WiFi channel to lock onto (0 = no change).
        on_batch:      Callback invoked with ``List[DeauthPacket]`` on flush.
    """

    def __init__(
        self,
        interface: str = "wlan0mon",
        bpf_filter: str = "subtype deauth",
        batch_size: int = 50,
        batch_timeout: float = 5.0,
        channel: int = 0,
        on_batch: Optional[Callable[[List[DeauthPacket]], None]] = None,
    ) -> None:
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.batch_size = batch_size
        self.batch_timeout = batch_timeout
        self.channel = channel
        self.on_batch = on_batch

        # Internal state ---------------------------------------------------
        self._buffer: Deque[DeauthPacket] = deque(maxlen=batch_size * 2)
        self._lock = threading.RLock()  # Reentrant: _flush_batch may be called under lock
        self._sniffer: Any = None        # scapy.AsyncSniffer (lazy import)
        self._flush_timer: Optional[threading.Timer] = None
        self._running = False
        self._last_flush_time = time.monotonic()

        # Diagnostics -------------------------------------------------------
        self.packets_captured: int = 0
        self.packets_dropped: int = 0
        self.batches_flushed: int = 0

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the asynchronous sniffer and periodic flush timer."""
        if self._running:
            logger.warning("Capture already running on %s", self.interface)
            return

        # Lazy-import scapy so unit tests can run without root / libpcap.
        try:
            from scapy.all import AsyncSniffer  # type: ignore[import-untyped]
        except ImportError as exc:
            raise RuntimeError(
                "Scapy is required for packet capture. "
                "Install it with: pip install scapy"
            ) from exc

        self._running = True
        self._last_flush_time = time.monotonic()

        logger.info(
            "Starting capture on %s  |  BPF: '%s'  |  batch=%d / %.1fs",
            self.interface,
            self.bpf_filter,
            self.batch_size,
            self.batch_timeout,
        )

        # Start the kernel-filtered sniffer --------------------------------
        self._sniffer = AsyncSniffer(
            iface=self.interface,
            filter=self.bpf_filter,
            prn=self._packet_handler,
            store=False,          # do not keep packets in scapy memory
        )
        self._sniffer.start()

        # Periodic flush for time-based batching ---------------------------
        self._schedule_flush()

    def stop(self) -> None:
        """Gracefully stop the sniffer and flush remaining packets."""
        if not self._running:
            return

        self._running = False
        logger.info("Stopping capture on %s …", self.interface)

        # Cancel the periodic flush timer ----------------------------------
        if self._flush_timer is not None:
            self._flush_timer.cancel()
            self._flush_timer = None

        # Stop the sniffer -------------------------------------------------
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception:
                pass  # sniffer may already be stopped
            self._sniffer = None

        # Flush any remaining packets --------------------------------------
        self._flush_batch(reason="shutdown")

        logger.info(
            "Capture stopped.  packets_captured=%d  dropped=%d  batches=%d",
            self.packets_captured,
            self.packets_dropped,
            self.batches_flushed,
        )

    # ------------------------------------------------------------------
    # Packet handler (called by sniffer thread)
    # ------------------------------------------------------------------

    def _packet_handler(self, pkt: Any) -> None:
        """Process a single raw Scapy packet.

        Extracts deauth-specific fields and appends to the batch buffer.
        The ``pkt`` is a Scapy ``Packet`` object with possible layers:
        RadioTap / Dot11 / Dot11Deauth.
        """
        try:
            parsed = self._extract_fields(pkt)
            if parsed is None:
                return

            with self._lock:
                self._buffer.append(parsed)
                self.packets_captured += 1

                # Count-based flush trigger --------------------------------
                if len(self._buffer) >= self.batch_size:
                    self._flush_batch(reason="count")

        except Exception:
            self.packets_dropped += 1
            logger.debug("Dropped malformed packet", exc_info=True)

    def _extract_fields(self, pkt: Any) -> Optional[DeauthPacket]:
        """Extract deauth-relevant fields from a Scapy packet.

        Returns ``None`` if the packet is not a valid deauth frame.
        """
        # Guard: must contain Dot11 and Dot11Deauth layers -----------------
        from scapy.layers.dot11 import Dot11, Dot11Deauth, RadioTap  # type: ignore

        if not pkt.haslayer(Dot11Deauth):
            return None

        dot11: Any = pkt.getlayer(Dot11)
        deauth: Any = pkt.getlayer(Dot11Deauth)

        # MAC addresses from the Dot11 header ------------------------------
        #   addr1 = Receiver Address (RA)  → target
        #   addr2 = Transmitter Address (TA) → source / attacker
        #   addr3 = BSSID
        source_mac: str = dot11.addr2 or "00:00:00:00:00:00"
        target_mac: str = dot11.addr1 or "ff:ff:ff:ff:ff:ff"
        bssid: str = dot11.addr3 or source_mac

        # Reason code from Dot11Deauth layer --------------------------------
        reason: int = int(deauth.reason) if hasattr(deauth, "reason") else 0

        # Signal strength from RadioTap (dBm) — may be absent ---------------
        signal: int = -100  # default if RadioTap not present
        if pkt.haslayer(RadioTap):
            radiotap = pkt.getlayer(RadioTap)
            # Scapy exposes signal as 'dBm_AntSignal' in RadioTap
            signal = int(getattr(radiotap, "dBm_AntSignal", -100))

        # Channel — try to extract from RadioTap ----------------------------
        channel: int = 0
        if pkt.haslayer(RadioTap):
            radiotap = pkt.getlayer(RadioTap)
            channel = int(getattr(radiotap, "ChannelFrequency", 0))
            # Convert frequency → channel number if needed
            if channel > 2000:
                channel = self._freq_to_channel(channel)

        return DeauthPacket(
            source_mac=source_mac,
            target_mac=target_mac,
            bssid=bssid,
            reason=reason,
            signal=signal,
            timestamp=time.time(),
            channel=channel or self.channel,
        )

    # ------------------------------------------------------------------
    # Batching logic
    # ------------------------------------------------------------------

    def _flush_batch(self, reason: str = "timer") -> None:
        """Drain the buffer into a batch and invoke the callback.

        Args:
            reason: Why the flush was triggered (``count`` | ``timer`` | ``shutdown``).
        """
        with self._lock:
            if not self._buffer:
                return

            batch: List[DeauthPacket] = list(self._buffer)
            self._buffer.clear()
            self._last_flush_time = time.monotonic()

        self.batches_flushed += 1

        logger.debug(
            "Flushed batch #%d  (%d packets, reason=%s)",
            self.batches_flushed,
            len(batch),
            reason,
        )

        # Deliver to the downstream consumer --------------------------------
        if self.on_batch is not None:
            try:
                self.on_batch(batch)
            except Exception:
                logger.error("Batch callback failed", exc_info=True)

    def _schedule_flush(self) -> None:
        """Schedule the next time-based batch flush."""
        if not self._running:
            return

        self._flush_timer = threading.Timer(
            self.batch_timeout,
            self._timer_flush,
        )
        self._flush_timer.daemon = True
        self._flush_timer.start()

    def _timer_flush(self) -> None:
        """Handler for the periodic flush timer."""
        if not self._running:
            return
        self._flush_batch(reason="timer")
        self._schedule_flush()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _freq_to_channel(freq: int) -> int:
        """Convert a 2.4 GHz / 5 GHz frequency to a WiFi channel number."""
        if 2412 <= freq <= 2484:
            if freq == 2484:
                return 14
            return (freq - 2407) // 5
        elif 5170 <= freq <= 5825:
            return (freq - 5000) // 5
        return 0

    def get_stats(self) -> Dict[str, int]:
        """Return capture diagnostics."""
        return {
            "packets_captured": self.packets_captured,
            "packets_dropped": self.packets_dropped,
            "batches_flushed": self.batches_flushed,
            "buffer_size": len(self._buffer),
        }
