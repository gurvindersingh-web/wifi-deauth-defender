"""
Tests for capture.py — Packet batching logic.

Since actual packet capture requires root and a monitor-mode interface,
these tests focus on the batching mechanics (count-based and time-based
flush) and field extraction using mock Scapy packets.
"""

import threading
import time
from typing import List
from unittest.mock import MagicMock, patch

from capture import PacketCapture
from models import DeauthPacket


class MockRadioTap:
    """Simulated RadioTap layer."""
    def __init__(self, signal=-45, freq=2437):
        self.dBm_AntSignal = signal
        self.ChannelFrequency = freq


class MockDot11:
    """Simulated Dot11 layer."""
    def __init__(self, addr1="11:22:33:44:55:66", addr2="aa:bb:cc:dd:ee:ff", addr3="aa:bb:cc:dd:ee:ff"):
        self.addr1 = addr1
        self.addr2 = addr2
        self.addr3 = addr3


class MockDot11Deauth:
    """Simulated Dot11Deauth layer."""
    def __init__(self, reason=7):
        self.reason = reason


class MockPacket:
    """Simulated Scapy packet with configurable layers."""
    def __init__(self, radiotap=None, dot11=None, deauth=None):
        self._layers = {}
        if radiotap:
            self._layers["RadioTap"] = radiotap
        if dot11:
            self._layers["Dot11"] = dot11
        if deauth:
            self._layers["Dot11Deauth"] = deauth

    def haslayer(self, layer_cls):
        name = layer_cls.__name__ if hasattr(layer_cls, '__name__') else str(layer_cls)
        return name in self._layers

    def getlayer(self, layer_cls):
        name = layer_cls.__name__ if hasattr(layer_cls, '__name__') else str(layer_cls)
        return self._layers.get(name)


class TestBatchingLogic:
    """Tests for the capture batching mechanism."""

    def test_count_based_flush(self):
        """Buffer should flush when batch_size is reached."""
        received_batches: List[List[DeauthPacket]] = []

        cap = PacketCapture(
            batch_size=5,
            batch_timeout=60.0,  # won't trigger in this test
            on_batch=lambda batch: received_batches.append(batch),
        )

        # Simulate adding packets directly to the buffer.
        for i in range(5):
            pkt = DeauthPacket(
                source_mac="aa:bb:cc:dd:ee:ff",
                target_mac="11:22:33:44:55:66",
                bssid="aa:bb:cc:dd:ee:ff",
                reason=7, signal=-45,
                timestamp=time.time(),
                channel=6,
            )
            with cap._lock:
                cap._buffer.append(pkt)
                cap.packets_captured += 1
                if len(cap._buffer) >= cap.batch_size:
                    cap._flush_batch(reason="count")

        assert len(received_batches) == 1
        assert len(received_batches[0]) == 5

    def test_partial_batch_not_flushed_by_count(self):
        """A partial buffer (< batch_size) should NOT auto-flush."""
        received_batches: List[List[DeauthPacket]] = []

        cap = PacketCapture(
            batch_size=10,
            batch_timeout=60.0,
            on_batch=lambda batch: received_batches.append(batch),
        )

        for i in range(3):
            pkt = DeauthPacket(
                source_mac="aa:bb:cc:dd:ee:ff",
                target_mac="11:22:33:44:55:66",
                bssid="aa:bb:cc:dd:ee:ff",
                reason=7, signal=-45,
                timestamp=time.time(),
                channel=6,
            )
            with cap._lock:
                cap._buffer.append(pkt)

        assert len(received_batches) == 0
        assert len(cap._buffer) == 3

    def test_timer_based_flush(self):
        """The periodic timer should flush partial batches."""
        received_batches: List[List[DeauthPacket]] = []

        cap = PacketCapture(
            batch_size=100,
            batch_timeout=0.5,  # 500ms
            on_batch=lambda batch: received_batches.append(batch),
        )

        # Add a few packets without reaching batch_size.
        for i in range(3):
            pkt = DeauthPacket(
                source_mac="aa:bb:cc:dd:ee:ff",
                target_mac="11:22:33:44:55:66",
                bssid="aa:bb:cc:dd:ee:ff",
                reason=7, signal=-45,
                timestamp=time.time(),
                channel=6,
            )
            with cap._lock:
                cap._buffer.append(pkt)

        # Manually trigger the timer flush.
        cap._flush_batch(reason="timer")

        assert len(received_batches) == 1
        assert len(received_batches[0]) == 3

    def test_empty_flush_is_noop(self):
        """Flushing an empty buffer should not invoke the callback."""
        received_batches: List[List[DeauthPacket]] = []

        cap = PacketCapture(
            batch_size=10,
            on_batch=lambda batch: received_batches.append(batch),
        )

        cap._flush_batch(reason="timer")
        assert len(received_batches) == 0

    def test_thread_safety(self):
        """Multiple threads writing to the buffer should not corrupt it."""
        received_batches: List[List[DeauthPacket]] = []
        lock = threading.Lock()

        def safe_callback(batch):
            with lock:
                received_batches.append(batch)

        cap = PacketCapture(
            batch_size=50,
            batch_timeout=60.0,
            on_batch=safe_callback,
        )

        def add_packets(n):
            for _ in range(n):
                pkt = DeauthPacket(
                    source_mac="aa:bb:cc:dd:ee:ff",
                    target_mac="11:22:33:44:55:66",
                    bssid="aa:bb:cc:dd:ee:ff",
                    reason=7, signal=-45,
                    timestamp=time.time(),
                    channel=6,
                )
                with cap._lock:
                    cap._buffer.append(pkt)
                    cap.packets_captured += 1
                    if len(cap._buffer) >= cap.batch_size:
                        cap._flush_batch(reason="count")

        threads = [threading.Thread(target=add_packets, args=(20,)) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Total packets = 5 threads × 20 = 100.
        # With batch_size=50, we should have at least 2 flushes.
        total = sum(len(b) for b in received_batches) + len(cap._buffer)
        assert total == 100

    def test_freq_to_channel(self):
        """Verify frequency → channel conversion."""
        assert PacketCapture._freq_to_channel(2412) == 1
        assert PacketCapture._freq_to_channel(2437) == 6
        assert PacketCapture._freq_to_channel(2462) == 11
        assert PacketCapture._freq_to_channel(2484) == 14
        assert PacketCapture._freq_to_channel(5180) == 36
        assert PacketCapture._freq_to_channel(5745) == 149
        assert PacketCapture._freq_to_channel(1000) == 0  # out of range

    def test_get_stats(self):
        """Stats should reflect current state."""
        cap = PacketCapture(batch_size=10)
        stats = cap.get_stats()
        assert stats["packets_captured"] == 0
        assert stats["packets_dropped"] == 0
        assert stats["batches_flushed"] == 0
        assert stats["buffer_size"] == 0
