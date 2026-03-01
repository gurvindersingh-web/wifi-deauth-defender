from scapy.all import sniff, IP, TCP, UDP, conf
from collections import defaultdict
from threading import Thread, Lock
import argparse
import time
import json
import signal
import sys
import os
from webhook_alerter import get_alerter

# Performance backend
conf.use_pcap = True

# ================= CONFIG =================
FLOOD_THRESHOLD = 100
PORT_SCAN_THRESHOLD = 20
UDP_RATIO_THRESHOLD = 0.85

packet_count = defaultdict(int)
protocol_count = defaultdict(int)
unique_ports = defaultdict(set)

total_packets = 0
running = True
lock = Lock()

# ==========================================
# ALERT ENGINE
# ==========================================

alert_cache = set()  # Track recent alerts to avoid duplicates

def alert(level, attack, source, extra=None):
    """
    Send alert to n8n via webhook and also print to console
    Deduplicates alerts within 10 second window
    """
    # Create alert signature for deduplication
    alert_sig = f"{level}:{attack}:{source}"
    if alert_sig in alert_cache:
        return
    
    alert_cache.add(alert_sig)
    
    # Schedule cache removal after 10 seconds
    def clear_from_cache():
        time.sleep(10)
        alert_cache.discard(alert_sig)
    
    Thread(target=clear_from_cache, daemon=True).start()
    
    # Send via webhook
    alerter = get_alerter()
    alerter.send_alert(
        severity=level,
        attack=attack,
        source=source,
        details=extra
    )
    
    # Also print locally for debugging
    alert_data = {
        "severity": level,
        "attack": attack,
        "source": source,
        "timestamp": time.time(),
        "details": extra
    }
    print("🚨 ALERT:", json.dumps(alert_data, indent=2))


# ==========================================
# RULE ENGINE
# ==========================================

def run_rules(window):
    global total_packets

    if total_packets == 0:
        return

    udp_ratio = protocol_count["UDP"] / total_packets
    pps = total_packets / window

    # Flood Detection
    for ip, count in packet_count.items():
        if count > FLOOD_THRESHOLD:
            alert("HIGH", "Traffic Flood", ip, {"packet_count": count, "message": f"High packet rate: {count} packets"})

    # Port Scan Detection
    for ip, ports in unique_ports.items():
        if len(ports) > PORT_SCAN_THRESHOLD:
            alert("MEDIUM", "Port Scan", ip, {"unique_ports": len(ports), "packet_count": packet_count[ip], "message": f"Scanning {len(ports)} ports"})

    # UDP Spike
    if udp_ratio > UDP_RATIO_THRESHOLD:
        alert("MEDIUM", "UDP Traffic Spike", "Network",
              {"udp_ratio": round(udp_ratio, 2), "packet_count": total_packets, "message": f"UDP ratio {round(udp_ratio, 2)}"})

    # PPS anomaly
    if pps > 500:
        alert("HIGH", "Abnormal Packet Rate", "Network", {"pps": pps, "packet_rate": pps, "message": f"Abnormal PPS: {pps}"})


# ==========================================
# PACKET HANDLER
# ==========================================

def process_packet(packet):
    global total_packets

    if IP in packet:
        src = packet[IP].src

        with lock:
            packet_count[src] += 1
            total_packets += 1

            if TCP in packet:
                protocol_count["TCP"] += 1
                unique_ports[src].add(packet[TCP].dport)

                # Proper SYN detection
                if packet[TCP].flags & 0x02:
                    alert("LOW", "SYN Probe", src)

            elif UDP in packet:
                protocol_count["UDP"] += 1
            else:
                protocol_count["OTHER"] += 1


# ==========================================
# AGGREGATION THREAD
# ==========================================

def aggregator(window):
    global total_packets

    while running:
        time.sleep(window)

        with lock:
            print("\n====== Traffic Snapshot ======")
            print("Packets per IP:", dict(packet_count))
            print("Protocols:", dict(protocol_count))
            print("==============================")

            run_rules(window)

            packet_count.clear()
            protocol_count.clear()
            unique_ports.clear()
            total_packets = 0


# ==========================================
# SHUTDOWN HANDLER
# ==========================================

def stop_capture(sig, frame):
    global running
    print("\nStopping IDS...")
    running = False
    sys.exit(0)


# ==========================================
# MAIN
# ==========================================

def main():
    parser = argparse.ArgumentParser(description="AI Ready Network IDS")
    parser.add_argument("-i", "--interface", default=None)
    parser.add_argument("-f", "--filter", default="ip")
    parser.add_argument("-w", "--window", type=int, default=10)

    args = parser.parse_args()

    signal.signal(signal.SIGINT, stop_capture)

    Thread(target=aggregator, args=(args.window,), daemon=True).start()

    print("Starting IDS monitoring...")
    print("Interface:", args.interface)
    print("Filter:", args.filter)
    print("Window:", args.window, "seconds\n")

    sniff(
        iface=args.interface,
        filter=args.filter,
        prn=process_packet,
        store=False
    )


if __name__ == "__main__":
    main()
