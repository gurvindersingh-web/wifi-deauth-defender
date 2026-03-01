from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict
from threading import Thread, Lock
import argparse
import time
import signal
import sys

# Shared storage
packet_count = defaultdict(int)
protocol_count = defaultdict(int)
total_packets = 0

lock = Lock()
running = True


def process_packet(packet):
    global total_packets

    if IP in packet:
        with lock:
            src = packet[IP].src
            packet_count[src] += 1
            total_packets += 1

            if TCP in packet:
                protocol_count["TCP"] += 1
            elif UDP in packet:
                protocol_count["UDP"] += 1
            else:
                protocol_count["OTHER"] += 1


def aggregator(window):
    global running

    while running:
        time.sleep(window)

        with lock:
            if total_packets == 0:
                continue

            print("\n===== Aggregated Stats =====")

            print("\nPacket count per IP:")
            for ip, count in sorted(packet_count.items(), key=lambda x: x[1], reverse=True):
                print(f"{ip} : {count}")

            print("\nProtocol usage:")
            for proto, count in protocol_count.items():
                percent = (count / total_packets) * 100
                print(f"{proto} : {count} ({percent:.2f}%)")

            pps = total_packets / window
            print(f"\nPackets Per Second: {pps:.2f}")

            print("===========================\n")

            # Reset
            packet_count.clear()
            protocol_count.clear()
            globals()["total_packets"] = 0


def stop_sniffer(signal, frame):
    global running
    print("\nStopping capture...")
    running = False
    sys.exit(0)


def main():
    parser = argparse.ArgumentParser(description="Scapy Packet Aggregator")
    parser.add_argument("-i", "--interface", default=None, help="Network interface")
    parser.add_argument("-f", "--filter", default="ip", help="BPF filter")
    parser.add_argument("-w", "--window", type=int, default=10, help="Aggregation window (seconds)")

    args = parser.parse_args()

    # Handle Ctrl+C
    signal.signal(signal.SIGINT, stop_sniffer)

    # Start aggregator thread
    Thread(target=aggregator, args=(args.window,), daemon=True).start()

    print("Starting capture...")
    print(f"Interface: {args.interface}")
    print(f"Filter: {args.filter}")
    print(f"Window: {args.window}s\n")

    sniff(
        iface=args.interface,
        filter=args.filter,
        prn=process_packet,
        store=False
    )


if __name__ == "__main__":
    main()
