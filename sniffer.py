from scapy.all import sniff, IP, TCP, UDP
import argparse
from datetime import datetime

def packet_callback(packet):
    try:
        if IP in packet:
            src = packet[IP].src
            dst = packet[IP].dst
            protocol = "OTHER"

            if TCP in packet:
                protocol = "TCP"
                sport = packet[TCP].sport
                dport = packet[TCP].dport

            elif UDP in packet:
                protocol = "UDP"
                sport = packet[UDP].sport
                dport = packet[UDP].dport
            else:
                sport = "-"
                dport = "-"

            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            print(f"[{timestamp}] {protocol} {src}:{sport} -> {dst}:{dport}")

    except Exception as e:
        print("Error processing packet:", e)


def main():
    parser = argparse.ArgumentParser(description="Advanced Packet Sniffer")
    parser.add_argument("-i", "--interface", default=None, help="Network interface")
    parser.add_argument("-f", "--filter", default="ip", help="BPF filter (default: ip)")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture")

    args = parser.parse_args()

    print("Starting packet capture...")
    print(f"Interface: {args.interface}")
    print(f"Filter: {args.filter}")

    sniff(
        iface=args.interface,
        filter=args.filter,
        prn=packet_callback,
        store=False,
        count=args.count
    )


if __name__ == "__main__":
    main()
