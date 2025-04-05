from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from datetime import datetime

def process_packet(packet):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Initialize values
    src_ip = dst_ip = protocol = payload = "N/A"

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        if TCP in packet:
            protocol = "TCP"
        elif UDP in packet:
            protocol = "UDP"
        elif ICMP in packet:
            protocol = "ICMP"
        else:
            protocol = "Other"

        if Raw in packet:
            payload = bytes(packet[Raw].load)[:50]  # Show only first 50 bytes
            payload = payload.decode(errors="replace")

        print(f"[{timestamp}] {protocol} Packet")
        print(f"From: {src_ip} --> To: {dst_ip}")
        print(f"Payload (first 50 bytes): {payload}")
        print("-" * 60)

def start_sniffing(interface=None):
    print("Starting packet sniffer...")
    sniff(prn=process_packet, iface=interface, store=False)

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Simple Packet Sniffer (Educational Use Only)")
    parser.add_argument("-i", "--interface", help="Network interface to sniff on (e.g., eth0, wlan0)")
    args = parser.parse_args()

    try:
        start_sniffing(interface=args.interface)
    except KeyboardInterrupt:
        print("\nSniffing stopped by user.")
    except Exception as e:
        print(f"Error: {e}")
