import sys
from scapy.all import sniff, IP, TCP, UDP, ICMP

def packet_callback(packet):
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto = ip_layer.proto
        proto_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto, str(proto))
        print(f"Packet: {src_ip} -> {dst_ip} Protocol: {proto_name}")
    else:
        print("Non-IP Packet")

def main():
    if len(sys.argv) > 1:
        iface = sys.argv[1]
        print(f"Starting packet capture on interface: {iface}")
        sniff(iface=iface, prn=packet_callback, store=False)
    else:
        print("Usage: python sniffer.py <interface>")
        print("Example: python sniffer.py eth0")

if __name__ == "__main__":
    main()
