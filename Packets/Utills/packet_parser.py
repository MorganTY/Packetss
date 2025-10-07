from datetime import datetime
from scapy.layers.inet import IP, TCP, UDP, ICMP

def parse_packet(packet):
    if IP in packet:
        ip_layer = packet[IP]
        src = ip_layer.src
        dst = ip_layer.dst
        proto = ip_layer.proto
        info = ""

        if TCP in packet:
            proto_name = "TCP"
            info = f"{packet[TCP].sport} > {packet[TCP].dport}"
        elif UDP in packet:
            proto_name = "UDP"
            info = f"{packet[UDP].sport} > {packet[UDP].dport}"
        elif ICMP in packet:
            proto_name = "ICMP"
            info = "ICMP Echo Request" if packet[ICMP].type == 8 else "ICMP Reply"
        else:
            proto_name = str(proto)

        return {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "src": src,
            "dst": dst,
            "protocol": proto_name,
            "info": info
        }
