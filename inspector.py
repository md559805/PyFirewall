from scapy.all import IP, TCP, UDP, ICMP

def inspect_packet(packet):
    if IP not in packet:
        return None

    ip_layer = packet[IP]

    packet_info = {
        "src": ip_layer.src,
        "dst": ip_layer.dst,
        "protocol": None,
        "sport": None,
        "dport": None
    }

    if TCP in packet:
        packet_info["protocol"] = "TCP"
        packet_info["sport"] = packet[TCP].sport
        packet_info["dport"] = packet[TCP].dport

    elif UDP in packet:
        packet_info["protocol"] = "UDP"
        packet_info["sport"] = packet[UDP].sport
        packet_info["dport"] = packet[UDP].dport

    elif ICMP in packet:
        packet_info["protocol"] = "ICMP"
        packet_info["sport"] = None
        packet_info["dport"] = None

    return packet_info