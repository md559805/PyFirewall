from scapy.all import IP, IPv6, TCP, UDP, ICMP, ARP, Raw

try:
    from scapy.layers.dns import DNS
except Exception:
    DNS = None

try:
    from scapy.layers.http import HTTPRequest
except Exception:
    HTTPRequest = None
from scapy.all import IP, TCP, UDP, ICMP

def inspect_packet(packet):
    """Return a dict with packet summary information or None if unsupported.

    Fields: src, dst, protocol, sport, dport, extra
    """
    # ARP (link-layer)
    if ARP in packet:
        arp = packet[ARP]
        return {
            "src": getattr(arp, "psrc", None),
            "dst": getattr(arp, "pdst", None),
            "protocol": "ARP",
            "sport": None,
            "dport": None,
            "extra": {"hwsrc": getattr(arp, "hwsrc", None), "hwdst": getattr(arp, "hwdst", None), "op": getattr(arp, "op", None)}
        }

    # Only handle IP/IPv6 packets here
    if IP not in packet and IPv6 not in packet:
        return None

    ip_layer = packet[IP] if IP in packet else packet[IPv6]

    packet_info = {
        "src": getattr(ip_layer, "src", None),
        "dst": getattr(ip_layer, "dst", None),
        "protocol": None,
        "sport": None,
        "dport": None,
        "extra": {}
    }

    # Transport layers
    if TCP in packet:
        t = packet[TCP]
        packet_info.update({"protocol": "TCP", "sport": getattr(t, "sport", None), "dport": getattr(t, "dport", None)})

    elif UDP in packet:
        u = packet[UDP]
        packet_info.update({"protocol": "UDP", "sport": getattr(u, "sport", None), "dport": getattr(u, "dport", None)})

    elif ICMP in packet:
        packet_info.update({"protocol": "ICMP", "sport": None, "dport": None})

    else:
        # Unknown transport — keep the IP proto name
        packet_info["protocol"] = type(ip_layer).__name__

    # DNS (if present)
    if DNS is not None and DNS in packet:
        try:
            dns = packet[DNS]
            qnames = []
            if hasattr(dns, "qd") and dns.qd is not None:
                # Single or multiple queries
                qd = dns.qd
                if isinstance(qd, list):
                    for entry in qd:
                        qnames.append(getattr(entry, "qname", b"").decode(errors="ignore"))
                else:
                    qnames.append(getattr(qd, "qname", b"").decode(errors="ignore"))

            packet_info["extra"]["dns_qnames"] = qnames
        except Exception:
            pass

    # HTTP requests (scapy's HTTP layer)
    if HTTPRequest is not None and packet.haslayer(HTTPRequest):
        try:
            http = packet[HTTPRequest]
            method = getattr(http, "Method", None)
            host = getattr(http, "Host", None)
            path = getattr(http, "Path", None)
            if isinstance(method, bytes):
                method = method.decode(errors="ignore")
            if isinstance(host, bytes):
                host = host.decode(errors="ignore")
            if isinstance(path, bytes):
                path = path.decode(errors="ignore")

            packet_info["extra"].update({"http_method": method, "http_host": host, "http_path": path})
        except Exception:
            pass

    # Raw payload length
    if Raw in packet:
        try:
            packet_info["extra"]["raw_len"] = len(packet[Raw].load)
        except Exception:
            pass

    return packet_info

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
