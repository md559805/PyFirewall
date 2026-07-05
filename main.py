from sniffer import start_sniffing
from inspector import inspect_packet
from rules import match_rule
from actions import take_action
from logger import log_packet

def process_packet(packet):
    packet_info = inspect_packet(packet)
    
    if not packet_info:
        return
    
    action = match_rule(packet_info)
    take_action(action, packet_info)
    log_packet(packet_info, action)


if __name__ == "__main__":
    print("[*] Firewall Started...")
    start_sniffing(process_packet)