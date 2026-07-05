import datetime

LOG_FILE = "firewall.log"

def log_packet(packet_info, action):
    with open (LOG_FILE, "a") as f:
        f.write(f"{datetime.datetime.now()} | {action} | {packet_info}\n")