RULES = [
    {"action": "block", "src": "192.168.0.0"},
    {"action": "block", "dport": 80},
    {"action": "allow", "protocol": "TCP"},
    {"action": "block", "protocol": "UDP"},
]