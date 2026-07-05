from config import RULES

def match_rule(packet_info):
    for rule in RULES:
        match = True

        for key, value in rule.items():
            if key == "action":
                continue

            if packet_info.get(key) != value:
                match = False
                break

        if match:
            return rule["action"]

    return "allow"