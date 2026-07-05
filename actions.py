def take_action(action, packet_info):
    if action == "block":
        print(f"BLOCKED {packet_info}")
    
    elif action == "allow":
        print(f"ALLOWED {packet_info}")
    
    else:
        print(f"UNKNOWN ACTION {packet_info}")
        

# IT'S CONNECTABLE TO "IPTABLES" OR "NETFILTER".