def simple_firewall(packet):
    trusted_ips = ["192.168.1.100"]
    trusted_ports = [80, 443]  # HTTP and HTTPS
    if packet["src_ip"] in trusted_ips:
        if packet["dst_port"] in trusted_ports:
            return True
    return False

packets = [
    {"src_ip": "192.168.1.100", "dst_ip": "192.168.1.200", "dst_port": 80},
    {"src_ip": "192.168.1.101", "dst_ip": "192.168.1.200", "dst_port": 80},
    {"src_ip": "192.168.1.100", "dst_ip": "192.168.1.200", "dst_port": 22},
]

for packet in packets:
    if simple_firewall(packet):
        print(f"Packet allowed: {packet}")
    else:
        print(f"Packet blocked: {packet}")
