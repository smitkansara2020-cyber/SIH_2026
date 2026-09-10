from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6


def extract_packet_info(packet):

    info = {
        "src_ip": None,
        "dst_ip": None,
        "src_port": 0,
        "dst_port": 0,
        "proto": "other",
        "size": len(packet),
        "timestamp": float(packet.time)
    }

    # IPv4
    if IP in packet:
        info["src_ip"] = packet[IP].src
        info["dst_ip"] = packet[IP].dst

    # IPv6
    elif IPv6 in packet:
        info["src_ip"] = packet[IPv6].src
        info["dst_ip"] = packet[IPv6].dst

    else:
        return None


    # TCP
    if TCP in packet:

        info["proto"] = "tcp"

        info["src_port"] = packet[TCP].sport
        info["dst_port"] = packet[TCP].dport


    # UDP
    elif UDP in packet:

        info["proto"] = "udp"

        info["src_port"] = packet[UDP].sport
        info["dst_port"] = packet[UDP].dport


    return info