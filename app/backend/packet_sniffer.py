from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import defaultdict, deque
import time

# History Buffers
packet_history = deque(maxlen=1000)  # Stores last 1000 packets
service_count = defaultdict(int)  # {dst_port: count}
host_count = defaultdict(set)  # {dst_ip: {src_ips}}

def extract_features(packet):
    """Extract real-time features from a captured packet."""
    features = {}

    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        packet_size = len(packet)
        dst_port = None

        if packet.haslayer(TCP) or packet.haslayer(UDP):
            dst_port = packet[TCP].dport if packet.haslayer(TCP) else packet[UDP].dport
            src_port = packet[TCP].sport if packet.haslayer(TCP) else packet[UDP].sport
        else:
            src_port, dst_port = None, None

        # Add to history buffer
        packet_history.append((time.time(), src_ip, dst_ip, dst_port, proto))

        # Track service count
        if dst_port:
            service_count[dst_port] += 1

        # Track host interactions
        host_count[dst_ip].add(src_ip)

        # Calculate Feature Values
        features["src_ip"] = src_ip
        features["dst_ip"] = dst_ip
        features["protocol"] = proto
        features["packet_size"] = packet_size
        features["dst_port"] = dst_port

        # Historical Features
        same_srv_rate = service_count[dst_port] / len(packet_history) if dst_port else 0
        dst_host_srv_count = service_count[dst_port] if dst_port else 0
        dst_host_same_srv_rate = dst_host_srv_count / len(host_count[dst_ip]) if dst_ip in host_count else 0
        dst_host_count = len(host_count[dst_ip])

        # Error Tracking
        serror_count = sum(1 for p in packet_history if p[3] == dst_port and p[2] == dst_ip)
        serror_rate = serror_count / len(packet_history)

        # TCP Flags for Session Tracking
        flag = "OTH"
        if packet.haslayer(TCP):
            flags = packet.sprintf("%TCP.flags%")
            flag = flags if flags else "OTH"

        # Store Computed Features
        features["same_srv_rate"] = same_srv_rate
        features["dst_host_srv_count"] = dst_host_srv_count
        features["dst_host_same_srv_rate"] = dst_host_same_srv_rate
        features["logged_in"] = 1 if flag == "A" else 0  # Assume ACK means logged in
        features["dst_host_srv_serror_rate"] = serror_rate
        features["dst_host_serror_rate"] = serror_rate
        features["serror_rate"] = serror_rate
        features["srv_serror_rate"] = serror_rate
        features["flag"] = flag
        features["count"] = len([p for p in packet_history if p[2] == dst_ip])
        features["dst_host_count"] = dst_host_count

    return features

def capture_packets(count=10):
    """Capture packets and extract their features."""
    packets = sniff(count=count)
    return [extract_features(pkt) for pkt in packets]
