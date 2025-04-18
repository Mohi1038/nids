from scapy.all import sniff, IP, TCP, UDP, ICMP, get_if_list
from collections import defaultdict, deque
import time
import traceback

packet_history = deque(maxlen=1000)  # Keep last 1000 packets
service_count = defaultdict(int)     # {dst_port: count}
host_count = defaultdict(set)        # {dst_ip: {src_ips}}

def extract_features(packet):
    features = {}
    try:
        if packet.haslayer(IP):
            print("[DEBUG] IP layer found.")
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            proto = packet[IP].proto
            packet_size = len(packet)
            dst_port, src_port = None, None
            service = "unknown"

            if packet.haslayer(TCP) or packet.haslayer(UDP):
                print("[DEBUG] TCP or UDP layer found.")
                dst_port = packet[TCP].dport if packet.haslayer(TCP) else packet[UDP].dport
                src_port = packet[TCP].sport if packet.haslayer(TCP) else packet[UDP].sport
                service = str(dst_port)

            # Add packet to history
            packet_history.append((time.time(), src_ip, dst_ip, dst_port, proto))
            print(f"[DEBUG] Packet added to history. Total packets stored: {len(packet_history)}")

            # Update service/host tracking
            if dst_port:
                service_count[dst_port] += 1
                print(f"[DEBUG] Service count for port {dst_port}: {service_count[dst_port]}")
            if dst_ip:
                host_count[dst_ip].add(src_ip)
                print(f"[DEBUG] Host count for {dst_ip}: {len(host_count[dst_ip])}")

            # Historical & behavioral features
            same_srv_rate = service_count[dst_port] / len(packet_history) if dst_port else 0
            dst_host_srv_count = service_count[dst_port] if dst_port else 0
            dst_host_same_srv_rate = dst_host_srv_count / len(host_count[dst_ip]) if dst_ip in host_count and len(host_count[dst_ip]) > 0 else 0
            dst_host_count = len(host_count[dst_ip])
            count = len([p for p in packet_history if p[2] == dst_ip])

            # Error and flag tracking
            serror_count = sum(1 for p in packet_history if p[3] == dst_port and p[2] == dst_ip)
            serror_rate = serror_count / len(packet_history) if len(packet_history) > 0 else 0
            srv_serror_rate = serror_rate
            dst_host_srv_serror_rate = serror_rate
            dst_host_serror_rate = serror_rate
            rerror_rate = 0  # Placeholder

            flag = "OTH"
            if packet.haslayer(TCP):
                flags = packet.sprintf("%TCP.flags%")
                flag = flags if flags else "OTH"

            logged_in = 1 if "A" in flag else 0

            # Placeholder logic for difficulty_score
            difficulty_score = 1 if dst_port in (22, 23, 80, 443) else 0

            # Populate all features
            features["same_srv_rate"] = same_srv_rate
            features["dst_host_srv_count"] = dst_host_srv_count
            features["dst_host_same_srv_rate"] = dst_host_same_srv_rate
            features["logged_in"] = logged_in
            features["flag"] = 1 if "A" in flag else 0
            features["dst_host_srv_serror_rate"] = dst_host_srv_serror_rate
            features["dst_host_serror_rate"] = dst_host_serror_rate
            features["serror_rate"] = serror_rate
            features["srv_serror_rate"] = srv_serror_rate
            features["count"] = count
            features["dst_host_count"] = dst_host_count
            features["difficulty_score"] = difficulty_score
            features["service"] = service
            features["rerror_rate"] = rerror_rate
            print(f"[DEBUG] Features extracted successfully for {src_ip} → {dst_ip}:{dst_port}")

            print("feats = ", features)

        else:
            print("[DEBUG] Packet skipped: No IP layer detected.")
    except Exception as e:
        print("[ERROR] Exception during feature extraction:")
        traceback.print_exc()

    return features

def capture_packets(count=None):
    try:
        interfaces = get_if_list()
        print("Sniffing on interfaces:", interfaces)

        def handle_packet(pkt):
            print("\n[DEBUG] Packet received.")
            features = extract_features(pkt)
            print("[INFO] Features:", features)

        if count:
            print(f"[DEBUG] Capturing {count} packets...")
            packets = sniff(iface=interfaces, count=count)
            return [extract_features(pkt) for pkt in packets]
        else:
            print("[DEBUG] Starting live packet sniffing...")
            sniff(iface=interfaces, prn=handle_packet, store=False)

    except Exception as e:
        print("[ERROR] Exception during packet capture:")
        traceback.print_exc()

# Uncomment to test:
# if __name__ == "__main__":
#     try:
#         capture_packets(count=None)  # or count=X for fixed number
#     except KeyboardInterrupt:
#         print("\n[INFO] Stopped by user.")
