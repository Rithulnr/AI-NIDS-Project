from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
import queue
from collections import deque
import time

packet_queue = queue.Queue()

# Flow tracking dictionary
# Key: (ip1, ip2, port1, port2, proto) -> sorted so bidirectional packets map to same flow
active_flows = {}

def get_flow_key(src_ip, dst_ip, src_port, dst_port, proto):
    if src_ip < dst_ip:
        return (src_ip, dst_ip, src_port, dst_port, proto)
    else:
        return (dst_ip, src_ip, dst_port, src_port, proto)

def process_packet(pkt):
    if IP not in pkt:
        return None

    ip = pkt[IP]
    proto = 0
    if TCP in pkt:
        proto = 1
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
    elif UDP in pkt:
        proto = 2
        src_port = pkt[UDP].sport
        dst_port = pkt[UDP].dport
    else:
        return None

    flow_key = get_flow_key(ip.src, ip.dst, src_port, dst_port, proto)
    current_time = time.time()
    pkt_len = len(pkt)

    if flow_key not in active_flows:
        # Initialize new flow
        active_flows[flow_key] = {
            "start_time": current_time,
            "src_ip_init": ip.src,  # The one who started the flow
            "Spkts": 0,
            "Dpkts": 0,
            "sbytes": 0,
            "dbytes": 0,
            "last_s_time": current_time,
            "last_d_time": current_time,
            "Sintpkt": 0.0,
            "Dintpkt": 0.0
        }
    
    flow = active_flows[flow_key]
    
    # Update stats based on direction
    if ip.src == flow["src_ip_init"]:
        if flow["Spkts"] > 0:
            delta = (current_time - flow["last_s_time"]) * 1000 # to mSec to match UNSW-NB15
            flow["Sintpkt"] = (flow["Sintpkt"] * flow["Spkts"] + delta) / (flow["Spkts"] + 1)
        flow["Spkts"] += 1
        flow["sbytes"] += pkt_len
        flow["last_s_time"] = current_time
    else:
        if flow["Dpkts"] > 0:
            delta = (current_time - flow["last_d_time"]) * 1000
            flow["Dintpkt"] = (flow["Dintpkt"] * flow["Dpkts"] + delta) / (flow["Dpkts"] + 1)
        flow["Dpkts"] += 1
        flow["dbytes"] += pkt_len
        flow["last_d_time"] = current_time

    dur = current_time - flow["start_time"]
    
    smeansz = flow["sbytes"] / max(flow["Spkts"], 1)
    dmeansz = flow["dbytes"] / max(flow["Dpkts"], 1)

    # Emit flow stats
    features = {
        "src_ip": flow["src_ip_init"],
        "dur": dur,
        "Spkts": flow["Spkts"],
        "Dpkts": flow["Dpkts"],
        "sbytes": flow["sbytes"],
        "dbytes": flow["dbytes"],
        "smeansz": smeansz,
        "dmeansz": dmeansz,
        "Sintpkt": flow["Sintpkt"],
        "Dintpkt": flow["Dintpkt"],
        "src_port": src_port,
        "dst_port": dst_port # Keep for demo server filtering
    }

    return features


# Global buffer for PCAP export
pcap_buffer = deque(maxlen=200)

def start_sniffer(q):

    print("Starting packet sniffer...")

    def packet_handler(pkt):
        features = process_packet(pkt)
        if features:
            # Include a raw summary for DPI
            try:
                raw_summary = pkt.summary()
                if pkt.haslayer("Raw"):
                    raw_summary += " | Data: " + str(pkt["Raw"].load[:50])
            except:
                raw_summary = "Could not decode packet"

            features["raw"] = raw_summary
            q.put(features)
            
            # Store raw packet for PCAP export
            pcap_buffer.append(pkt)

    from scapy.all import sniff, conf
    
    # Dynamically find the loopback interface on Windows
    loopback_iface = None
    try:
        from scapy.arch.windows import get_windows_if_list
        interfaces = get_windows_if_list()
        # Look for "Loopback" or "NPF_Loopback"
        for iface in interfaces:
            if "loopback" in iface['name'].lower() or "loopback" in iface['description'].lower():
                loopback_iface = iface['name']
                break
    except:
        pass
            
    if not loopback_iface:
        for iface in conf.ifaces.values():
            if iface.ip == "127.0.0.1":
                loopback_iface = iface.name
                break
            
    if not loopback_iface:
        # Fallback to a common default
        loopback_iface = "Software Loopback Interface 1"

    print(f"[*] Sniffer watching interface: {loopback_iface}")
    print("[*] Monitoring Port 8000 for threats...")

    while True:
        try:
            sniff(
                iface=loopback_iface,
                filter="tcp port 8000",
                prn=packet_handler,
                store=False,
                timeout=1
            )
        except Exception as e:
            print(f"Sniffer error: {e}")
            time.sleep(1)