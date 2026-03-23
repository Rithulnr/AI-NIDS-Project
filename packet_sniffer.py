from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
import queue

packet_queue = queue.Queue()

def extract_features(pkt):
     
     

    if IP not in pkt:
        return None

    ip = pkt[IP]

    proto = 0
    if TCP in pkt:
        proto = 1
    elif UDP in pkt:
        proto = 2

    src_port = pkt[TCP].sport if TCP in pkt else 0
    dst_port = pkt[TCP].dport if TCP in pkt else 0   

    features = {
        "src_ip": ip.src,
        "packet_len": len(pkt),
        "ttl": ip.ttl,
        "protocol": proto,
        "ip_len": ip.len,
        "src_port": src_port,
        "dst_port": dst_port
    }

    return features


def packet_handler(pkt):

    # print("PACKET DETECTED")   # debug

    features = extract_features(pkt)

    if features:
        packet_queue.put(features)

    


def start_sniffer():

    print("Starting packet sniffer...")

    sniff(
    iface="\\Device\\NPF_Loopback",
    prn=packet_handler,
    store=False
)