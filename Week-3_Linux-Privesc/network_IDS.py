# ----------------------------------------
# Mini Network IDS (Simplified)
# Detects:
#  - ICMP pings (echo request/reply)
#  - TCP SYN attempts
#  - NULL & FIN scans
#  - Simple ICMP/TCP floods
# ----------------------------------------

from scapy.all import rdpcap, IP, TCP, ICMP
from collections import defaultdict

# --- Simple counters ---
icmp_count = defaultdict(int)
syn_count = defaultdict(int)

def analyze_packet(pkt):
    if not pkt.haslayer(IP):
        return
    
    src, dst = pkt[IP].src, pkt[IP].dst
    
    # ICMP detection
    if pkt.haslayer(ICMP):
        if pkt[ICMP].type == 8:   # Echo request
            icmp_count[src] += 1
            print(f"[ICMP] Request from {src} to {dst}")
            if icmp_count[src] > 10:
                print(f"[ALERT] ICMP flood suspected from {src}")
        elif pkt[ICMP].type == 0: # Echo reply
            print(f"[ICMP] Reply from {src} to {dst}")
    
    # TCP detection
    if pkt.haslayer(TCP):
        flags = pkt[TCP].flags
        dport = pkt[TCP].dport

        if flags & 0x02:  # SYN
            syn_count[src] += 1
            print(f"[TCP] SYN attempt from {src} to {dst}:{dport}")
            if syn_count[src] > 15:
                print(f"[ALERT] High-rate SYNs from {src}")

        elif flags == 0:  # NULL scan
            print(f"[ALERT] NULL scan from {src} to {dst}:{dport}")

        elif flags & 0x01:  # FIN scan
            print(f"[ALERT] FIN scan from {src} to {dst}:{dport}")

def main():
    pcap_file = input("Enter PCAP file path: ")
    print(f"[*] Reading packets from {pcap_file}...")
    
    try:
        packets = rdpcap(pcap_file)
    except FileNotFoundError:
        print("[ERROR] File not found.")
        return

    for pkt in packets:
        analyze_packet(pkt)
    
    print("[+] Analysis complete.")

if __name__ == "__main__":
    main()
