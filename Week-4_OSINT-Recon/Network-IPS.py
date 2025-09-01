from scapy.all import rdpcap, IP, TCP, ICMP, UDP, Raw, DNS

# Load packets (replace with your malicious/benign pcap file)
packets = rdpcap("traffic_sample.pcap")

# Tracking dictionaries
icmp_count = {}
syn_count = {}
scan_ports = {}
dns_count = {}

# SQL injection keywords for payload detection
sql_keywords = ["UNION SELECT", "' OR 1=1", "DROP TABLE", "--", "INSERT INTO"]

# Blocklist to store malicious IPs
blocklist = set()

def is_sql_injection(payload):
    """Check if HTTP payload contains suspicious SQL keywords."""
    for keyword in sql_keywords:
        if keyword.lower() in payload.lower():
            return True
    return False

for pkt in packets:
    if IP not in pkt:
        continue
    
    src = pkt[IP].src
    dst = pkt[IP].dst

    # Skip packets from already blocked IPs
    if src in blocklist:
        print(f"[BLOCKED] Traffic from {src} -> {dst}")
        continue

    # ------------------------
    # 1. ICMP Flood Detection
    # ------------------------
    if ICMP in pkt and pkt[ICMP].type == 8:  # Echo Request
        icmp_count[src] = icmp_count.get(src, 0) + 1
        if icmp_count[src] > 20:
            print(f"[ICMP-FLOOD] {src} -> {dst} : BLOCK")
            blocklist.add(src)
            continue

    # ------------------------
    # 2. SYN Flood Detection
    # ------------------------
    if TCP in pkt and pkt[TCP].flags == "S":
        syn_count[src] = syn_count.get(src, 0) + 1
        if syn_count[src] > 40:
            print(f"[SYN-FLOOD] {src} -> {dst} : BLOCK")
            blocklist.add(src)
            continue

    # ------------------------
    # 3. Port Scan Detection
    # ------------------------
    if TCP in pkt:
        dport = pkt[TCP].dport
        if src not in scan_ports:
            scan_ports[src] = set()
        scan_ports[src].add(dport)

        if len(scan_ports[src]) > 15:
            print(f"[PORT-SCAN] {src} -> multiple ports : BLOCK")
            blocklist.add(src)
            continue

    # ------------------------
    # 4. Suspicious HTTP Payloads (SQL Injection)
    # ------------------------
    if TCP in pkt and pkt[TCP].dport == 80 and Raw in pkt:
        try:
            payload = pkt[Raw].load.decode(errors="ignore")
            if is_sql_injection(payload):
                print(f"[SQLi-ATTEMPT] {src} -> {dst} : BLOCK")
                blocklist.add(src)
                continue
        except Exception:
            pass

    # ------------------------
    # 5. DNS Flood Detection
    # ------------------------
    if UDP in pkt and pkt[UDP].dport == 53 and DNS in pkt:
        dns_count[src] = dns_count.get(src, 0) + 1
        if dns_count[src] > 50:
            print(f"[DNS-FLOOD] {src} -> {dst} : BLOCK")
            blocklist.add(src)
            continue

    # ------------------------
    # Default: Allow
    # ------------------------
    print(f"{src} -> {dst} : ALLOW")

# ------------------------
# Summary of blocked IPs
# ------------------------
print("\n--- IPS Summary ---")
if blocklist:
    print("Blocked IPs:")
    for ip in blocklist:
        print(f" - {ip}")
else:
    print("No IPs blocked.")

