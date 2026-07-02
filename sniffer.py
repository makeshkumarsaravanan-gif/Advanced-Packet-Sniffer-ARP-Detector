import scapy.all as scapy

def process_packet(packet):
    """
    Callback function that triggers every time a packet is captured.
    It extracts basic IP and Protocol layer details.
    """
    # Check if the packet has an IP layer (Layer 3)
    if packet.haslayer(scapy.IP):
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        proto = packet[scapy.IP].proto
        
        # Translate protocol numbers to readable strings
        proto_name = "TCP" if proto == 6 else "UDP" if proto == 17 else f"Protocol({proto})"
        
        print(f"[+] Packet: {src_ip} -> {dst_ip} | {proto_name}")

def start_sniffing(interface):
    """
    Starts the continuous packet sniffer loop on a specific network card.
    """
    print(f"[*] Starting Packet Sniffer on interface: {interface}...")
    print("[-] Press Ctrl+C to stop.\n" + "="*50)
    
    # store=False keeps memory usage minimal by destroying processed packets
    scapy.sniff(iface=interface, store=False, prn=process_packet)