import scapy.all as scapy
import os
from datetime import datetime

# Global dictionary to track IP to MAC bindings in memory
# Format: { "192.168.1.1": "00:11:22:33:44:55" }
ip_mac_table = {}
LOG_FILE = "logs/attack_alerts.log"

def log_incident(message):
    """Appends security incidents to a local log file with a timestamp."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] {message}\n"
    
    # Ensure logs directory exists safely
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    with open(LOG_FILE, "a") as f:
        f.write(log_entry)

def process_arp_packet(packet):
    """
    Analyzes captured ARP packets to look for conflicting MAC mappings.
    """
    # op=2 means it's an ARP Reply (response telling a machine who an IP belongs to)
    if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
        src_ip = packet[scapy.ARP].psrc   # Source IP
        src_mac = packet[scapy.ARP].hwsrc # Real Source MAC Address Claimed
        
        # Scenario 1: The IP address is brand new to our network monitor
        if src_ip not in ip_mac_table:
            ip_mac_table[src_ip] = src_mac
            print(f"[*] Learned: {src_ip} is at {src_mac}")
            
        # Scenario 2: The IP already exists, check if the MAC address has changed
        elif ip_mac_table[src_ip] != src_mac:
            old_mac = ip_mac_table[src_ip]
            alert_msg = (
                f"⚠️ ALERT: Potential ARP Spoofing Detected! "
                f"IP [{src_ip}] changed MAC from [{old_mac}] to [{src_mac}]!"
            )
            print(f"\n\033[91m{alert_msg}\033[0m\n") # Prints in red text
            log_incident(alert_msg)

def start_detector(interface):
    """Starts the ARP spoof detector targeting Layer 2 infrastructure."""
    print(f"[*] Starting ARP Spoof Detector on interface: {interface}...")
    print("[-] Monitoring local network mappings. Press Ctrl+C to exit.\n" + "="*50)
    
    # filter="arp" ensures Scapy ignores all other web traffic to save CPU
    scapy.sniff(iface=interface, store=False, prn=process_arp_packet, filter="arp")