import sys
import sniffer
import detector

def get_interface():
    """Prompts user for their network interface card name."""
    print("--- Network Interfaces Hint ---")
    print("Run 'ip link show' in another terminal to find your interface (e.g., wlo1, enp3s0, eth0)")
    print("-" * 31)
    interface = input("Enter your network interface name: ").strip()
    if not interface:
        print("[!] Interface cannot be empty. Exiting.")
        sys.exit(1)
    return interface

def main():
    print("="*50)
    print("  ADVANCED PACKET SNIFFER & ARP SPOOFING DETECTOR  ")
    print("="*50)
    print("1. Run Live Packet Sniffer")
    print("2. Run ARP Spoofing Detector")
    print("3. Exit")
    print("-" * 50)
    
    choice = input("Select an option (1-3): ").strip()
    
    if choice == '1':
        interface = get_interface()
        sniffer.start_sniffing(interface)
    elif choice == '2':
        interface = get_interface()
        detector.start_detector(interface)
    elif choice == '3':
        print("[*] Exiting tool. Stay secure!")
        sys.exit(0)
    else:
        print("[!] Invalid option selected. Exiting.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Program interrupted by user. Shutting down cleanly.")
        sys.exit(0)