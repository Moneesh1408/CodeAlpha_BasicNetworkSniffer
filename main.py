"""
                                        TASK-1 : BASIC NETWORK SNIFFER USING PYTHON
"""

import sys
from scapy.all import sniff, IP, TCP, UDP, ICMP 

def process_packet(packet):
    
    # Check if the packet contains an IP Layer (Layer 3)
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        
        # Determine the protocol name from the protocol number
        if proto == 6:
            proto_name = "TCP"
        elif proto == 17:
            proto_name = "UDP"
        elif proto == 1:
            proto_name = "ICMP"
        else:
            proto_name = f"Protocol ({proto})"
        
        print(f"\n[+] Packet Captured: {src_ip} -> {dst_ip} | Type: {proto_name}")
        
        # Extract and display payload data if present in TCP or UDP
        if packet.haslayer(TCP) and packet[TCP].payload:
            payload_data = bytes(packet[TCP].payload)
            # Display a clean snippet of the payload (up to 60 characters)
            print(f"    [TCP Payload]: {payload_data[:60]}")
            
        elif packet.haslayer(UDP) and packet[UDP].payload:
            payload_data = bytes(packet[UDP].payload)
            print(f"    [UDP Payload]: {payload_data[:60]}")

def main():
    print("=" * 60)
    print("          BASIC NETWORK SNIFFER        ")
    print("=" * 60)
    print("[*] Initializing packet capture network interface...")
    print("[*] Sniffing active. Press Ctrl+C to safely terminate.")
    print("-" * 60)
    
    try:
        # Start sniffing. store=0 prevents memory bloating during prolonged capture.
        sniff(prn=process_packet, store=0)
    except KeyboardInterrupt:
        print("\n[-] Sniffing stopped by user. Exiting script.")
        sys.exit(0)
    except PermissionError:
        print("\n[!] Access Denied: This script requires administrative/root privileges.")
        print("[!] Windows: Run Command Prompt as Administrator.")
        print("[!] Linux/Mac: Execute using 'sudo python3 sniffer.py'.")
        sys.exit(1)

if __name__ == "__main__":
    main()
