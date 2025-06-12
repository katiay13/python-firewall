from scapy.all import sniff, IP
    # sniff: captures network packets
    # Can detect and access IP layer details inside packets

# Packet filter function
def packet_filter(packet):
    if IP in packet:
        src = packet[IP].src    # Source IP address
        dst = packet[IP].dst    # Dest IP address
        print(f"Packet: {src} --> {dst}")
        return True # Packet passed filter
    return False

# Sniff packets and apply filter
def main():
    print("Starting firewall...")
    sniff(filter="ip", prn=packet_filter, store=0)
        # store=0 : Don't keep the packets in memory

if __name__ == "__main__":
    main()