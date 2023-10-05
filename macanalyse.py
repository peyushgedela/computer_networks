from scapy.all import *
import matplotlib.pyplot as plt
from collections import defaultdict

captured_packets = []  # List to store packet information

def packet_handler_mac(packet):
    if Ether in packet:
        src_mac = packet[Ether].src
        dst_mac = packet[Ether].dst
        packet_info = (src_mac, dst_mac)
        captured_packets.append(packet_info)

def analyze_packets_mac():
    # Process captured packet data for MAC addresses
    mac_counts = defaultdict(int)
    for src_mac, dst_mac in captured_packets:
        # You can further process or filter MAC addresses as needed
        mac_counts[(src_mac, dst_mac)] += 1

    return mac_counts

def create_bar_chart(mac_counts):
    # Extract data for plotting
    mac_pairs = list(mac_counts.keys())
    counts = list(mac_counts.values())

    # Create a bar chart
    plt.bar(range(len(mac_pairs)), counts)
    plt.xlabel('MAC Address Pairs')
    plt.ylabel('Count')
    plt.title('MAC Address Communication Counts')
    plt.xticks(range(len(mac_pairs)), mac_pairs, rotation='vertical')

    # Show the graph
    plt.tight_layout()
    plt.show()

def main():
    try:
        # Start capturing packets
        sniff(prn=packet_handler_mac, store=False)

        # Analyze captured packets for MAC addresses
        mac_counts = analyze_packets()
        
        # Create a bar chart for MAC address communication counts
        create_bar_chart(mac_counts)
    except KeyboardInterrupt:
        print("Packet capture stopped.")

if __name__ == "__main__":
    main()
