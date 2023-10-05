from scapy.all import *
import matplotlib.pyplot as plt
import plotly.express as px
from collections import defaultdict

captured_packets = []  # List to store packet information

def packet_handler(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        packet_info = (src_ip, dst_ip)
        captured_packets.append(packet_info)

def analyze_packets(protocol):
    # Start capturing packets with the specified protocol filter
    sniff(count=500, prn=packet_handler, filter=protocol)

    # Process captured packet data
    communication_counts = defaultdict(int)
    for src_ip, dst_ip in captured_packets:
        communication_counts[(src_ip, dst_ip)] += 1

    return communication_counts

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


def create_scatter_chart(communication_counts, protocol):
    # Extract data for plotting
    communication_pairs = list(communication_counts.keys())
    counts = list(communication_counts.values())

    # Create a scatter plot
    plt.scatter(range(len(communication_pairs)), counts)
    plt.xlabel('Communication Pairs')
    plt.ylabel('Count')
    plt.title('Scatter Plot for Protocol: ' + protocol)
    plt.xticks(range(len(communication_pairs)), communication_pairs, rotation='vertical')

    # Show the graph
    plt.tight_layout()
    plt.show()

def create_pie_chart(communication_counts, protocol):
    # Extract data for plotting
    labels = list(communication_counts.keys())
    counts = list(communication_counts.values())

    # Create a pie chart
    plt.pie(counts, labels=labels, autopct='%1.1f%%', startangle=140)
    plt.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle.

    plt.title('Pie Chart for Protocol: ' + protocol)

    # Show the graph
    plt.show()

def create_line_chart(communication_counts, protocol):
    # Extract data for plotting
    communication_pairs = list(communication_counts.keys())
    counts = list(communication_counts.values())

    # Create a line chart
    plt.plot(range(len(communication_pairs)), counts, marker='o')
    plt.xlabel('Communication Pairs')
    plt.ylabel('Count')
    plt.title('Line Chart for Protocol: ' + protocol)
    plt.xticks(range(len(communication_pairs)), communication_pairs, rotation='vertical')

    # Show the graph
    plt.tight_layout()
    plt.show()

def create_bar_chart(communication_counts, protocol):
    # Extract data for plotting
    communication_pairs = list(communication_counts.keys())
    counts = list(communication_counts.values())

    # Create a line chart
    plt.bar(range(len(communication_pairs)), counts)
    plt.xlabel('Communication Pairs')
    plt.ylabel('Count')
    plt.title('Bar Chart for Protocol: ' + protocol)
    plt.xticks(range(len(communication_pairs)), communication_pairs, rotation='vertical')

    # Show the graph
    plt.tight_layout()
    plt.show()
    
def create_treemap(communication_counts, analyze_protocol):
    data = []
    labels = list(communication_counts.keys())
    counts = list(communication_counts.values())

    for i in range(len(labels)):
        data.append({'Label': labels[i], 'Count': counts[i]})

    # Create a treemap
    fig = px.treemap(data, path=['Label'], values='Count')

    fig.update_layout(title=f'Treemap for {analyze_protocol.upper()} Address Communication Counts')
    fig.show()

def main():
    try:
        lay = input("Enter for IP/MAC address ('ip', 'mac'): ")
        if(lay == 'ip'):
            # Prompt the user to enter a protocol
            protocol = input("Enter the protocol to capture (e.g., 'ip', 'tcp', 'udp', 'icmp'): ")
            # Analyze captured packets for the specified protocol
            communication_counts = analyze_packets(protocol)
        elif(lay == 'mac'):
            protocol = 'mac'
            # Start capturing packets
            sniff(prn=packet_handler_mac, store=False, count=500)
            communication_counts = analyze_packets_mac()

        # Prompt the user to select a graph type
        print("Select a graph type:")
        print("1. Scatter Plot")
        print("2. Pie Chart")
        print("3. Line Chart")
        print("4. Bar Chart")
        print("5. TreeMap Chart")
        graph_type = input("Enter the number for your choice (1/2/3/4/5): ")

        if graph_type == '1':
            create_scatter_chart(communication_counts, protocol)
        elif graph_type == '2':
            create_pie_chart(communication_counts, protocol)
        elif graph_type == '3':
            create_line_chart(communication_counts, protocol)
        elif graph_type == '4':
            create_bar_chart(communication_counts, protocol)
        elif graph_type == '5':
            create_treemap(communication_counts, protocol)
        else:
            print("Invalid choice. Please select a valid graph type (1/2/3/4).")
    except KeyboardInterrupt:
        print("Packet capture stopped.")

if __name__ == "__main__":
    main()
