from scapy.all import *
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet

# List to store packet information
packet_info_list = []

def packet_handler(packet):
    if IP in packet:
        src_port = None
        dst_port = None
        protocol = packet[IP].proto

        # Check if the packet has a transport layer (TCP or UDP)
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        # Determine the protocol name based on protocol number
        if protocol == 6:
            protocol_name = "TCP"
        elif protocol == 17:
            protocol_name = "UDP"
        elif protocol == 1:
            protocol_name = "ICMP"
        else:
            protocol_name = "Other"

        packet_info = f"Source Port: {src_port}, Destination Port: {dst_port}, Protocol: {protocol_name}"
        packet_info_list.append(packet_info)

def generate_pdf_summary():
    doc = SimpleDocTemplate("packet_portsummary.pdf", pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []

    for packet_info in packet_info_list:
        elements.append(Paragraph(packet_info, styles["Normal"]))
        elements.append(Spacer(1, 12))  # Add some space between entries

    doc.build(elements)

def main():
    pcap_file = 'lab8chk1.pcap'  # Replace with the path to your pcap file

    try:
        # Read the pcap file and capture packets
        packets = rdpcap(pcap_file)

        # Process each packet and gather packet information
        for packet in packets:
            packet_handler(packet)

        # Generate a PDF summary containing all packet details
        generate_pdf_summary()

        print("Packet analysis and PDF generation complete.")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
