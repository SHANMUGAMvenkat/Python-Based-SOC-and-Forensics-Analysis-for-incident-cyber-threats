import pyshark
import networkx as nx
import matplotlib.pyplot as plt

# Function to analyze the pcap file and create a graph
def analyze_pcap(pcap_file):
    # Create a network graph
    G = nx.Graph()

    # Open the pcap file for reading
    cap = pyshark.FileCapture(pcap_file)

    # Iterate over each packet in the pcap file
    for packet in cap:
        # Check if the packet has IP layer
        if 'IP' in packet:
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            protocol = packet.transport_layer   # TCP, UDP, ICMP, etc.

            # Add edges between source and destination IPs
            G.add_edge(src_ip, dst_ip, protocol=protocol)

    # Close the pcap file
    cap.close()

    return G

# Function to visualize the graph
def visualize_graph(G):
    # Draw the graph
    pos = nx.spring_layout(G)
    nx.draw(G, pos, with_labels=True, node_size=300, node_color="skyblue", font_size=10)
    plt.title("Network Graph")
    plt.show()

    # Print source and destination of packets with protocol
    print("Packet Source-Destination pairs:")
    for edge in G.edges(data=True):
        src = edge[0]
        dst = edge[1]
        protocol = edge[2]['protocol']
        print(f"Source: {src}, Destination: {dst}, Protocol: {protocol}")

# Function to check for potentially malicious destinations
def check_malicious_destinations(G):
    # Initialize a list to store potentially malicious destinations
    malicious_destinations = []

    # Iterate over nodes in the graph
    for node in G.nodes():
        # Check if the node has only one connection (unusual behavior)
        if len(list(G.neighbors(node))) == 1:
            malicious_destinations.append(node)

    return malicious_destinations

# Main function
def main():
    pcap_file = "networklogs.pcap"

    # Analyze the pcap file
    G = analyze_pcap(pcap_file)

    # Visualize the graph
    visualize_graph(G)

    # Check for potentially malicious destinations
    malicious_destinations = check_malicious_destinations(G)
    if malicious_destinations:
        print("Potentially malicious destinations found:")
        for dest in malicious_destinations:
            print(dest)
    else:
        print("No potentially malicious destinations found.")

if __name__ == "__main__":
    main()
