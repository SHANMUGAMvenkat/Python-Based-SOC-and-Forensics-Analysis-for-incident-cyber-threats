from scapy.all import sniff, wrpcap
import time

# List to store captured packets
captured_packets = []

# Define a function to process each packet
def process_packet(packet):
    # Append the packet to the list
    captured_packets.append(packet)
    # Print the packet summary
    print(packet.summary())

# Start time
start_time = time.time()

# Capture packets for 2 minutes
sniff(prn=process_packet, store=0, timeout=120)

# End time
end_time = time.time()

# Calculate duration of capture
capture_duration = end_time - start_time
print("Capture duration:", capture_duration, "seconds")

# Save captured packets to a PCAP file
wrpcap("networklogs.pcap", captured_packets)
print("Packets saved to networklogs.pcap")
