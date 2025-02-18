import tkinter as tk
import threading
import os
from scapy.all import *

packet_count = 0
ids_detected = 0
ips_enabled = False
intrusion_detected = False
intrusion_ip = ""
intrusion_mac = ""

def packet_callback(packet):
    global packet_count
    global ids_detected
    global intrusion_detected
    global intrusion_ip
    global intrusion_mac

    packet_count += 1
    print(packet.summary())

    # Check if packet indicates an intrusion
    if packet.haslayer(IP):
        try:
            # Example: Detecting if packet contains certain payload
            if b'intrusion_pattern' in packet[Raw].load:
                intrusion_detected = True
                intrusion_ip = packet[IP].src
                intrusion_mac = packet.src
        except IndexError:
            # 'Raw' layer not found, ignore this packet
            pass

def start_sniffing():
    sniff(prn=packet_callback, store=0)

def start_snort():
    global ids_detected
    global ips_enabled
    snort_cmd = 'snort -A console -q -c your_config_file.conf'
    os.system(snort_cmd)
    # Assuming Snort prints detection logs to the console
    # You can parse these logs to determine IDS detections
    # For simplicity, let's assume it increments the counter when a detection occurs
    ids_detected += 1

def update_gui():
    global packet_count
    global ids_detected
    global ips_enabled
    global intrusion_detected
    global intrusion_ip
    global intrusion_mac

    root = tk.Tk()
    root.title("Network Monitoring")

    packet_label = tk.Label(root, text="Packet Count: ")
    packet_label.grid(row=0, column=0)
    packet_count_label = tk.Label(root, text=str(packet_count))
    packet_count_label.grid(row=0, column=1)

    ids_label = tk.Label(root, text="IDS Detected: ")
    ids_label.grid(row=1, column=0)
    ids_detected_label = tk.Label(root, text=str(ids_detected))
    ids_detected_label.grid(row=1, column=1)

    intrusion_label = tk.Label(root, text="Intrusion Detected: ")
    intrusion_label.grid(row=2, column=0)
    intrusion_detected_label = tk.Label(root, text=str(intrusion_detected))
    intrusion_detected_label.grid(row=2, column=1)

    intrusion_details_label = tk.Label(root, text="Intrusion Details: ")
    intrusion_details_label.grid(row=3, column=0)
    intrusion_details_text = tk.Text(root, height=5, width=30)
    intrusion_details_text.grid(row=3, column=1)

    def update_labels():
        packet_count_label.config(text=str(packet_count))
        ids_detected_label.config(text=str(ids_detected))
        intrusion_detected_label.config(text=str(intrusion_detected))
        if intrusion_detected:
            intrusion_details_text.delete(1.0, tk.END)
            intrusion_details_text.insert(tk.END, f"IP: {intrusion_ip}\nMAC: {intrusion_mac}")
        root.after(1000, update_labels)  # Update every 1 second

    update_labels()

    root.mainloop()

if __name__ == "__main__":
    sniff_thread = threading.Thread(target=start_sniffing)
    sniff_thread.start()
    snort_thread = threading.Thread(target=start_snort)
    snort_thread.start()
    gui_thread = threading.Thread(target=update_gui)
    gui_thread.start()
    sniff_thread.join()
    snort_thread.join()
    gui_thread.join()
