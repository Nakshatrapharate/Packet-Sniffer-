import tkinter as tk
from tkinter import messagebox
from threading import Thread
import scapy.all as scapy
import argparse
from scapy.layers import http

def get_interface():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface", help="Specify interface on which to sniff packets")
    arguments = parser.parse_args()
    return arguments.interface

def sniff(iface):
    try:
        scapy.sniff(iface=iface, store=False, prn=process_packet)
    except Exception as e:
        print("An error occurred while sniffing packets:", e)

def process_packet(packet):
    try:
        if packet.haslayer(http.HTTPRequest):
            host = packet[http.HTTPRequest].Host.decode() if isinstance(packet[http.HTTPRequest].Host, bytes) else packet[http.HTTPRequest].Host
            path = packet[http.HTTPRequest].Path.decode() if isinstance(packet[http.HTTPRequest].Path, bytes) else packet[http.HTTPRequest].Path
            method = packet[http.HTTPRequest].Method.decode() if isinstance(packet[http.HTTPRequest].Method, bytes) else packet[http.HTTPRequest].Method

            if packet.haslayer(scapy.IP):
                src_ip = packet[scapy.IP].src
                dst_ip = packet[scapy.IP].dst
            elif packet.haslayer(scapy.IPv6):
                src_ip = packet[scapy.IPv6].src
                dst_ip = packet[scapy.IPv6].dst

            src_port = packet[scapy.TCP].sport
            dst_port = packet[scapy.TCP].dport

            output_text.insert(tk.END, "[+] HTTP Request >> Method: {}\nHost: {}\nPath: {}\nSrc_IP: {}\nSrc_Port: {}\nDst_IP: {}\nDst_Port: {}\n\n".format(method, host, path, src_ip, src_port, dst_ip, dst_port))
            
            if packet.haslayer(scapy.Raw):
                load = packet[scapy.Raw].load.decode() if isinstance(packet[scapy.Raw].load, bytes) else packet[scapy.Raw].load
                keys = ["username", "password", "pass", "email"]
                
                for key in keys:
                    if key in load:
                        output_text.insert(tk.END, "\n\n[+] Possible password/username >> " + load + "\n\n")
                        messagebox.showwarning("Vulnerability Detected", "Site is vulnerable! Possible password/username detected.")
                        return  # Exit the function after displaying the vulnerability message
    except Exception as e:
        print("An error occurred while processing packet:", e)

def start_sniffing():
    iface = interface_entry.get()
    if iface:
        # Start packet sniffing in a separate thread
        Thread(target=sniff, args=(iface,)).start()
    else:
        messagebox.showerror("Error", "Please enter an interface name.")

# Create the main window
root = tk.Tk()
root.title("Packet Sniffer")

# Create and place interface label and entry
interface_label = tk.Label(root, text="Interface:")
interface_label.grid(row=0, column=0, padx=5, pady=5)
interface_entry = tk.Entry(root)
interface_entry.grid(row=0, column=1, padx=5, pady=5)

# Create and place start button
start_button = tk.Button(root, text="Start Sniffing", command=start_sniffing)
start_button.grid(row=1, column=0, columnspan=2, padx=5, pady=5)

# Create output text widget
output_text = tk.Text(root, height=20, width=80)
output_text.grid(row=2, column=0, columnspan=2, padx=5, pady=5)

# Run the GUI main loop
root.mainloop()
