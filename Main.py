import csv
import tkinter as tk
from tkinter import ttk
import threading
import numpy as np, datetime
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.http import HTTPRequest
from datetime import datetime
import os

CSV_FILE = '/PythonProject1/data.csv'

if not os.path.exists(CSV_FILE) or os.path.getsize(CSV_FILE) == 0:
    with open(CSV_FILE, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["protocol_name", "src_ip", "dst_ip", "time", "full_url"])


def packet_callback(packet):
    if IP in packet:
        ip_layer = packet[IP]
        protocol = ip_layer.proto
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        protocol_name = ""
        full_url = ""

        if packet.haslayer(HTTPRequest):
            http_layer = packet[HTTPRequest]
            host = http_layer.Host.decode() if http_layer.Host else ''
            path = http_layer.Path.decode() if http_layer.Path else ''
            full_url = f"http://{host}{path}"
            print(f"URL visited {full_url}")
        if protocol == 1:
            protocol_name = "ICMP"
        elif protocol == 6:
            protocol_name = "TCP"
        elif protocol == 17:
            protocol_name = "UDP"
        else:
            protocol_name = "Unknown protocol"

        with open('/PythonProject1/data.csv', 'a') as f:
            time = datetime.now()
            np.savetxt(f, [[protocol_name, src_ip, dst_ip, time, full_url]], delimiter=',', fmt='%s')

        print(f"Protocol: {protocol_name}")
        print(f"Source IP: {src_ip}")
        print(f"Destination IP: {dst_ip}")
        print(f"Time: {time}")
        print("-" * 50)

def display_csv_data(filepath, tree, status_label):

    filepath = "/PythonProject1/data.csv"
    try:
        with open(filepath, 'r', newline='') as file:

            csv_reader = csv.reader(file)
            header = next(csv_reader)

            tree.delete(*tree.get_children())

            tree["columns"] = header
            for col in header:
                tree.heading(col, text=col)
                tree.column(col, width=220)


            for row in csv_reader:
                tree.insert("", "end", values=row)
            status_label.config(text=f"CSV file loaded: {filepath}")
    except Exception as e:
        status_label.config(text=f"Error: {str(e)}")

def update_data():
    display_csv_data("/PythonProject1/data.csv", tree, status_label)
    root.after(3000, update_data)

def sniff_thread():
    sniff(prn=packet_callback, filter="ip", store=0)

def main():
    global root, tree, status_label
    root = tk.Tk()
    root.title("Live Traffic Monitor")

    root.attributes('-fullscreen', True)
    root.resizable(False, False)

    tree = ttk.Treeview(root)
    tree.pack(fill='both', expand=True)

    status_label = tk.Label(root, text="Status: Waiting for data...")
    status_label.pack()

    # Start sniffing in a separate thread
    threading.Thread(target=sniff_thread, daemon=True).start()

    update_data()
    root.mainloop()

if __name__ == "__main__":
    main()
