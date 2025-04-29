import threading
import time
from datetime import datetime
import tkinter as tk
from tkinter import ttk, messagebox
from scapy.all import sniff, IP
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

class PacketSnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Packet Sniffer")
        self.root.geometry("900x600")

        self.is_sniffing = False
        self.packets = []
        self.protocol_counts = {}

        # Setup UI
        self.setup_ui()

    def setup_ui(self):
        # Frame for controls
        control_frame = ttk.Frame(self.root)
        control_frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Label(control_frame, text="Interface:").pack(side=tk.LEFT)
        self.interface_entry = ttk.Entry(control_frame, width=15)
        self.interface_entry.pack(side=tk.LEFT, padx=5)
        self.interface_entry.insert(0, "eth0")

        self.start_button = ttk.Button(control_frame, text="Start Capture", command=self.start_capture)
        self.start_button.pack(side=tk.LEFT, padx=5)

        self.stop_button = ttk.Button(control_frame, text="Stop Capture", command=self.stop_capture, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)

        # Treeview for packet list
        columns = ("timestamp", "src_ip", "dst_ip", "protocol")
        self.tree = ttk.Treeview(self.root, columns=columns, show="headings")
        self.tree.heading("timestamp", text="Timestamp")
        self.tree.heading("src_ip", text="Source IP")
        self.tree.heading("dst_ip", text="Destination IP")
        self.tree.heading("protocol", text="Protocol")
        self.tree.column("timestamp", width=150)
        self.tree.column("src_ip", width=150)
        self.tree.column("dst_ip", width=150)
        self.tree.column("protocol", width=100)
        self.tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # Matplotlib figure for protocol distribution
        self.fig, self.ax = plt.subplots(figsize=(5, 3))
        self.canvas = FigureCanvasTkAgg(self.fig, master=self.root)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=False, padx=10, pady=5)

        self.ax.set_title("Protocol Distribution")
        self.ax.axis('equal')

    def start_capture(self):
        iface = self.interface_entry.get().strip()
        if not iface:
            messagebox.showerror("Error", "Please enter a network interface.")
            return
        self.is_sniffing = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.packets.clear()
        self.protocol_counts.clear()
        self.tree.delete(*self.tree.get_children())
        self.ax.clear()
        self.ax.set_title("Protocol Distribution")
        self.ax.axis('equal')
        self.canvas.draw()
        self.sniff_thread = threading.Thread(target=self.sniff_packets, args=(iface,), daemon=True)
        self.sniff_thread.start()
        self.update_gui()

    def stop_capture(self):
        self.is_sniffing = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

    def sniff_packets(self, iface):
        sniff(iface=iface, prn=self.packet_callback, store=False, stop_filter=lambda x: not self.is_sniffing)

    def packet_callback(self, packet):
        if IP in packet:
            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            proto_num = ip_layer.proto
            proto_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto_num, str(proto_num))
            timestamp = datetime.now().strftime("%H:%M:%S")
            self.packets.append((timestamp, src_ip, dst_ip, proto_name))
            self.protocol_counts[proto_name] = self.protocol_counts.get(proto_name, 0) + 1

    def update_gui(self):
        if not self.is_sniffing:
            return
        # Update treeview with new packets
        for pkt in self.packets:
            self.tree.insert("", tk.END, values=pkt)
        self.packets.clear()

        # Update protocol distribution pie chart
        self.ax.clear()
        self.ax.pie(self.protocol_counts.values(), labels=self.protocol_counts.keys(), autopct='%1.1f%%', startangle=140)
        self.ax.set_title("Protocol Distribution")
        self.ax.axis('equal')
        self.canvas.draw()

        # Schedule next update
        self.root.after(1000, self.update_gui)

def main():
    root = tk.Tk()
    app = PacketSnifferGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
