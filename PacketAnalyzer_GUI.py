import tkinter as tk
from tkinter import ttk
from threading import Thread, Event
from scapy.all import sniff, IP, TCP, UDP, ICMP, BOOTP, DHCP, ARP, Ether
from scapy.layers.http import HTTPRequest

# Define functions for processing packet layers
def get_tcp_flags(flags):
    flag_names = {
        'S': 'SYN',
        'A': 'ACK',
        'P': 'PSH',
        'F': 'FIN',
        'R': 'RST',
        'U': 'URG',
    }
    return ', '.join(flag_names.get(flag, flag) for flag in flags)

def get_icmp_type_name(icmp_type):
    icmp_type_name = {
        0: "Echo reply",
        3: "Destination Unreachable",
        4: "Source quench",
        5: "Redirect",
        8: "Echo",
        9: "Router advertisment",
        10: "Router selection",
        11: "Timer exceeded",
        13: "Timestamp",
        14: "Timestamp reply",
        15: "Information request",
        16: "Information reply",
        17: "Address mask request",
        18: "Address mask reply",
        30: "Traceroute",
    }
    return icmp_type_name.get(icmp_type, f"Unknown({icmp_type})")

def get_dhcp_type_name(dhcp_type):
    dhcp_type_name = {
        1: "DHCPDISCOVER",
        2: "DHCPOFFER",
        3: "DHCPREQUEST",
        4: "DHCPDECLINE",
        5: "DHCPACK",
        6: "DHCPNAK",
        7: "DHCPRELEASE",
        8: "DHCPINFORM",
        9: "DHCPFORCERENEW",
        10: "DHCPLEASEQUERYDONE",
        11: "DHCPLEASEUNASSIGNED",
        12: "DHCPLEASEUNKNOWN",
        13: "DHCPLEASEACTIVE",
        14: "DHCPBULKLEASEQUERY",
        15: "DHCPLEASEQUERYDONE",
        16: "DHCPACTIVELEASEQUERY",
        17: "DHCPLEASEQUERYSTATUS",
        18: "DHCPACTIVELEASEQUERY",
    }
    return dhcp_type_name.get(dhcp_type, f"Unknown({dhcp_type})")

# Define the callback function for packet sniffing
def packet_callback(packet, filter, gui_queue):
    src_mac = dst_mac = src_ip = dst_ip = "N/A"
    if Ether in packet:
        ether_layer = packet[Ether]
        src_mac = ether_layer.src
        dst_mac = ether_layer.dst

    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        if TCP in packet and filter in ['TCP', 'ALL']:
            tcp_layer = packet[TCP]
            flags = get_tcp_flags(tcp_layer.flags)
            packet_info = f"TCP Packet, Flags: {flags}"
        elif UDP in packet and filter in ['UDP', 'ALL']:
            udp_layer = packet[UDP]
            udp_payload = udp_layer.payload
            packet_info = f"UDP Packet, Length: {udp_layer.len}, Payload: {udp_payload}"
        elif ICMP in packet and filter in ['ICMP', 'ALL']:
            icmp_layer = packet[ICMP]
            type_name = get_icmp_type_name(icmp_layer.type)
            packet_info = f"ICMP Packet, Type: {type_name}, Code: {icmp_layer.type}, Payload: {bytes(icmp_layer.payload)}"
        elif ARP in packet and filter in ['ARP', 'ALL']:
            arp_layer = packet[ARP]
            arp_op_code = arp_layer.op
            if arp_op_code == 1:
                packet_info = f"ARP Packet, Who has {arp_layer.pdst}? Tell {arp_layer.psrc}"
            elif arp_op_code == 2:
                packet_info = f"ARP Packet, {arp_layer.pdst} is at {arp_layer.hwdst}"
        elif packet.haslayer(HTTPRequest) and filter in ['HTTP', 'ALL']:
            http_layer = packet[HTTPRequest]
            packet_info = f"HTTP Packet, {http_layer.Host.decode()} {http_layer.Path.decode()}"
        elif packet.haslayer(BOOTP) and packet.haslayer(DHCP) and filter in ['DHCP', 'ALL']:
            bootp_layer = packet[BOOTP]
            dhcp_layer = packet[DHCP]
            dhcp_type_name = get_dhcp_type_name(dhcp_layer.options[0][1])
            packet_info = f"DHCP Packet, Transaction ID: {bootp_layer.xid}, Type: {dhcp_layer.options[0][1]}, Name: {dhcp_type_name}"
        else:
            return

        gui_queue.put((src_ip, dst_ip, packet_info, src_mac, dst_mac))

# Define the sniffing thread function
def sniff_packets(filter, stop_event, gui_queue):
    sniff(prn=lambda x: packet_callback(x, filter, gui_queue), stop_filter=lambda x: stop_event.is_set())

# Define the main GUI class
class PacketSnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Packet Sniffer")

        self.gui_queue = queue.Queue()
        self.stop_event = Event()
        self.sniff_thread = None

        self.filter_var = tk.StringVar(value='ALL')

        self.create_widgets()
        self.update_display()

    def create_widgets(self):
        frame = ttk.Frame(self.root)
        frame.pack(fill=tk.BOTH, expand=True)

        # Filter dropdown
        filter_label = ttk.Label(frame, text="Filter:")
        filter_label.grid(row=0, column=0, padx=5, pady=5)

        filter_options = ['ALL', 'TCP', 'UDP', 'ICMP', 'HTTP', 'DHCP', 'ARP']
        filter_menu = ttk.OptionMenu(frame, self.filter_var, filter_options[0], *filter_options)
        filter_menu.grid(row=0, column=1, padx=5, pady=5)

        # Start and Stop buttons
        self.start_button = ttk.Button(frame, text="Start Sniffer", command=self.start_sniffer)
        self.start_button.grid(row=0, column=2, padx=5, pady=5)

        self.stop_button = ttk.Button(frame, text="Stop Sniffer", command=self.stop_sniffer, state=tk.DISABLED)
        self.stop_button.grid(row=0, column=3, padx=5, pady=5)

        # Packet display
        self.tree = ttk.Treeview(frame, columns=('Src', 'Dst', 'Info', 'Src MAC', 'Dst MAC'), show='headings')
        self.tree.heading('Src', text='Source IP')
        self.tree.heading('Dst', text='Destination IP')
        self.tree.heading('Info', text='Packet Info')
        self.tree.heading('Src MAC', text='Source MAC')
        self.tree.heading('Dst MAC', text='Destination MAC')

        self.tree.column('Src', width=150)
        self.tree.column('Dst', width=150)
        self.tree.column('Info', width=400)
        self.tree.column('Src MAC', width=150)
        self.tree.column('Dst MAC', width=150)

        self.tree.grid(row=1, column=0, columnspan=4, sticky='nsew')
        frame.rowconfigure(1, weight=1)
        frame.columnconfigure(3, weight=1)

    def start_sniffer(self):
        self.stop_event.clear()
        self.sniff_thread = Thread(target=sniff_packets, args=(self.filter_var.get(), self.stop_event, self.gui_queue))
        self.sniff_thread.start()
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)

    def stop_sniffer(self):
        self.stop_event.set()
        self.sniff_thread.join()
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

    def update_display(self):
        while not self.gui_queue.empty():
            src_ip, dst_ip, packet_info, src_mac, dst_mac = self.gui_queue.get()
            self.tree.insert('', tk.END, values=(src_ip, dst_ip, packet_info, src_mac, dst_mac))
        self.root.after(100, self.update_display)

if __name__ == "__main__":
    import queue
    root = tk.Tk()
    app = PacketSnifferApp(root)
    root.mainloop()
