from scapy.all import sniff, IP, TCP, UDP, ICMP, BOOTP, DHCP, ARP, Ether # Ether package to handle ethernet layer (Data link layer)
from scapy.layers.http import HTTPRequest

def get_tcp_flags(flags):
    flag_names={
        'S':'SYN',
        'A':'ACK',
        'P':'PSH',
        'F':'FIN',
        'R':'RST',
        'U':'URG',               
    }
    return ', '.join(flag_names.get(flag,flag) for flag in flags) 

def get_icmp_type_name(icmp_type):
    icmp_type_name = {
        0:"Echo reply",
        3:"Destination Unreachable",
        4:"Source quench",
        5:"Redirect",
        8:"Echo",
        9:"Router advertisment",
        10:"Router selection",
        11:"Timer exceeded",
        13:"Timestamp",
        14:"Timestamp reply",
        15:"Information request",
        16:"Information reply",
        17:"Address mask request",
        18:"Address mask reply",
        30:"Traceroute",
    }
    return icmp_type_name.get(icmp_type,f"Unknown({icmp_type})")

def get_dhcp_type_name(dhcp_type):
    dhcp_type_name = {
        1:"DHCPDISCOVER",
        2:"DHCPOFFER",
        3:"DHCPREQUEST",
        4:"DHCPDECLINE",
        5:"DHCPACK",
        6:"DHCPNAK",
        7:"DHCPRELEASE",
        7:"DHCPRELEASE",
        8:"DHCPINFORM",
        9:"DHCPFORCERENEW",
        10:"DHCPFORCERENEW",
        11:"DHCPLEASEUNASSIGNED",
        12:"DHCPLEASEUNKOWN",
        13:"DHCPLEASEACTIVE",
        14:"DHCPBULKLEASEQUERY",
        15:"DHCPLEASEQUERYDONE",
        16:"DHCPACTIVELEASEQUERY",
        17:"DHCPLEASEQUERYSTATUS",
        18:"DHCPACTIVELEASEQUERY",
    }
    return dhcp_type_name.get(dhcp_type,f"Unknown({dhcp_type})")


def packet_callback(packet, filter):
    # print("packet recived")
    if Ether in packet:                  # Does packet contain an ethernet or Data Link layer
        ether_layer = packet[Ether]       # Acces ethernet layer
        src_mac = ether_layer.src
        dst_mac=ether_layer.dst
    # NOTE: You can access Ethernet layer after IP layer
    if IP in packet:                     # Does packet contain an IP or Network layer
        ip_layer = packet[IP]            # Access network layer
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        

        if TCP in packet and filter in ['TCP', 'ALL']:
            tcp_layer = packet[TCP]
            flags=get_tcp_flags(tcp_layer.flags)  #tcp_layer.flags
            print(f"TCP Packet: {src_ip}( {src_mac} ) -> {dst_ip}( {dst_mac} ), Flags: {flags}")
            
        elif UDP in packet and filter in ['UDP', 'ALL']:
            udp_layer = packet[UDP]
            udp_payload=(udp_layer.payload)
            print(f"UDP Packet: {src_ip}( {src_mac} ) -> {dst_ip}( {dst_mac} ), Length:{udp_layer.len}, Payload:{udp_payload}")
            
        elif ICMP in packet and filter in ['ICMP', 'ALL']:
            icmp_layer = packet[ICMP]
            type_name = get_icmp_type_name(icmp_layer.type)
            type_code = icmp_layer.type
            payload = bytes(icmp_layer.payload)
            print(f"ICMP Packet: {src_ip}( {src_mac} ) -> {dst_ip}( {dst_mac} ), Type: {type_name}, Code: {type_code}, Payload: {payload}")
            
        elif ARP in packet and filter in ['ARP','ALL']:
            ARP_layer = packet[ARP]
            arp_op_code=ARP_layer.op
            print(f"ARP Packet: {ARP_layer.psrc} -> {ARP_layer.pdst}, Operation: {arp_op_code} ")  # No src_ip and dst_ip because ARP operates at "data link" layer
            if(arp_op_code==1): # Who has (request) 
                print(f"Who has {ARP_layer.pdst}? Tell {ARP_layer.psrc}")    # psrc (Protocol Source Address)    pdst (Protocol Destination Address)
            elif(arp_op_code==2):  # is-at (reply)
                print(f"{ARP_layer.pdst} is at {ARP_layer.hwdst}")                         # hwsrc (Hardware Source Address)
            
            
        elif packet.haslayer(HTTPRequest) and filter in ['HTTP', 'ALL']:
            http_layer = packet[HTTPRequest]
            print(f"HTTP Packet: {src_ip}( {src_mac} ) -> {dst_ip}( {dst_mac} ), {http_layer.Host.decode()} {http_layer.Path.decode()}")
        
        elif packet.haslayer(BOOTP) and packet.haslayer(DHCP) and filter in ['DHCP','ALL']:
            bootp_layer = packet[BOOTP]
            dhcp_layer = packet[DHCP]
            dhcp_options = dhcp_layer.options
            dhcp_type_name = get_dhcp_type_name(dhcp_layer.options[0][1])
            print(f"DHCP Packet: {src_ip}( {src_mac} ) -> {dst_ip}( {dst_mac} ), Transaction ID: {bootp_layer.xid}, Type code: {dhcp_options[0][1]} , Type name: {dhcp_type_name}")
            
            
def run_sniffer(filter='ALL'):
    sniff(prn=lambda x: packet_callback(x, filter))

if __name__ == "__main__": 
    filterInput=input("Enter Display filter (Options: 'TCP', 'UDP', 'ICMP', 'HTTP', 'DHCP', 'ARP', 'ALL'): ")
    filter = filterInput  # Options: 'TCP', 'UDP', 'ICMP', 'HTTP', 'DHCP', 'ARP', 'ALL'
    run_sniffer(filter)
