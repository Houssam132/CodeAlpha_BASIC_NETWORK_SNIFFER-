import ifaddr
from scapy.all import sniff, Raw
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.http import HTTPRequest
def packet_handler(packet):
    if packet.haslayer(IP):
        ip_layer = packet.getlayer(IP)
        print(f"IP Packet: {ip_layer.src} -> {ip_layer.dst}")

        if packet.haslayer(TCP):
            tcp_layer = packet.getlayer(TCP)
            print(f"TCP Segment: {tcp_layer.sport} -> {tcp_layer.dport}")
            print(f"   Length: {ip_layer.len}")
            print(f"   Checksum: {ip_layer.chksum}")
            print(f"   TTL: {ip_layer.ttl}")
            print(f"   Version: {ip_layer.version}")
            print(f"   Protocol: {ip_layer.proto}")
            if packet.haslayer(Raw):
                print(f"Data: {packet[Raw].load}")
            else:
                print("There is no data")

        elif packet.haslayer(UDP):
            udp_layer = packet.getlayer(UDP)
            print(f"UDP Datagram: {udp_layer.sport} -> {udp_layer.dport}")
            print(f"   Length: {udp_layer.len}")
            print(f"   Checksum: {udp_layer.chksum}")

            if packet.haslayer(Raw):
                print(f"Data: {packet[Raw].load}")
def process_packet(packet):
    if packet.haslayer(HTTPRequest):
        print(packet)

def start_sniffing(interface):
    print(f"Starting packet capture on {interface}")
    try:
        sniff(iface=interface, prn=packet_handler, count=10)
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    print("Available interfaces:")
    adapters = ifaddr.get_adapters()
    for adapter in adapters:
        for ip in adapter.ips:
            print(f"{adapter.nice_name}: {ip.ip}")

    # Replace this with the name of the interface you want to use for sniffing
    interface = "Intel(R) Wireless-AC 9560 160MHz"  # Example interface name, replace with your actual interface name
    start_sniffing(interface)
