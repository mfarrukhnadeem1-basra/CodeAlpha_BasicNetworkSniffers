from scapy.all import sniff
from scapy.layers.inet import IP, TCP
import time

def process_packet(packet):
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        print(f"Time: {time.strftime('%H:%M:%S')}")
        print(f"Source IP: {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")
        print(f"Protocol: {ip_layer.proto}")
        
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            print(f"Source Port: {tcp_layer.sport}")
            print(f"Destination Port: {tcp_layer.dport}")
            print(f"Flags: {tcp_layer.flags}")
        
        print("-" * 40)

print("Sniffing only TCP packets...")
sniff(prn=process_packet, store=False, filter="tcp", count=10)
