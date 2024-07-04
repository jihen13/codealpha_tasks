from scapy.all import sniff, TCP, UDP, ICMP, IP, ARP
import logging


logging.basicConfig(format='%(asctime)s - %(message)s', level=logging.INFO)

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        logging.info(f"IP Packet: {ip_src} -> {ip_dst}")

        if TCP in packet:
            tcp_src_port = packet[TCP].sport
            tcp_dst_port = packet[TCP].dport
            logging.info(f"TCP Packet: {ip_src}:{tcp_src_port} -> {ip_dst}:{tcp_dst_port}")
        
        elif UDP in packet:
            udp_src_port = packet[UDP].sport
            udp_dst_port = packet[UDP].dport
            logging.info(f"UDP Packet: {ip_src}:{udp_src_port} -> {ip_dst}:{udp_dst_port}")
        
        elif ICMP in packet:
            icmp_type = packet[ICMP].type
            icmp_code = packet[ICMP].code
            logging.info(f"ICMP Packet: {ip_src} -> {ip_dst} (Type: {icmp_type}, Code: {icmp_code})")
    
    elif ARP in packet:
        arp_src_ip = packet[ARP].psrc
        arp_dst_ip = packet[ARP].pdst
        arp_op = packet[ARP].op
        logging.info(f"ARP Packet: {arp_src_ip} -> {arp_dst_ip} (Operation: {arp_op})")


def start_sniffing(interface=None, packet_count=0):
    if interface:
        sniff(iface=interface, prn=packet_callback, count=packet_count)
    else:
        sniff(prn=packet_callback, count=packet_count)

if __name__ == "__main__":
   
    interface = None  
    packet_count = 10  
    logging.info("Starting the network sniffer...")
    start_sniffing(interface=interface, packet_count=packet_count)
