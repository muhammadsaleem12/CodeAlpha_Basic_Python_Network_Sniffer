from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
import datetime


def packet_handler(packet):


    if IP in packet:
        timestamp = datetime.datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S')

        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = "OTHER"


        if TCP in packet:
            protocol = "TCP"
        elif UDP in packet:
            protocol = "UDP"
        elif ICMP in packet:
            protocol = "ICMP"


        print(f"TimeStamp : {timestamp} Source IP :[{src_ip}] -> Destination IP [{dst_ip}] | protocol : {protocol}")

        if Raw in packet:
            payload = packet[Raw].load
            try:
                print(f"Payload : {payload[:50]}")
            except:
                print("Payload : (non-readable data)")
            

            print("-" * 60)


print("Starting packet capture... Press Ctrl+C to stop./n")
sniff(prn=packet_handler, store=False)
    