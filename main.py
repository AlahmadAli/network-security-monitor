from scapy.all import IP, TCP, UDP, sniff

stats = {
    "total": 0,
    "tcp": 0,
    "udp": 0,
    "other": 0
}

def process_packet(packet):
    if IP in packet:
        stats["total"] += 1
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst

        #tcp packet info
        if TCP in packet:
            stats["tcp"] += 1
            protocol = "TCP"
            source_port = packet[TCP].sport
            destination_port = packet[TCP].dport

        #udp packet info
        elif UDP in packet:
            stats["udp"] += 1
            protocol = "UDP"
            source_port = packet[UDP].sport
            destination_port = packet[UDP].dport

        #other (unimplemented yet) packet info
        else:
            stats["other"] += 1
            protocol = "Other"
            source_port, destination_port = None, None

        #summary
        print(f"Source: {source_ip}:{source_port}\n"
              f"Destination: {destination_ip}:{destination_port}\n"
              f"Protocol: {protocol}\n"
              f"-------------------------\n"
              )


print("Monitoring network traffic... Press Ctrl+C to stop.\n")
sniff(prn=process_packet, count= 10, filter = "ip")

#packet summary
print(f"Network Summary\n"
      f"-------------------------\n"
      f"Total IP packets: {stats["total"]}\n"
      f"TCP packets: {stats["tcp"]}\n"
      f"UDP packets: {stats["udp"]}\n"
      f"Other packets: {stats["other"]}\n"
      )