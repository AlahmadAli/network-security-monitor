from scapy.all import IP, TCP, UDP, sniff

stats = {
    "total": 0,
    "tcp": 0,
    "udp": 0,
    "other": 0
}

ip_counts = {}
local_ip = "10.0.0.71"

def process_packet(packet):
    if IP in packet:
        stats["total"] += 1
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst

        if destination_ip == local_ip:
            remote_ip = source_ip

        elif source_ip == local_ip:
            remote_ip = destination_ip

        else:
            remote_ip = None

        if remote_ip is not None:
            if remote_ip not in ip_counts:
                ip_counts[remote_ip] = 1

            else:
                ip_counts[remote_ip] += 1

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
sniff(prn=process_packet, count=10, filter="ip")

#packet summary
print(f"Network Summary\n"
      f"-------------------------\n"
      f"Total IP packets: {stats["total"]}\n"
      f"TCP packets: {stats["tcp"]}\n"
      f"UDP packets: {stats["udp"]}\n"
      f"Other packets: {stats["other"]}\n"
      )

print("Remote connections\n-------------------------")

for ip_address, count in sorted(
        ip_counts.items(),
        key=lambda item: item[1],
        reverse=True):
    print(f"{ip_address}: {count} packets")