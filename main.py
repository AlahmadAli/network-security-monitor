import packet_analyzer
from scapy.all import sniff

print("Monitoring network traffic... Press Ctrl+C to stop.\n")
sniff(prn=packet_analyzer.process_packet, count=200, filter="ip")

#packet summary
print(f"Network Summary\n"
      f"-------------------------\n"
      f"Total IP packets: {packet_analyzer.stats["total"]}\n"
      f"TCP packets: {packet_analyzer.stats["tcp"]}\n"
      f"UDP packets: {packet_analyzer.stats["udp"]}\n"
      f"Other packets: {packet_analyzer.stats["other"]}\n"
      )

print("Remote connections\n-------------------------")

for ip_address, count in sorted(
        packet_analyzer.ip_counts.items(),
        key=lambda item: item[1],
        reverse=True):
    print(f"{ip_address}: {count} packets")


print("\nRemote ports\n-------------------------")
for ip_address, ports in sorted(
        packet_analyzer.ip_ports.items(),
        key=lambda item: len(item[1]),
        reverse=True):
    print(f"{ip_address}: {', '.join(map(str, sorted(ports)))}")