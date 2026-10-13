import packet_analyzer
from scapy.all import sniff

print("Monitoring network traffic... Press Ctrl+C to stop.\n")
sniff(prn=packet_analyzer.process_packet, count=20, filter="ip")

#packet summary
print(f"Network Summary\n"
      f"-------------------------\n"
      f"Total IP packets: {packet_analyzer.stats["total"]}\n"
      f"TCP packets: {packet_analyzer.stats["tcp"]}\n"
      f"UDP packets: {packet_analyzer.stats["udp"]}\n"
      f"Other packets: {packet_analyzer.stats["other"]}\n"
      )

print("Remote connections\n-------------------------")

for ip_address, host_data in sorted(
        packet_analyzer.hosts.items(),
        key=lambda item: item[1]["packets"],
        reverse=True):
    print(f"{ip_address} ({packet_analyzer.get_hostname(ip_address)}): {host_data['packets']} packets")


print("\nRemote ports\n-------------------------")
for ip_address, host_data in sorted(
        packet_analyzer.hosts.items(),
        key=lambda item: len(item[1]["ports"]),
        reverse=True):
    port_info = []
    for port in sorted(host_data["ports"]):
        service = packet_analyzer.get_service(port)
        port_info.append(f"{port} ({service})")
    print(f"{ip_address}: {', '.join(port_info)}")

print("\nTraffic Volume\n-------------------------")
for ip_address, host_data in sorted(
        packet_analyzer.hosts.items(),
        key=lambda item: item[1]["bytes"],
        reverse=True):
    print(f"{ip_address}: {packet_analyzer.format_bytes(host_data['bytes'])}")