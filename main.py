import packet_analyzer
from scapy.all import sniff

print("Monitoring network traffic... Press Ctrl+C to stop.\n")
sniff(prn=packet_analyzer.process_packet, count=20, filter="ip")


for ip_address, host_data in packet_analyzer.hosts.items():
    packet_analyzer.detect_suspicious_activity(ip_address, host_data)

# packet summary
print(f"Network Summary\n"
      f"-------------------------\n"
      f"Total IP packets: {packet_analyzer.stats["total"]}\n"
      f"TCP packets: {packet_analyzer.stats["tcp"]}\n"
      f"UDP packets: {packet_analyzer.stats["udp"]}\n"
      f"Other packets: {packet_analyzer.stats["other"]}\n"
      )

# Get hostname for local IP address and print its packet count
print("Remote hosts\n-------------------------")

for ip_address, host_data in sorted(
        packet_analyzer.hosts.items(),
        key=lambda item: item[1]["packets"],
        reverse=True):
    print(
        f"{ip_address} ({packet_analyzer.get_hostname(ip_address)}): {host_data['packets']} packets")

# Get remote ports and print them in a sorted manner
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

# Prints out the traffic volume for each remote IP address in descending order
print("\nTraffic Volume\n-------------------------")
for ip_address, host_data in sorted(
        packet_analyzer.hosts.items(),
        key=lambda item: item[1]["bytes"],
        reverse=True):
    print(f"{ip_address}: {packet_analyzer.format_bytes(host_data['bytes'])}")

alerts_found = False

# Alert printing section
for ip_address, host_data in packet_analyzer.hosts.items():
    if host_data["alerts"]:
        alerts_found = True
        print(
            f"\nSuspicious Activity Detected for {ip_address} ({packet_analyzer.get_hostname(ip_address)}):")
        for alert in host_data["alerts"]:
            print(
                f"-[{alert['first_seen']}] [{alert['severity']}] {alert['message']}")
            for update in alert.get("incident_update", []):
                print(f"   - {update}")
if not alerts_found:
    print("\nNo suspicious activity detected.")
