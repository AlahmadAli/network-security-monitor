from scapy.all import IP, TCP, UDP
import socket

stats = {
    "total": 0,
    "tcp": 0,
    "udp": 0,
    "other": 0
}

ip_counts = {}

def get_local_ip():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.connect(("8.8.8.8", 0))
    local_ip = sock.getsockname()[0]
    sock.close()
    return local_ip

local_ip = get_local_ip()

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

