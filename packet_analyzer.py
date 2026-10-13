from scapy.all import IP, TCP, UDP
import socket

stats = {
    "total": 0,
    "tcp": 0,
    "udp": 0,
    "other": 0
}


hosts = {}
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
            remote_port_location = "source_port"

        elif source_ip == local_ip:
            remote_ip = destination_ip
            remote_port_location = "destination_port"

        else:
            remote_ip = None
            remote_port_location = None

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


        # update packet count and traffic volume for remote IP address
        if remote_ip is not None:
            if remote_ip not in hosts:
                hosts[remote_ip] = {"packets": 0,
                                     "ports": set(),
                                     "bytes": 0}

            hosts[remote_ip]["packets"] += 1
            hosts[remote_ip]["bytes"] += len(packet)

        # determine the remote port based on the direction of the packet

        if remote_port_location == "source_port" and source_port is not None:
            remote_port = source_port
        elif remote_port_location == "destination_port" and destination_port is not None:
            remote_port = destination_port
        else:
            remote_port = None

        if remote_port is not None:
            hosts[remote_ip]["ports"].add(remote_port)

        #summary
        print(f"Source: {source_ip}:{source_port}\n"
              f"Destination: {destination_ip}:{destination_port}\n"
              f"Protocol: {protocol}\n"
              f"-------------------------\n"
              )

def get_service(port):
    try:
        service = socket.getservbyport(port)
    except OSError:
        service = "Unknown"

    return service

def get_hostname(ip_address):
    try:
        hostname = socket.gethostbyaddr(ip_address)[0]
    except OSError: #includes gaierror and herror, and whatever else may occur
        hostname = "Unknown"

    return hostname

def format_bytes(size):
    if size < 1024:
        return f"{size} B"
    elif size < 1024 ** 2:
        return f"{size / 1024:.2f} KB"
    elif size < 1024 ** 3:
        return f"{size / (1024 ** 2):.2f} MB"
    else:
        return f"{size / (1024 ** 3):.2f} GB"

