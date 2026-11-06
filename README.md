# Network Security Monitor

A Python command-line project that captures IPv4 packets, summarizes network activity, and flags possible port scans and high traffic volume. Built with Scapy as a learning project.

## Features

- Count total IPv4 packets and separate TCP, UDP, and other traffic.
- Track remote hosts, packet counts, remote ports, and traffic volume.
- Look up hostnames and service names, with `Unknown` as a fallback.
- Detect possible incoming TCP port scans.
- Flag high traffic volume for each remote host.
- Group related detections into incidents and print timestamped update history.

## Setup and usage

Use Python 3.12 or newer. The current summary strings use syntax introduced in Python 3.12.

Install Scapy:

```powershell
python -m pip install scapy
```

Live capture also requires packet-capture support on your operating system and permission to capture packets. On Windows, install Npcap if it is not already available.

From the project directory, run:

```powershell
python main.py
```

The program prints packet details, then displays network statistics, remote hosts, remote ports, traffic volume, and alerts. Capture currently stops after **20 IPv4 packets**. (you can easily change this just edit count in main.py)
## Alert rules

| Alert | Severity | Trigger |
| --- | --- | --- |
| Possible TCP port scan | WARNING | One remote host sends incoming SYN packets without ACK to at least 10 distinct local destination ports within 10 seconds. |
| High traffic volume | INFO | Total captured traffic to and from one remote host reaches 10 MiB (10 × 1024² bytes) during the run. |

Outgoing SYN packets and incoming SYN+ACK packets do not count toward port-scan detection. Repeated attempts to one destination port refresh its timestamp but do not increase the distinct-port count.

### Incident history

Both alert types track when an incident first appeared and retain update messages:

- A qualifying packet less than five seconds after the latest detection updates the most recent incident of that type for the host.
- A qualifying packet after a gap of five seconds or more starts a new incident.
- The gap is measured from the latest qualifying packet, rather than the start of the incident.
- Summary checks do not create incidents or add updates.

Port-scan detections still require the ten-port threshold to be met. High traffic volume uses a cumulative total: after a host reaches the threshold, later packets qualify without needing another 10 MiB of traffic. This is a volume alert, not a measurement of transfer speed.

## Tests

Run the automated tests from the project directory:

```powershell
python -m unittest -v test_packet_analyzer
```

The tests construct Scapy packets in memory and mock monotonic time; they do not send packets or start live capture. They cover port-scan thresholds, repeated ports, expired ports, packet direction, SYN+ACK exclusion, and high traffic incident creation and updates, including the five-second boundary and summary checks.

The analyzer currently determines the local IP address when imported, including during the normal test command. That lookup requires a working local network route. Hostname lookup during a normal monitor run can also use DNS.

## Project files

| File | Purpose |
| --- | --- |
| `main.py` | Starts capture and prints summaries and alert history. |
| `packet_analyzer.py` | Processes packets, maintains host statistics, and manages alerts. |
| `test_packet_analyzer.py` | Tests packet detection and high traffic incident tracking. |

## Current limitations

- Tracks IPv4 traffic associated with one automatically selected local IP address.
- Stores statistics and incident history in memory for the current run only.
- Uses fixed detection thresholds; legitimate traffic can trigger an alert.
- Reports possible suspicious activity; it does not block traffic.
