# Network Packet Sniffer

This is a Python-based network packet sniffer that captures live network traffic on a specified interface and displays basic packet information.

## Prerequisites

- Python 3.x
- Scapy library

Install Scapy using pip:

```
pip install scapy
```

## Usage

Run the sniffer script with the network interface as an argument:

```
python sniffer.py <interface>
```

Or run the GUI application:

```
python gui.py
```

Example:

```
python sniffer.py eth0
```

This will start capturing packets on the specified interface and print source IP, destination IP, and protocol information.

The GUI application provides a user-friendly interface to start/stop packet capture, view captured packets in a table, and see visual protocol distribution.

## Next Steps

- Implement packet filtering based on rules
- Add deep packet inspection (DPI)
- Store captured data in SQLite database
- Enhance GUI and CLI interfaces
- Implement real-time alerts and logging
