# Packet Sniffer with Proxy Detection

This repository contains a Python script for capturing network packets and analyzing them to determine if they originate from a proxy or VPN. The script uses `scapy` for packet sniffing, `geoip2` for geolocation, and `requests` for proxy detection.

## Features

- Capture network packets and save them to a `.pcap` file.
- Log packet details including source and destination IP addresses, ports, and protocols to a `.txt` file.
- Detect if the source IP of the packet is associated with a proxy or VPN.
- Retrieve geolocation information for the source IP.

## Requirements

- ![Python 3.x](https://img.shields.io/badge/-Python-000?&logo=Python)
- `scapy`
- `geoip2`
- `requests`

## Credit
- [Sureking](https://github.com/SurekingDevone)
- [GeoLite2](https://github.com/P3TERX/GeoLite.mmdb)
