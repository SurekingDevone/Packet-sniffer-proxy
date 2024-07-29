# Packet Sniffer with proxy detection good for tracking suspicious traffic to your server / internet #
# Github : https://github.com/SurekingDevone/


from scapy.all import sniff, PcapWriter
from scapy.layers.inet import IP, TCP, UDP
import geoip2.database
import requests
import threading

pcap_file = "packets.pcap"
txt_file = "packets.txt"
geoip_db = "GeoLite2-City.mmdb"

pcap_writer = PcapWriter(pcap_file, append=True, sync=True)
geoip_reader = geoip2.database.Reader(geoip_db)

# Cache for IP proxy checks to avoid repeated requests
proxy_cache = {}

def is_proxy(ip):
    if ip in proxy_cache:
        return proxy_cache[ip]

    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json")
        data = response.json()

        is_proxy_ip = 'proxy' in data or 'hosting' in data
        proxy_cache[ip] = is_proxy_ip
        return is_proxy_ip
    except Exception as e:
        print(f"Error checking proxy for IP {ip}: {e}")
        return False

def packet_callback(packet):
    pcap_writer.write(packet)

    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto
        details = f"IP Packet: {ip_src} -> {ip_dst}, Protocol: {proto}"

        if packet.haslayer(TCP):
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            details += f", TCP: {sport} -> {dport}"
        elif packet.haslayer(UDP):
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            details += f", UDP: {sport} -> {dport}"

        try:
            geoip_info = geoip_reader.city(ip_src)
            country = geoip_info.country.name
            city = geoip_info.city.name
            details += f", Location: {city}, {country}"
        except Exception as e:
            details += ", Location: Unknown"

        #check if its proxy or not.
        if is_proxy(ip_src):
            details += ", Proxy: Yes"
        else:
            details += ", Proxy: No"

        with open(txt_file, "a") as f:
            f.write(details + "\n")
    else:
        with open(txt_file, "a") as f:
            f.write("Non-IP Packet\n")

    print(f"Packet: {packet.summary()}")

def start_sniffing():
    # "Ethernet" as your interface / change to your interface id or remove the iface to scan from all interface.
    sniff(iface="Ethernet", prn=packet_callback, count=0)

# Use threading to ensure non-blocking behavior
sniff_thread = threading.Thread(target=start_sniffing)
sniff_thread.start()