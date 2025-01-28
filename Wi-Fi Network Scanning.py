from scapy.all import *

# Function to scan Wi-Fi networks
def scan_wifi():
    print("Scanning for Wi-Fi networks...")
    
    # Send a beacon request (probe request) to get all nearby networks
    iface = "wlan0"  # Change this to your network interface (e.g., wlan0, wlan1, etc.)
    packet = RadioTap()/Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2="00:00:00:00:00:00", addr3="00:00:00:00:00:00")/Dot11Beacon()/Dot11Elt(ID="SSID", info="")

    # Send the packet
    networks = sniff(iface=iface, prn=lambda x: x.summary(), timeout=10)
    
    print("Wi-Fi networks found:")
    for network in networks:
        if network.haslayer(Dot11Beacon):
            ssid = network[Dot11Elt].info.decode()
            print(f"Network SSID: {ssid}")
    
# Run the Wi-Fi scan
scan_wifi()
