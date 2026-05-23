#!/bin/bash
# ──────────────────────────────────────────────────────────────────
# ARP Guardian — Wireshark Capture Script
# ──────────────────────────────────────────────────────────────────
# This script captures raw network traffic from the Docker LAN and 
# extracts it to a .pcap file so you can open it in Wireshark to 
# validate the attack for the judges.

echo "[*] Starting packet capture inside the ARP Monitor container..."
echo "    (Capturing the next 100 ARP packets... Run your attack now!)"

# Capture 100 ARP packets and save to a pcap file inside the container
docker exec arp-monitor tcpdump -i eth0 -n arp -c 100 -w /app/data/wireshark_validation.pcap

echo "[*] Packet capture complete. Extracting file to host..."

# Copy the file from the container to the host machine
docker cp arp-monitor:/app/data/wireshark_validation.pcap ./wireshark_validation.pcap

echo ""
echo "✅ SUCCESS: The capture file has been saved as 'wireshark_validation.pcap' in your project folder!"
echo "➡️  Next Step: Double-click 'wireshark_validation.pcap' to open it in Wireshark."
echo "              Show the judges the duplicate ARP replies and MAC spoofing!"
