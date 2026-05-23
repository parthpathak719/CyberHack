"""
ARP Guardian — ARP Spoofing Detection & Automated Network Segmentation

A continuous ARP watch daemon that detects ARP cache poisoning attacks
(MITRE ATT&CK T1557.002), identifies the attacking host, and automatically
pushes VLAN isolation rules to quarantine the attacker on a managed switch.

Architecture: On-Premises LAN
Tech Stack: Python (scapy), pysnmp, Docker, Wireshark
"""

__version__ = "1.0.0"
__author__ = "ARP Guardian Team"
__mitre_technique__ = "T1557.002"
__mitre_name__ = "ARP Cache Poisoning"
