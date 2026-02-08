#!/usr/bin/env python3
"""
NimPacket Python Bindings - Simple Port Scanner Example

This is an educational example showing how to build SYN packets
for port scanning. DO NOT use this on networks you don't own
or have explicit permission to test.

LEGAL DISCLAIMER:
This tool is for educational purposes only. Unauthorized port
scanning may be illegal in your jurisdiction. Always obtain
proper authorization before scanning any network.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import nimpacket as np


def create_syn_packet(src_ip, dst_ip, src_port, dst_port):
    """Creates a TCP SYN packet for port scanning"""

    # Create IPv4 header
    ip = np.IPv4(
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=np.PROTO_TCP,
        ttl=64
    )

    # Create TCP SYN header
    tcp = np.TCP(
        src_port=src_port,
        dst_port=dst_port,
        flags=np.TCP_SYN,
        seq_num=1000,
        window=65535
    )

    # Build packet
    packet = ip + tcp

    return packet.to_bytes()


def main():
    print("=" * 60)
    print("NimPacket Port Scanner Example (Educational)")
    print("=" * 60)

    # Example configuration
    target_ip = "192.168.1.1"  # Change to your target
    source_ip = "192.168.1.100"  # Change to your source
    common_ports = [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 993, 995, 3306, 3389, 8080]

    print(f"\nTarget: {target_ip}")
    print(f"Source: {source_ip}")
    print(f"Ports to scan: {len(common_ports)}")
    print("\n[This is a demonstration - packets are not actually sent]")
    print("-" * 60)

    for port in common_ports:
        packet = create_syn_packet(source_ip, target_ip, 54321, port)
        print(f"Port {port:5d}: {len(packet)} bytes - {packet[:20].hex()}...")

    print("-" * 60)
    print("\nTo actually send these packets, you would need:")
    print("1. Root/Administrator privileges")
    print("2. A raw socket library (like scapy)")
    print("3. Permission to scan the target network")


if __name__ == "__main__":
    main()
