#!/usr/bin/env python3
"""
NimPacket Python Bindings - Basic Usage Examples

This script demonstrates the basic usage of NimPacket Python bindings
for packet manipulation and creation.

Run with: python basic_usage.py
"""

import sys
import os

# Add parent directory to path for development
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import nimpacket as np


def example_ipv4_tcp():
    """Example: Create IPv4 + TCP SYN packet"""
    print("\n=== IPv4 + TCP SYN Packet ===")

    # Create IPv4 header
    ip = np.IPv4(
        src_ip="192.168.1.100",
        dst_ip="192.168.1.1",
        protocol=np.PROTO_TCP,
        ttl=64
    )
    print(f"IPv4: {ip.to_dict()}")

    # Create TCP header with SYN flag
    tcp = np.TCP(
        src_port=54321,
        dst_port=80,
        flags=np.TCP_SYN
    )
    print(f"TCP: {tcp.to_dict()}")

    # Combine into packet
    packet = ip + tcp
    packet_bytes = packet.to_bytes()

    print(f"Packet: {packet}")
    print(f"Bytes ({len(packet_bytes)}): {packet_bytes.hex()}")


def example_ethernet_arp():
    """Example: Create Ethernet + ARP request"""
    print("\n=== Ethernet + ARP Request ===")

    # Create Ethernet header
    eth = np.Ethernet(
        src_mac="AA:BB:CC:DD:EE:FF",
        dst_mac="FF:FF:FF:FF:FF:FF",  # Broadcast
        ether_type=np.ETHERTYPE_ARP
    )
    print(f"Ethernet: {eth.to_dict()}")

    # Create ARP request
    arp = np.ARP(
        sender_mac="AA:BB:CC:DD:EE:FF",
        sender_ip="192.168.1.100",
        target_ip="192.168.1.1"
    )
    print(f"ARP: {arp.to_dict()}")

    # Combine into frame
    frame = eth + arp
    print(f"Frame: {frame}")


def example_icmp_ping():
    """Example: Create ICMP Echo Request (ping)"""
    print("\n=== ICMP Echo Request (Ping) ===")

    # Create IPv4 header for ICMP
    ip = np.IPv4(
        src_ip="192.168.1.100",
        dst_ip="8.8.8.8",
        protocol=np.PROTO_ICMP,
        ttl=64
    )

    # Create ICMP echo request
    icmp = np.ICMP(
        icmp_type=np.ICMP_ECHO_REQUEST,
        code=0,
        identifier=1234,
        sequence=1
    )
    print(f"ICMP: {icmp.to_dict()}")

    # Add payload
    payload = b"Hello from NimPacket!"

    # Combine
    packet = ip + icmp + payload
    packet_bytes = packet.to_bytes()

    print(f"Packet: {packet}")
    print(f"Total size: {len(packet_bytes)} bytes")


def example_udp_dns():
    """Example: Create UDP + DNS query"""
    print("\n=== UDP + DNS Query ===")

    # Create IPv4 header
    ip = np.IPv4(
        src_ip="192.168.1.100",
        dst_ip="8.8.8.8",
        protocol=np.PROTO_UDP
    )

    # Create UDP header (DNS port 53)
    udp = np.UDP(
        src_port=54321,
        dst_port=53
    )
    print(f"UDP: {udp.to_dict()}")

    # Create DNS query
    dns = np.DNS(
        domain="example.com",
        query_type=np.DNS_A
    )
    print(f"DNS: {dns.to_dict()}")

    # Combine
    packet = ip + udp + dns
    print(f"Packet: {packet}")


def example_dhcp_discover():
    """Example: Create DHCP Discover"""
    print("\n=== DHCP Discover ===")

    # Create DHCP discover message
    dhcp = np.DHCP(
        client_mac="AA:BB:CC:DD:EE:FF",
        message_type=np.DHCP_DISCOVER,
        transaction_id=0x12345678
    )
    print(f"DHCP: {dhcp.to_dict()}")


def example_ipv6():
    """Example: Create IPv6 packet"""
    print("\n=== IPv6 + TCP ===")

    # Create IPv6 header
    ipv6 = np.IPv6(
        src_ip="2001:db8::1",
        dst_ip="2001:db8::2",
        next_header=np.PROTO_TCP,
        hop_limit=64
    )
    print(f"IPv6: {ipv6.to_dict()}")

    # Create TCP header
    tcp = np.TCP(
        src_port=54321,
        dst_port=443,
        flags=np.TCP_SYN
    )

    # Combine
    packet = ipv6 + tcp
    print(f"Packet: {packet}")


def example_utilities():
    """Example: Utility functions"""
    print("\n=== Utility Functions ===")

    # IP conversion
    ip_str = "192.168.1.100"
    ip_int = np.ip_to_int(ip_str)
    print(f"IP '{ip_str}' as integer: {ip_int}")
    print(f"Integer {ip_int} as IP: {np.int_to_ip(ip_int)}")

    # MAC conversion
    mac_str = "AA:BB:CC:DD:EE:FF"
    mac_bytes = np.mac_to_bytes(mac_str)
    print(f"MAC '{mac_str}' as bytes: {mac_bytes.hex()}")
    print(f"Bytes back to MAC: {np.bytes_to_mac(mac_bytes)}")

    # Checksum
    data = b"\x45\x00\x00\x28\xab\xcd\x00\x00\x40\x06\x00\x00\xc0\xa8\x01\x64\xc0\xa8\x01\x01"
    cs = np.checksum(data)
    print(f"Checksum: 0x{cs:04X}")

    # Version
    print(f"NimPacket version: {np.version()}")


def example_tcp_flags():
    """Example: TCP flag combinations"""
    print("\n=== TCP Flag Combinations ===")

    # SYN
    syn = np.TCP(54321, 80, flags=np.TCP_SYN)
    print(f"SYN: flags={syn.flags}")

    # SYN-ACK
    syn_ack = np.TCP(80, 54321, flags=np.TCP_SYN | np.TCP_ACK)
    print(f"SYN-ACK: flags={syn_ack.flags}")

    # ACK
    ack = np.TCP(54321, 80, flags=np.TCP_ACK)
    print(f"ACK: flags={ack.flags}")

    # FIN-ACK
    fin_ack = np.TCP(54321, 80, flags=np.TCP_FIN | np.TCP_ACK)
    print(f"FIN-ACK: flags={fin_ack.flags}")

    # RST
    rst = np.TCP(54321, 80, flags=np.TCP_RST)
    print(f"RST: flags={rst.flags}")

    # PSH-ACK (for data transfer)
    psh_ack = np.TCP(54321, 80, flags=np.TCP_PSH | np.TCP_ACK)
    print(f"PSH-ACK: flags={psh_ack.flags}")


def main():
    print("=" * 60)
    print("NimPacket Python Bindings - Examples")
    print("=" * 60)

    example_ipv4_tcp()
    example_ethernet_arp()
    example_icmp_ping()
    example_udp_dns()
    example_dhcp_discover()
    example_ipv6()
    example_tcp_flags()
    example_utilities()

    print("\n" + "=" * 60)
    print("All examples completed successfully!")
    print("=" * 60)


if __name__ == "__main__":
    main()
