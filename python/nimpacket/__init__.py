"""
NimPacket - Complete Python Bindings for Low-Level Packet Manipulation

ALL NimPacket functionality is accessible from Python!

This module provides:
- All protocol headers (IPv4, IPv6, TCP, UDP, ICMP, ICMPv6, Ethernet, ARP, DNS, DHCP)
- All parsing functions
- All checksum calculations
- Raw socket operations (send/receive packets)
- IP fragmentation with 5 evasion strategies
- All utility functions

Example:
    >>> import nimpacket as np
    >>>
    >>> # Build a complete TCP SYN packet
    >>> packet = np.build_tcp_syn_packet("192.168.1.100", "192.168.1.1", 54321, 80)
    >>>
    >>> # Send it (requires admin privileges)
    >>> if np.is_admin():
    ...     np.create_tcp_socket()
    ...     np.send_packet(packet, "192.168.1.1")
    ...     np.close_socket()
"""

__version__ = "0.2.0"
__author__ = "NimPacket Contributors"

# Try to import the compiled Nim module
_nim = None
try:
    from . import nimpacket_py as _nim
except ImportError:
    try:
        import nimpacket_py as _nim
    except ImportError:
        pass

if _nim is None:
    raise ImportError(
        "NimPacket native module not found!\n"
        "Please build it with:\n"
        "  cd python && python build.py\n"
        "Or:\n"
        "  nim c --app:lib --out:python/nimpacket/nimpacket_py.pyd -d:release src/nimpacket_py.nim"
    )

# =============================================================================
# CONSTANTS - Import all from Nim
# =============================================================================

# TCP Flags
TCP_FIN = _nim.TCP_FIN()
TCP_SYN = _nim.TCP_SYN()
TCP_RST = _nim.TCP_RST()
TCP_PSH = _nim.TCP_PSH()
TCP_ACK = _nim.TCP_ACK()
TCP_URG = _nim.TCP_URG()

# IP Protocols
IPPROTO_ICMP = _nim.IPPROTO_ICMP()
IPPROTO_TCP = _nim.IPPROTO_TCP()
IPPROTO_UDP = _nim.IPPROTO_UDP()
IPPROTO_ICMPV6 = _nim.IPPROTO_ICMPV6()

# Aliases
PROTO_ICMP = IPPROTO_ICMP
PROTO_TCP = IPPROTO_TCP
PROTO_UDP = IPPROTO_UDP
PROTO_ICMPV6 = IPPROTO_ICMPV6

# ICMP Types
ICMP_ECHO_REPLY = _nim.ICMP_ECHO_REPLY()
ICMP_ECHO_REQUEST = _nim.ICMP_ECHO_REQUEST()
ICMP_TIME_EXCEEDED = _nim.ICMP_TIME_EXCEEDED()

# EtherTypes
ETHERTYPE_IPV4 = _nim.ETHERTYPE_IPV4()
ETHERTYPE_IPV6 = _nim.ETHERTYPE_IPV6()
ETHERTYPE_ARP = _nim.ETHERTYPE_ARP()

# ARP
ARP_REQUEST = _nim.ARP_REQUEST()
ARP_REPLY = _nim.ARP_REPLY()

# DNS Record Types
DNS_TYPE_A = _nim.DNS_TYPE_A()
DNS_TYPE_AAAA = _nim.DNS_TYPE_AAAA()
DNS_TYPE_CNAME = _nim.DNS_TYPE_CNAME()
DNS_TYPE_MX = _nim.DNS_TYPE_MX()
DNS_TYPE_TXT = _nim.DNS_TYPE_TXT()
DNS_TYPE_NS = _nim.DNS_TYPE_NS()
DNS_TYPE_PTR = _nim.DNS_TYPE_PTR()
DNS_TYPE_SOA = _nim.DNS_TYPE_SOA()
DNS_TYPE_SRV = _nim.DNS_TYPE_SRV()
DNS_TYPE_ANY = _nim.DNS_TYPE_ANY()

# DNS Aliases
DNS_A = DNS_TYPE_A
DNS_AAAA = DNS_TYPE_AAAA
DNS_CNAME = DNS_TYPE_CNAME
DNS_MX = DNS_TYPE_MX
DNS_TXT = DNS_TYPE_TXT
DNS_NS = DNS_TYPE_NS
DNS_PTR = DNS_TYPE_PTR
DNS_SOA = DNS_TYPE_SOA
DNS_SRV = DNS_TYPE_SRV
DNS_ANY = DNS_TYPE_ANY

# DHCP Message Types
DHCP_DISCOVER = _nim.DHCP_DISCOVER()
DHCP_OFFER = _nim.DHCP_OFFER()
DHCP_REQUEST = _nim.DHCP_REQUEST()
DHCP_DECLINE = _nim.DHCP_DECLINE()
DHCP_ACK = _nim.DHCP_ACK()
DHCP_NAK = _nim.DHCP_NAK()
DHCP_RELEASE = _nim.DHCP_RELEASE()
DHCP_INFORM = _nim.DHCP_INFORM()

# ICMPv6 Types
ICMPV6_ECHO_REQUEST = _nim.ICMPV6_ECHO_REQUEST()
ICMPV6_ECHO_REPLY = _nim.ICMPV6_ECHO_REPLY()
ICMPV6_ROUTER_SOLICITATION = _nim.ICMPV6_ROUTER_SOLICITATION()
ICMPV6_NEIGHBOR_SOLICITATION = _nim.ICMPV6_NEIGHBOR_SOLICITATION()

# IPv6 Next Headers
IPV6_NEXT_HEADER_TCP = _nim.IPV6_NEXT_HEADER_TCP()
IPV6_NEXT_HEADER_UDP = _nim.IPV6_NEXT_HEADER_UDP()
IPV6_NEXT_HEADER_ICMPV6 = _nim.IPV6_NEXT_HEADER_ICMPV6()

# Fragmentation Strategies
FRAG_TINY = _nim.FRAG_TINY()
FRAG_OVERLAP = _nim.FRAG_OVERLAP()
FRAG_OUT_OF_ORDER = _nim.FRAG_OUT_OF_ORDER()
FRAG_TIME_DELAYED = _nim.FRAG_TIME_DELAYED()
FRAG_POLYMORPHIC = _nim.FRAG_POLYMORPHIC()

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def parse_ipv4(ip: str) -> int:
    """Convert IPv4 string to integer"""
    return _nim.parse_ipv4_address(ip)

def ip_to_string(ip: int) -> str:
    """Convert integer to IPv4 string"""
    return _nim.ipv4_to_string(ip)

def parse_mac(mac: str) -> bytes:
    """Convert MAC string to bytes"""
    return bytes(_nim.parse_mac_address(mac))

def mac_to_string(mac: bytes) -> str:
    """Convert bytes to MAC string"""
    return _nim.mac_to_string(list(mac))

def parse_ipv6(ip: str) -> bytes:
    """Convert IPv6 string to bytes"""
    return bytes(_nim.parse_ipv6_address(ip))

def ipv6_to_string(ip: bytes) -> str:
    """Convert bytes to IPv6 string"""
    return _nim.ipv6_to_string(list(ip))

def htons(x: int) -> int:
    """Host to network byte order (16-bit)"""
    return _nim.htons(x)

def ntohs(x: int) -> int:
    """Network to host byte order (16-bit)"""
    return _nim.ntohs(x)

def htonl(x: int) -> int:
    """Host to network byte order (32-bit)"""
    return _nim.htonl(x)

def ntohl(x: int) -> int:
    """Network to host byte order (32-bit)"""
    return _nim.ntohl(x)

def broadcast_mac() -> bytes:
    """Get broadcast MAC address (FF:FF:FF:FF:FF:FF)"""
    return bytes(_nim.get_broadcast_mac())

# =============================================================================
# IPv4 FUNCTIONS
# =============================================================================

def create_ipv4_header(src_ip: str, dst_ip: str, protocol: int,
                       ttl: int = 64, identification: int = 0,
                       total_length: int = 20) -> bytes:
    """Create an IPv4 header"""
    return bytes(_nim.create_ipv4_header(src_ip, dst_ip, protocol, ttl, identification, total_length))

def parse_ipv4_header(data: bytes) -> dict:
    """Parse IPv4 header from bytes"""
    return _nim.parse_ipv4_header(list(data))

def calculate_ipv4_checksum(data: bytes) -> int:
    """Calculate IPv4 header checksum"""
    return _nim.calculate_ipv4_checksum(list(data))

# =============================================================================
# IPv6 FUNCTIONS
# =============================================================================

def create_ipv6_header(src_ip: str, dst_ip: str, next_header: int,
                       payload_length: int = 0, hop_limit: int = 64) -> bytes:
    """Create an IPv6 header"""
    return bytes(_nim.create_ipv6_header(src_ip, dst_ip, next_header, payload_length, hop_limit))

def parse_ipv6_header(data: bytes) -> dict:
    """Parse IPv6 header from bytes"""
    return _nim.parse_ipv6_header(list(data))

# =============================================================================
# TCP FUNCTIONS
# =============================================================================

def create_tcp_header(src_port: int, dst_port: int, flags: int,
                      seq_num: int = 0, ack_num: int = 0,
                      window_size: int = 65535) -> bytes:
    """Create a TCP header"""
    return bytes(_nim.create_tcp_header(src_port, dst_port, flags, seq_num, ack_num, window_size))

def parse_tcp_header(data: bytes) -> dict:
    """Parse TCP header from bytes"""
    return _nim.parse_tcp_header(list(data))

def calculate_tcp_checksum(ip_header: bytes, tcp_header: bytes,
                           payload: bytes = b"") -> int:
    """Calculate TCP checksum with pseudo-header"""
    return _nim.calculate_tcp_checksum(list(ip_header), list(tcp_header), list(payload))

# =============================================================================
# UDP FUNCTIONS
# =============================================================================

def create_udp_header(src_port: int, dst_port: int, length: int = 8) -> bytes:
    """Create a UDP header"""
    return bytes(_nim.create_udp_header(src_port, dst_port, length))

def parse_udp_header(data: bytes) -> dict:
    """Parse UDP header from bytes"""
    return _nim.parse_udp_header(list(data))

def calculate_udp_checksum(ip_header: bytes, udp_header: bytes,
                           payload: bytes = b"") -> int:
    """Calculate UDP checksum with pseudo-header"""
    return _nim.calculate_udp_checksum(list(ip_header), list(udp_header), list(payload))

# =============================================================================
# ICMP FUNCTIONS
# =============================================================================

def create_icmp_header(icmp_type: int, code: int = 0,
                       identifier: int = 0, sequence: int = 0) -> bytes:
    """Create an ICMP header"""
    return bytes(_nim.create_icmp_header(icmp_type, code, identifier, sequence))

def parse_icmp_header(data: bytes) -> dict:
    """Parse ICMP header from bytes"""
    return _nim.parse_icmp_header(list(data))

def calculate_icmp_checksum(icmp_header: bytes, payload: bytes = b"") -> int:
    """Calculate ICMP checksum"""
    return _nim.calculate_icmp_checksum(list(icmp_header), list(payload))

# =============================================================================
# ICMPv6 FUNCTIONS
# =============================================================================

def create_icmpv6_echo_request(identifier: int, sequence: int) -> bytes:
    """Create an ICMPv6 Echo Request"""
    return bytes(_nim.create_icmpv6_echo_request(identifier, sequence))

def create_icmpv6_echo_reply(identifier: int, sequence: int) -> bytes:
    """Create an ICMPv6 Echo Reply"""
    return bytes(_nim.create_icmpv6_echo_reply(identifier, sequence))

def parse_icmpv6_header(data: bytes) -> dict:
    """Parse ICMPv6 header from bytes"""
    return _nim.parse_icmpv6_header(list(data))

# =============================================================================
# ETHERNET FUNCTIONS
# =============================================================================

def create_ethernet_header(src_mac: str, dst_mac: str, ether_type: int) -> bytes:
    """Create an Ethernet header"""
    return bytes(_nim.create_ethernet_header(src_mac, dst_mac, ether_type))

def parse_ethernet_header(data: bytes) -> dict:
    """Parse Ethernet header from bytes"""
    return _nim.parse_ethernet_header(list(data))

# =============================================================================
# ARP FUNCTIONS
# =============================================================================

def create_arp_request(sender_mac: str, sender_ip: str, target_ip: str) -> bytes:
    """Create an ARP request packet"""
    return bytes(_nim.create_arp_request(sender_mac, sender_ip, target_ip))

def create_arp_reply(sender_mac: str, sender_ip: str,
                     target_mac: str, target_ip: str) -> bytes:
    """Create an ARP reply packet"""
    return bytes(_nim.create_arp_reply(sender_mac, sender_ip, target_mac, target_ip))

def parse_arp_packet(data: bytes) -> dict:
    """Parse ARP packet from bytes"""
    return _nim.parse_arp_packet(list(data))

# =============================================================================
# DNS FUNCTIONS
# =============================================================================

def create_dns_query(domain: str, query_type: int = 1, transaction_id: int = 0) -> bytes:
    """Create a DNS query packet"""
    return bytes(_nim.create_dns_query(domain, query_type, transaction_id))

def parse_dns_packet(data: bytes) -> dict:
    """Parse DNS packet from bytes"""
    return _nim.parse_dns_packet(list(data))

def encode_domain_name(domain: str) -> bytes:
    """Encode a domain name to DNS wire format"""
    return bytes(_nim.encode_domain_name(domain))

# =============================================================================
# DHCP FUNCTIONS
# =============================================================================

def create_dhcp_discover(mac: str, transaction_id: int = 0) -> bytes:
    """Create a DHCP DISCOVER packet"""
    return bytes(_nim.create_dhcp_discover(mac, transaction_id))

def create_dhcp_request(mac: str, requested_ip: str, server_ip: str,
                        transaction_id: int = 0) -> bytes:
    """Create a DHCP REQUEST packet"""
    return bytes(_nim.create_dhcp_request(mac, requested_ip, server_ip, transaction_id))

def create_dhcp_release(mac: str, client_ip: str, server_ip: str,
                        transaction_id: int = 0) -> bytes:
    """Create a DHCP RELEASE packet"""
    return bytes(_nim.create_dhcp_release(mac, client_ip, server_ip, transaction_id))

def parse_dhcp_packet(data: bytes) -> dict:
    """Parse DHCP packet from bytes"""
    return _nim.parse_dhcp_packet(list(data))

# =============================================================================
# COMPLETE PACKET PARSING
# =============================================================================

def parse_packet(data: bytes) -> dict:
    """Parse a complete packet (auto-detects IPv4/IPv6, TCP/UDP/ICMP, etc.)"""
    return _nim.parse_packet(list(data))

# =============================================================================
# RAW SOCKET OPERATIONS
# =============================================================================

def is_admin() -> bool:
    """Check if running with administrator/root privileges"""
    return _nim.is_admin()

def create_raw_socket(protocol: int = 6) -> bool:
    """Create a raw socket. Returns True on success.
    protocol: 1=ICMP, 6=TCP, 17=UDP, 255=RAW
    """
    return _nim.create_raw_socket(protocol)

def create_icmp_socket() -> bool:
    """Create an ICMP socket for ping operations"""
    return _nim.create_icmp_socket()

def create_tcp_socket() -> bool:
    """Create a TCP raw socket"""
    return _nim.create_tcp_socket()

def create_udp_socket() -> bool:
    """Create a UDP raw socket"""
    return _nim.create_udp_socket()

def close_socket() -> bool:
    """Close the raw socket"""
    return _nim.close_socket()

def send_packet(packet: bytes, dest_ip: str) -> int:
    """Send a raw packet. Returns bytes sent or -1 on error."""
    return _nim.send_packet(list(packet), dest_ip)

def receive_packet(timeout_ms: int = 5000, max_size: int = 65535) -> bytes:
    """Receive a packet. Returns empty bytes on timeout/error."""
    return bytes(_nim.receive_packet(timeout_ms, max_size))

def set_socket_timeout(timeout_ms: int) -> bool:
    """Set receive timeout on socket"""
    return _nim.set_socket_timeout(timeout_ms)

def set_ip_header_include(enable: bool) -> bool:
    """Enable/disable IP_HDRINCL option"""
    return _nim.set_ip_header_include(enable)

def set_broadcast(enable: bool) -> bool:
    """Enable/disable broadcast"""
    return _nim.set_broadcast(enable)

# =============================================================================
# IP FRAGMENTATION
# =============================================================================

def fragment_packet(ip_header: bytes, payload: bytes,
                    strategy: int, fragment_size: int = 8) -> list:
    """Fragment a packet using the specified strategy.

    strategy:
        0 = FRAG_TINY (8-byte fragments)
        1 = FRAG_OVERLAP (overlapping with poison data)
        2 = FRAG_OUT_OF_ORDER (reversed sequence)
        3 = FRAG_TIME_DELAYED (with delays between)
        4 = FRAG_POLYMORPHIC (random strategy)

    Returns list of fragment bytes.
    """
    fragments = _nim.fragment_packet(list(ip_header), list(payload), strategy, fragment_size)
    return [bytes(f) for f in fragments]

def send_fragmented(ip_header: bytes, payload: bytes, dest_ip: str,
                    strategy: int, delay_ms: int = 100) -> int:
    """Send a fragmented packet using the specified strategy.
    Returns total bytes sent or -1 on error.
    """
    return _nim.send_fragmented(list(ip_header), list(payload), dest_ip, strategy, delay_ms)

# =============================================================================
# PACKET BUILDING HELPERS
# =============================================================================

def build_tcp_syn_packet(src_ip: str, dst_ip: str, src_port: int,
                         dst_port: int, ttl: int = 64) -> bytes:
    """Build a complete TCP SYN packet ready to send"""
    return bytes(_nim.build_tcp_syn_packet(src_ip, dst_ip, src_port, dst_port, ttl))

def build_icmp_echo_packet(src_ip: str, dst_ip: str, identifier: int,
                           sequence: int, payload: bytes = b"",
                           ttl: int = 64) -> bytes:
    """Build a complete ICMP Echo Request packet"""
    return bytes(_nim.build_icmp_echo_packet(src_ip, dst_ip, identifier, sequence, list(payload), ttl))

def build_udp_packet(src_ip: str, dst_ip: str, src_port: int,
                     dst_port: int, payload: bytes = b"",
                     ttl: int = 64) -> bytes:
    """Build a complete UDP packet"""
    return bytes(_nim.build_udp_packet(src_ip, dst_ip, src_port, dst_port, list(payload), ttl))

def build_arp_frame(src_mac: str, src_ip: str, dst_ip: str,
                    dst_mac: str = "FF:FF:FF:FF:FF:FF") -> bytes:
    """Build a complete ARP request/reply Ethernet frame"""
    return bytes(_nim.build_arp_frame(src_mac, src_ip, dst_ip, dst_mac))

# =============================================================================
# VERSION INFO
# =============================================================================

def version() -> str:
    """Get NimPacket version"""
    return _nim.get_version()

def supported_protocols() -> list:
    """Get list of supported protocols"""
    return _nim.get_supported_protocols()

# =============================================================================
# CONVENIENCE ALIASES
# =============================================================================

# For compatibility
ip_to_int = parse_ipv4
int_to_ip = ip_to_string
mac_to_bytes = parse_mac
bytes_to_mac = mac_to_string

# Protocol aliases
IP = create_ipv4_header
IPv4 = create_ipv4_header
IPv6 = create_ipv6_header
TCP = create_tcp_header
UDP = create_udp_header
ICMP = create_icmp_header
Ethernet = create_ethernet_header
ARP = create_arp_request
DNS = create_dns_query
DHCP = create_dhcp_discover


# Print available functions when imported in interactive mode
def _show_help():
    """Show available functions and constants"""
    print("""
NimPacket Python Bindings - Full API

PROTOCOLS:
  create_ipv4_header()    create_ipv6_header()    create_tcp_header()
  create_udp_header()     create_icmp_header()    create_ethernet_header()
  create_arp_request()    create_arp_reply()      create_dns_query()
  create_dhcp_discover()  create_dhcp_request()   create_dhcp_release()

PARSING:
  parse_ipv4_header()     parse_ipv6_header()     parse_tcp_header()
  parse_udp_header()      parse_icmp_header()     parse_icmpv6_header()
  parse_ethernet_header() parse_arp_packet()      parse_dns_packet()
  parse_dhcp_packet()     parse_packet()          (auto-detect)

CHECKSUMS:
  calculate_ipv4_checksum()   calculate_tcp_checksum()
  calculate_udp_checksum()    calculate_icmp_checksum()

RAW SOCKETS:
  is_admin()              create_raw_socket()     create_icmp_socket()
  create_tcp_socket()     create_udp_socket()     close_socket()
  send_packet()           receive_packet()        set_socket_timeout()

FRAGMENTATION:
  fragment_packet()       send_fragmented()
  Strategies: FRAG_TINY, FRAG_OVERLAP, FRAG_OUT_OF_ORDER, FRAG_TIME_DELAYED, FRAG_POLYMORPHIC

PACKET BUILDERS:
  build_tcp_syn_packet()  build_icmp_echo_packet()
  build_udp_packet()      build_arp_frame()

UTILITIES:
  parse_ipv4()  ip_to_string()  parse_mac()  mac_to_string()
  parse_ipv6()  ipv6_to_string() htons() ntohs() htonl() ntohl()

CONSTANTS:
  TCP_SYN, TCP_ACK, TCP_FIN, TCP_RST, TCP_PSH, TCP_URG
  IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMP, IPPROTO_ICMPV6
  ETHERTYPE_IPV4, ETHERTYPE_IPV6, ETHERTYPE_ARP
  DNS_TYPE_A, DNS_TYPE_AAAA, DNS_TYPE_MX, DNS_TYPE_TXT, etc.
  DHCP_DISCOVER, DHCP_OFFER, DHCP_REQUEST, DHCP_ACK, etc.
""")

help = _show_help
