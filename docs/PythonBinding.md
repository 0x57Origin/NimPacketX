# NimPacket Python Bindings

> **Fast, low-level packet manipulation from Python**

NimPacket now includes Python bindings, bringing the speed of Nim to the convenience of Python. Build network packets, craft security tools, and manipulate protocols with a simple, Pythonic API.

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [API Reference](#api-reference)
  - [IPv4](#ipv4)
  - [IPv6](#ipv6)
  - [TCP](#tcp)
  - [UDP](#udp)
  - [ICMP](#icmp)
  - [Ethernet](#ethernet)
  - [ARP](#arp)
  - [DNS](#dns)
  - [DHCP](#dhcp)
- [Constants](#constants)
- [Utility Functions](#utility-functions)
- [Examples](#examples)
- [Building from Source](#building-from-source)

---

## Installation

### Option 1: Install from pip (when available)

```bash
pip install nimpacket
```

### Option 2: Install from source

```bash
# Clone the repository
git clone https://github.com/0x57Origin/NimPacket.git
cd NimPacket/python

# Install in development mode
pip install -e .

# Build the Nim extension (optional, for best performance)
python build.py
```

### Requirements

- Python 3.8+
- Nim 1.6.0+ (only if building the Nim extension)
- nimpy (`nimble install nimpy`)

---

## Quick Start

```python
import nimpacket as np

# Build a complete TCP SYN packet (with checksums!)
packet = np.build_tcp_syn_packet("192.168.1.100", "192.168.1.1", 54321, 80)
print(f"Packet size: {len(packet)} bytes")
print(f"Hex: {packet.hex()}")

# Or create headers individually
ip_header = np.create_ipv4_header("192.168.1.100", "192.168.1.1", np.PROTO_TCP)
tcp_header = np.create_tcp_header(54321, 80, np.TCP_SYN)
full_packet = ip_header + tcp_header  # Concatenate bytes
```

### Create a DNS Query

```python
import nimpacket as np

# Create DNS query for example.com
dns_query = np.create_dns_query("example.com", np.DNS_TYPE_A)
print(dns_query.hex())

# Parse DNS response
parsed = np.parse_dns_packet(dns_response_bytes)
print(parsed['questions'], parsed['answers'])
```

### Create a DHCP Discover

```python
import nimpacket as np

# DHCP Discover message
dhcp_discover = np.create_dhcp_discover("AA:BB:CC:DD:EE:FF")
print(f"DHCP packet: {len(dhcp_discover)} bytes")

# Parse DHCP response
parsed = np.parse_dhcp_packet(dhcp_response_bytes)
print(parsed['message_type'], parsed['your_ip'])
```

---

## API Reference

### IPv4

```python
class IPv4(src_ip, dst_ip, protocol=PROTO_TCP, ttl=64, identification=0)
```

Creates an IPv4 header.

**Parameters:**
- `src_ip` (str): Source IP address (e.g., "192.168.1.1")
- `dst_ip` (str): Destination IP address
- `protocol` (int): Protocol number (PROTO_TCP=6, PROTO_UDP=17, PROTO_ICMP=1)
- `ttl` (int): Time to live (default: 64)
- `identification` (int): IP identification field

**Example:**
```python
ip = np.IPv4("192.168.1.100", "10.0.0.1", protocol=np.PROTO_TCP, ttl=128)
```

---

### IPv6

```python
class IPv6(src_ip, dst_ip, next_header=PROTO_TCP, hop_limit=64)
```

Creates an IPv6 header.

**Parameters:**
- `src_ip` (str): Source IPv6 address (e.g., "2001:db8::1")
- `dst_ip` (str): Destination IPv6 address
- `next_header` (int): Next header type
- `hop_limit` (int): Hop limit (default: 64)

**Example:**
```python
ipv6 = np.IPv6("2001:db8::1", "2001:db8::2", next_header=np.PROTO_TCP)
```

---

### TCP

```python
class TCP(src_port, dst_port, flags=TCP_SYN, seq_num=0, ack_num=0, window=65535)
```

Creates a TCP header.

**Parameters:**
- `src_port` (int): Source port
- `dst_port` (int): Destination port
- `flags` (int): TCP flags (can be combined with `|`)
- `seq_num` (int): Sequence number
- `ack_num` (int): Acknowledgment number
- `window` (int): Window size

**Example:**
```python
# SYN packet
tcp = np.TCP(54321, 80, flags=np.TCP_SYN)

# SYN-ACK packet
tcp = np.TCP(80, 54321, flags=np.TCP_SYN | np.TCP_ACK)
```

---

### UDP

```python
class UDP(src_port, dst_port, length=8)
```

Creates a UDP header.

**Parameters:**
- `src_port` (int): Source port
- `dst_port` (int): Destination port
- `length` (int): UDP length (header + data)

**Example:**
```python
udp = np.UDP(54321, 53)  # DNS query
```

---

### ICMP

```python
class ICMP(icmp_type=ICMP_ECHO_REQUEST, code=0, identifier=0, sequence=0)
```

Creates an ICMP header.

**Parameters:**
- `icmp_type` (int): ICMP type (8 = Echo Request, 0 = Echo Reply)
- `code` (int): ICMP code
- `identifier` (int): Identifier (for echo request/reply)
- `sequence` (int): Sequence number

**Example:**
```python
# Ping request
icmp = np.ICMP(icmp_type=np.ICMP_ECHO_REQUEST, identifier=1234, sequence=1)
```

---

### Ethernet

```python
class Ethernet(src_mac, dst_mac, ether_type=ETHERTYPE_IPV4)
```

Creates an Ethernet header.

**Parameters:**
- `src_mac` (str): Source MAC address (e.g., "AA:BB:CC:DD:EE:FF")
- `dst_mac` (str): Destination MAC address
- `ether_type` (int): EtherType (0x0800=IPv4, 0x86DD=IPv6, 0x0806=ARP)

**Example:**
```python
eth = np.Ethernet("AA:BB:CC:DD:EE:FF", "FF:FF:FF:FF:FF:FF", np.ETHERTYPE_ARP)
```

---

### ARP

```python
class ARP(sender_mac, sender_ip, target_ip, target_mac="00:00:00:00:00:00", opcode=1)
```

Creates an ARP packet.

**Parameters:**
- `sender_mac` (str): Sender MAC address
- `sender_ip` (str): Sender IP address
- `target_ip` (str): Target IP address
- `target_mac` (str): Target MAC address (zeros for request)
- `opcode` (int): 1 = Request, 2 = Reply

**Example:**
```python
# ARP Request
arp = np.ARP("AA:BB:CC:DD:EE:FF", "192.168.1.100", "192.168.1.1")
```

---

### DNS

```python
class DNS(domain, query_type=DNS_A, transaction_id=0x1234)
```

Creates a DNS query packet.

**Parameters:**
- `domain` (str): Domain name to query
- `query_type` (int): Query type (A=1, AAAA=28, MX=15, etc.)
- `transaction_id` (int): Transaction ID

**Static Methods:**
- `DNS.parse(data)`: Parse DNS packet from bytes

**Example:**
```python
# A record query
dns = np.DNS("example.com", query_type=np.DNS_A)

# MX record query
dns = np.DNS("example.com", query_type=np.DNS_MX)
```

---

### DHCP

```python
class DHCP(client_mac, message_type=DHCP_DISCOVER, transaction_id=0x12345678,
           requested_ip=None, server_ip=None)
```

Creates a DHCP packet.

**Parameters:**
- `client_mac` (str): Client MAC address
- `message_type` (int): DHCP message type
- `transaction_id` (int): Transaction ID
- `requested_ip` (str): Requested IP (for REQUEST)
- `server_ip` (str): Server IP (for REQUEST)

**Static Methods:**
- `DHCP.parse(data)`: Parse DHCP packet from bytes

**Example:**
```python
# DHCP Discover
dhcp = np.DHCP("AA:BB:CC:DD:EE:FF", message_type=np.DHCP_DISCOVER)

# DHCP Request
dhcp = np.DHCP(
    "AA:BB:CC:DD:EE:FF",
    message_type=np.DHCP_REQUEST,
    requested_ip="192.168.1.100",
    server_ip="192.168.1.1"
)
```

---

## Constants

### Protocol Numbers
```python
PROTO_ICMP = 1
PROTO_TCP = 6
PROTO_UDP = 17
PROTO_ICMPV6 = 58
```

### TCP Flags
```python
TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10
TCP_URG = 0x20
```

### EtherTypes
```python
ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_ARP = 0x0806
```

### DNS Record Types
```python
DNS_A = 1       # IPv4 address
DNS_AAAA = 28   # IPv6 address
DNS_CNAME = 5   # Canonical name
DNS_MX = 15     # Mail exchange
DNS_TXT = 16    # Text record
DNS_NS = 2      # Nameserver
DNS_PTR = 12    # Pointer
DNS_SOA = 6     # Start of authority
DNS_SRV = 33    # Service
DNS_ANY = 255   # Any record type
```

### DHCP Message Types
```python
DHCP_DISCOVER = 1
DHCP_OFFER = 2
DHCP_REQUEST = 3
DHCP_DECLINE = 4
DHCP_ACK = 5
DHCP_NAK = 6
DHCP_RELEASE = 7
DHCP_INFORM = 8
```

### ICMP Types
```python
ICMP_ECHO_REPLY = 0
ICMP_ECHO_REQUEST = 8
ICMP_TIME_EXCEEDED = 11
```

---

## Utility Functions

### ip_to_int(ip)
Converts IPv4 string to integer.
```python
>>> np.ip_to_int("192.168.1.1")
3232235777
```

### int_to_ip(n)
Converts integer to IPv4 string.
```python
>>> np.int_to_ip(3232235777)
'192.168.1.1'
```

### mac_to_bytes(mac)
Converts MAC string to bytes.
```python
>>> np.mac_to_bytes("AA:BB:CC:DD:EE:FF")
b'\xaa\xbb\xcc\xdd\xee\xff'
```

### bytes_to_mac(data)
Converts bytes to MAC string.
```python
>>> np.bytes_to_mac(b'\xaa\xbb\xcc\xdd\xee\xff')
'AA:BB:CC:DD:EE:FF'
```

### checksum(data)
Calculates Internet checksum.
```python
>>> np.checksum(b'\x45\x00\x00\x28...')
12345
```

### version()
Returns NimPacket version.
```python
>>> np.version()
'0.2.0'
```

---

## Examples

### Complete TCP SYN Scan Packet

```python
import nimpacket as np

def create_syn_packet(src_ip, dst_ip, src_port, dst_port):
    ip = np.IPv4(src_ip, dst_ip, protocol=np.PROTO_TCP, ttl=64)
    tcp = np.TCP(src_port, dst_port, flags=np.TCP_SYN, seq_num=1000)
    return (ip + tcp).to_bytes()

# Create packet
packet = create_syn_packet("192.168.1.100", "192.168.1.1", 54321, 80)
print(f"SYN packet: {len(packet)} bytes")
```

### ICMP Ping Packet

```python
import nimpacket as np

ip = np.IPv4("192.168.1.100", "8.8.8.8", protocol=np.PROTO_ICMP)
icmp = np.ICMP(
    icmp_type=np.ICMP_ECHO_REQUEST,
    identifier=1234,
    sequence=1
)
payload = b"Hello from NimPacket!"

packet = ip + icmp + payload
print(f"Ping packet: {len(packet.to_bytes())} bytes")
```

### ARP Discovery Frame

```python
import nimpacket as np

eth = np.Ethernet(
    src_mac="AA:BB:CC:DD:EE:FF",
    dst_mac="FF:FF:FF:FF:FF:FF",
    ether_type=np.ETHERTYPE_ARP
)

arp = np.ARP(
    sender_mac="AA:BB:CC:DD:EE:FF",
    sender_ip="192.168.1.100",
    target_ip="192.168.1.1"
)

frame = eth + arp
print(f"ARP frame: {len(frame.to_bytes())} bytes")
```

### DNS Query

```python
import nimpacket as np

# Create full DNS query packet
ip = np.IPv4("192.168.1.100", "8.8.8.8", protocol=np.PROTO_UDP)
udp = np.UDP(54321, 53)
dns = np.DNS("google.com", query_type=np.DNS_A)

packet = ip + udp + dns
print(f"DNS query: {packet.to_bytes().hex()}")
```

---

## Building from Source

### Prerequisites

1. Install Nim (1.6.0+): https://nim-lang.org/install.html
2. Install nimpy: `nimble install nimpy`

### Build Steps

```bash
cd NimPacket/python

# Build the Nim extension
python build.py

# Clean build artifacts
python build.py --clean

# Build and test
python build.py --test
```

### Manual Build

```bash
cd NimPacket/src

# Windows
nim c --app:lib --out:../python/nimpacket/nimpacket_py.pyd -d:release nimpacket_py.nim

# Linux/macOS
nim c --app:lib --out:../python/nimpacket/nimpacket_py.so -d:release nimpacket_py.nim
```

---

## Performance

The Python bindings work in two modes:

1. **With Nim Extension** (recommended): Uses the compiled Nim code for maximum performance
2. **Pure Python Fallback**: Works without Nim, but with reduced functionality

When the Nim extension is available, packet creation and serialization is significantly faster than pure Python implementations.

---

## Legal Disclaimer

This library is intended for:
- Authorized security testing
- Network research and education
- Building legitimate network tools

Do NOT use this library for:
- Unauthorized network scanning
- Attacking systems without permission
- Any illegal activities

Always obtain proper authorization before testing any network.

---

## Contributing

Contributions are welcome! Please see the main [NimPacket repository](https://github.com/0x57Origin/NimPacket) for contribution guidelines.

---
