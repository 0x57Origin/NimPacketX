import ../src/nimpacket
import std/[strformat, strutils]

echo "NimPacket IPv6 Demo"
echo "=" .repeat(50)

# Demo 1: Create IPv6 header
echo "\n1. Creating IPv6 header:"
let ipv6 = IPv6Header(
  version: 6,
  trafficClass: 0,
  flowLabel: 0,
  payloadLength: 8,
  nextHeader: IPV6_NEXT_HEADER_ICMPV6,
  hopLimit: 64,
  sourceIP: parseIPv6("2001:db8::1"),
  destIP: parseIPv6("2001:db8::2")
)

echo fmt"   Source: {ipv6ToString(ipv6.sourceIP)}"
echo fmt"   Dest: {ipv6ToString(ipv6.destIP)}"
echo fmt"   Next Header: {ipv6.nextHeader} (ICMPv6)"
echo fmt"   Hop Limit: {ipv6.hopLimit}"

# Demo 2: ICMPv6 Echo Request (Ping)
echo "\n2. Creating ICMPv6 Echo Request (IPv6 Ping):"
var icmpv6 = newICMPv6EchoRequest(1234, 1)
let checksum = calculateICMPv6Checksum(ipv6, icmpv6, @[])
icmpv6.checksum = checksum

echo fmt"   Type: {icmpv6.icmpType} (Echo Request)"
echo fmt"   Code: {icmpv6.code}"
echo fmt"   Checksum: 0x{icmpv6.checksum:04x}"

# Demo 3: Build complete packet
echo "\n3. Building complete IPv6 + ICMPv6 packet:"
let packet = ipv6 / icmpv6
let bytes = packet.toBytes()

echo fmt"   Total size: {bytes.len} bytes (40 IPv6 + 8 ICMPv6)"
echo "   Hex dump (first 48 bytes):"
var hexLine = "   "
for i in 0..<min(48, bytes.len):
  hexLine.add(fmt"{bytes[i]:02x} ")
  if (i + 1) mod 16 == 0:
    echo hexLine
    hexLine = "   "
if hexLine != "   ":
  echo hexLine

# Demo 4: IPv6 with TCP
echo "\n4. IPv6 with TCP (SYN packet):"
let ipv6Tcp = IPv6Header(
  version: 6,
  trafficClass: 0,
  flowLabel: 0,
  payloadLength: 20,
  nextHeader: IPV6_NEXT_HEADER_TCP,
  hopLimit: 64,
  sourceIP: parseIPv6("fe80::1"),
  destIP: parseIPv6("fe80::2")
)

let tcp = TCPHeader(
  sourcePort: 54321,
  destPort: 80,
  sequenceNumber: 1000,
  acknowledgmentNumber: 0,
  headerLength: 5,
  flags: TCP_SYN,
  windowSize: 65535,
  checksum: 0,
  urgentPointer: 0
)

let tcpPacket = ipv6Tcp / tcp
echo fmt"   IPv6 + TCP packet size: {tcpPacket.toBytes().len} bytes"
echo fmt"   TCP SYN from port {tcp.sourcePort} to port {tcp.destPort}"

# Demo 5: IPv6 with UDP
echo "\n5. IPv6 with UDP (DNS query):"
let ipv6Udp = IPv6Header(
  version: 6,
  trafficClass: 0,
  flowLabel: 0,
  payloadLength: 8,
  nextHeader: IPV6_NEXT_HEADER_UDP,
  hopLimit: 64,
  sourceIP: parseIPv6("2001:db8::100"),
  destIP: parseIPv6("2001:db8::53")
)

let udp = UDPHeader(
  sourcePort: 12345,
  destPort: 53,
  length: 8,
  checksum: 0
)

let udpPacket = ipv6Udp / udp
echo fmt"   IPv6 + UDP packet size: {udpPacket.toBytes().len} bytes"
echo fmt"   UDP from port {udp.sourcePort} to DNS port {udp.destPort}"

# Demo 6: Parsing IPv6 packet
echo "\n6. Parsing IPv6 packet:"
let parsed = parsePacket(bytes)
if parsed.hasIPv6:
  echo "   Successfully parsed IPv6 packet!"
  echo fmt"   Parsed source: {ipv6ToString(parsed.ipv6.sourceIP)}"
  echo fmt"   Parsed dest: {ipv6ToString(parsed.ipv6.destIP)}"
  echo fmt"   Parsed ICMPv6 type: {parsed.icmpv6.icmpType}"
else:
  echo "   Error: Failed to parse as IPv6 packet"

# Demo 7: IPv6 address formats
echo "\n7. IPv6 address format examples:"
let addresses = [
  "2001:db8::1",
  "::1",
  "::",
  "fe80::1",
  "ff02::1",
  "2001:db8:85a3::8a2e:370:7334"
]

for addr in addresses:
  let parsed = parseIPv6(addr)
  let formatted = ipv6ToString(parsed)
  echo fmt"   {addr:30} -> {formatted}"

# Demo 8: Ethernet + IPv6 + ICMPv6
echo "\n8. Complete Ethernet frame with IPv6:"
let ethHeader = EthernetHeader(
  destMAC: parseMAC("33:33:00:00:00:01"),  # IPv6 multicast MAC
  srcMAC: parseMAC("00:11:22:33:44:55"),
  etherType: ETHERTYPE_IPV6
)

let ipv6Multicast = IPv6Header(
  version: 6,
  trafficClass: 0,
  flowLabel: 0,
  payloadLength: 8,
  nextHeader: IPV6_NEXT_HEADER_ICMPV6,
  hopLimit: 255,
  sourceIP: parseIPv6("fe80::1"),
  destIP: parseIPv6("ff02::1")  # All-nodes multicast
)

let icmpv6Rs = ICMPv6Header(
  icmpType: ICMPV6_ROUTER_SOLICITATION,
  code: 0,
  checksum: 0
)

let fullPacket = ethHeader / ipv6Multicast / icmpv6Rs
let fullBytes = fullPacket.toBytes()
echo fmt"   Total frame size: {fullBytes.len} bytes"
echo fmt"   (14 Ethernet + 40 IPv6 + 8 ICMPv6 = {fullBytes.len})"

# Demo 9: ICMPv6 Neighbor Discovery types
echo "\n9. ICMPv6 Neighbor Discovery message types:"
echo fmt"   Router Solicitation: {ICMPV6_ROUTER_SOLICITATION}"
echo fmt"   Router Advertisement: {ICMPV6_ROUTER_ADVERTISEMENT}"
echo fmt"   Neighbor Solicitation: {ICMPV6_NEIGHBOR_SOLICITATION}"
echo fmt"   Neighbor Advertisement: {ICMPV6_NEIGHBOR_ADVERTISEMENT}"

# Demo 10: Roundtrip test
echo "\n10. Roundtrip serialization test:"
let originalIpv6 = IPv6Header(
  version: 6,
  trafficClass: 0x20,
  flowLabel: 0xABCDE,
  payloadLength: 8,
  nextHeader: IPV6_NEXT_HEADER_ICMPV6,
  hopLimit: 128,
  sourceIP: parseIPv6("2001:db8:cafe::1"),
  destIP: parseIPv6("2001:db8:beef::2")
)

var originalIcmpv6 = newICMPv6EchoRequest(9999, 123)
originalIcmpv6.checksum = calculateICMPv6Checksum(originalIpv6, originalIcmpv6, @[])

let originalPacket = originalIpv6 / originalIcmpv6
let serialized = originalPacket.toBytes()
let deserialized = parsePacket(serialized)

echo fmt"   Original source: {ipv6ToString(originalIpv6.sourceIP)}"
echo fmt"   Parsed source: {ipv6ToString(deserialized.ipv6.sourceIP)}"
echo fmt"   Match: {ipv6ToString(originalIpv6.sourceIP) == ipv6ToString(deserialized.ipv6.sourceIP)}"
echo fmt"   Original ICMPv6 type: {originalIcmpv6.icmpType}"
echo fmt"   Parsed ICMPv6 type: {deserialized.icmpv6.icmpType}"
echo fmt"   Match: {originalIcmpv6.icmpType == deserialized.icmpv6.icmpType}"

echo "\nDemo complete!"
