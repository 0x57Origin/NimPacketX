import ../src/nimpacket
import std/[strformat, strutils]

echo "NimPacket - Ethernet Frame Demo"
echo repeat("=", 60)

# Demo 1: Create a basic Ethernet header
echo "\n1. Creating Ethernet header:"
let ethHeader = EthernetHeader(
  destMAC: parseMAC("00:11:22:33:44:55"),
  srcMAC: parseMAC("AA:BB:CC:DD:EE:FF"),
  etherType: ETHERTYPE_IPV4
)

echo fmt"   Destination MAC: {macToString(ethHeader.destMAC)}"
echo fmt"   Source MAC: {macToString(ethHeader.srcMAC)}"
echo fmt"   EtherType: 0x{ethHeader.etherType:04x} (IPv4)"

# Demo 2: Complete Ethernet + IPv4 + TCP frame
echo "\n2. Building complete Ethernet frame (Ethernet + IPv4 + TCP):"
let completeFrame = (EthernetHeader(
  destMAC: parseMAC("11:22:33:44:55:66"),
  srcMAC: parseMAC("AA:BB:CC:DD:EE:FF"),
  etherType: ETHERTYPE_IPV4
) / IPv4Header(
  version: 4,
  headerLength: 5,
  totalLength: 40,
  protocol: IPPROTO_TCP,
  sourceIP: parseIPv4("192.168.1.10"),
  destIP: parseIPv4("192.168.1.1")
) / TCPHeader(
  sourcePort: 54321,
  destPort: 443,
  flags: TCP_SYN,
  windowSize: 65535
))

let frameBytes = completeFrame.toBytes()
echo fmt"   Total frame size: {frameBytes.len} bytes"
echo fmt"   - Ethernet header: 14 bytes"
echo fmt"   - IPv4 header: 20 bytes"
echo fmt"   - TCP header: 20 bytes"

# Demo 3: Ethernet frame with payload
echo "\n3. Ethernet frame with data payload:"
let dataFrame = (EthernetHeader(
  destMAC: parseMAC("FF:FF:FF:FF:FF:FF"),  # Broadcast
  srcMAC: parseMAC("AA:BB:CC:DD:EE:FF"),
  etherType: ETHERTYPE_IPV4
) / IPv4Header(
  version: 4,
  headerLength: 5,
  totalLength: 45,
  protocol: IPPROTO_TCP,
  sourceIP: parseIPv4("10.0.0.5"),
  destIP: parseIPv4("10.0.0.1")
) / TCPHeader(
  sourcePort: 8080,
  destPort: 80,
  flags: TCP_PSH or TCP_ACK,
  windowSize: 4096
) / "Hello".toBytes())

let dataBytes = dataFrame.toBytes()
echo fmt"   Frame with payload size: {dataBytes.len} bytes"
echo fmt"   Payload: 'Hello' (5 bytes)"

# Demo 4: Parse Ethernet frame
echo "\n4. Parsing Ethernet frame back:"
let parsed = parsePacket(frameBytes)

if parsed.hasEthernet:
  echo "   ✓ Ethernet header detected"
  echo fmt"   Source MAC: {macToString(parsed.ethernet.srcMAC)}"
  echo fmt"   Dest MAC: {macToString(parsed.ethernet.destMAC)}"
  echo fmt"   Source IP: {ipToString(parsed.ipv4.sourceIP)}"
  echo fmt"   Dest IP: {ipToString(parsed.ipv4.destIP)}"
  echo fmt"   TCP Port: {parsed.tcp.sourcePort} → {parsed.tcp.destPort}"
else:
  echo "   ✗ No Ethernet header found"

# Demo 5: Different EtherTypes
echo "\n5. Different Ethernet frame types:"

# IPv4 frame
let ipv4Frame = EthernetHeader(
  destMAC: parseMAC("00:00:00:00:00:01"),
  srcMAC: parseMAC("00:00:00:00:00:02"),
  etherType: ETHERTYPE_IPV4
)
echo fmt"   IPv4 frame - EtherType: 0x{ipv4Frame.etherType:04x}"

# ARP frame
let arpFrame = EthernetHeader(
  destMAC: broadcastMAC(),
  srcMAC: parseMAC("AA:BB:CC:DD:EE:FF"),
  etherType: ETHERTYPE_ARP
)
echo fmt"   ARP frame - EtherType: 0x{arpFrame.etherType:04x}"
echo fmt"   ARP frame uses broadcast MAC: {macToString(arpFrame.destMAC)}"

# Demo 6: Hex dump of frame
echo "\n6. Hex dump of Ethernet frame (first 54 bytes):"
let dumpBytes = completeFrame.toBytes()
for i in 0..<min(54, dumpBytes.len):
  if i mod 16 == 0:
    stdout.write(fmt"   {i:04x}: ")
  stdout.write(fmt"{dumpBytes[i]:02x} ")
  if (i + 1) mod 16 == 0:
    stdout.write("\n")

echo "\n" & repeat("=", 60)
echo "Ethernet demo complete! Layer 2 frames working perfectly."
