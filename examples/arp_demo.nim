import ../src/nimpacket
import std/[strformat, strutils]

echo "NimPacket - ARP Protocol Demo"
echo repeat("=", 60)

# Demo 1: Create ARP request
echo "\n1. Creating ARP Request (Who has 192.168.1.1?):"
let myMAC = parseMAC("AA:BB:CC:DD:EE:FF")
let myIP = parseIPv4("192.168.1.10")
let targetIP = parseIPv4("192.168.1.1")

let arpRequest = newARPRequest(myMAC, myIP, targetIP)

echo fmt"   Operation: ARP Request ({arpRequest.opcode})"
echo fmt"   Sender MAC: {macToString(arpRequest.senderMAC)}"
echo fmt"   Sender IP: {ipToString(arpRequest.senderIP)}"
echo fmt"   Target IP: {ipToString(arpRequest.targetIP)}"
echo fmt"   Target MAC: {macToString(arpRequest.targetMAC)} (unknown)"

# Demo 2: Create ARP reply
echo "\n2. Creating ARP Reply (192.168.1.1 is at 11:22:33:44:55:66):"
let gatewayMAC = parseMAC("11:22:33:44:55:66")
let gatewayIP = parseIPv4("192.168.1.1")

let arpReply = newARPReply(gatewayMAC, gatewayIP, myMAC, myIP)

echo fmt"   Operation: ARP Reply ({arpReply.opcode})"
echo fmt"   Sender MAC: {macToString(arpReply.senderMAC)}"
echo fmt"   Sender IP: {ipToString(arpReply.senderIP)}"
echo fmt"   Target MAC: {macToString(arpReply.targetMAC)}"
echo fmt"   Target IP: {ipToString(arpReply.targetIP)}"

# Demo 3: Complete ARP frame with Ethernet
echo "\n3. Building complete ARP frame (Ethernet + ARP Request):"
let arpFrame = (EthernetHeader(
  destMAC: broadcastMAC(),  # Broadcast to all devices
  srcMAC: myMAC,
  etherType: ETHERTYPE_ARP
) / newARPRequest(myMAC, myIP, targetIP))

let frameBytes = arpFrame.toBytes()
echo fmt"   Total frame size: {frameBytes.len} bytes"
echo fmt"   - Ethernet header: 14 bytes"
echo fmt"   - ARP packet: 28 bytes"
echo fmt"   Destination: Broadcast ({macToString(broadcastMAC())})"

# Demo 4: Parse ARP frame
echo "\n4. Parsing ARP frame back:"
let parsed = parsePacket(frameBytes)

if parsed.hasARP:
  echo "   ✓ ARP packet detected"
  let opType = if parsed.arp.opcode == ARP_REQUEST: "REQUEST" else: "REPLY"
  echo fmt"   Operation: {opType}"
  echo fmt"   Who has {ipToString(parsed.arp.targetIP)}?"
  echo fmt"   Tell {ipToString(parsed.arp.senderIP)}"
else:
  echo "   ✗ No ARP packet found"

# Demo 5: ARP network scan simulation
echo "\n5. Simulating ARP network scan (192.168.1.0/24):"
echo "   Scanning first 5 addresses..."

for i in 1..5:
  let scanTarget = parseIPv4("192.168.1." & $i)
  let scanRequest = (EthernetHeader(
    destMAC: broadcastMAC(),
    srcMAC: myMAC,
    etherType: ETHERTYPE_ARP
  ) / newARPRequest(myMAC, myIP, scanTarget))

  let scanBytes = scanRequest.toBytes()
  echo fmt"   [{i}] Who has {ipToString(scanTarget)}? ({scanBytes.len} bytes)"

# Demo 6: ARP cache poisoning detection (educational)
echo "\n6. ARP packet types:"

# Gratuitous ARP (announce own IP)
let gratuitous = newARPReply(myMAC, myIP, broadcastMAC(), myIP)
echo fmt"   Gratuitous ARP: Announcing {ipToString(myIP)} is at {macToString(myMAC)}"

# Standard request
let standard = newARPRequest(myMAC, myIP, parseIPv4("192.168.1.254"))
echo fmt"   Standard Request: Who has 192.168.1.254?"

# Reply
let reply = newARPReply(
  parseMAC("DE:AD:BE:EF:CA:FE"),
  parseIPv4("192.168.1.254"),
  myMAC,
  myIP
)
echo fmt"   Standard Reply: 192.168.1.254 is at DE:AD:BE:EF:CA:FE"

# Demo 7: Hex dump of ARP packet
echo "\n7. Hex dump of ARP request packet:"
let arpBytes = arpRequest.toBytes()
for i in 0..<arpBytes.len:
  if i mod 16 == 0:
    stdout.write(fmt"   {i:04x}: ")
  stdout.write(fmt"{arpBytes[i]:02x} ")
  if (i + 1) mod 16 == 0 or i == arpBytes.len - 1:
    stdout.write("\n")

# Demo 8: ARP packet structure breakdown
echo "\n8. ARP packet structure:"
echo "   Hardware Type: Ethernet (1)"
echo "   Protocol Type: IPv4 (0x0800)"
echo "   Hardware Size: 6 bytes (MAC address)"
echo "   Protocol Size: 4 bytes (IPv4 address)"
echo "   Opcode: 1 (Request) / 2 (Reply)"
echo "   Sender MAC: 6 bytes"
echo "   Sender IP: 4 bytes"
echo "   Target MAC: 6 bytes"
echo "   Target IP: 4 bytes"
echo "   Total: 28 bytes"

echo "\n" & repeat("=", 60)
echo "ARP demo complete! Network discovery tools ready to build."
