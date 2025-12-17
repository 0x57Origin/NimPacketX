import unittest
import ../src/nimpacket

suite "ARP Packet Tests":
  test "Create ARP request":
    let senderMAC = parseMAC("AA:BB:CC:DD:EE:FF")
    let senderIP = parseIPv4("192.168.1.10")
    let targetIP = parseIPv4("192.168.1.1")

    let arp = newARPRequest(senderMAC, senderIP, targetIP)

    check arp.hardwareType == ARP_HARDWARE_ETHERNET
    check arp.protocolType == ARP_PROTOCOL_IPV4
    check arp.hardwareSize == 6
    check arp.protocolSize == 4
    check arp.opcode == ARP_REQUEST
    check arp.senderIP == senderIP
    check arp.targetIP == targetIP

  test "Create ARP reply":
    let senderMAC = parseMAC("11:22:33:44:55:66")
    let senderIP = parseIPv4("192.168.1.1")
    let targetMAC = parseMAC("AA:BB:CC:DD:EE:FF")
    let targetIP = parseIPv4("192.168.1.10")

    let arp = newARPReply(senderMAC, senderIP, targetMAC, targetIP)

    check arp.opcode == ARP_REPLY
    check arp.senderIP == senderIP
    check arp.targetIP == targetIP
    check macToString(arp.senderMAC) == "11:22:33:44:55:66"
    check macToString(arp.targetMAC) == "AA:BB:CC:DD:EE:FF"

  test "ARP packet serialization":
    let arp = ARPPacket(
      hardwareType: ARP_HARDWARE_ETHERNET,
      protocolType: ARP_PROTOCOL_IPV4,
      hardwareSize: 6,
      protocolSize: 4,
      opcode: ARP_REQUEST,
      senderMAC: parseMAC("AA:BB:CC:DD:EE:FF"),
      senderIP: parseIPv4("10.0.0.1"),
      targetMAC: [0'u8, 0'u8, 0'u8, 0'u8, 0'u8, 0'u8],
      targetIP: parseIPv4("10.0.0.2")
    )

    let bytes = arp.toBytes()
    check bytes.len == 28

    # Check hardware type (big-endian)
    check bytes[0] == 0x00'u8
    check bytes[1] == 0x01'u8

    # Check protocol type (big-endian, 0x0800 for IPv4)
    check bytes[2] == 0x08'u8
    check bytes[3] == 0x00'u8

    # Check sizes
    check bytes[4] == 6'u8  # Hardware size
    check bytes[5] == 4'u8  # Protocol size

    # Check opcode (big-endian)
    check bytes[6] == 0x00'u8
    check bytes[7] == 0x01'u8

  test "ARP packet parsing":
    let original = ARPPacket(
      hardwareType: ARP_HARDWARE_ETHERNET,
      protocolType: ARP_PROTOCOL_IPV4,
      hardwareSize: 6,
      protocolSize: 4,
      opcode: ARP_REPLY,
      senderMAC: parseMAC("11:22:33:44:55:66"),
      senderIP: parseIPv4("192.168.1.1"),
      targetMAC: parseMAC("AA:BB:CC:DD:EE:FF"),
      targetIP: parseIPv4("192.168.1.10")
    )

    let bytes = original.toBytes()
    let parsed = parseARP(bytes)

    check parsed.hardwareType == original.hardwareType
    check parsed.protocolType == original.protocolType
    check parsed.hardwareSize == original.hardwareSize
    check parsed.protocolSize == original.protocolSize
    check parsed.opcode == original.opcode
    check parsed.senderIP == original.senderIP
    check parsed.targetIP == original.targetIP
    check macToString(parsed.senderMAC) == macToString(original.senderMAC)
    check macToString(parsed.targetMAC) == macToString(original.targetMAC)

  test "Ethernet + ARP frame":
    let eth = EthernetHeader(
      destMAC: broadcastMAC(),
      srcMAC: parseMAC("AA:BB:CC:DD:EE:FF"),
      etherType: ETHERTYPE_ARP
    )

    let arp = newARPRequest(
      parseMAC("AA:BB:CC:DD:EE:FF"),
      parseIPv4("192.168.1.10"),
      parseIPv4("192.168.1.1")
    )

    let packet = eth / arp
    check packet.hasEthernet == true
    check packet.hasARP == true
    check packet.ethernet.etherType == ETHERTYPE_ARP

  test "Complete ARP frame serialization":
    let frame = (EthernetHeader(
      destMAC: broadcastMAC(),
      srcMAC: parseMAC("11:22:33:44:55:66"),
      etherType: ETHERTYPE_ARP
    ) / newARPRequest(
      parseMAC("11:22:33:44:55:66"),
      parseIPv4("10.0.0.5"),
      parseIPv4("10.0.0.1")
    ))

    let bytes = frame.toBytes()
    check bytes.len == 42  # 14 Ethernet + 28 ARP

  test "ARP frame roundtrip":
    let original = (EthernetHeader(
      destMAC: broadcastMAC(),
      srcMAC: parseMAC("AA:BB:CC:DD:EE:FF"),
      etherType: ETHERTYPE_ARP
    ) / newARPRequest(
      parseMAC("AA:BB:CC:DD:EE:FF"),
      parseIPv4("192.168.1.100"),
      parseIPv4("192.168.1.1")
    ))

    let bytes = original.toBytes()
    let parsed = parsePacket(bytes)

    check parsed.hasEthernet == true
    check parsed.hasARP == true
    check parsed.ethernet.etherType == ETHERTYPE_ARP
    check parsed.arp.opcode == ARP_REQUEST
    check ipToString(parsed.arp.senderIP) == "192.168.1.100"
    check ipToString(parsed.arp.targetIP) == "192.168.1.1"

  test "ARP Who-has simulation":
    # "Who has 192.168.1.1? Tell 192.168.1.10"
    let whoHas = (EthernetHeader(
      destMAC: broadcastMAC(),
      srcMAC: parseMAC("00:11:22:33:44:55"),
      etherType: ETHERTYPE_ARP
    ) / newARPRequest(
      parseMAC("00:11:22:33:44:55"),
      parseIPv4("192.168.1.10"),
      parseIPv4("192.168.1.1")
    ))

    let bytes = whoHas.toBytes()
    check bytes.len == 42

    let parsed = parsePacket(bytes)
    check parsed.arp.opcode == ARP_REQUEST
    check macToString(parsed.ethernet.destMAC) == "FF:FF:FF:FF:FF:FF"

  test "ARP reply simulation":
    # "192.168.1.1 is at AA:BB:CC:DD:EE:FF"
    let reply = (EthernetHeader(
      destMAC: parseMAC("00:11:22:33:44:55"),
      srcMAC: parseMAC("AA:BB:CC:DD:EE:FF"),
      etherType: ETHERTYPE_ARP
    ) / newARPReply(
      parseMAC("AA:BB:CC:DD:EE:FF"),
      parseIPv4("192.168.1.1"),
      parseMAC("00:11:22:33:44:55"),
      parseIPv4("192.168.1.10")
    ))

    let bytes = reply.toBytes()
    let parsed = parsePacket(bytes)

    check parsed.arp.opcode == ARP_REPLY
    check ipToString(parsed.arp.senderIP) == "192.168.1.1"
    check macToString(parsed.arp.senderMAC) == "AA:BB:CC:DD:EE:FF"

  test "ARP constants":
    check ARP_REQUEST == 1'u16
    check ARP_REPLY == 2'u16
    check ARP_HARDWARE_ETHERNET == 1'u16
    check ARP_PROTOCOL_IPV4 == 0x0800'u16
