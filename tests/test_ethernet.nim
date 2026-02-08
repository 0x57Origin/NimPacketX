import unittest
import ../src/nimpacket

suite "Ethernet Header Tests":
  test "Create basic Ethernet header":
    let header = EthernetHeader(
      destMAC: parseMAC("FF:FF:FF:FF:FF:FF"),
      srcMAC: parseMAC("00:11:22:33:44:55"),
      etherType: ETHERTYPE_IPV4
    )

    check macToString(header.destMAC) == "FF:FF:FF:FF:FF:FF"
    check macToString(header.srcMAC) == "00:11:22:33:44:55"
    check header.etherType == ETHERTYPE_IPV4

  test "MAC address parsing with colon separator":
    let mac = parseMAC("AA:BB:CC:DD:EE:FF")
    check mac[0] == 0xAA'u8
    check mac[1] == 0xBB'u8
    check mac[2] == 0xCC'u8
    check mac[3] == 0xDD'u8
    check mac[4] == 0xEE'u8
    check mac[5] == 0xFF'u8

  test "MAC address parsing with dash separator":
    let mac = parseMAC("11-22-33-44-55-66")
    check mac[0] == 0x11'u8
    check mac[1] == 0x22'u8
    check mac[2] == 0x33'u8
    check mac[3] == 0x44'u8
    check mac[4] == 0x55'u8
    check mac[5] == 0x66'u8

  test "MAC address to string conversion":
    var mac: array[6, uint8]
    mac[0] = 0xDE'u8
    mac[1] = 0xAD'u8
    mac[2] = 0xBE'u8
    mac[3] = 0xEF'u8
    mac[4] = 0xCA'u8
    mac[5] = 0xFE'u8

    check macToString(mac) == "DE:AD:BE:EF:CA:FE"

  test "Ethernet header serialization":
    let header = EthernetHeader(
      destMAC: parseMAC("FF:FF:FF:FF:FF:FF"),
      srcMAC: parseMAC("AA:BB:CC:DD:EE:FF"),
      etherType: ETHERTYPE_IPV4
    )

    let bytes = header.toBytes()
    check bytes.len == 14

    # Check destination MAC
    check bytes[0] == 0xFF'u8
    check bytes[1] == 0xFF'u8
    check bytes[5] == 0xFF'u8

    # Check source MAC
    check bytes[6] == 0xAA'u8
    check bytes[7] == 0xBB'u8
    check bytes[11] == 0xFF'u8

    # Check EtherType (big-endian)
    check bytes[12] == 0x08'u8
    check bytes[13] == 0x00'u8

  test "Ethernet header parsing":
    let original = EthernetHeader(
      destMAC: parseMAC("11:22:33:44:55:66"),
      srcMAC: parseMAC("AA:BB:CC:DD:EE:FF"),
      etherType: ETHERTYPE_ARP
    )

    let bytes = original.toBytes()
    let parsed = parseEthernet(bytes)

    check macToString(parsed.destMAC) == macToString(original.destMAC)
    check macToString(parsed.srcMAC) == macToString(original.srcMAC)
    check parsed.etherType == original.etherType

  test "Broadcast MAC address":
    let broadcast = broadcastMAC()
    check broadcast[0] == 0xFF'u8
    check broadcast[1] == 0xFF'u8
    check broadcast[2] == 0xFF'u8
    check broadcast[3] == 0xFF'u8
    check broadcast[4] == 0xFF'u8
    check broadcast[5] == 0xFF'u8

  test "Ethernet + IPv4 layer stacking":
    let eth = EthernetHeader(
      destMAC: parseMAC("00:11:22:33:44:55"),
      srcMAC: parseMAC("AA:BB:CC:DD:EE:FF"),
      etherType: ETHERTYPE_IPV4
    )

    let ip = IPv4Header(
      version: 4,
      headerLength: 5,
      totalLength: 40,
      protocol: IPPROTO_TCP,
      sourceIP: parseIPv4("192.168.1.1"),
      destIP: parseIPv4("192.168.1.2")
    )

    let packet = eth / ip
    check packet.hasEthernet == true
    check packet.ethernet.etherType == ETHERTYPE_IPV4

  test "Complete Ethernet frame serialization":
    let frame = (EthernetHeader(
      destMAC: parseMAC("FF:FF:FF:FF:FF:FF"),
      srcMAC: parseMAC("00:11:22:33:44:55"),
      etherType: ETHERTYPE_IPV4
    ) / IPv4Header(
      version: 4,
      headerLength: 5,
      totalLength: 40,
      protocol: IPPROTO_ICMP,
      sourceIP: parseIPv4("10.0.0.1"),
      destIP: parseIPv4("10.0.0.2")
    ) / ICMPHeader(
      icmpType: ICMP_ECHO_REQUEST,
      code: 0,
      identifier: 1,
      sequenceNumber: 1
    ))

    let bytes = frame.toBytes()
    check bytes.len == 14 + 20 + 8  # Ethernet + IPv4 + ICMP

  test "Ethernet frame roundtrip":
    let original = (EthernetHeader(
      destMAC: parseMAC("AA:BB:CC:DD:EE:FF"),
      srcMAC: parseMAC("11:22:33:44:55:66"),
      etherType: ETHERTYPE_IPV4
    ) / IPv4Header(
      version: 4,
      headerLength: 5,
      totalLength: 28,
      protocol: IPPROTO_ICMP,
      sourceIP: parseIPv4("192.168.1.100"),
      destIP: parseIPv4("8.8.8.8")
    ) / ICMPHeader(
      icmpType: ICMP_ECHO_REQUEST,
      code: 0,
      identifier: 0x1234,
      sequenceNumber: 5
    ))

    let bytes = original.toBytes()
    let parsed = parsePacket(bytes)

    check parsed.hasEthernet == true
    check macToString(parsed.ethernet.srcMAC) == "11:22:33:44:55:66"
    check parsed.ethernet.etherType == ETHERTYPE_IPV4
    check parsed.icmp.icmpType == ICMP_ECHO_REQUEST
    check parsed.icmp.identifier == 0x1234

  test "Multiple EtherType constants":
    check ETHERTYPE_IPV4 == 0x0800'u16
    check ETHERTYPE_ARP == 0x0806'u16
    check ETHERTYPE_IPV6 == 0x86DD'u16
