import unittest
import ../src/nimpacket

suite "IPv6 Header Tests":
  test "Create basic IPv6 header":
    let header = IPv6Header(
      version: 6,
      trafficClass: 0,
      flowLabel: 0,
      payloadLength: 8,
      nextHeader: IPV6_NEXT_HEADER_ICMPV6,
      hopLimit: 64,
      sourceIP: parseIPv6("2001:db8::1"),
      destIP: parseIPv6("2001:db8::2")
    )

    check header.version == 6
    check header.nextHeader == IPV6_NEXT_HEADER_ICMPV6
    check header.hopLimit == 64
    check ipv6ToString(header.sourceIP) == "2001:db8::1"
    check ipv6ToString(header.destIP) == "2001:db8::2"

  test "IPv6 address parsing - full notation":
    let ip = parseIPv6("2001:0db8:0000:0000:0000:0000:0000:0001")
    check ipv6ToString(ip) == "2001:db8::1"

  test "IPv6 address parsing - compressed notation":
    let ip1 = parseIPv6("2001:db8::1")
    let ip2 = parseIPv6("::1")  # Loopback
    let ip3 = parseIPv6("::")   # All zeros
    let ip4 = parseIPv6("fe80::1")

    check ipv6ToString(ip1) == "2001:db8::1"
    check ipv6ToString(ip2) == "::1"
    check ipv6ToString(ip3) == "::"
    check ipv6ToString(ip4) == "fe80::1"

  test "IPv6 address parsing - no compression needed":
    let ip = parseIPv6("2001:db8:0:0:0:0:0:1")
    check ipv6ToString(ip) == "2001:db8::1"

  test "IPv6 address parsing - various formats":
    let ip1 = parseIPv6("2001:db8:85a3::8a2e:370:7334")
    let ip2 = parseIPv6("2001:db8:85a3:0:0:8a2e:370:7334")
    check ipv6ToString(ip1) == ipv6ToString(ip2)

  test "IPv6 header serialization":
    let header = IPv6Header(
      version: 6,
      trafficClass: 0,
      flowLabel: 0x12345,
      payloadLength: 40,
      nextHeader: IPV6_NEXT_HEADER_TCP,
      hopLimit: 255,
      sourceIP: parseIPv6("2001:db8::1"),
      destIP: parseIPv6("2001:db8::2")
    )

    let bytes = header.toBytes()
    check bytes.len == 40  # IPv6 header is always 40 bytes
    check (bytes[0] shr 4) == 6  # Version
    check bytes[6] == IPV6_NEXT_HEADER_TCP
    check bytes[7] == 255

  test "IPv6 header roundtrip":
    let original = IPv6Header(
      version: 6,
      trafficClass: 0x20,
      flowLabel: 0xABCDE,
      payloadLength: 100,
      nextHeader: IPV6_NEXT_HEADER_UDP,
      hopLimit: 128,
      sourceIP: parseIPv6("fe80::1"),
      destIP: parseIPv6("ff02::1")
    )

    let bytes = original.toBytes()
    let parsed = parseIPv6Header(bytes)

    check parsed.version == original.version
    check parsed.trafficClass == original.trafficClass
    check parsed.flowLabel == original.flowLabel
    check parsed.payloadLength == original.payloadLength
    check parsed.nextHeader == original.nextHeader
    check parsed.hopLimit == original.hopLimit
    check parsed.sourceIP == original.sourceIP
    check parsed.destIP == original.destIP

  test "IPv6 layer stacking with ICMPv6":
    let ipv6 = IPv6Header(
      version: 6,
      payloadLength: 8,
      nextHeader: IPV6_NEXT_HEADER_ICMPV6,
      hopLimit: 64,
      sourceIP: parseIPv6("::1"),
      destIP: parseIPv6("::1")
    )

    let icmpv6 = ICMPv6Header(
      icmpType: ICMPV6_ECHO_REQUEST,
      code: 0
    )

    let packet = ipv6 / icmpv6
    check packet.hasIPv6 == true
    check packet.ipv6.version == 6
    check packet.icmpv6.icmpType == ICMPV6_ECHO_REQUEST

  test "IPv6 layer stacking with TCP":
    let ipv6 = IPv6Header(
      version: 6,
      payloadLength: 20,
      nextHeader: IPV6_NEXT_HEADER_TCP,
      hopLimit: 64,
      sourceIP: parseIPv6("2001:db8::1"),
      destIP: parseIPv6("2001:db8::2")
    )

    let tcp = TCPHeader(
      sourcePort: 54321,
      destPort: 80,
      flags: TCP_SYN,
      windowSize: 65535
    )

    let packet = ipv6 / tcp
    check packet.hasIPv6 == true
    check packet.tcp.sourcePort == 54321
    check packet.tcp.destPort == 80

  test "IPv6 layer stacking with UDP":
    let ipv6 = IPv6Header(
      version: 6,
      payloadLength: 8,
      nextHeader: IPV6_NEXT_HEADER_UDP,
      hopLimit: 64,
      sourceIP: parseIPv6("fe80::1"),
      destIP: parseIPv6("fe80::2")
    )

    let udp = UDPHeader(
      sourcePort: 12345,
      destPort: 53,
      length: 8,
      checksum: 0
    )

    let packet = ipv6 / udp
    check packet.hasIPv6 == true
    check packet.udp.sourcePort == 12345

  test "IPv6 packet serialization":
    let ipv6 = IPv6Header(
      version: 6,
      payloadLength: 8,
      nextHeader: IPV6_NEXT_HEADER_ICMPV6,
      hopLimit: 64,
      sourceIP: parseIPv6("2001:db8::1"),
      destIP: parseIPv6("2001:db8::2")
    )

    let icmpv6 = ICMPv6Header(
      icmpType: ICMPV6_ECHO_REQUEST,
      code: 0
    )

    let packet = ipv6 / icmpv6
    let bytes = packet.toBytes()

    # Should be 40 (IPv6) + 8 (ICMPv6) = 48 bytes
    check bytes.len == 48

  test "IPv6 with Ethernet layer":
    let eth = EthernetHeader(
      destMAC: parseMAC("00:11:22:33:44:55"),
      srcMAC: parseMAC("AA:BB:CC:DD:EE:FF"),
      etherType: ETHERTYPE_IPV6
    )

    let ipv6 = IPv6Header(
      version: 6,
      payloadLength: 8,
      nextHeader: IPV6_NEXT_HEADER_ICMPV6,
      hopLimit: 64,
      sourceIP: parseIPv6("::1"),
      destIP: parseIPv6("::1")
    )

    let packet = eth / ipv6
    check packet.hasEthernet == true
    check packet.hasIPv6 == true
    check packet.ethernet.etherType == ETHERTYPE_IPV6

  test "IPv6 address to string - compression":
    # Test that longest run of zeros is compressed
    let ip1 = parseIPv6("2001:db8:0:0:1:0:0:1")
    check ipv6ToString(ip1) == "2001:db8::1:0:0:1"

    # All zeros
    let ip2 = parseIPv6("0:0:0:0:0:0:0:0")
    check ipv6ToString(ip2) == "::"

    # Loopback
    let ip3 = parseIPv6("0:0:0:0:0:0:0:1")
    check ipv6ToString(ip3) == "::1"

  test "IPv6 flow label handling":
    let header = IPv6Header(
      version: 6,
      trafficClass: 0,
      flowLabel: 0xFFFFF,  # Max 20-bit value
      payloadLength: 0,
      nextHeader: IPV6_NEXT_HEADER_NO_NEXT,
      hopLimit: 64,
      sourceIP: parseIPv6("::1"),
      destIP: parseIPv6("::1")
    )

    let bytes = header.toBytes()
    let parsed = parseIPv6Header(bytes)

    # Flow label should be preserved (20 bits)
    check parsed.flowLabel == 0xFFFFF
