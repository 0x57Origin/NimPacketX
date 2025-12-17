import unittest
import ../src/nimpacket

suite "ICMPv6 Header Tests":
  test "Create ICMPv6 Echo Request":
    let icmpv6 = newICMPv6EchoRequest(0x1234, 1)
    check icmpv6.icmpType == ICMPV6_ECHO_REQUEST
    check icmpv6.code == 0
    check icmpv6.checksum == 0  # Initially zero, calculated later

  test "Create ICMPv6 Echo Reply":
    let icmpv6 = newICMPv6EchoReply(0x5678, 42)
    check icmpv6.icmpType == ICMPV6_ECHO_REPLY
    check icmpv6.code == 0

  test "ICMPv6 header serialization":
    let header = ICMPv6Header(
      icmpType: ICMPV6_ECHO_REQUEST,
      code: 0,
      checksum: 0
    )

    let bytes = header.toBytes()
    check bytes.len == 8
    check bytes[0] == ICMPV6_ECHO_REQUEST
    check bytes[1] == 0

  test "ICMPv6 header roundtrip":
    let original = newICMPv6EchoReply(5678, 42)
    let bytes = original.toBytes()
    let parsed = parseICMPv6Header(bytes)

    check parsed.icmpType == original.icmpType
    check parsed.code == original.code
    check parsed.messageBody == original.messageBody

  test "ICMPv6 checksum calculation":
    let ipv6 = IPv6Header(
      version: 6,
      payloadLength: 8,
      nextHeader: IPV6_NEXT_HEADER_ICMPV6,
      hopLimit: 64,
      sourceIP: parseIPv6("2001:db8::1"),
      destIP: parseIPv6("2001:db8::2")
    )

    var icmpv6 = newICMPv6EchoRequest(1, 1)
    let checksum = calculateICMPv6Checksum(ipv6, icmpv6, @[])

    check checksum != 0

    # Set the checksum
    icmpv6.checksum = checksum

    # Verify by recalculating
    let verify = calculateICMPv6Checksum(ipv6, icmpv6, @[])
    check verify == checksum

  test "ICMPv6 checksum with payload":
    let ipv6 = IPv6Header(
      version: 6,
      payloadLength: 16,  # 8 ICMPv6 + 8 payload
      nextHeader: IPV6_NEXT_HEADER_ICMPV6,
      hopLimit: 64,
      sourceIP: parseIPv6("fe80::1"),
      destIP: parseIPv6("fe80::2")
    )

    var icmpv6 = newICMPv6EchoRequest(100, 200)
    let payload = @[byte 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]

    let checksum = calculateICMPv6Checksum(ipv6, icmpv6, payload)
    check checksum != 0

  test "ICMPv6 neighbor solicitation type":
    let icmpv6 = ICMPv6Header(
      icmpType: ICMPV6_NEIGHBOR_SOLICITATION,
      code: 0,
      checksum: 0
    )

    check icmpv6.icmpType == ICMPV6_NEIGHBOR_SOLICITATION
    check icmpv6.icmpType == 135

  test "ICMPv6 neighbor advertisement type":
    let icmpv6 = ICMPv6Header(
      icmpType: ICMPV6_NEIGHBOR_ADVERTISEMENT,
      code: 0,
      checksum: 0
    )

    check icmpv6.icmpType == ICMPV6_NEIGHBOR_ADVERTISEMENT
    check icmpv6.icmpType == 136

  test "ICMPv6 router solicitation type":
    let icmpv6 = ICMPv6Header(
      icmpType: ICMPV6_ROUTER_SOLICITATION,
      code: 0,
      checksum: 0
    )

    check icmpv6.icmpType == ICMPV6_ROUTER_SOLICITATION
    check icmpv6.icmpType == 133

  test "ICMPv6 router advertisement type":
    let icmpv6 = ICMPv6Header(
      icmpType: ICMPV6_ROUTER_ADVERTISEMENT,
      code: 0,
      checksum: 0
    )

    check icmpv6.icmpType == ICMPV6_ROUTER_ADVERTISEMENT
    check icmpv6.icmpType == 134

  test "ICMPv6 layer stacking":
    let ipv6 = IPv6Header(
      version: 6,
      payloadLength: 8,
      nextHeader: IPV6_NEXT_HEADER_ICMPV6,
      hopLimit: 64,
      sourceIP: parseIPv6("::1"),
      destIP: parseIPv6("::1")
    )

    let icmpv6 = newICMPv6EchoRequest(1, 1)
    let packet = ipv6 / icmpv6

    check packet.hasIPv6 == true
    check packet.ipv6.nextHeader == IPV6_NEXT_HEADER_ICMPV6
    check packet.icmpv6.icmpType == ICMPV6_ECHO_REQUEST

  test "ICMPv6 packet serialization and parsing":
    let ipv6 = IPv6Header(
      version: 6,
      payloadLength: 8,
      nextHeader: IPV6_NEXT_HEADER_ICMPV6,
      hopLimit: 64,
      sourceIP: parseIPv6("2001:db8::1"),
      destIP: parseIPv6("2001:db8::2")
    )

    var icmpv6 = newICMPv6EchoRequest(1234, 5)
    icmpv6.checksum = calculateICMPv6Checksum(ipv6, icmpv6, @[])

    let packet = ipv6 / icmpv6
    let bytes = packet.toBytes()

    # Parse it back
    let parsed = parsePacket(bytes)

    check parsed.hasIPv6 == true
    check parsed.ipv6.version == 6
    check parsed.icmpv6.icmpType == ICMPV6_ECHO_REQUEST

  test "ICMPv6 destination unreachable":
    let icmpv6 = ICMPv6Header(
      icmpType: ICMPV6_DEST_UNREACH,
      code: 0,
      checksum: 0
    )

    check icmpv6.icmpType == ICMPV6_DEST_UNREACH
    check icmpv6.icmpType == 1

  test "ICMPv6 time exceeded":
    let icmpv6 = ICMPv6Header(
      icmpType: ICMPV6_TIME_EXCEEDED,
      code: 0,
      checksum: 0
    )

    check icmpv6.icmpType == ICMPV6_TIME_EXCEEDED
    check icmpv6.icmpType == 3

  test "ICMPv6 with Ethernet frame":
    let eth = EthernetHeader(
      destMAC: parseMAC("33:33:00:00:00:01"),
      srcMAC: parseMAC("00:11:22:33:44:55"),
      etherType: ETHERTYPE_IPV6
    )

    let ipv6 = IPv6Header(
      version: 6,
      payloadLength: 8,
      nextHeader: IPV6_NEXT_HEADER_ICMPV6,
      hopLimit: 255,
      sourceIP: parseIPv6("fe80::1"),
      destIP: parseIPv6("ff02::1")
    )

    let icmpv6 = newICMPv6EchoRequest(1, 1)

    let packet = eth / ipv6 / icmpv6

    check packet.hasEthernet == true
    check packet.hasIPv6 == true
    check packet.ethernet.etherType == ETHERTYPE_IPV6
    check packet.icmpv6.icmpType == ICMPV6_ECHO_REQUEST
