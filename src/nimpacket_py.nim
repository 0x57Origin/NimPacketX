## NimPacket Python Bindings - Complete API
##
## This module provides FULL Python bindings for ALL NimPacket functionality.
## Build with: nim c --app:lib --out:nimpacket_py.pyd -d:release nimpacket_py.nim
##
## ALL Nim functionality is accessible from Python!

import nimpy
import std/[strutils, endians, json, tables, random, times]
import nimpacket
import ethernet, arp, ipv6, icmpv6, dns, dhcp, rawsocket, fragmentation

# ============================================================================
# CONSTANTS - All protocol constants exported
# ============================================================================

# TCP Flags
proc TCP_FIN*(): int {.exportpy.} = nimpacket.TCP_FIN.int
proc TCP_SYN*(): int {.exportpy.} = nimpacket.TCP_SYN.int
proc TCP_RST*(): int {.exportpy.} = nimpacket.TCP_RST.int
proc TCP_PSH*(): int {.exportpy.} = nimpacket.TCP_PSH.int
proc TCP_ACK*(): int {.exportpy.} = nimpacket.TCP_ACK.int
proc TCP_URG*(): int {.exportpy.} = nimpacket.TCP_URG.int

# IP Protocols
proc IPPROTO_ICMP*(): int {.exportpy.} = nimpacket.IPPROTO_ICMP.int
proc IPPROTO_TCP*(): int {.exportpy.} = nimpacket.IPPROTO_TCP.int
proc IPPROTO_UDP*(): int {.exportpy.} = nimpacket.IPPROTO_UDP.int
proc IPPROTO_ICMPV6*(): int {.exportpy.} = nimpacket.IPPROTO_ICMPV6.int

# ICMP Types
proc ICMP_ECHO_REPLY*(): int {.exportpy.} = nimpacket.ICMP_ECHO_REPLY.int
proc ICMP_ECHO_REQUEST*(): int {.exportpy.} = nimpacket.ICMP_ECHO_REQUEST.int
proc ICMP_TIME_EXCEEDED*(): int {.exportpy.} = nimpacket.ICMP_TIME_EXCEEDED.int

# EtherTypes
proc ETHERTYPE_IPV4*(): int {.exportpy.} = ethernet.ETHERTYPE_IPV4.int
proc ETHERTYPE_IPV6*(): int {.exportpy.} = ethernet.ETHERTYPE_IPV6.int
proc ETHERTYPE_ARP*(): int {.exportpy.} = ethernet.ETHERTYPE_ARP.int

# ARP
proc ARP_REQUEST*(): int {.exportpy.} = arp.ARP_REQUEST.int
proc ARP_REPLY*(): int {.exportpy.} = arp.ARP_REPLY.int

# DNS Types
proc DNS_TYPE_A*(): int {.exportpy.} = dns.DNS_TYPE_A.int
proc DNS_TYPE_AAAA*(): int {.exportpy.} = dns.DNS_TYPE_AAAA.int
proc DNS_TYPE_CNAME*(): int {.exportpy.} = dns.DNS_TYPE_CNAME.int
proc DNS_TYPE_MX*(): int {.exportpy.} = dns.DNS_TYPE_MX.int
proc DNS_TYPE_TXT*(): int {.exportpy.} = dns.DNS_TYPE_TXT.int
proc DNS_TYPE_NS*(): int {.exportpy.} = dns.DNS_TYPE_NS.int
proc DNS_TYPE_PTR*(): int {.exportpy.} = dns.DNS_TYPE_PTR.int
proc DNS_TYPE_SOA*(): int {.exportpy.} = dns.DNS_TYPE_SOA.int
proc DNS_TYPE_SRV*(): int {.exportpy.} = dns.DNS_TYPE_SRV.int
proc DNS_TYPE_ANY*(): int {.exportpy.} = dns.DNS_TYPE_ANY.int

# DHCP Types
proc DHCP_DISCOVER*(): int {.exportpy.} = dhcp.DHCP_DISCOVER.int
proc DHCP_OFFER*(): int {.exportpy.} = dhcp.DHCP_OFFER.int
proc DHCP_REQUEST*(): int {.exportpy.} = dhcp.DHCP_REQUEST.int
proc DHCP_DECLINE*(): int {.exportpy.} = dhcp.DHCP_DECLINE.int
proc DHCP_ACK*(): int {.exportpy.} = dhcp.DHCP_ACK.int
proc DHCP_NAK*(): int {.exportpy.} = dhcp.DHCP_NAK.int
proc DHCP_RELEASE*(): int {.exportpy.} = dhcp.DHCP_RELEASE.int
proc DHCP_INFORM*(): int {.exportpy.} = dhcp.DHCP_INFORM.int

# ICMPv6 Types
proc ICMPV6_ECHO_REQUEST*(): int {.exportpy.} = icmpv6.ICMPV6_ECHO_REQUEST.int
proc ICMPV6_ECHO_REPLY*(): int {.exportpy.} = icmpv6.ICMPV6_ECHO_REPLY.int
proc ICMPV6_ROUTER_SOLICITATION*(): int {.exportpy.} = icmpv6.ICMPV6_ROUTER_SOLICITATION.int
proc ICMPV6_NEIGHBOR_SOLICITATION*(): int {.exportpy.} = icmpv6.ICMPV6_NEIGHBOR_SOLICITATION.int

# IPv6 Next Headers
proc IPV6_NEXT_HEADER_TCP*(): int {.exportpy.} = ipv6.IPV6_NEXT_HEADER_TCP.int
proc IPV6_NEXT_HEADER_UDP*(): int {.exportpy.} = ipv6.IPV6_NEXT_HEADER_UDP.int
proc IPV6_NEXT_HEADER_ICMPV6*(): int {.exportpy.} = ipv6.IPV6_NEXT_HEADER_ICMPV6.int

# Fragmentation Strategies
proc FRAG_TINY*(): int {.exportpy.} = FragmentationStrategy.TinyFragments.ord
proc FRAG_OVERLAP*(): int {.exportpy.} = FragmentationStrategy.OverlapPoison.ord
proc FRAG_OUT_OF_ORDER*(): int {.exportpy.} = FragmentationStrategy.OutOfOrder.ord
proc FRAG_TIME_DELAYED*(): int {.exportpy.} = FragmentationStrategy.TimeDelayed.ord
proc FRAG_POLYMORPHIC*(): int {.exportpy.} = FragmentationStrategy.PolymorphicRandom.ord

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

proc parse_ipv4_address*(ip: string): int {.exportpy.} =
  ## Converts IPv4 string to integer
  return nimpacket.parseIPv4(ip).int

proc ipv4_to_string*(ip: int): string {.exportpy.} =
  ## Converts integer to IPv4 string
  return nimpacket.ipToString(ip.uint32)

proc parse_mac_address*(mac: string): seq[int] {.exportpy.} =
  ## Converts MAC string to bytes
  let parsed = ethernet.parseMAC(mac)
  result = newSeq[int](6)
  for i in 0..5:
    result[i] = parsed[i].int

proc mac_to_string*(data: seq[int]): string {.exportpy.} =
  ## Converts bytes to MAC string
  var macArray: array[6, uint8]
  for i in 0..5:
    macArray[i] = data[i].uint8
  return ethernet.macToString(macArray)

proc parse_ipv6_address*(ip: string): seq[int] {.exportpy.} =
  ## Converts IPv6 string to bytes
  let parsed = ipv6.parseIPv6(ip)
  result = newSeq[int](16)
  for i in 0..15:
    result[i] = parsed[i].int

proc ipv6_to_string*(data: seq[int]): string {.exportpy.} =
  ## Converts bytes to IPv6 string
  var arr: array[16, uint8]
  for i in 0..15:
    arr[i] = data[i].uint8
  return ipv6.ipv6ToString(arr)

proc htons*(x: int): int {.exportpy.} =
  ## Host to network short
  return nimpacket.htons(x.uint16).int

proc ntohs*(x: int): int {.exportpy.} =
  ## Network to host short
  return nimpacket.ntohs(x.uint16).int

proc htonl*(x: int): int {.exportpy.} =
  ## Host to network long
  return nimpacket.htonl(x.uint32).int

proc ntohl*(x: int): int {.exportpy.} =
  ## Network to host long
  return nimpacket.ntohl(x.uint32).int

proc get_broadcast_mac*(): seq[int] {.exportpy.} =
  ## Returns broadcast MAC address
  let mac = ethernet.broadcastMAC()
  result = newSeq[int](6)
  for i in 0..5:
    result[i] = mac[i].int

# ============================================================================
# IPv4 HEADER
# ============================================================================

proc create_ipv4_header*(srcIP: string, dstIP: string, protocol: int,
                         ttl: int = 64, identification: int = 0,
                         totalLength: int = 20): seq[int] {.exportpy.} =
  ## Creates an IPv4 header and returns bytes
  var header = IPv4Header(
    version: 4,
    headerLength: 5,
    totalLength: totalLength.uint16,
    identification: identification.uint16,
    timeToLive: ttl.uint8,
    protocol: protocol.uint8,
    sourceIP: parseIPv4(srcIP),
    destIP: parseIPv4(dstIP)
  )
  header.checksum = calculateIPv4Checksum(header)

  let bytes = header.toBytes()
  result = newSeq[int](bytes.len)
  for i, b in bytes:
    result[i] = b.int

proc parse_ipv4_header*(data: seq[int]): PyObject {.exportpy.} =
  ## Parses IPv4 header from bytes and returns dict
  var bytes = newSeq[byte](data.len)
  for i, b in data:
    bytes[i] = b.byte

  let header = nimpacket.parseIPv4(bytes)

  let result = %*{
    "version": header.version,
    "header_length": header.headerLength,
    "type_of_service": header.typeOfService,
    "total_length": header.totalLength,
    "identification": header.identification,
    "flags": header.flags,
    "fragment_offset": header.fragmentOffset,
    "ttl": header.timeToLive,
    "protocol": header.protocol,
    "checksum": header.checksum,
    "src_ip": ipToString(header.sourceIP),
    "dst_ip": ipToString(header.destIP)
  }
  return pyImport("json").loads($result)

proc calculate_ipv4_checksum*(data: seq[int]): int {.exportpy.} =
  ## Calculates IPv4 header checksum
  var bytes = newSeq[byte](data.len)
  for i, b in data:
    bytes[i] = b.byte
  let header = nimpacket.parseIPv4(bytes)
  return calculateIPv4Checksum(header).int

# ============================================================================
# IPv6 HEADER
# ============================================================================

proc create_ipv6_header*(srcIP: string, dstIP: string, nextHeader: int,
                         payloadLength: int = 0, hopLimit: int = 64): seq[int] {.exportpy.} =
  ## Creates an IPv6 header and returns bytes
  let header = IPv6Header(
    version: 6,
    payloadLength: payloadLength.uint16,
    nextHeader: nextHeader.uint8,
    hopLimit: hopLimit.uint8,
    sourceIP: parseIPv6(srcIP),
    destIP: parseIPv6(dstIP)
  )

  let bytes = header.toBytes()
  result = newSeq[int](bytes.len)
  for i, b in bytes:
    result[i] = b.int

proc parse_ipv6_header*(data: seq[int]): PyObject {.exportpy.} =
  ## Parses IPv6 header from bytes
  var bytes = newSeq[byte](data.len)
  for i, b in data:
    bytes[i] = b.byte

  let header = ipv6.parseIPv6Header(bytes)

  var srcArr: array[16, uint8]
  var dstArr: array[16, uint8]
  for i in 0..15:
    srcArr[i] = header.sourceIP[i]
    dstArr[i] = header.destIP[i]

  let result = %*{
    "version": header.version,
    "traffic_class": header.trafficClass,
    "flow_label": header.flowLabel,
    "payload_length": header.payloadLength,
    "next_header": header.nextHeader,
    "hop_limit": header.hopLimit,
    "src_ip": ipv6.ipv6ToString(srcArr),
    "dst_ip": ipv6.ipv6ToString(dstArr)
  }
  return pyImport("json").loads($result)

# ============================================================================
# TCP HEADER
# ============================================================================

proc create_tcp_header*(srcPort: int, dstPort: int, flags: int,
                        seqNum: int = 0, ackNum: int = 0,
                        windowSize: int = 65535): seq[int] {.exportpy.} =
  ## Creates a TCP header and returns bytes
  let header = TCPHeader(
    sourcePort: srcPort.uint16,
    destPort: dstPort.uint16,
    sequenceNumber: seqNum.uint32,
    acknowledgmentNumber: ackNum.uint32,
    headerLength: 5,
    flags: flags.uint16,
    windowSize: windowSize.uint16
  )

  let bytes = header.toBytes()
  result = newSeq[int](bytes.len)
  for i, b in bytes:
    result[i] = b.int

proc parse_tcp_header*(data: seq[int]): PyObject {.exportpy.} =
  ## Parses TCP header from bytes
  var bytes = newSeq[byte](data.len)
  for i, b in data:
    bytes[i] = b.byte

  let header = nimpacket.parseTCP(bytes)

  let result = %*{
    "src_port": header.sourcePort,
    "dst_port": header.destPort,
    "seq_num": header.sequenceNumber,
    "ack_num": header.acknowledgmentNumber,
    "header_length": header.headerLength,
    "flags": header.flags,
    "window_size": header.windowSize,
    "checksum": header.checksum,
    "urgent_pointer": header.urgentPointer
  }
  return pyImport("json").loads($result)

proc calculate_tcp_checksum*(ipData: seq[int], tcpData: seq[int],
                             payload: seq[int] = @[]): int {.exportpy.} =
  ## Calculates TCP checksum with pseudo-header
  var ipBytes = newSeq[byte](ipData.len)
  for i, b in ipData:
    ipBytes[i] = b.byte

  var tcpBytes = newSeq[byte](tcpData.len)
  for i, b in tcpData:
    tcpBytes[i] = b.byte

  var payloadBytes = newSeq[byte](payload.len)
  for i, b in payload:
    payloadBytes[i] = b.byte

  let ip = nimpacket.parseIPv4(ipBytes)
  let tcp = nimpacket.parseTCP(tcpBytes)

  return calculateTCPChecksum(ip, tcp, payloadBytes).int

# ============================================================================
# UDP HEADER
# ============================================================================

proc create_udp_header*(srcPort: int, dstPort: int, length: int = 8): seq[int] {.exportpy.} =
  ## Creates a UDP header and returns bytes
  let header = UDPHeader(
    sourcePort: srcPort.uint16,
    destPort: dstPort.uint16,
    length: length.uint16
  )

  let bytes = header.toBytes()
  result = newSeq[int](bytes.len)
  for i, b in bytes:
    result[i] = b.int

proc parse_udp_header*(data: seq[int]): PyObject {.exportpy.} =
  ## Parses UDP header from bytes
  var bytes = newSeq[byte](data.len)
  for i, b in data:
    bytes[i] = b.byte

  let header = nimpacket.parseUDP(bytes)

  let result = %*{
    "src_port": header.sourcePort,
    "dst_port": header.destPort,
    "length": header.length,
    "checksum": header.checksum
  }
  return pyImport("json").loads($result)

proc calculate_udp_checksum*(ipData: seq[int], udpData: seq[int],
                             payload: seq[int] = @[]): int {.exportpy.} =
  ## Calculates UDP checksum with pseudo-header
  var ipBytes = newSeq[byte](ipData.len)
  for i, b in ipData:
    ipBytes[i] = b.byte

  var udpBytes = newSeq[byte](udpData.len)
  for i, b in udpData:
    udpBytes[i] = b.byte

  var payloadBytes = newSeq[byte](payload.len)
  for i, b in payload:
    payloadBytes[i] = b.byte

  let ip = nimpacket.parseIPv4(ipBytes)
  let udp = nimpacket.parseUDP(udpBytes)

  return calculateUDPChecksum(ip, udp, payloadBytes).int

# ============================================================================
# ICMP HEADER
# ============================================================================

proc create_icmp_header*(icmpType: int, code: int = 0,
                         identifier: int = 0, sequence: int = 0): seq[int] {.exportpy.} =
  ## Creates an ICMP header and returns bytes
  var header = ICMPHeader(
    icmpType: icmpType.uint8,
    code: code.uint8,
    identifier: identifier.uint16,
    sequenceNumber: sequence.uint16
  )
  header.checksum = calculateICMPChecksum(header, @[])

  let bytes = header.toBytes()
  result = newSeq[int](bytes.len)
  for i, b in bytes:
    result[i] = b.int

proc parse_icmp_header*(data: seq[int]): PyObject {.exportpy.} =
  ## Parses ICMP header from bytes
  var bytes = newSeq[byte](data.len)
  for i, b in data:
    bytes[i] = b.byte

  let header = nimpacket.parseICMP(bytes)

  let result = %*{
    "icmp_type": header.icmpType,
    "code": header.code,
    "checksum": header.checksum,
    "identifier": header.identifier,
    "sequence": header.sequenceNumber
  }
  return pyImport("json").loads($result)

proc calculate_icmp_checksum*(icmpData: seq[int], payload: seq[int] = @[]): int {.exportpy.} =
  ## Calculates ICMP checksum
  var icmpBytes = newSeq[byte](icmpData.len)
  for i, b in icmpData:
    icmpBytes[i] = b.byte

  var payloadBytes = newSeq[byte](payload.len)
  for i, b in payload:
    payloadBytes[i] = b.byte

  let header = nimpacket.parseICMP(icmpBytes)
  return calculateICMPChecksum(header, payloadBytes).int

# ============================================================================
# ICMPv6 HEADER
# ============================================================================

proc create_icmpv6_echo_request*(identifier: int, sequence: int): seq[int] {.exportpy.} =
  ## Creates an ICMPv6 Echo Request
  let header = icmpv6.newICMPv6EchoRequest(identifier.uint16, sequence.uint16)
  let bytes = header.toBytes()
  result = newSeq[int](bytes.len)
  for i, b in bytes:
    result[i] = b.int

proc create_icmpv6_echo_reply*(identifier: int, sequence: int): seq[int] {.exportpy.} =
  ## Creates an ICMPv6 Echo Reply
  let header = icmpv6.newICMPv6EchoReply(identifier.uint16, sequence.uint16)
  let bytes = header.toBytes()
  result = newSeq[int](bytes.len)
  for i, b in bytes:
    result[i] = b.int

proc parse_icmpv6_header*(data: seq[int]): PyObject {.exportpy.} =
  ## Parses ICMPv6 header from bytes
  var bytes = newSeq[byte](data.len)
  for i, b in data:
    bytes[i] = b.byte

  let header = icmpv6.parseICMPv6Header(bytes)

  let result = %*{
    "icmp_type": header.icmpType,
    "code": header.code,
    "checksum": header.checksum
  }
  return pyImport("json").loads($result)

# ============================================================================
# ETHERNET HEADER
# ============================================================================

proc create_ethernet_header*(srcMAC: string, dstMAC: string,
                             etherType: int): seq[int] {.exportpy.} =
  ## Creates an Ethernet header and returns bytes
  let header = EthernetHeader(
    srcMAC: parseMAC(srcMAC),
    destMAC: parseMAC(dstMAC),
    etherType: etherType.uint16
  )

  let bytes = header.toBytes()
  result = newSeq[int](bytes.len)
  for i, b in bytes:
    result[i] = b.int

proc parse_ethernet_header*(data: seq[int]): PyObject {.exportpy.} =
  ## Parses Ethernet header from bytes
  var bytes = newSeq[byte](data.len)
  for i, b in data:
    bytes[i] = b.byte

  let header = ethernet.parseEthernet(bytes)

  let result = %*{
    "dst_mac": macToString(header.destMAC),
    "src_mac": macToString(header.srcMAC),
    "ether_type": header.etherType
  }
  return pyImport("json").loads($result)

# ============================================================================
# ARP PACKET
# ============================================================================

proc create_arp_request*(senderMAC: string, senderIP: string,
                         targetIP: string): seq[int] {.exportpy.} =
  ## Creates an ARP request packet
  let packet = arp.newARPRequest(
    parseMAC(senderMAC),
    parseIPv4(senderIP),
    parseIPv4(targetIP)
  )

  let bytes = packet.toBytes()
  result = newSeq[int](bytes.len)
  for i, b in bytes:
    result[i] = b.int

proc create_arp_reply*(senderMAC: string, senderIP: string,
                       targetMAC: string, targetIP: string): seq[int] {.exportpy.} =
  ## Creates an ARP reply packet
  let packet = arp.newARPReply(
    parseMAC(senderMAC),
    parseIPv4(senderIP),
    parseMAC(targetMAC),
    parseIPv4(targetIP)
  )

  let bytes = packet.toBytes()
  result = newSeq[int](bytes.len)
  for i, b in bytes:
    result[i] = b.int

proc parse_arp_packet*(data: seq[int]): PyObject {.exportpy.} =
  ## Parses ARP packet from bytes
  var bytes = newSeq[byte](data.len)
  for i, b in data:
    bytes[i] = b.byte

  let packet = arp.parseARP(bytes)

  let result = %*{
    "hardware_type": packet.hardwareType,
    "protocol_type": packet.protocolType,
    "hardware_size": packet.hardwareSize,
    "protocol_size": packet.protocolSize,
    "opcode": packet.opcode,
    "sender_mac": macToString(packet.senderMAC),
    "sender_ip": ipToString(packet.senderIP),
    "target_mac": macToString(packet.targetMAC),
    "target_ip": ipToString(packet.targetIP)
  }
  return pyImport("json").loads($result)

# ============================================================================
# DNS PACKET
# ============================================================================

proc create_dns_query*(domain: string, queryType: int = 1,
                       transactionID: int = 0): seq[int] {.exportpy.} =
  ## Creates a DNS query packet
  var packet = dns.newDNSQuery(domain, queryType.uint16)
  if transactionID != 0:
    packet.header.transactionID = transactionID.uint16
  else:
    packet.header.transactionID = rand(65535).uint16

  let bytes = packet.toBytes()
  result = newSeq[int](bytes.len)
  for i, b in bytes:
    result[i] = b.int

proc parse_dns_packet*(data: seq[int]): PyObject {.exportpy.} =
  ## Parses DNS packet from bytes
  var bytes = newSeq[byte](data.len)
  for i, b in data:
    bytes[i] = b.byte

  let packet = dns.parseDNSPacket(bytes)
  let flags = dns.parseDNSFlags(packet.header.flags)

  var questions = newSeq[JsonNode]()
  for q in packet.questions:
    questions.add(%*{
      "name": q.name,
      "type": q.qtype,
      "type_name": dns.getRecordTypeName(q.qtype),
      "class": q.qclass
    })

  var answers = newSeq[JsonNode]()
  for a in packet.answers:
    answers.add(%*{
      "name": a.name,
      "type": a.rrtype,
      "type_name": dns.getRecordTypeName(a.rrtype),
      "class": a.rrclass,
      "ttl": a.ttl,
      "rdlength": a.rdlength
    })

  let result = %*{
    "transaction_id": packet.header.transactionID,
    "is_response": flags.qr,
    "opcode": flags.opcode,
    "authoritative": flags.aa,
    "truncated": flags.tc,
    "recursion_desired": flags.rd,
    "recursion_available": flags.ra,
    "rcode": flags.rcode,
    "question_count": packet.header.questionCount,
    "answer_count": packet.header.answerCount,
    "authority_count": packet.header.authorityCount,
    "additional_count": packet.header.additionalCount,
    "questions": questions,
    "answers": answers
  }
  return pyImport("json").loads($result)

proc encode_domain_name*(domain: string): seq[int] {.exportpy.} =
  ## Encodes a domain name to DNS wire format
  let bytes = dns.encodeDomainName(domain)
  result = newSeq[int](bytes.len)
  for i, b in bytes:
    result[i] = b.int

# ============================================================================
# DHCP PACKET
# ============================================================================

proc create_dhcp_discover*(mac: string, transactionID: int = 0): seq[int] {.exportpy.} =
  ## Creates a DHCP DISCOVER packet
  let macBytes = parseMAC(mac)
  var macArray: array[6, uint8]
  for i in 0..5:
    macArray[i] = macBytes[i]

  let xid = if transactionID == 0: rand(high(int32)).uint32 else: transactionID.uint32
  let packet = dhcp.newDHCPDiscover(macArray, xid)
  let bytes = packet.toBytes()

  result = newSeq[int](bytes.len)
  for i, b in bytes:
    result[i] = b.int

proc create_dhcp_request*(mac: string, requestedIP: string, serverIP: string,
                          transactionID: int = 0): seq[int] {.exportpy.} =
  ## Creates a DHCP REQUEST packet
  let macBytes = parseMAC(mac)
  var macArray: array[6, uint8]
  for i in 0..5:
    macArray[i] = macBytes[i]

  let xid = if transactionID == 0: rand(high(int32)).uint32 else: transactionID.uint32
  let packet = dhcp.newDHCPRequest(macArray, requestedIP, serverIP, xid)
  let bytes = packet.toBytes()

  result = newSeq[int](bytes.len)
  for i, b in bytes:
    result[i] = b.int

proc create_dhcp_release*(mac: string, clientIP: string, serverIP: string,
                          transactionID: int = 0): seq[int] {.exportpy.} =
  ## Creates a DHCP RELEASE packet
  let macBytes = parseMAC(mac)
  var macArray: array[6, uint8]
  for i in 0..5:
    macArray[i] = macBytes[i]

  let xid = if transactionID == 0: rand(high(int32)).uint32 else: transactionID.uint32
  let packet = dhcp.newDHCPRelease(macArray, clientIP, serverIP, xid)
  let bytes = packet.toBytes()

  result = newSeq[int](bytes.len)
  for i, b in bytes:
    result[i] = b.int

proc parse_dhcp_packet*(data: seq[int]): PyObject {.exportpy.} =
  ## Parses DHCP packet from bytes
  var bytes = newSeq[byte](data.len)
  for i, b in data:
    bytes[i] = b.byte

  let packet = dhcp.parseDHCPPacket(bytes)
  let msgType = packet.getMessageType()

  var options = newSeq[JsonNode]()
  for opt in packet.options:
    options.add(%*{
      "code": opt.code,
      "length": opt.length
    })

  var macStr = ""
  for i in 0..5:
    if i > 0:
      macStr.add(":")
    macStr.add(packet.chaddr[i].toHex(2))

  let result = %*{
    "op": packet.op,
    "htype": packet.htype,
    "hlen": packet.hlen,
    "hops": packet.hops,
    "transaction_id": packet.xid,
    "secs": packet.secs,
    "flags": packet.flags,
    "client_ip": ipToString(packet.ciaddr),
    "your_ip": ipToString(packet.yiaddr),
    "server_ip": ipToString(packet.siaddr),
    "gateway_ip": ipToString(packet.giaddr),
    "client_mac": macStr,
    "message_type": dhcp.getMessageTypeName(msgType),
    "message_type_code": msgType,
    "options": options
  }
  return pyImport("json").loads($result)

# ============================================================================
# COMPLETE PACKET PARSING
# ============================================================================

proc parse_packet*(data: seq[int]): PyObject {.exportpy.} =
  ## Parses a complete packet (auto-detects IPv4/IPv6, TCP/UDP/ICMP)
  var bytes = newSeq[byte](data.len)
  for i, b in data:
    bytes[i] = b.byte

  let packet = nimpacket.parsePacket(bytes)

  var result = %*{
    "has_ethernet": packet.hasEthernet,
    "has_arp": packet.hasARP,
    "has_ipv6": packet.hasIPv6
  }

  if packet.hasEthernet:
    result["ethernet"] = %*{
      "dst_mac": macToString(packet.ethernet.destMAC),
      "src_mac": macToString(packet.ethernet.srcMAC),
      "ether_type": packet.ethernet.etherType
    }

  if packet.hasARP:
    result["arp"] = %*{
      "opcode": packet.arp.opcode,
      "sender_mac": macToString(packet.arp.senderMAC),
      "sender_ip": ipToString(packet.arp.senderIP),
      "target_mac": macToString(packet.arp.targetMAC),
      "target_ip": ipToString(packet.arp.targetIP)
    }

  if packet.hasIPv6:
    var srcArr: array[16, uint8]
    var dstArr: array[16, uint8]
    for i in 0..15:
      srcArr[i] = packet.ipv6.sourceIP[i]
      dstArr[i] = packet.ipv6.destIP[i]

    result["ipv6"] = %*{
      "version": packet.ipv6.version,
      "payload_length": packet.ipv6.payloadLength,
      "next_header": packet.ipv6.nextHeader,
      "hop_limit": packet.ipv6.hopLimit,
      "src_ip": ipv6.ipv6ToString(srcArr),
      "dst_ip": ipv6.ipv6ToString(dstArr)
    }
  else:
    result["ipv4"] = %*{
      "version": packet.ipv4.version,
      "header_length": packet.ipv4.headerLength,
      "total_length": packet.ipv4.totalLength,
      "protocol": packet.ipv4.protocol,
      "ttl": packet.ipv4.timeToLive,
      "src_ip": ipToString(packet.ipv4.sourceIP),
      "dst_ip": ipToString(packet.ipv4.destIP)
    }

  if packet.ipv4.protocol == IPPROTO_TCP or
     (packet.hasIPv6 and packet.ipv6.nextHeader == IPV6_NEXT_HEADER_TCP):
    result["tcp"] = %*{
      "src_port": packet.tcp.sourcePort,
      "dst_port": packet.tcp.destPort,
      "seq_num": packet.tcp.sequenceNumber,
      "ack_num": packet.tcp.acknowledgmentNumber,
      "flags": packet.tcp.flags
    }

  if packet.ipv4.protocol == IPPROTO_UDP or
     (packet.hasIPv6 and packet.ipv6.nextHeader == IPV6_NEXT_HEADER_UDP):
    result["udp"] = %*{
      "src_port": packet.udp.sourcePort,
      "dst_port": packet.udp.destPort,
      "length": packet.udp.length
    }

  if packet.ipv4.protocol == IPPROTO_ICMP:
    result["icmp"] = %*{
      "type": packet.icmp.icmpType,
      "code": packet.icmp.code,
      "identifier": packet.icmp.identifier,
      "sequence": packet.icmp.sequenceNumber
    }

  if packet.payload.len > 0:
    var payloadInts = newSeq[int](packet.payload.len)
    for i, b in packet.payload:
      payloadInts[i] = b.int
    result["payload"] = %payloadInts
    result["payload_length"] = %packet.payload.len

  return pyImport("json").loads($result)

# ============================================================================
# RAW SOCKET OPERATIONS
# ============================================================================

var globalSocket: RawSocket

proc is_admin*(): bool {.exportpy.} =
  ## Checks if running with administrator/root privileges
  return rawsocket.isRunningAsAdmin()

proc create_raw_socket*(protocol: int = 6): bool {.exportpy.} =
  ## Creates a raw socket. Returns true on success.
  ## protocol: 1=ICMP, 6=TCP, 17=UDP, 255=RAW
  try:
    globalSocket = rawsocket.createRawSocket(AF_INET, protocol.cint)
    return true
  except:
    return false

proc create_icmp_socket*(): bool {.exportpy.} =
  ## Creates an ICMP socket for ping operations
  try:
    globalSocket = rawsocket.createICMPSocket()
    return true
  except:
    return false

proc create_tcp_socket*(): bool {.exportpy.} =
  ## Creates a TCP raw socket
  try:
    globalSocket = rawsocket.createTCPSocket()
    return true
  except:
    return false

proc create_udp_socket*(): bool {.exportpy.} =
  ## Creates a UDP raw socket
  try:
    globalSocket = rawsocket.createUDPSocket()
    return true
  except:
    return false

proc close_socket*(): bool {.exportpy.} =
  ## Closes the raw socket
  try:
    globalSocket.close()
    return true
  except:
    return false

proc send_packet*(packet: seq[int], destIP: string): int {.exportpy.} =
  ## Sends a raw packet. Returns bytes sent or -1 on error.
  try:
    var bytes = newSeq[byte](packet.len)
    for i, b in packet:
      bytes[i] = b.byte
    return globalSocket.sendPacket(bytes, destIP)
  except:
    return -1

proc receive_packet*(timeoutMs: int = 5000, maxSize: int = 65535): seq[int] {.exportpy.} =
  ## Receives a packet. Returns empty seq on timeout/error.
  try:
    let bytes = globalSocket.receivePacket(maxSize, timeoutMs)
    result = newSeq[int](bytes.len)
    for i, b in bytes:
      result[i] = b.int
  except:
    return @[]

proc set_socket_timeout*(timeoutMs: int): bool {.exportpy.} =
  ## Sets receive timeout on socket
  try:
    globalSocket.setReceiveTimeout(timeoutMs)
    return true
  except:
    return false

proc set_ip_header_include*(enable: bool): bool {.exportpy.} =
  ## Enables/disables IP_HDRINCL option
  try:
    globalSocket.setIPHeaderInclude(enable)
    return true
  except:
    return false

proc set_broadcast*(enable: bool): bool {.exportpy.} =
  ## Enables/disables broadcast
  try:
    globalSocket.setBroadcast(enable)
    return true
  except:
    return false

# ============================================================================
# IP FRAGMENTATION
# ============================================================================

proc fragment_packet*(ipHeader: seq[int], payload: seq[int],
                      strategy: int, fragmentSize: int = 8): seq[seq[int]] {.exportpy.} =
  ## Fragments a packet using the specified strategy
  ## strategy: 0=Tiny, 1=Overlap, 2=OutOfOrder, 3=TimeDelayed, 4=Polymorphic
  var ipBytes = newSeq[byte](ipHeader.len)
  for i, b in ipHeader:
    ipBytes[i] = b.byte

  var payloadBytes = newSeq[byte](payload.len)
  for i, b in payload:
    payloadBytes[i] = b.byte

  let baseHeader = nimpacket.parseIPv4(ipBytes)

  var config = fragmentation.createDefaultConfig(FragmentationStrategy(strategy))
  config.fragmentSize = fragmentSize

  let fragments = fragmentation.applyStrategy(config, baseHeader, payloadBytes)

  result = @[]
  for frag in fragments:
    var fragBytes = frag.header.toBytes()
    fragBytes &= frag.payload

    var fragInts = newSeq[int](fragBytes.len)
    for i, b in fragBytes:
      fragInts[i] = b.int
    result.add(fragInts)

proc send_fragmented*(ipHeader: seq[int], payload: seq[int], destIP: string,
                      strategy: int, delayMs: int = 100): int {.exportpy.} =
  ## Sends a fragmented packet using the specified strategy
  ## Returns total bytes sent or -1 on error
  try:
    var ipBytes = newSeq[byte](ipHeader.len)
    for i, b in ipHeader:
      ipBytes[i] = b.byte

    var payloadBytes = newSeq[byte](payload.len)
    for i, b in payload:
      payloadBytes[i] = b.byte

    let baseHeader = nimpacket.parseIPv4(ipBytes)

    return globalSocket.sendFragmented(
      baseHeader, payloadBytes, destIP,
      FragmentationStrategy(strategy), delayMs
    )
  except:
    return -1

# ============================================================================
# PACKET BUILDING HELPERS
# ============================================================================

proc build_tcp_syn_packet*(srcIP: string, dstIP: string, srcPort: int,
                           dstPort: int, ttl: int = 64): seq[int] {.exportpy.} =
  ## Builds a complete TCP SYN packet ready to send
  let totalLen = 40  # IP(20) + TCP(20)

  var ip = IPv4Header(
    version: 4,
    headerLength: 5,
    totalLength: totalLen.uint16,
    identification: rand(65535).uint16,
    timeToLive: ttl.uint8,
    protocol: IPPROTO_TCP,
    sourceIP: parseIPv4(srcIP),
    destIP: parseIPv4(dstIP)
  )

  var tcp = TCPHeader(
    sourcePort: srcPort.uint16,
    destPort: dstPort.uint16,
    sequenceNumber: rand(high(int32)).uint32,
    headerLength: 5,
    flags: TCP_SYN,
    windowSize: 65535
  )

  ip.checksum = calculateIPv4Checksum(ip)
  tcp.checksum = calculateTCPChecksum(ip, tcp, @[])

  let packet = (ip / tcp).toBytes()
  result = newSeq[int](packet.len)
  for i, b in packet:
    result[i] = b.int

proc build_icmp_echo_packet*(srcIP: string, dstIP: string, identifier: int,
                             sequence: int, payload: seq[int] = @[],
                             ttl: int = 64): seq[int] {.exportpy.} =
  ## Builds a complete ICMP Echo Request packet
  var payloadBytes = newSeq[byte](payload.len)
  for i, b in payload:
    payloadBytes[i] = b.byte

  let totalLen = 20 + 8 + payloadBytes.len

  var ip = IPv4Header(
    version: 4,
    headerLength: 5,
    totalLength: totalLen.uint16,
    identification: rand(65535).uint16,
    timeToLive: ttl.uint8,
    protocol: IPPROTO_ICMP,
    sourceIP: parseIPv4(srcIP),
    destIP: parseIPv4(dstIP)
  )

  var icmp = ICMPHeader(
    icmpType: ICMP_ECHO_REQUEST,
    code: 0,
    identifier: identifier.uint16,
    sequenceNumber: sequence.uint16
  )

  ip.checksum = calculateIPv4Checksum(ip)
  icmp.checksum = calculateICMPChecksum(icmp, payloadBytes)

  let packet = (ip / icmp / payloadBytes).toBytes()
  result = newSeq[int](packet.len)
  for i, b in packet:
    result[i] = b.int

proc build_udp_packet*(srcIP: string, dstIP: string, srcPort: int,
                       dstPort: int, payload: seq[int] = @[],
                       ttl: int = 64): seq[int] {.exportpy.} =
  ## Builds a complete UDP packet
  var payloadBytes = newSeq[byte](payload.len)
  for i, b in payload:
    payloadBytes[i] = b.byte

  let udpLen = 8 + payloadBytes.len
  let totalLen = 20 + udpLen

  var ip = IPv4Header(
    version: 4,
    headerLength: 5,
    totalLength: totalLen.uint16,
    identification: rand(65535).uint16,
    timeToLive: ttl.uint8,
    protocol: IPPROTO_UDP,
    sourceIP: parseIPv4(srcIP),
    destIP: parseIPv4(dstIP)
  )

  var udp = UDPHeader(
    sourcePort: srcPort.uint16,
    destPort: dstPort.uint16,
    length: udpLen.uint16
  )

  ip.checksum = calculateIPv4Checksum(ip)
  udp.checksum = calculateUDPChecksum(ip, udp, payloadBytes)

  let packet = (ip / udp / payloadBytes).toBytes()
  result = newSeq[int](packet.len)
  for i, b in packet:
    result[i] = b.int

proc build_arp_frame*(srcMAC: string, srcIP: string, dstIP: string,
                      dstMAC: string = "FF:FF:FF:FF:FF:FF"): seq[int] {.exportpy.} =
  ## Builds a complete ARP request/reply Ethernet frame
  let eth = EthernetHeader(
    srcMAC: parseMAC(srcMAC),
    destMAC: parseMAC(dstMAC),
    etherType: ETHERTYPE_ARP
  )

  let arpPkt = if dstMAC == "FF:FF:FF:FF:FF:FF":
    arp.newARPRequest(parseMAC(srcMAC), parseIPv4(srcIP), parseIPv4(dstIP))
  else:
    arp.newARPReply(parseMAC(srcMAC), parseIPv4(srcIP), parseMAC(dstMAC), parseIPv4(dstIP))

  let frame = (eth / arpPkt).toBytes()
  result = newSeq[int](frame.len)
  for i, b in frame:
    result[i] = b.int

# ============================================================================
# VERSION & INFO
# ============================================================================

proc get_version*(): string {.exportpy.} =
  ## Returns NimPacket version
  return "0.2.0"

proc get_supported_protocols*(): seq[string] {.exportpy.} =
  ## Returns list of supported protocols
  return @[
    "IPv4", "IPv6", "TCP", "UDP", "ICMP", "ICMPv6",
    "Ethernet", "ARP", "DNS", "DHCP"
  ]

# Initialize random
randomize()
