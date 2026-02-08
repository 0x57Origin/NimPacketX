## DHCP Protocol Tests

import unittest
import ../src/dhcp

suite "DHCP Protocol Tests":

  test "DHCP option creation - byte":
    let opt = newDHCPOptionByte(DHCP_OPT_MESSAGE_TYPE, DHCP_DISCOVER)
    check opt.code == DHCP_OPT_MESSAGE_TYPE
    check opt.length == 1
    check opt.data[0] == DHCP_DISCOVER

  test "DHCP option creation - uint32":
    let opt = newDHCPOptionUint32(DHCP_OPT_LEASE_TIME, 86400)
    check opt.code == DHCP_OPT_LEASE_TIME
    check opt.length == 4

  test "DHCP option creation - IP":
    let opt = newDHCPOptionIP(DHCP_OPT_ROUTER, "192.168.1.1")
    check opt.code == DHCP_OPT_ROUTER
    check opt.length == 4
    check opt.data[0] == 192
    check opt.data[1] == 168
    check opt.data[2] == 1
    check opt.data[3] == 1

  test "DHCP option creation - string":
    let opt = newDHCPOptionString(DHCP_OPT_HOSTNAME, "myhost")
    check opt.code == DHCP_OPT_HOSTNAME
    check opt.length == 6

  test "DHCP option creation - multiple IPs":
    let opt = newDHCPOptionIPs(DHCP_OPT_DNS, @["8.8.8.8", "8.8.4.4"])
    check opt.code == DHCP_OPT_DNS
    check opt.length == 8  # 2 IPs x 4 bytes

  test "DHCP option serialization":
    let opt = newDHCPOptionByte(DHCP_OPT_MESSAGE_TYPE, DHCP_DISCOVER)
    let bytes = opt.toBytes()
    check bytes.len == 3  # code + length + data
    check bytes[0] == DHCP_OPT_MESSAGE_TYPE
    check bytes[1] == 1
    check bytes[2] == DHCP_DISCOVER

  test "DHCP DISCOVER creation":
    var mac: array[6, uint8]
    mac[0] = 0xAA
    mac[1] = 0xBB
    mac[2] = 0xCC
    mac[3] = 0xDD
    mac[4] = 0xEE
    mac[5] = 0xFF

    let packet = newDHCPDiscover(mac, 0x12345678)

    check packet.op == DHCP_BOOTREQUEST
    check packet.htype == DHCP_HTYPE_ETHERNET
    check packet.hlen == 6
    check packet.xid == 0x12345678
    check packet.flags == DHCP_FLAG_BROADCAST
    check packet.chaddr[0] == 0xAA
    check packet.options.len > 0

  test "DHCP packet serialization":
    var mac: array[6, uint8]
    for i in 0..5:
      mac[i] = (0xAA + i.uint8)

    let packet = newDHCPDiscover(mac)
    let bytes = packet.toBytes()

    # DHCP packets are minimum 300 bytes
    check bytes.len >= 300

    # Check magic cookie
    check bytes[236] == DHCP_MAGIC_COOKIE[0]
    check bytes[237] == DHCP_MAGIC_COOKIE[1]
    check bytes[238] == DHCP_MAGIC_COOKIE[2]
    check bytes[239] == DHCP_MAGIC_COOKIE[3]

  test "DHCP packet parsing":
    var mac: array[6, uint8]
    for i in 0..5:
      mac[i] = (0x11 + i.uint8)

    let original = newDHCPDiscover(mac, 0xDEADBEEF'u32)
    let bytes = original.toBytes()
    let parsed = parseDHCPPacket(bytes)

    check parsed.op == DHCP_BOOTREQUEST
    check parsed.htype == DHCP_HTYPE_ETHERNET
    check parsed.hlen == 6
    check parsed.xid == 0xDEADBEEF'u32
    check parsed.chaddr[0] == 0x11
    check parsed.getMessageType() == DHCP_DISCOVER

  test "DHCP REQUEST creation":
    var mac: array[6, uint8]
    for i in 0..5:
      mac[i] = 0xAA'u8

    let packet = newDHCPRequest(mac, "192.168.1.100", "192.168.1.1", 0x12345678)

    check packet.op == DHCP_BOOTREQUEST
    check packet.xid == 0x12345678
    check packet.hasOption(DHCP_OPT_MESSAGE_TYPE)
    check packet.hasOption(DHCP_OPT_REQUESTED_IP)
    check packet.hasOption(DHCP_OPT_SERVER_ID)
    check packet.getMessageType() == DHCP_REQUEST

  test "DHCP OFFER creation":
    var mac: array[6, uint8]
    for i in 0..5:
      mac[i] = 0xBB'u8

    let packet = newDHCPOffer(
      mac,
      offeredIP = "192.168.1.100",
      serverIP = "192.168.1.1",
      subnetMask = "255.255.255.0",
      router = "192.168.1.1",
      dns = @["8.8.8.8"],
      leaseTime = 3600
    )

    check packet.op == DHCP_BOOTREPLY
    check packet.getMessageType() == DHCP_OFFER
    check packet.hasOption(DHCP_OPT_SUBNET_MASK)
    check packet.hasOption(DHCP_OPT_ROUTER)
    check packet.hasOption(DHCP_OPT_DNS)
    check packet.hasOption(DHCP_OPT_LEASE_TIME)

  test "DHCP ACK creation":
    var mac: array[6, uint8]
    for i in 0..5:
      mac[i] = 0xCC'u8

    let packet = newDHCPAck(
      mac,
      assignedIP = "192.168.1.100",
      serverIP = "192.168.1.1",
      subnetMask = "255.255.255.0",
      router = "192.168.1.1",
      dns = @["8.8.8.8", "8.8.4.4"]
    )

    check packet.op == DHCP_BOOTREPLY
    check packet.getMessageType() == DHCP_ACK

  test "DHCP RELEASE creation":
    var mac: array[6, uint8]
    for i in 0..5:
      mac[i] = 0xDD'u8

    let packet = newDHCPRelease(mac, "192.168.1.100", "192.168.1.1")

    check packet.op == DHCP_BOOTREQUEST
    check packet.getMessageType() == DHCP_RELEASE

  test "Get message type name":
    check getMessageTypeName(DHCP_DISCOVER) == "DISCOVER"
    check getMessageTypeName(DHCP_OFFER) == "OFFER"
    check getMessageTypeName(DHCP_REQUEST) == "REQUEST"
    check getMessageTypeName(DHCP_DECLINE) == "DECLINE"
    check getMessageTypeName(DHCP_ACK) == "ACK"
    check getMessageTypeName(DHCP_NAK) == "NAK"
    check getMessageTypeName(DHCP_RELEASE) == "RELEASE"
    check getMessageTypeName(DHCP_INFORM) == "INFORM"
    check "UNKNOWN" in getMessageTypeName(99)

  test "DHCP roundtrip":
    var mac: array[6, uint8]
    for i in 0..5:
      mac[i] = (0x10 + i.uint8)

    let original = newDHCPRequest(mac, "10.0.0.50", "10.0.0.1", 0xCAFEBABE'u32)
    let bytes = original.toBytes()
    let parsed = parseDHCPPacket(bytes)

    check parsed.xid == 0xCAFEBABE'u32
    check parsed.getMessageType() == DHCP_REQUEST
    check parsed.hasOption(DHCP_OPT_REQUESTED_IP)
    check parsed.hasOption(DHCP_OPT_SERVER_ID)

echo "All DHCP tests passed!"
