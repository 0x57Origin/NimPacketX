## ARP (Address Resolution Protocol) Packet Handling
##
## This module provides data structures and functions for creating and parsing
## ARP packets.

import std/endians

type
  ARPPacket* = object
    hardwareType*: uint16      # Hardware type (1 = Ethernet)
    protocolType*: uint16      # Protocol type (0x0800 = IPv4)
    hardwareSize*: uint8       # Hardware address length (6 for MAC)
    protocolSize*: uint8       # Protocol address length (4 for IPv4)
    opcode*: uint16            # Operation (1 = request, 2 = reply)
    senderMAC*: array[6, uint8]
    senderIP*: uint32
    targetMAC*: array[6, uint8]
    targetIP*: uint32

# ARP constants
const
  ARP_HARDWARE_ETHERNET* = 1'u16
  ARP_PROTOCOL_IPV4* = 0x0800'u16
  ARP_REQUEST* = 1'u16
  ARP_REPLY* = 2'u16

# Serialization
proc toBytes*(arp: ARPPacket): seq[byte] =
  ## Convert ARP packet to byte sequence
  result = newSeq[byte](28)  # ARP packet is 28 bytes for Ethernet/IPv4

  # Hardware type (2 bytes, big-endian)
  var hwType = arp.hardwareType
  bigEndian16(addr result[0], addr hwType)

  # Protocol type (2 bytes, big-endian)
  var protoType = arp.protocolType
  bigEndian16(addr result[2], addr protoType)

  # Hardware size (1 byte)
  result[4] = arp.hardwareSize

  # Protocol size (1 byte)
  result[5] = arp.protocolSize

  # Opcode (2 bytes, big-endian)
  var opcode = arp.opcode
  bigEndian16(addr result[6], addr opcode)

  # Sender MAC (6 bytes)
  for i in 0..5:
    result[8 + i] = arp.senderMAC[i]

  # Sender IP (4 bytes, big-endian)
  var senderIP = arp.senderIP
  bigEndian32(addr result[14], addr senderIP)

  # Target MAC (6 bytes)
  for i in 0..5:
    result[18 + i] = arp.targetMAC[i]

  # Target IP (4 bytes, big-endian)
  var targetIP = arp.targetIP
  bigEndian32(addr result[24], addr targetIP)

# Parsing
proc parseARP*(data: seq[byte]): ARPPacket =
  ## Parse ARP packet from byte sequence
  if data.len < 28:
    raise newException(ValueError, "Insufficient data for ARP packet")

  # Hardware type (2 bytes, big-endian)
  bigEndian16(addr result.hardwareType, unsafeAddr data[0])

  # Protocol type (2 bytes, big-endian)
  bigEndian16(addr result.protocolType, unsafeAddr data[2])

  # Hardware size (1 byte)
  result.hardwareSize = data[4]

  # Protocol size (1 byte)
  result.protocolSize = data[5]

  # Opcode (2 bytes, big-endian)
  bigEndian16(addr result.opcode, unsafeAddr data[6])

  # Sender MAC (6 bytes)
  for i in 0..5:
    result.senderMAC[i] = data[8 + i]

  # Sender IP (4 bytes, big-endian)
  bigEndian32(addr result.senderIP, unsafeAddr data[14])

  # Target MAC (6 bytes)
  for i in 0..5:
    result.targetMAC[i] = data[18 + i]

  # Target IP (4 bytes, big-endian)
  bigEndian32(addr result.targetIP, unsafeAddr data[24])

# Helper constructors
proc newARPRequest*(senderMAC: array[6, uint8], senderIP: uint32,
                   targetIP: uint32): ARPPacket =
  ## Create an ARP request packet
  result = ARPPacket(
    hardwareType: ARP_HARDWARE_ETHERNET,
    protocolType: ARP_PROTOCOL_IPV4,
    hardwareSize: 6,
    protocolSize: 4,
    opcode: ARP_REQUEST,
    senderMAC: senderMAC,
    senderIP: senderIP,
    targetMAC: [0'u8, 0'u8, 0'u8, 0'u8, 0'u8, 0'u8],  # Unknown in request
    targetIP: targetIP
  )

proc newARPReply*(senderMAC: array[6, uint8], senderIP: uint32,
                 targetMAC: array[6, uint8], targetIP: uint32): ARPPacket =
  ## Create an ARP reply packet
  result = ARPPacket(
    hardwareType: ARP_HARDWARE_ETHERNET,
    protocolType: ARP_PROTOCOL_IPV4,
    hardwareSize: 6,
    protocolSize: 4,
    opcode: ARP_REPLY,
    senderMAC: senderMAC,
    senderIP: senderIP,
    targetMAC: targetMAC,
    targetIP: targetIP
  )
