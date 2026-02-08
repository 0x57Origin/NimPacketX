## Ethernet Frame Handling
##
## This module provides data structures and functions for creating and parsing
## Ethernet frames (Layer 2).

import std/[strutils, endians]

type
  EthernetHeader* = object
    destMAC*: array[6, uint8]
    srcMAC*: array[6, uint8]
    etherType*: uint16

# EtherType constants
const
  ETHERTYPE_IPV4* = 0x0800'u16
  ETHERTYPE_ARP* = 0x0806'u16
  ETHERTYPE_IPV6* = 0x86DD'u16

# MAC address parsing
proc parseMAC*(mac: string): array[6, uint8] =
  ## Parse MAC address from string format "AA:BB:CC:DD:EE:FF" or "AA-BB-CC-DD-EE-FF"
  let separator = if ':' in mac: ':' else: '-'
  let parts = mac.split(separator)
  if parts.len != 6:
    raise newException(ValueError, "Invalid MAC address format")

  for i, part in parts:
    result[i] = parseHexInt(part).uint8

proc macToString*(mac: array[6, uint8]): string =
  ## Convert MAC address to string format "AA:BB:CC:DD:EE:FF"
  result = ""
  for i, byte in mac:
    if i > 0:
      result.add(":")
    result.add(byte.toHex(2))

# Serialization
proc toBytes*(header: EthernetHeader): seq[byte] =
  ## Convert Ethernet header to byte sequence
  result = newSeq[byte](14)  # Ethernet header is always 14 bytes

  # Destination MAC (6 bytes)
  for i in 0..5:
    result[i] = header.destMAC[i]

  # Source MAC (6 bytes)
  for i in 0..5:
    result[6 + i] = header.srcMAC[i]

  # EtherType (2 bytes, big-endian)
  var etherType = header.etherType
  bigEndian16(addr result[12], addr etherType)

# Parsing
proc parseEthernet*(data: seq[byte]): EthernetHeader =
  ## Parse Ethernet header from byte sequence
  if data.len < 14:
    raise newException(ValueError, "Insufficient data for Ethernet header")

  # Destination MAC (6 bytes)
  for i in 0..5:
    result.destMAC[i] = data[i]

  # Source MAC (6 bytes)
  for i in 0..5:
    result.srcMAC[i] = data[6 + i]

  # EtherType (2 bytes, big-endian)
  bigEndian16(addr result.etherType, unsafeAddr data[12])

# Broadcast MAC address constant
proc broadcastMAC*(): array[6, uint8] =
  ## Return broadcast MAC address FF:FF:FF:FF:FF:FF
  [0xFF'u8, 0xFF'u8, 0xFF'u8, 0xFF'u8, 0xFF'u8, 0xFF'u8]
