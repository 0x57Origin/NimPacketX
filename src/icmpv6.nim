## ICMPv6 (Internet Control Message Protocol version 6) Packet Handling
##
## This module provides data structures and functions for creating and parsing
## ICMPv6 packets.

import std/endians
import ipv6

type
  ICMPv6Header* = object
    icmpType*: uint8
    code*: uint8
    checksum*: uint16
    # The rest of the header is type-specific
    # For echo request/reply: identifier (2 bytes) + sequence (2 bytes)
    # For neighbor discovery: varies
    # We'll store as generic 4-byte field
    messageBody*: array[4, uint8]

# ICMPv6 Type constants
const
  ICMPV6_DEST_UNREACH* = 1
  ICMPV6_PACKET_TOO_BIG* = 2
  ICMPV6_TIME_EXCEEDED* = 3
  ICMPV6_PARAM_PROBLEM* = 4
  ICMPV6_ECHO_REQUEST* = 128
  ICMPV6_ECHO_REPLY* = 129
  ICMPV6_ROUTER_SOLICITATION* = 133
  ICMPV6_ROUTER_ADVERTISEMENT* = 134
  ICMPV6_NEIGHBOR_SOLICITATION* = 135
  ICMPV6_NEIGHBOR_ADVERTISEMENT* = 136
  ICMPV6_REDIRECT* = 137

# Private checksum calculation (RFC 1071 algorithm)
proc calculateChecksum(data: openArray[byte]): uint16 =
  var sum: uint32 = 0
  var i = 0

  # Sum 16-bit words
  while i < data.len - 1:
    sum += (data[i].uint32 shl 8) + data[i + 1].uint32
    i += 2

  # Add left-over byte, if any
  if i < data.len:
    sum += data[i].uint32 shl 8

  # Fold carry bits
  while (sum shr 16) != 0:
    sum = (sum and 0xFFFF) + (sum shr 16)

  result = (not sum).uint16

# Serialization
proc toBytes*(header: ICMPv6Header): seq[byte] =
  ## Convert ICMPv6 header to byte sequence (8 bytes)
  result = newSeq[byte](8)
  result[0] = header.icmpType
  result[1] = header.code
  bigEndian16(addr result[2], unsafeAddr header.checksum)

  # Message body (4 bytes)
  for i in 0..3:
    result[4 + i] = header.messageBody[i]

# Parsing
proc parseICMPv6Header*(data: seq[byte]): ICMPv6Header =
  ## Parse ICMPv6 header from byte sequence
  if data.len < 8:
    raise newException(ValueError, "Insufficient data for ICMPv6 header")

  result.icmpType = data[0]
  result.code = data[1]
  bigEndian16(addr result.checksum, unsafeAddr data[2])

  # Message body
  for i in 0..3:
    result.messageBody[i] = data[4 + i]

# Checksum calculation with IPv6 pseudo-header
proc calculateICMPv6Checksum*(ipv6: IPv6Header, icmpv6: ICMPv6Header,
                              data: seq[byte]): uint16 =
  ## Calculate ICMPv6 checksum including IPv6 pseudo-header
  ## Pseudo-header: src IP (16) + dst IP (16) + length (4) + zeros (3) + next header (1)

  # Build 40-byte pseudo-header
  var pseudoHeader = newSeq[byte](40)

  # Source address (16 bytes)
  for i in 0..15:
    pseudoHeader[i] = ipv6.sourceIP[i]

  # Destination address (16 bytes)
  for i in 0..15:
    pseudoHeader[16 + i] = ipv6.destIP[i]

  # ICMPv6 length (4 bytes, big-endian): ICMPv6 header (8) + data length
  let icmpv6Length = (8 + data.len).uint32
  bigEndian32(addr pseudoHeader[32], unsafeAddr icmpv6Length)

  # Reserved zeros (3 bytes) - already zero from newSeq
  pseudoHeader[36] = 0
  pseudoHeader[37] = 0
  pseudoHeader[38] = 0

  # Next header (1 byte) - ICMPv6 = 58
  pseudoHeader[39] = IPV6_NEXT_HEADER_ICMPV6

  # ICMPv6 header bytes with checksum cleared
  var icmpv6Bytes = icmpv6.toBytes()
  icmpv6Bytes[2] = 0
  icmpv6Bytes[3] = 0

  # Concatenate: pseudo-header + ICMPv6 header + data
  let checksumData = pseudoHeader & icmpv6Bytes & data

  # Calculate checksum using RFC 1071 algorithm
  result = calculateChecksum(checksumData)

# Helper constructors
proc newICMPv6EchoRequest*(identifier: uint16, sequence: uint16): ICMPv6Header =
  ## Create ICMPv6 Echo Request
  var msgBody: array[4, uint8]
  bigEndian16(addr msgBody[0], unsafeAddr identifier)
  bigEndian16(addr msgBody[2], unsafeAddr sequence)

  result = ICMPv6Header(
    icmpType: ICMPV6_ECHO_REQUEST,
    code: 0,
    checksum: 0,  # Will be calculated later
    messageBody: msgBody
  )

proc newICMPv6EchoReply*(identifier: uint16, sequence: uint16): ICMPv6Header =
  ## Create ICMPv6 Echo Reply
  var msgBody: array[4, uint8]
  bigEndian16(addr msgBody[0], unsafeAddr identifier)
  bigEndian16(addr msgBody[2], unsafeAddr sequence)

  result = ICMPv6Header(
    icmpType: ICMPV6_ECHO_REPLY,
    code: 0,
    checksum: 0,
    messageBody: msgBody
  )
