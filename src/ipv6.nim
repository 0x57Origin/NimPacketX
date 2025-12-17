## IPv6 (Internet Protocol version 6) Packet Handling
##
## This module provides data structures and functions for creating and parsing
## IPv6 packets.

import std/[strutils, endians]

type
  IPv6Header* = object
    version*: uint8              # Always 6
    trafficClass*: uint8         # 8-bit traffic class
    flowLabel*: uint32           # 20-bit flow label (stored in uint32, only lower 20 bits used)
    payloadLength*: uint16       # Length of payload (excluding this header)
    nextHeader*: uint8           # Next header type (same values as IPv4 protocol field)
    hopLimit*: uint8             # Hop limit (like IPv4 TTL)
    sourceIP*: array[16, uint8]  # 128-bit source address
    destIP*: array[16, uint8]    # 128-bit destination address

# Protocol constants for nextHeader (reuse IPv4 values)
const
  IPV6_NEXT_HEADER_TCP* = 6
  IPV6_NEXT_HEADER_UDP* = 17
  IPV6_NEXT_HEADER_ICMPV6* = 58
  IPV6_NEXT_HEADER_NO_NEXT* = 59

# IPv6 Address parsing
proc parseIPv6*(ip: string): array[16, uint8] =
  ## Parse IPv6 address from string format
  ## Supports full notation: "2001:0db8:0000:0000:0000:0000:0000:0001"
  ## Supports compressed notation: "2001:db8::1"
  ## Supports special cases: "::1" (loopback), "::" (all zeros)

  # Handle special case: all zeros
  if ip == "::":
    return result  # Already initialized to zeros

  # Check for compression marker
  let hasCompression = "::" in ip

  if hasCompression:
    # Count occurrences of "::" - should be exactly one
    var compressionCount = 0
    var i = 0
    while i < ip.len - 1:
      if ip[i] == ':' and ip[i + 1] == ':':
        compressionCount += 1
        i += 2
      else:
        i += 1

    if compressionCount > 1:
      raise newException(ValueError, "Invalid IPv6 address: multiple :: found")

    # Split around "::"
    let parts = ip.split("::")
    if parts.len != 2:
      raise newException(ValueError, "Invalid IPv6 address: multiple :: found")

    let leftPart = if parts[0] == "": @[] else: parts[0].split(":")
    let rightPart = if parts[1] == "": @[] else: parts[1].split(":")

    # Validate total hextets don't exceed 8
    if leftPart.len + rightPart.len >= 8:
      raise newException(ValueError, "Invalid IPv6 address: too many groups")

    # Parse left side
    var byteIndex = 0
    for hextet in leftPart:
      if hextet == "":
        raise newException(ValueError, "Invalid IPv6 address: empty hextet")
      let value = parseHexInt(hextet).uint16
      result[byteIndex] = (value shr 8).uint8
      result[byteIndex + 1] = (value and 0xFF).uint8
      byteIndex += 2

    # Skip zeros (represented by ::)
    let zerosCount = (8 - leftPart.len - rightPart.len) * 2
    byteIndex += zerosCount

    # Parse right side
    for hextet in rightPart:
      if hextet == "":
        raise newException(ValueError, "Invalid IPv6 address: empty hextet")
      let value = parseHexInt(hextet).uint16
      result[byteIndex] = (value shr 8).uint8
      result[byteIndex + 1] = (value and 0xFF).uint8
      byteIndex += 2
  else:
    # Full notation - must have exactly 8 hextets
    let hextets = ip.split(":")
    if hextets.len != 8:
      raise newException(ValueError, "Invalid IPv6 address: expected 8 groups, got " & $hextets.len)

    var byteIndex = 0
    for hextet in hextets:
      if hextet == "":
        raise newException(ValueError, "Invalid IPv6 address: empty hextet")
      let value = parseHexInt(hextet).uint16
      result[byteIndex] = (value shr 8).uint8
      result[byteIndex + 1] = (value and 0xFF).uint8
      byteIndex += 2

proc ipv6ToString*(ip: array[16, uint8]): string =
  ## Convert IPv6 address to compressed string format
  ## Uses RFC 5952 canonical format (compress longest run of zeros)

  # Convert bytes to hextets
  var hextets: array[8, uint16]
  for i in 0..7:
    hextets[i] = (ip[i * 2].uint16 shl 8) or ip[i * 2 + 1].uint16

  # Find longest run of consecutive zeros for compression
  var maxZeroStart = -1
  var maxZeroLen = 0
  var currentZeroStart = -1
  var currentZeroLen = 0

  for i in 0..7:
    if hextets[i] == 0:
      if currentZeroStart == -1:
        currentZeroStart = i
        currentZeroLen = 1
      else:
        currentZeroLen += 1
    else:
      if currentZeroLen > maxZeroLen:
        maxZeroStart = currentZeroStart
        maxZeroLen = currentZeroLen
      currentZeroStart = -1
      currentZeroLen = 0

  # Check final run
  if currentZeroLen > maxZeroLen:
    maxZeroStart = currentZeroStart
    maxZeroLen = currentZeroLen

  # Helper to format hextet without leading zeros
  proc formatHextet(value: uint16): string =
    let hex = value.toHex().toLowerAscii()
    # Remove "0x" prefix
    if hex.startsWith("0x"):
      result = hex[2..^1]
    else:
      result = hex
    # Remove leading zeros but keep at least one digit
    while result.len > 1 and result[0] == '0':
      result = result[1..^1]

  # Build string with compression if applicable (only compress runs of 2+)
  if maxZeroLen >= 2:
    result = ""
    var i = 0
    while i < 8:
      if i == maxZeroStart:
        # Add :: for compression
        if i == 0:
          result.add("::")
        else:
          result.add("::")
        i += maxZeroLen
        # Add next hextet if there is one
        if i < 8:
          result.add(formatHextet(hextets[i]))
          i += 1
      else:
        if i > 0:
          result.add(":")
        result.add(formatHextet(hextets[i]))
        i += 1
  else:
    # No compression - output all hextets
    result = ""
    for i in 0..7:
      if i > 0:
        result.add(":")
      result.add(formatHextet(hextets[i]))

# Serialization
proc toBytes*(header: IPv6Header): seq[byte] =
  ## Convert IPv6 header to 40-byte sequence
  result = newSeq[byte](40)

  # Byte 0: Version (4 bits) | Traffic Class upper 4 bits
  result[0] = (header.version shl 4) or ((header.trafficClass shr 4) and 0x0F)

  # Byte 1: Traffic Class lower 4 bits | Flow Label upper 4 bits
  result[1] = ((header.trafficClass and 0x0F) shl 4) or
              ((header.flowLabel shr 16).uint8 and 0x0F)

  # Bytes 2-3: Flow Label lower 16 bits
  let flowLower = (header.flowLabel and 0xFFFF).uint16
  bigEndian16(addr result[2], unsafeAddr flowLower)

  # Bytes 4-5: Payload Length
  bigEndian16(addr result[4], unsafeAddr header.payloadLength)

  # Byte 6: Next Header
  result[6] = header.nextHeader

  # Byte 7: Hop Limit
  result[7] = header.hopLimit

  # Bytes 8-23: Source Address (16 bytes)
  for i in 0..15:
    result[8 + i] = header.sourceIP[i]

  # Bytes 24-39: Destination Address (16 bytes)
  for i in 0..15:
    result[24 + i] = header.destIP[i]

# Parsing
proc parseIPv6Header*(data: seq[byte]): IPv6Header =
  ## Parse IPv6 header from byte sequence
  if data.len < 40:
    raise newException(ValueError, "Insufficient data for IPv6 header")

  # Byte 0: Version and Traffic Class upper bits
  result.version = data[0] shr 4
  result.trafficClass = ((data[0] and 0x0F) shl 4) or (data[1] shr 4)

  # Bytes 1-3: Flow Label (20 bits)
  result.flowLabel = ((data[1] and 0x0F).uint32 shl 16) or
                     (data[2].uint32 shl 8) or
                     data[3].uint32

  # Bytes 4-5: Payload Length
  bigEndian16(addr result.payloadLength, unsafeAddr data[4])

  # Byte 6: Next Header
  result.nextHeader = data[6]

  # Byte 7: Hop Limit
  result.hopLimit = data[7]

  # Bytes 8-23: Source Address
  for i in 0..15:
    result.sourceIP[i] = data[8 + i]

  # Bytes 24-39: Destination Address
  for i in 0..15:
    result.destIP[i] = data[24 + i]
