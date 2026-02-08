## DHCP (Dynamic Host Configuration Protocol) Packet Handling
##
## This module provides data structures and functions for creating and parsing
## DHCP packets for network security testing and research.
##
## Supports:
## - DHCP message types (DISCOVER, OFFER, REQUEST, ACK, NAK, RELEASE, INFORM)
## - DHCP options parsing and building
## - BOOTP compatibility
## - Standard DHCP port: 67 (server), 68 (client)

import std/[strutils, endians, sequtils, tables]

type
  DHCPPacket* = object
    op*: uint8                    ## Message op code: 1 = BOOTREQUEST, 2 = BOOTREPLY
    htype*: uint8                 ## Hardware address type: 1 = Ethernet
    hlen*: uint8                  ## Hardware address length: 6 for Ethernet
    hops*: uint8                  ## Hops
    xid*: uint32                  ## Transaction ID
    secs*: uint16                 ## Seconds elapsed
    flags*: uint16                ## Flags (broadcast bit)
    ciaddr*: uint32               ## Client IP address
    yiaddr*: uint32               ## 'Your' (client) IP address
    siaddr*: uint32               ## Server IP address
    giaddr*: uint32               ## Gateway IP address
    chaddr*: array[16, uint8]     ## Client hardware address
    sname*: array[64, uint8]      ## Server host name
    file*: array[128, uint8]      ## Boot file name
    options*: seq[DHCPOption]     ## DHCP options

  DHCPOption* = object
    code*: uint8
    length*: uint8
    data*: seq[byte]

# DHCP Operation Codes
const
  DHCP_BOOTREQUEST* = 1'u8
  DHCP_BOOTREPLY* = 2'u8

# Hardware Types
const
  DHCP_HTYPE_ETHERNET* = 1'u8
  DHCP_HTYPE_IEEE802* = 6'u8
  DHCP_HTYPE_FDDI* = 8'u8

# DHCP Message Types (Option 53)
const
  DHCP_DISCOVER* = 1'u8
  DHCP_OFFER* = 2'u8
  DHCP_REQUEST* = 3'u8
  DHCP_DECLINE* = 4'u8
  DHCP_ACK* = 5'u8
  DHCP_NAK* = 6'u8
  DHCP_RELEASE* = 7'u8
  DHCP_INFORM* = 8'u8

# DHCP Option Codes
const
  DHCP_OPT_PAD* = 0'u8                    ## Padding
  DHCP_OPT_SUBNET_MASK* = 1'u8            ## Subnet Mask
  DHCP_OPT_ROUTER* = 3'u8                 ## Router/Gateway
  DHCP_OPT_DNS* = 6'u8                    ## DNS Servers
  DHCP_OPT_HOSTNAME* = 12'u8              ## Host Name
  DHCP_OPT_DOMAIN_NAME* = 15'u8           ## Domain Name
  DHCP_OPT_BROADCAST* = 28'u8             ## Broadcast Address
  DHCP_OPT_REQUESTED_IP* = 50'u8          ## Requested IP Address
  DHCP_OPT_LEASE_TIME* = 51'u8            ## IP Address Lease Time
  DHCP_OPT_MESSAGE_TYPE* = 53'u8          ## DHCP Message Type
  DHCP_OPT_SERVER_ID* = 54'u8             ## Server Identifier
  DHCP_OPT_PARAM_REQUEST* = 55'u8         ## Parameter Request List
  DHCP_OPT_RENEWAL_TIME* = 58'u8          ## Renewal (T1) Time
  DHCP_OPT_REBINDING_TIME* = 59'u8        ## Rebinding (T2) Time
  DHCP_OPT_CLIENT_ID* = 61'u8             ## Client Identifier
  DHCP_OPT_TFTP_SERVER* = 66'u8           ## TFTP Server Name
  DHCP_OPT_BOOTFILE* = 67'u8              ## Bootfile Name
  DHCP_OPT_END* = 255'u8                  ## End

# DHCP Magic Cookie (RFC 2131)
const
  DHCP_MAGIC_COOKIE*: array[4, uint8] = [99'u8, 130'u8, 83'u8, 99'u8]

# DHCP Flags
const
  DHCP_FLAG_BROADCAST* = 0x8000'u16

proc newDHCPOption*(code: uint8, data: seq[byte]): DHCPOption =
  ## Creates a new DHCP option
  result.code = code
  result.length = data.len.uint8
  result.data = data

proc newDHCPOptionByte*(code: uint8, value: uint8): DHCPOption =
  ## Creates a DHCP option with single byte value
  result.code = code
  result.length = 1
  result.data = @[value]

proc newDHCPOptionUint32*(code: uint8, value: uint32): DHCPOption =
  ## Creates a DHCP option with uint32 value
  result.code = code
  result.length = 4
  result.data = newSeq[byte](4)
  bigEndian32(addr result.data[0], unsafeAddr value)

proc newDHCPOptionIP*(code: uint8, ip: string): DHCPOption =
  ## Creates a DHCP option with IP address value
  let parts = ip.split('.')
  if parts.len != 4:
    raise newException(ValueError, "Invalid IP address")

  result.code = code
  result.length = 4
  result.data = newSeq[byte](4)
  for i, part in parts:
    result.data[i] = parseUInt(part).uint8

proc newDHCPOptionString*(code: uint8, s: string): DHCPOption =
  ## Creates a DHCP option with string value
  result.code = code
  result.length = s.len.uint8
  result.data = newSeq[byte](s.len)
  for i, c in s:
    result.data[i] = c.uint8

proc newDHCPOptionIPs*(code: uint8, ips: seq[string]): DHCPOption =
  ## Creates a DHCP option with multiple IP addresses
  result.code = code
  result.length = (ips.len * 4).uint8
  result.data = newSeq[byte](ips.len * 4)

  for i, ip in ips:
    let parts = ip.split('.')
    if parts.len != 4:
      raise newException(ValueError, "Invalid IP address: " & ip)
    for j, part in parts:
      result.data[i * 4 + j] = parseUInt(part).uint8

proc parseIPv4(ip: uint32): string =
  ## Converts uint32 IP to string
  let a = (ip shr 24) and 0xFF
  let b = (ip shr 16) and 0xFF
  let c = (ip shr 8) and 0xFF
  let d = ip and 0xFF
  result = $a & "." & $b & "." & $c & "." & $d

proc toIPv4(ip: string): uint32 =
  ## Converts string IP to uint32
  let parts = ip.split('.')
  if parts.len != 4:
    raise newException(ValueError, "Invalid IP address")
  result = 0
  for i, part in parts:
    let octet = parseUInt(part)
    if octet > 255:
      raise newException(ValueError, "IP octet out of range")
    result = result or (octet.uint32 shl (24 - i * 8))

proc toBytes*(option: DHCPOption): seq[byte] =
  ## Serializes DHCP option to bytes
  if option.code == DHCP_OPT_PAD or option.code == DHCP_OPT_END:
    result = @[option.code]
  else:
    result = @[option.code, option.length]
    result.add(option.data)

proc toBytes*(packet: DHCPPacket): seq[byte] =
  ## Serializes DHCP packet to bytes (minimum 300 bytes per RFC)
  result = newSeq[byte](240)  # Fixed header size

  result[0] = packet.op
  result[1] = packet.htype
  result[2] = packet.hlen
  result[3] = packet.hops

  bigEndian32(addr result[4], unsafeAddr packet.xid)
  bigEndian16(addr result[8], unsafeAddr packet.secs)
  bigEndian16(addr result[10], unsafeAddr packet.flags)
  bigEndian32(addr result[12], unsafeAddr packet.ciaddr)
  bigEndian32(addr result[16], unsafeAddr packet.yiaddr)
  bigEndian32(addr result[20], unsafeAddr packet.siaddr)
  bigEndian32(addr result[24], unsafeAddr packet.giaddr)

  # Client hardware address (16 bytes)
  for i in 0..15:
    result[28 + i] = packet.chaddr[i]

  # Server name (64 bytes)
  for i in 0..63:
    result[44 + i] = packet.sname[i]

  # Boot file (128 bytes)
  for i in 0..127:
    result[108 + i] = packet.file[i]

  # Magic cookie
  result.add(DHCP_MAGIC_COOKIE[0])
  result.add(DHCP_MAGIC_COOKIE[1])
  result.add(DHCP_MAGIC_COOKIE[2])
  result.add(DHCP_MAGIC_COOKIE[3])

  # Options
  for option in packet.options:
    result.add(option.toBytes())

  # End option
  result.add(DHCP_OPT_END)

  # Pad to minimum 300 bytes if needed
  while result.len < 300:
    result.add(DHCP_OPT_PAD)

proc parseDHCPOption*(data: seq[byte], offset: var int): DHCPOption =
  ## Parses a single DHCP option
  if offset >= data.len:
    raise newException(ValueError, "No more data for DHCP option")

  result.code = data[offset]
  offset += 1

  # PAD and END have no length or data
  if result.code == DHCP_OPT_PAD or result.code == DHCP_OPT_END:
    result.length = 0
    result.data = @[]
    return

  if offset >= data.len:
    raise newException(ValueError, "No length for DHCP option")

  result.length = data[offset]
  offset += 1

  if offset + result.length.int > data.len:
    raise newException(ValueError, "Insufficient data for DHCP option")

  result.data = data[offset..<(offset + result.length.int)]
  offset += result.length.int

proc parseDHCPPacket*(data: seq[byte]): DHCPPacket =
  ## Parses DHCP packet from bytes
  if data.len < 240:
    raise newException(ValueError, "Insufficient data for DHCP packet")

  result.op = data[0]
  result.htype = data[1]
  result.hlen = data[2]
  result.hops = data[3]

  bigEndian32(addr result.xid, unsafeAddr data[4])
  bigEndian16(addr result.secs, unsafeAddr data[8])
  bigEndian16(addr result.flags, unsafeAddr data[10])
  bigEndian32(addr result.ciaddr, unsafeAddr data[12])
  bigEndian32(addr result.yiaddr, unsafeAddr data[16])
  bigEndian32(addr result.siaddr, unsafeAddr data[20])
  bigEndian32(addr result.giaddr, unsafeAddr data[24])

  # Client hardware address
  for i in 0..15:
    result.chaddr[i] = data[28 + i]

  # Server name
  for i in 0..63:
    result.sname[i] = data[44 + i]

  # Boot file
  for i in 0..127:
    result.file[i] = data[108 + i]

  # Check magic cookie at offset 236
  if data.len < 240:
    return

  if data[236] != DHCP_MAGIC_COOKIE[0] or
     data[237] != DHCP_MAGIC_COOKIE[1] or
     data[238] != DHCP_MAGIC_COOKIE[2] or
     data[239] != DHCP_MAGIC_COOKIE[3]:
    return  # No DHCP options (BOOTP only)

  # Parse options starting at offset 240
  var offset = 240
  while offset < data.len:
    let option = parseDHCPOption(data, offset)
    if option.code == DHCP_OPT_END:
      break
    if option.code != DHCP_OPT_PAD:
      result.options.add(option)

proc getOption*(packet: DHCPPacket, code: uint8): DHCPOption =
  ## Gets a specific option from the packet
  for option in packet.options:
    if option.code == code:
      return option
  raise newException(KeyError, "Option not found: " & $code)

proc hasOption*(packet: DHCPPacket, code: uint8): bool =
  ## Checks if packet has a specific option
  for option in packet.options:
    if option.code == code:
      return true
  return false

proc getMessageType*(packet: DHCPPacket): uint8 =
  ## Gets the DHCP message type from options
  if packet.hasOption(DHCP_OPT_MESSAGE_TYPE):
    let opt = packet.getOption(DHCP_OPT_MESSAGE_TYPE)
    if opt.data.len >= 1:
      return opt.data[0]
  return 0

proc getMessageTypeName*(msgType: uint8): string =
  ## Returns human-readable name for DHCP message type
  case msgType:
  of DHCP_DISCOVER: "DISCOVER"
  of DHCP_OFFER: "OFFER"
  of DHCP_REQUEST: "REQUEST"
  of DHCP_DECLINE: "DECLINE"
  of DHCP_ACK: "ACK"
  of DHCP_NAK: "NAK"
  of DHCP_RELEASE: "RELEASE"
  of DHCP_INFORM: "INFORM"
  else: "UNKNOWN(" & $msgType & ")"

# Helper constructors

proc newDHCPDiscover*(mac: array[6, uint8], xid: uint32 = 0x12345678): DHCPPacket =
  ## Creates a DHCP DISCOVER packet
  result.op = DHCP_BOOTREQUEST
  result.htype = DHCP_HTYPE_ETHERNET
  result.hlen = 6
  result.hops = 0
  result.xid = xid
  result.secs = 0
  result.flags = DHCP_FLAG_BROADCAST
  result.ciaddr = 0
  result.yiaddr = 0
  result.siaddr = 0
  result.giaddr = 0

  # Set MAC address
  for i in 0..5:
    result.chaddr[i] = mac[i]

  # Add options
  result.options.add(newDHCPOptionByte(DHCP_OPT_MESSAGE_TYPE, DHCP_DISCOVER))

  # Common parameter request list
  result.options.add(DHCPOption(
    code: DHCP_OPT_PARAM_REQUEST,
    length: 4,
    data: @[
      DHCP_OPT_SUBNET_MASK,
      DHCP_OPT_ROUTER,
      DHCP_OPT_DNS,
      DHCP_OPT_DOMAIN_NAME
    ]
  ))

proc newDHCPRequest*(mac: array[6, uint8], requestedIP: string,
                     serverIP: string, xid: uint32 = 0x12345678): DHCPPacket =
  ## Creates a DHCP REQUEST packet
  result.op = DHCP_BOOTREQUEST
  result.htype = DHCP_HTYPE_ETHERNET
  result.hlen = 6
  result.hops = 0
  result.xid = xid
  result.secs = 0
  result.flags = DHCP_FLAG_BROADCAST
  result.ciaddr = 0
  result.yiaddr = 0
  result.siaddr = 0
  result.giaddr = 0

  for i in 0..5:
    result.chaddr[i] = mac[i]

  result.options.add(newDHCPOptionByte(DHCP_OPT_MESSAGE_TYPE, DHCP_REQUEST))
  result.options.add(newDHCPOptionIP(DHCP_OPT_REQUESTED_IP, requestedIP))
  result.options.add(newDHCPOptionIP(DHCP_OPT_SERVER_ID, serverIP))

proc newDHCPOffer*(mac: array[6, uint8], offeredIP: string, serverIP: string,
                   subnetMask: string, router: string, dns: seq[string],
                   leaseTime: uint32 = 86400, xid: uint32 = 0x12345678): DHCPPacket =
  ## Creates a DHCP OFFER packet
  result.op = DHCP_BOOTREPLY
  result.htype = DHCP_HTYPE_ETHERNET
  result.hlen = 6
  result.hops = 0
  result.xid = xid
  result.secs = 0
  result.flags = 0
  result.ciaddr = 0
  result.yiaddr = toIPv4(offeredIP)
  result.siaddr = toIPv4(serverIP)
  result.giaddr = 0

  for i in 0..5:
    result.chaddr[i] = mac[i]

  result.options.add(newDHCPOptionByte(DHCP_OPT_MESSAGE_TYPE, DHCP_OFFER))
  result.options.add(newDHCPOptionIP(DHCP_OPT_SERVER_ID, serverIP))
  result.options.add(newDHCPOptionUint32(DHCP_OPT_LEASE_TIME, leaseTime))
  result.options.add(newDHCPOptionIP(DHCP_OPT_SUBNET_MASK, subnetMask))
  result.options.add(newDHCPOptionIP(DHCP_OPT_ROUTER, router))
  if dns.len > 0:
    result.options.add(newDHCPOptionIPs(DHCP_OPT_DNS, dns))

proc newDHCPAck*(mac: array[6, uint8], assignedIP: string, serverIP: string,
                 subnetMask: string, router: string, dns: seq[string],
                 leaseTime: uint32 = 86400, xid: uint32 = 0x12345678): DHCPPacket =
  ## Creates a DHCP ACK packet
  result.op = DHCP_BOOTREPLY
  result.htype = DHCP_HTYPE_ETHERNET
  result.hlen = 6
  result.hops = 0
  result.xid = xid
  result.secs = 0
  result.flags = 0
  result.ciaddr = 0
  result.yiaddr = toIPv4(assignedIP)
  result.siaddr = toIPv4(serverIP)
  result.giaddr = 0

  for i in 0..5:
    result.chaddr[i] = mac[i]

  result.options.add(newDHCPOptionByte(DHCP_OPT_MESSAGE_TYPE, DHCP_ACK))
  result.options.add(newDHCPOptionIP(DHCP_OPT_SERVER_ID, serverIP))
  result.options.add(newDHCPOptionUint32(DHCP_OPT_LEASE_TIME, leaseTime))
  result.options.add(newDHCPOptionIP(DHCP_OPT_SUBNET_MASK, subnetMask))
  result.options.add(newDHCPOptionIP(DHCP_OPT_ROUTER, router))
  if dns.len > 0:
    result.options.add(newDHCPOptionIPs(DHCP_OPT_DNS, dns))

proc newDHCPRelease*(mac: array[6, uint8], clientIP: string, serverIP: string,
                     xid: uint32 = 0x12345678): DHCPPacket =
  ## Creates a DHCP RELEASE packet
  result.op = DHCP_BOOTREQUEST
  result.htype = DHCP_HTYPE_ETHERNET
  result.hlen = 6
  result.hops = 0
  result.xid = xid
  result.secs = 0
  result.flags = 0
  result.ciaddr = toIPv4(clientIP)
  result.yiaddr = 0
  result.siaddr = 0
  result.giaddr = 0

  for i in 0..5:
    result.chaddr[i] = mac[i]

  result.options.add(newDHCPOptionByte(DHCP_OPT_MESSAGE_TYPE, DHCP_RELEASE))
  result.options.add(newDHCPOptionIP(DHCP_OPT_SERVER_ID, serverIP))
