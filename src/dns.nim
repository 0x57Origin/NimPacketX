## DNS (Domain Name System) Protocol Handling
##
## This module provides data structures and functions for creating and parsing
## DNS packets for network security testing and research.
##
## Supports:
## - DNS query and response building
## - Multiple record types (A, AAAA, CNAME, MX, TXT, NS, PTR, SOA)
## - Domain name encoding/decoding
## - DNS over UDP (standard port 53)

import std/[strutils, endians, sequtils]

type
  DNSHeader* = object
    transactionID*: uint16      ## Query/Response identifier
    flags*: uint16              ## QR, Opcode, AA, TC, RD, RA, Z, RCODE
    questionCount*: uint16      ## Number of questions
    answerCount*: uint16        ## Number of answers
    authorityCount*: uint16     ## Number of authority records
    additionalCount*: uint16    ## Number of additional records

  DNSQuestion* = object
    name*: string               ## Domain name
    qtype*: uint16              ## Query type
    qclass*: uint16             ## Query class (usually IN = 1)

  DNSResourceRecord* = object
    name*: string               ## Domain name
    rrtype*: uint16             ## Record type
    rrclass*: uint16            ## Record class
    ttl*: uint32                ## Time to live
    rdlength*: uint16           ## Resource data length
    rdata*: seq[byte]           ## Resource data

  DNSPacket* = object
    header*: DNSHeader
    questions*: seq[DNSQuestion]
    answers*: seq[DNSResourceRecord]
    authorities*: seq[DNSResourceRecord]
    additionals*: seq[DNSResourceRecord]

# DNS Record Types
const
  DNS_TYPE_A* = 1'u16           ## IPv4 address
  DNS_TYPE_NS* = 2'u16          ## Nameserver
  DNS_TYPE_CNAME* = 5'u16       ## Canonical name
  DNS_TYPE_SOA* = 6'u16         ## Start of authority
  DNS_TYPE_PTR* = 12'u16        ## Pointer record
  DNS_TYPE_MX* = 15'u16         ## Mail exchange
  DNS_TYPE_TXT* = 16'u16        ## Text record
  DNS_TYPE_AAAA* = 28'u16       ## IPv6 address
  DNS_TYPE_SRV* = 33'u16        ## Service record
  DNS_TYPE_ANY* = 255'u16       ## Any record type

# DNS Classes
const
  DNS_CLASS_IN* = 1'u16         ## Internet
  DNS_CLASS_CS* = 2'u16         ## CSNET (obsolete)
  DNS_CLASS_CH* = 3'u16         ## CHAOS
  DNS_CLASS_HS* = 4'u16         ## Hesiod
  DNS_CLASS_ANY* = 255'u16      ## Any class

# DNS Opcodes
const
  DNS_OPCODE_QUERY* = 0'u16     ## Standard query
  DNS_OPCODE_IQUERY* = 1'u16    ## Inverse query (obsolete)
  DNS_OPCODE_STATUS* = 2'u16    ## Server status
  DNS_OPCODE_NOTIFY* = 4'u16    ## Notify
  DNS_OPCODE_UPDATE* = 5'u16    ## Dynamic update

# DNS Response Codes
const
  DNS_RCODE_NOERROR* = 0'u16    ## No error
  DNS_RCODE_FORMERR* = 1'u16    ## Format error
  DNS_RCODE_SERVFAIL* = 2'u16   ## Server failure
  DNS_RCODE_NXDOMAIN* = 3'u16   ## Non-existent domain
  DNS_RCODE_NOTIMP* = 4'u16     ## Not implemented
  DNS_RCODE_REFUSED* = 5'u16    ## Query refused

# DNS Flag bits
const
  DNS_FLAG_QR* = 0x8000'u16     ## Query (0) or Response (1)
  DNS_FLAG_AA* = 0x0400'u16     ## Authoritative Answer
  DNS_FLAG_TC* = 0x0200'u16     ## Truncated
  DNS_FLAG_RD* = 0x0100'u16     ## Recursion Desired
  DNS_FLAG_RA* = 0x0080'u16     ## Recursion Available
  DNS_FLAG_AD* = 0x0020'u16     ## Authenticated Data (DNSSEC)
  DNS_FLAG_CD* = 0x0010'u16     ## Checking Disabled (DNSSEC)

proc encodeDomainName*(name: string): seq[byte] =
  ## Encodes a domain name to DNS wire format
  ## Example: "www.example.com" -> [3]www[7]example[3]com[0]
  result = @[]

  if name.len == 0 or name == ".":
    result.add(0'u8)
    return

  let labels = name.strip(chars = {'.'}).split('.')

  for label in labels:
    if label.len > 63:
      raise newException(ValueError, "DNS label too long (max 63 chars)")
    if label.len == 0:
      continue

    result.add(label.len.uint8)
    for c in label:
      result.add(c.uint8)

  result.add(0'u8)  # Null terminator

proc decodeDomainName*(data: seq[byte], offset: var int): string =
  ## Decodes a domain name from DNS wire format
  ## Handles compression pointers
  result = ""
  var jumped = false
  var jumpOffset = offset
  var maxJumps = 50  # Prevent infinite loops
  var jumps = 0

  while true:
    if offset >= data.len:
      break

    let length = data[offset]

    # Check for compression pointer (top 2 bits set)
    if (length and 0xC0) == 0xC0:
      if offset + 1 >= data.len:
        break

      # Calculate pointer offset
      let pointer = ((length.uint16 and 0x3F) shl 8) or data[offset + 1].uint16

      if not jumped:
        jumpOffset = offset + 2

      offset = pointer.int
      jumped = true
      jumps += 1

      if jumps > maxJumps:
        raise newException(ValueError, "Too many DNS compression jumps")

      continue

    if length == 0:
      offset += 1
      break

    if result.len > 0:
      result.add('.')

    offset += 1
    for i in 0..<length.int:
      if offset >= data.len:
        break
      result.add(data[offset].char)
      offset += 1

  if jumped:
    offset = jumpOffset

proc buildDNSFlags*(qr: bool = false, opcode: uint16 = 0, aa: bool = false,
                    tc: bool = false, rd: bool = true, ra: bool = false,
                    rcode: uint16 = 0): uint16 =
  ## Builds DNS flags field from individual components
  result = 0
  if qr: result = result or DNS_FLAG_QR
  result = result or ((opcode and 0x0F) shl 11)
  if aa: result = result or DNS_FLAG_AA
  if tc: result = result or DNS_FLAG_TC
  if rd: result = result or DNS_FLAG_RD
  if ra: result = result or DNS_FLAG_RA
  result = result or (rcode and 0x0F)

proc parseDNSFlags*(flags: uint16): tuple[qr: bool, opcode: uint16, aa: bool,
                                          tc: bool, rd: bool, ra: bool,
                                          rcode: uint16] =
  ## Parses DNS flags field into individual components
  result.qr = (flags and DNS_FLAG_QR) != 0
  result.opcode = (flags shr 11) and 0x0F
  result.aa = (flags and DNS_FLAG_AA) != 0
  result.tc = (flags and DNS_FLAG_TC) != 0
  result.rd = (flags and DNS_FLAG_RD) != 0
  result.ra = (flags and DNS_FLAG_RA) != 0
  result.rcode = flags and 0x0F

proc toBytes*(header: DNSHeader): seq[byte] =
  ## Serializes DNS header to bytes
  result = newSeq[byte](12)

  bigEndian16(addr result[0], unsafeAddr header.transactionID)
  bigEndian16(addr result[2], unsafeAddr header.flags)
  bigEndian16(addr result[4], unsafeAddr header.questionCount)
  bigEndian16(addr result[6], unsafeAddr header.answerCount)
  bigEndian16(addr result[8], unsafeAddr header.authorityCount)
  bigEndian16(addr result[10], unsafeAddr header.additionalCount)

proc toBytes*(question: DNSQuestion): seq[byte] =
  ## Serializes DNS question to bytes
  result = encodeDomainName(question.name)

  var qtypeBytes: array[2, byte]
  var qclassBytes: array[2, byte]

  bigEndian16(addr qtypeBytes[0], unsafeAddr question.qtype)
  bigEndian16(addr qclassBytes[0], unsafeAddr question.qclass)

  result.add(qtypeBytes[0])
  result.add(qtypeBytes[1])
  result.add(qclassBytes[0])
  result.add(qclassBytes[1])

proc toBytes*(rr: DNSResourceRecord): seq[byte] =
  ## Serializes DNS resource record to bytes
  result = encodeDomainName(rr.name)

  var typeBytes: array[2, byte]
  var classBytes: array[2, byte]
  var ttlBytes: array[4, byte]
  var rdlenBytes: array[2, byte]

  bigEndian16(addr typeBytes[0], unsafeAddr rr.rrtype)
  bigEndian16(addr classBytes[0], unsafeAddr rr.rrclass)
  bigEndian32(addr ttlBytes[0], unsafeAddr rr.ttl)

  let rdlen = rr.rdata.len.uint16
  bigEndian16(addr rdlenBytes[0], unsafeAddr rdlen)

  result.add(typeBytes[0])
  result.add(typeBytes[1])
  result.add(classBytes[0])
  result.add(classBytes[1])
  result.add(ttlBytes[0])
  result.add(ttlBytes[1])
  result.add(ttlBytes[2])
  result.add(ttlBytes[3])
  result.add(rdlenBytes[0])
  result.add(rdlenBytes[1])
  result.add(rr.rdata)

proc toBytes*(packet: DNSPacket): seq[byte] =
  ## Serializes complete DNS packet to bytes
  result = packet.header.toBytes()

  for question in packet.questions:
    result.add(question.toBytes())

  for answer in packet.answers:
    result.add(answer.toBytes())

  for authority in packet.authorities:
    result.add(authority.toBytes())

  for additional in packet.additionals:
    result.add(additional.toBytes())

proc parseDNSHeader*(data: seq[byte]): DNSHeader =
  ## Parses DNS header from bytes
  if data.len < 12:
    raise newException(ValueError, "Insufficient data for DNS header")

  bigEndian16(addr result.transactionID, unsafeAddr data[0])
  bigEndian16(addr result.flags, unsafeAddr data[2])
  bigEndian16(addr result.questionCount, unsafeAddr data[4])
  bigEndian16(addr result.answerCount, unsafeAddr data[6])
  bigEndian16(addr result.authorityCount, unsafeAddr data[8])
  bigEndian16(addr result.additionalCount, unsafeAddr data[10])

proc parseDNSQuestion*(data: seq[byte], offset: var int): DNSQuestion =
  ## Parses DNS question from bytes
  result.name = decodeDomainName(data, offset)

  if offset + 4 > data.len:
    raise newException(ValueError, "Insufficient data for DNS question")

  bigEndian16(addr result.qtype, unsafeAddr data[offset])
  offset += 2
  bigEndian16(addr result.qclass, unsafeAddr data[offset])
  offset += 2

proc parseDNSResourceRecord*(data: seq[byte], offset: var int): DNSResourceRecord =
  ## Parses DNS resource record from bytes
  result.name = decodeDomainName(data, offset)

  if offset + 10 > data.len:
    raise newException(ValueError, "Insufficient data for DNS resource record")

  bigEndian16(addr result.rrtype, unsafeAddr data[offset])
  offset += 2
  bigEndian16(addr result.rrclass, unsafeAddr data[offset])
  offset += 2
  bigEndian32(addr result.ttl, unsafeAddr data[offset])
  offset += 4
  bigEndian16(addr result.rdlength, unsafeAddr data[offset])
  offset += 2

  if offset + result.rdlength.int > data.len:
    raise newException(ValueError, "Insufficient data for DNS rdata")

  result.rdata = data[offset..<(offset + result.rdlength.int)]
  offset += result.rdlength.int

proc parseDNSPacket*(data: seq[byte]): DNSPacket =
  ## Parses complete DNS packet from bytes
  if data.len < 12:
    raise newException(ValueError, "Insufficient data for DNS packet")

  result.header = parseDNSHeader(data)

  var offset = 12

  # Parse questions
  for i in 0..<result.header.questionCount.int:
    result.questions.add(parseDNSQuestion(data, offset))

  # Parse answers
  for i in 0..<result.header.answerCount.int:
    result.answers.add(parseDNSResourceRecord(data, offset))

  # Parse authorities
  for i in 0..<result.header.authorityCount.int:
    result.authorities.add(parseDNSResourceRecord(data, offset))

  # Parse additionals
  for i in 0..<result.header.additionalCount.int:
    result.additionals.add(parseDNSResourceRecord(data, offset))

# Helper constructors

proc newDNSQuery*(domain: string, qtype: uint16 = DNS_TYPE_A,
                  rd: bool = true): DNSPacket =
  ## Creates a standard DNS query packet
  result.header = DNSHeader(
    transactionID: 0x1234,  # Should be randomized in production
    flags: buildDNSFlags(qr = false, rd = rd),
    questionCount: 1,
    answerCount: 0,
    authorityCount: 0,
    additionalCount: 0
  )

  result.questions.add(DNSQuestion(
    name: domain,
    qtype: qtype,
    qclass: DNS_CLASS_IN
  ))

proc newDNSResponse*(query: DNSPacket, answers: seq[DNSResourceRecord],
                     rcode: uint16 = DNS_RCODE_NOERROR): DNSPacket =
  ## Creates a DNS response based on a query
  result.header = DNSHeader(
    transactionID: query.header.transactionID,
    flags: buildDNSFlags(qr = true, aa = true, rd = true, ra = true, rcode = rcode),
    questionCount: query.header.questionCount,
    answerCount: answers.len.uint16,
    authorityCount: 0,
    additionalCount: 0
  )

  result.questions = query.questions
  result.answers = answers

proc newARecord*(name: string, ip: string, ttl: uint32 = 300): DNSResourceRecord =
  ## Creates an A record (IPv4 address)
  result.name = name
  result.rrtype = DNS_TYPE_A
  result.rrclass = DNS_CLASS_IN
  result.ttl = ttl

  # Parse IPv4 address
  let parts = ip.split('.')
  if parts.len != 4:
    raise newException(ValueError, "Invalid IPv4 address")

  result.rdata = newSeq[byte](4)
  for i, part in parts:
    result.rdata[i] = parseUInt(part).uint8

  result.rdlength = 4

proc newAAAARecord*(name: string, ip: string, ttl: uint32 = 300): DNSResourceRecord =
  ## Creates an AAAA record (IPv6 address)
  result.name = name
  result.rrtype = DNS_TYPE_AAAA
  result.rrclass = DNS_CLASS_IN
  result.ttl = ttl

  # Simple IPv6 parsing (full notation only for now)
  let parts = ip.split(':')
  result.rdata = newSeq[byte](16)

  var byteIndex = 0
  for part in parts:
    if part == "":
      continue
    let value = parseHexInt(part).uint16
    result.rdata[byteIndex] = (value shr 8).uint8
    result.rdata[byteIndex + 1] = (value and 0xFF).uint8
    byteIndex += 2

  result.rdlength = 16

proc newCNAMERecord*(name: string, cname: string, ttl: uint32 = 300): DNSResourceRecord =
  ## Creates a CNAME record
  result.name = name
  result.rrtype = DNS_TYPE_CNAME
  result.rrclass = DNS_CLASS_IN
  result.ttl = ttl
  result.rdata = encodeDomainName(cname)
  result.rdlength = result.rdata.len.uint16

proc newMXRecord*(name: string, preference: uint16, exchange: string,
                  ttl: uint32 = 300): DNSResourceRecord =
  ## Creates an MX record
  result.name = name
  result.rrtype = DNS_TYPE_MX
  result.rrclass = DNS_CLASS_IN
  result.ttl = ttl

  # MX record: 2-byte preference + domain name
  result.rdata = newSeq[byte](2)
  bigEndian16(addr result.rdata[0], unsafeAddr preference)
  result.rdata.add(encodeDomainName(exchange))
  result.rdlength = result.rdata.len.uint16

proc newTXTRecord*(name: string, text: string, ttl: uint32 = 300): DNSResourceRecord =
  ## Creates a TXT record
  result.name = name
  result.rrtype = DNS_TYPE_TXT
  result.rrclass = DNS_CLASS_IN
  result.ttl = ttl

  # TXT record: length-prefixed strings
  result.rdata = @[]
  var remaining = text

  while remaining.len > 0:
    let chunkLen = min(remaining.len, 255)
    result.rdata.add(chunkLen.uint8)
    for i in 0..<chunkLen:
      result.rdata.add(remaining[i].uint8)
    remaining = remaining[chunkLen..^1]

  result.rdlength = result.rdata.len.uint16

proc getRecordTypeName*(rtype: uint16): string =
  ## Returns human-readable name for DNS record type
  case rtype:
  of DNS_TYPE_A: "A"
  of DNS_TYPE_NS: "NS"
  of DNS_TYPE_CNAME: "CNAME"
  of DNS_TYPE_SOA: "SOA"
  of DNS_TYPE_PTR: "PTR"
  of DNS_TYPE_MX: "MX"
  of DNS_TYPE_TXT: "TXT"
  of DNS_TYPE_AAAA: "AAAA"
  of DNS_TYPE_SRV: "SRV"
  of DNS_TYPE_ANY: "ANY"
  else: "TYPE" & $rtype
