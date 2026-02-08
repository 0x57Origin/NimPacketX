## DNS Protocol Tests

import unittest
import ../src/dns

suite "DNS Protocol Tests":

  test "Encode domain name":
    let encoded = encodeDomainName("www.example.com")
    check encoded.len > 0
    check encoded[0] == 3  # "www" length
    check encoded[4] == 7  # "example" length
    check encoded[12] == 3 # "com" length
    check encoded[^1] == 0 # Null terminator

  test "Encode domain name - empty":
    let encoded = encodeDomainName("")
    check encoded == @[0'u8]

  test "Encode domain name - root":
    let encoded = encodeDomainName(".")
    check encoded == @[0'u8]

  test "Build DNS flags - query":
    let flags = buildDNSFlags(qr = false, rd = true)
    check (flags and DNS_FLAG_QR) == 0  # Query
    check (flags and DNS_FLAG_RD) != 0  # Recursion desired

  test "Build DNS flags - response":
    let flags = buildDNSFlags(qr = true, aa = true, ra = true)
    check (flags and DNS_FLAG_QR) != 0  # Response
    check (flags and DNS_FLAG_AA) != 0  # Authoritative
    check (flags and DNS_FLAG_RA) != 0  # Recursion available

  test "Parse DNS flags":
    let flags = buildDNSFlags(qr = true, opcode = 0, aa = true, rd = true, ra = true, rcode = 0)
    let parsed = parseDNSFlags(flags)
    check parsed.qr == true
    check parsed.opcode == 0
    check parsed.aa == true
    check parsed.rd == true
    check parsed.ra == true
    check parsed.rcode == 0

  test "DNS header serialization":
    let header = DNSHeader(
      transactionID: 0x1234,
      flags: buildDNSFlags(rd = true),
      questionCount: 1,
      answerCount: 0,
      authorityCount: 0,
      additionalCount: 0
    )

    let bytes = header.toBytes()
    check bytes.len == 12
    check bytes[0] == 0x12
    check bytes[1] == 0x34

  test "DNS question serialization":
    let question = DNSQuestion(
      name: "example.com",
      qtype: DNS_TYPE_A,
      qclass: DNS_CLASS_IN
    )

    let bytes = question.toBytes()
    check bytes.len > 4  # Name + type + class

  test "Create DNS query":
    let query = newDNSQuery("example.com", DNS_TYPE_A)
    check query.header.questionCount == 1
    check query.questions.len == 1
    check query.questions[0].name == "example.com"
    check query.questions[0].qtype == DNS_TYPE_A

  test "DNS packet roundtrip":
    let original = newDNSQuery("test.example.com", DNS_TYPE_AAAA)
    let bytes = original.toBytes()
    let parsed = parseDNSPacket(bytes)

    check parsed.header.transactionID == original.header.transactionID
    check parsed.header.questionCount == 1
    check parsed.questions[0].qtype == DNS_TYPE_AAAA

  test "Create A record":
    let record = newARecord("example.com", "192.168.1.1", ttl = 300)
    check record.rrtype == DNS_TYPE_A
    check record.rdlength == 4
    check record.rdata[0] == 192
    check record.rdata[1] == 168
    check record.rdata[2] == 1
    check record.rdata[3] == 1

  test "Create CNAME record":
    let record = newCNAMERecord("www.example.com", "example.com")
    check record.rrtype == DNS_TYPE_CNAME
    check record.rdlength > 0

  test "Create MX record":
    let record = newMXRecord("example.com", 10, "mail.example.com")
    check record.rrtype == DNS_TYPE_MX
    check record.rdlength > 2  # Preference + domain

  test "Create TXT record":
    let record = newTXTRecord("example.com", "v=spf1 include:example.com ~all")
    check record.rrtype == DNS_TYPE_TXT
    check record.rdlength > 0

  test "Get record type name":
    check getRecordTypeName(DNS_TYPE_A) == "A"
    check getRecordTypeName(DNS_TYPE_AAAA) == "AAAA"
    check getRecordTypeName(DNS_TYPE_CNAME) == "CNAME"
    check getRecordTypeName(DNS_TYPE_MX) == "MX"
    check getRecordTypeName(DNS_TYPE_TXT) == "TXT"
    check getRecordTypeName(DNS_TYPE_NS) == "NS"
    check getRecordTypeName(DNS_TYPE_SOA) == "SOA"
    check getRecordTypeName(DNS_TYPE_PTR) == "PTR"

  test "DNS response creation":
    let query = newDNSQuery("example.com", DNS_TYPE_A)
    let answers = @[newARecord("example.com", "93.184.216.34")]
    let response = newDNSResponse(query, answers)

    check response.header.transactionID == query.header.transactionID
    check (response.header.flags and DNS_FLAG_QR) != 0  # Is response
    check response.header.answerCount == 1
    check response.answers.len == 1

echo "All DNS tests passed!"
