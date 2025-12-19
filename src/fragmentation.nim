## IP Fragmentation Module for NimPacket
##
## This module provides IP fragmentation and evasion techniques for advanced
## packet manipulation and testing.
##
## **IMPORTANT SECURITY NOTE:**
## Fragmentation techniques are for authorized security testing only:
## - Penetration testing with proper authorization
## - Security research and IDS/IPS testing
## - Educational purposes in controlled environments
## - Network forensics and analysis
##
## **DO NOT USE FOR:**
## - Unauthorized network scanning or intrusion
## - Bypassing security controls for malicious purposes
## - Any illegal activity
##
## Example usage:
## ```nim
## import fragmentation, nimpacket, rawsocket
##
## let sock = createRawSocket()
## defer: sock.close()
##
## let ip = IPv4Header(...)
## let payload = "Test data".toBytes()
##
## # Send with tiny fragments strategy
## sock.sendFragmented(ip, payload, "192.168.1.1", TinyFragments)
## ```

import std/[random, times, algorithm, os]
import nimpacket, rawsocket

type
  FragmentationStrategy* = enum
    ## Available fragmentation strategies for packet evasion
    TinyFragments,      ## 8-byte fragments (minimum size)
    OverlapPoison,      ## Overlapping fragments with conflicting data
    OutOfOrder,         ## Reversed fragment sequence
    TimeDelayed,        ## Configurable delays between fragments
    PolymorphicRandom   ## Randomized strategy selection

  FragmentConfig* = object
    ## Configuration for fragmentation behavior
    strategy*: FragmentationStrategy
    fragmentSize*: int          ## Size of each fragment (ignored for some strategies)
    delayMs*: int               ## Delay between fragments (for TimeDelayed)
    overlapOffset*: int         ## Offset for overlap (for OverlapPoison)
    poisonData*: seq[byte]      ## Data to use in overlapping fragments

  IPFragment* = object
    ## Represents a single IP fragment
    header*: IPv4Header
    payload*: seq[byte]

  FragmentationError* = object of CatchableError

# IP Flag constants
const
  IP_FLAG_RESERVED* = 0x8000'u16   ## Reserved, must be zero
  IP_FLAG_DF* = 0x4000'u16         ## Don't Fragment
  IP_FLAG_MF* = 0x2000'u16         ## More Fragments
  IP_OFFSET_MASK* = 0x1FFF'u16     ## Fragment offset mask

proc createDefaultConfig*(strategy: FragmentationStrategy): FragmentConfig =
  ## Creates a default configuration for the given strategy
  result = FragmentConfig(
    strategy: strategy,
    fragmentSize: 8,         ## Default to minimum fragment size
    delayMs: 100,            ## 100ms delay for TimeDelayed
    overlapOffset: 8,        ## 8-byte overlap for OverlapPoison
    poisonData: @[]
  )

proc calculateFragmentOffset*(byteOffset: int): uint16 =
  ## Calculates fragment offset in 8-byte units
  ## Fragment offset field is in units of 8 bytes
  if byteOffset mod 8 != 0:
    raise newException(FragmentationError,
      "Fragment offset must be a multiple of 8 bytes")
  result = (byteOffset div 8).uint16

proc setFragmentFlags*(header: var IPv4Header, moreFragments: bool,
                       offset: uint16) =
  ## Sets IP fragmentation flags and offset
  ## offset is in 8-byte units
  var flags: uint16 = 0

  if moreFragments:
    flags = flags or IP_FLAG_MF

  # Combine flags and offset
  # Top 3 bits are flags, bottom 13 bits are offset
  header.flags = flags or (offset and IP_OFFSET_MASK)

proc createIPFragment*(baseHeader: IPv4Header, payload: seq[byte],
                       offset: int, isLast: bool, fragmentID: uint16): IPFragment =
  ## Creates a complete IP fragment with proper headers
  result.header = baseHeader
  result.payload = payload

  # Set fragment identification
  result.header.identification = fragmentID

  # Calculate and set fragment offset
  let fragmentOffset = calculateFragmentOffset(offset)
  setFragmentFlags(result.header, not isLast, fragmentOffset)

  # Calculate total length (IP header + payload)
  result.header.totalLength = (20 + payload.len).uint16

  # Recalculate checksum with new header values
  result.header.checksum = 0
  result.header.checksum = calculateIPv4Checksum(result.header)

proc fragmentPayload*(payload: seq[byte], fragmentSize: int): seq[seq[byte]] =
  ## Splits payload into fragments of specified size
  ## Returns sequence of fragment payloads
  if fragmentSize < 8:
    raise newException(FragmentationError,
      "Fragment size must be at least 8 bytes")

  if fragmentSize mod 8 != 0:
    raise newException(FragmentationError,
      "Fragment size must be a multiple of 8 bytes")

  result = @[]
  var offset = 0

  while offset < payload.len:
    let remainingBytes = payload.len - offset
    let chunkSize = min(fragmentSize, remainingBytes)

    # For last fragment, take all remaining bytes
    if offset + chunkSize >= payload.len:
      result.add(payload[offset..^1])
    else:
      result.add(payload[offset..<(offset + chunkSize)])

    offset += chunkSize

proc fragmentTiny*(payload: seq[byte]): seq[seq[byte]] =
  ## Fragments payload into minimum size (8 bytes) fragments
  result = fragmentPayload(payload, 8)

proc fragmentOverlap*(payload: seq[byte], overlapOffset: int,
                      poisonData: seq[byte]): seq[IPFragment] =
  ## Creates overlapping fragments with poison data
  ## This creates fragments that overlap to confuse reassembly
  result = @[]

  if payload.len < 16:
    raise newException(FragmentationError,
      "Payload too small for overlap fragmentation (minimum 16 bytes)")

  # Create base header (will be customized per fragment)
  var baseHeader = IPv4Header(
    version: 4,
    headerLength: 5,
    timeToLive: 64
  )

  let fragmentID = rand(65535).uint16

  # First fragment: first 8 bytes
  let frag1 = createIPFragment(baseHeader, payload[0..<8], 0, false, fragmentID)
  result.add(frag1)

  # Overlapping fragment with poison data
  var overlapPayload: seq[byte]
  if poisonData.len > 0:
    overlapPayload = poisonData[0..<min(8, poisonData.len)]
    # Pad if needed
    while overlapPayload.len < 8:
      overlapPayload.add(0'u8)
  else:
    # Use garbage data
    overlapPayload = newSeq[byte](8)
    for i in 0..<8:
      overlapPayload[i] = rand(255).byte

  let frag2 = createIPFragment(baseHeader, overlapPayload, overlapOffset, false, fragmentID)
  result.add(frag2)

  # Final fragment: remaining data
  let lastFragOffset = max(8, overlapOffset + 8)
  if lastFragOffset < payload.len:
    let frag3 = createIPFragment(baseHeader, payload[lastFragOffset..^1],
                                 lastFragOffset, true, fragmentID)
    result.add(frag3)

proc fragmentOutOfOrder*(payload: seq[byte], fragmentSize: int): seq[seq[byte]] =
  ## Fragments payload and returns in reverse order
  result = fragmentPayload(payload, fragmentSize)
  result.reverse()

proc applyStrategy*(config: FragmentConfig, baseHeader: IPv4Header,
                   payload: seq[byte]): seq[IPFragment] =
  ## Applies the specified fragmentation strategy
  result = @[]

  case config.strategy:
  of TinyFragments:
    let chunks = fragmentTiny(payload)
    let fragmentID = rand(65535).uint16

    for i, chunk in chunks:
      let offset = i * 8
      let isLast = (i == chunks.len - 1)
      result.add(createIPFragment(baseHeader, chunk, offset, isLast, fragmentID))

  of OverlapPoison:
    result = fragmentOverlap(payload, config.overlapOffset, config.poisonData)

  of OutOfOrder:
    let chunks = fragmentOutOfOrder(payload, config.fragmentSize)
    let fragmentID = rand(65535).uint16

    # Calculate original offsets (before reversal)
    var offsets: seq[int] = @[]
    for i in 0..<chunks.len:
      offsets.add((chunks.len - 1 - i) * config.fragmentSize)

    for i, chunk in chunks:
      let isLast = (offsets[i] + chunk.len >= payload.len)
      result.add(createIPFragment(baseHeader, chunk, offsets[i], isLast, fragmentID))

  of TimeDelayed:
    let chunks = fragmentPayload(payload, config.fragmentSize)
    let fragmentID = rand(65535).uint16

    for i, chunk in chunks:
      let offset = i * config.fragmentSize
      let isLast = (i == chunks.len - 1)
      result.add(createIPFragment(baseHeader, chunk, offset, isLast, fragmentID))

  of PolymorphicRandom:
    # Randomly select a strategy
    let strategies = [TinyFragments, OutOfOrder, TimeDelayed]
    let selectedStrategy = strategies[rand(strategies.len - 1)]

    var newConfig = config
    newConfig.strategy = selectedStrategy
    result = applyStrategy(newConfig, baseHeader, payload)

proc sendFragmented*(sock: RawSocket, baseHeader: IPv4Header, payload: seq[byte],
                    destIP: string, strategy: FragmentationStrategy,
                    delayMs: int = 100): int {.discardable.} =
  ## Sends a fragmented packet using the specified strategy
  ## Returns total bytes sent across all fragments
  ##
  ## Parameters:
  ##   sock: Raw socket to use for sending
  ##   baseHeader: Base IPv4 header (will be modified for each fragment)
  ##   payload: Data to fragment and send
  ##   destIP: Destination IP address
  ##   strategy: Fragmentation strategy to use
  ##   delayMs: Delay in milliseconds between fragments (for TimeDelayed strategy)
  ##
  ## Example:
  ## ```nim
  ## let sock = createRawSocket()
  ## let ip = IPv4Header(sourceIP: parseIPv4("192.168.1.100"),
  ##                     destIP: parseIPv4("192.168.1.1"),
  ##                     protocol: IPPROTO_TCP,
  ##                     timeToLive: 64)
  ## sock.sendFragmented(ip, "Hello".toBytes(), "192.168.1.1", TinyFragments)
  ## ```

  if payload.len == 0:
    raise newException(FragmentationError, "Cannot fragment empty payload")

  # Create configuration
  var config = createDefaultConfig(strategy)
  config.delayMs = delayMs

  # Generate fragments
  let fragments = applyStrategy(config, baseHeader, payload)

  if fragments.len == 0:
    raise newException(FragmentationError, "No fragments generated")

  result = 0

  # Send each fragment
  for i, fragment in fragments:
    # Build complete packet
    var packet = fragment.header.toBytes()
    packet &= fragment.payload

    # Send the fragment
    let bytesSent = sock.sendPacket(packet, destIP)
    result += bytesSent

    # Apply delay if configured and not the last fragment
    if config.strategy == TimeDelayed and i < fragments.len - 1:
      sleep(config.delayMs)

proc sendFragmentedWithConfig*(sock: RawSocket, baseHeader: IPv4Header,
                               payload: seq[byte], destIP: string,
                               config: FragmentConfig): int {.discardable.} =
  ## Sends fragmented packet with custom configuration
  ## Provides more control than sendFragmented()

  if payload.len == 0:
    raise newException(FragmentationError, "Cannot fragment empty payload")

  let fragments = applyStrategy(config, baseHeader, payload)

  if fragments.len == 0:
    raise newException(FragmentationError, "No fragments generated")

  result = 0

  for i, fragment in fragments:
    var packet = fragment.header.toBytes()
    packet &= fragment.payload

    let bytesSent = sock.sendPacket(packet, destIP)
    result += bytesSent

    if config.strategy == TimeDelayed and i < fragments.len - 1:
      sleep(config.delayMs)

proc getFragmentInfo*(fragments: seq[IPFragment]): string =
  ## Returns human-readable information about fragments
  result = "Fragment Summary:\n"
  result &= "  Total fragments: " & $fragments.len & "\n"

  for i, frag in fragments:
    let offset = (frag.header.flags and IP_OFFSET_MASK) * 8
    let moreFrags = (frag.header.flags and IP_FLAG_MF) != 0
    result &= "  Fragment " & $i & ":\n"
    result &= "    Offset: " & $offset & " bytes\n"
    result &= "    Payload size: " & $frag.payload.len & " bytes\n"
    result &= "    More fragments: " & $moreFrags & "\n"
    result &= "    ID: " & $frag.header.identification & "\n"

# Initialize random number generator
randomize()
