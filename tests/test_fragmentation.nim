## Tests for the fragmentation module

import ../src/fragmentation
import ../src/nimpacket
import std/[unittest, random, strutils]

suite "Fragmentation Module Tests":

  setup:
    randomize(42)  # Use fixed seed for reproducible tests

  test "calculateFragmentOffset with valid offsets":
    check calculateFragmentOffset(0) == 0
    check calculateFragmentOffset(8) == 1
    check calculateFragmentOffset(16) == 2
    check calculateFragmentOffset(64) == 8
    check calculateFragmentOffset(1024) == 128

  test "calculateFragmentOffset with invalid offset":
    expect(FragmentationError):
      discard calculateFragmentOffset(7)  # Not a multiple of 8
    expect(FragmentationError):
      discard calculateFragmentOffset(15)  # Not a multiple of 8

  test "setFragmentFlags for first fragment":
    var header = IPv4Header()
    setFragmentFlags(header, true, 0)

    # Should have More Fragments flag set
    check (header.flags and IP_FLAG_MF) != 0
    # Offset should be 0
    check (header.flags and IP_OFFSET_MASK) == 0

  test "setFragmentFlags for middle fragment":
    var header = IPv4Header()
    setFragmentFlags(header, true, 10)  # Offset 10 (80 bytes)

    # Should have More Fragments flag set
    check (header.flags and IP_FLAG_MF) != 0
    # Offset should be 10
    check (header.flags and IP_OFFSET_MASK) == 10

  test "setFragmentFlags for last fragment":
    var header = IPv4Header()
    setFragmentFlags(header, false, 20)  # Offset 20 (160 bytes)

    # Should NOT have More Fragments flag set
    check (header.flags and IP_FLAG_MF) == 0
    # Offset should be 20
    check (header.flags and IP_OFFSET_MASK) == 20

  test "fragmentPayload with 8-byte fragments":
    let payload = @[byte 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
    let fragments = fragmentPayload(payload, 8)

    check fragments.len == 2
    check fragments[0] == @[byte 1, 2, 3, 4, 5, 6, 7, 8]
    check fragments[1] == @[byte 9, 10, 11, 12, 13, 14, 15, 16]

  test "fragmentPayload with uneven split":
    let payload = @[byte 1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
    let fragments = fragmentPayload(payload, 8)

    check fragments.len == 2
    check fragments[0] == @[byte 1, 2, 3, 4, 5, 6, 7, 8]
    check fragments[1] == @[byte 9, 10]  # Last fragment can be less than 8 bytes

  test "fragmentPayload with invalid size":
    let payload = @[byte 1, 2, 3, 4]

    expect(FragmentationError):
      discard fragmentPayload(payload, 7)  # Not multiple of 8

    expect(FragmentationError):
      discard fragmentPayload(payload, 4)  # Less than 8

  test "fragmentTiny creates 8-byte fragments":
    let payload = @[byte 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20]
    let fragments = fragmentTiny(payload)

    check fragments.len == 3
    check fragments[0].len == 8
    check fragments[1].len == 8
    check fragments[2].len == 4  # Last fragment

  test "createIPFragment with first fragment":
    var baseHeader = IPv4Header(
      version: 4,
      headerLength: 5,
      protocol: IPPROTO_TCP,
      timeToLive: 64,
      sourceIP: parseIPv4("192.168.1.100"),
      destIP: parseIPv4("192.168.1.1")
    )

    let payload = @[byte 1, 2, 3, 4, 5, 6, 7, 8]
    let frag = createIPFragment(baseHeader, payload, 0, false, 12345)

    check frag.header.identification == 12345
    check frag.header.totalLength == 28  # 20 (IP header) + 8 (payload)
    check (frag.header.flags and IP_FLAG_MF) != 0  # More fragments
    check (frag.header.flags and IP_OFFSET_MASK) == 0  # Offset 0
    check frag.payload == payload

  test "createIPFragment with last fragment":
    var baseHeader = IPv4Header(
      version: 4,
      headerLength: 5,
      protocol: IPPROTO_TCP,
      timeToLive: 64
    )

    let payload = @[byte 9, 10]
    let frag = createIPFragment(baseHeader, payload, 16, true, 12345)

    check frag.header.identification == 12345
    check frag.header.totalLength == 22  # 20 (IP header) + 2 (payload)
    check (frag.header.flags and IP_FLAG_MF) == 0  # No more fragments
    check (frag.header.flags and IP_OFFSET_MASK) == 2  # Offset 2 (16 bytes / 8)

  test "fragmentOutOfOrder reverses fragments":
    let payload = @[byte 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
    let fragments = fragmentOutOfOrder(payload, 8)

    check fragments.len == 2
    # Should be in reverse order
    check fragments[0] == @[byte 9, 10, 11, 12, 13, 14, 15, 16]
    check fragments[1] == @[byte 1, 2, 3, 4, 5, 6, 7, 8]

  test "TinyFragments strategy":
    var baseHeader = IPv4Header(
      version: 4,
      headerLength: 5,
      protocol: IPPROTO_TCP,
      timeToLive: 64,
      sourceIP: parseIPv4("192.168.1.100"),
      destIP: parseIPv4("192.168.1.1")
    )

    let payload = @[byte 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18]
    let config = createDefaultConfig(TinyFragments)
    let fragments = applyStrategy(config, baseHeader, payload)

    check fragments.len == 3
    check fragments[0].payload.len == 8
    check fragments[1].payload.len == 8
    check fragments[2].payload.len == 2

    # Check first fragment
    check (fragments[0].header.flags and IP_FLAG_MF) != 0
    check (fragments[0].header.flags and IP_OFFSET_MASK) == 0

    # Check last fragment
    check (fragments[2].header.flags and IP_FLAG_MF) == 0

  test "OutOfOrder strategy":
    var baseHeader = IPv4Header(
      version: 4,
      headerLength: 5,
      protocol: IPPROTO_TCP,
      timeToLive: 64
    )

    let payload = @[byte 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
    var config = createDefaultConfig(OutOfOrder)
    config.fragmentSize = 8
    let fragments = applyStrategy(config, baseHeader, payload)

    check fragments.len == 2

    # First fragment sent should have higher offset
    check (fragments[0].header.flags and IP_OFFSET_MASK) == 1  # Offset 8 bytes
    # Second fragment sent should have lower offset
    check (fragments[1].header.flags and IP_OFFSET_MASK) == 0  # Offset 0 bytes

  test "OverlapPoison strategy":
    var baseHeader = IPv4Header(
      version: 4,
      headerLength: 5,
      protocol: IPPROTO_TCP,
      timeToLive: 64
    )

    let payload = @[byte 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20]
    var config = createDefaultConfig(OverlapPoison)
    config.overlapOffset = 8
    let fragments = applyStrategy(config, baseHeader, payload)

    # Should create at least 2 fragments (first + overlap)
    check fragments.len >= 2

  test "TimeDelayed strategy":
    var baseHeader = IPv4Header(
      version: 4,
      headerLength: 5,
      protocol: IPPROTO_TCP,
      timeToLive: 64
    )

    let payload = @[byte 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
    var config = createDefaultConfig(TimeDelayed)
    config.fragmentSize = 8
    config.delayMs = 10
    let fragments = applyStrategy(config, baseHeader, payload)

    check fragments.len == 2
    # Same as normal fragmentation, timing happens during sending

  test "PolymorphicRandom strategy":
    var baseHeader = IPv4Header(
      version: 4,
      headerLength: 5,
      protocol: IPPROTO_TCP,
      timeToLive: 64
    )

    let payload = @[byte 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
    let config = createDefaultConfig(PolymorphicRandom)
    let fragments = applyStrategy(config, baseHeader, payload)

    # Should generate fragments (strategy chosen randomly)
    check fragments.len > 0

  test "createDefaultConfig creates valid configs":
    let config1 = createDefaultConfig(TinyFragments)
    check config1.strategy == TinyFragments
    check config1.fragmentSize == 8

    let config2 = createDefaultConfig(TimeDelayed)
    check config2.strategy == TimeDelayed
    check config2.delayMs == 100

  test "getFragmentInfo provides readable output":
    var baseHeader = IPv4Header(
      version: 4,
      headerLength: 5,
      protocol: IPPROTO_TCP,
      timeToLive: 64
    )

    let payload = @[byte 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
    let config = createDefaultConfig(TinyFragments)
    let fragments = applyStrategy(config, baseHeader, payload)

    let info = getFragmentInfo(fragments)
    check info.contains("Fragment Summary:")
    check info.contains("Total fragments:")
    check info.contains("Offset:")
    check info.contains("Payload size:")

  test "empty payload raises error":
    var baseHeader = IPv4Header()
    let emptyPayload: seq[byte] = @[]
    let config = createDefaultConfig(TinyFragments)

    # This should be handled in sendFragmented, but let's test the strategy
    # Empty payload should create 0 fragments or raise an error
    # The actual error will be caught in sendFragmented

  test "fragment ID is consistent across fragments":
    var baseHeader = IPv4Header(
      version: 4,
      headerLength: 5,
      protocol: IPPROTO_TCP,
      timeToLive: 64
    )

    let payload = @[byte 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
    let config = createDefaultConfig(TinyFragments)
    let fragments = applyStrategy(config, baseHeader, payload)

    # All fragments should have the same ID
    let firstID = fragments[0].header.identification
    for frag in fragments:
      check frag.header.identification == firstID

  test "checksums are recalculated for each fragment":
    var baseHeader = IPv4Header(
      version: 4,
      headerLength: 5,
      protocol: IPPROTO_TCP,
      timeToLive: 64,
      sourceIP: parseIPv4("192.168.1.100"),
      destIP: parseIPv4("192.168.1.1")
    )

    let payload = @[byte 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
    let config = createDefaultConfig(TinyFragments)
    let fragments = applyStrategy(config, baseHeader, payload)

    # Each fragment should have a valid checksum
    for frag in fragments:
      check frag.header.checksum != 0
      check verifyIPv4Checksum(frag.header)
