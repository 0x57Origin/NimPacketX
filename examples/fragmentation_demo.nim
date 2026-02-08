## Fragmentation Demo - Shows all fragmentation strategies
##
## This demo demonstrates how to use IP fragmentation for packet manipulation.
##
## IMPORTANT: This requires administrator/root privileges to run!
## - Windows: Run as Administrator
## - Linux/macOS: Run with sudo
##
## USAGE EXAMPLES:
##   nim c -r examples/fragmentation_demo.nim <strategy> <dest_ip>
##
##   nim c -r examples/fragmentation_demo.nim tiny 192.168.1.1
##   nim c -r examples/fragmentation_demo.nim overlap 192.168.1.1
##   nim c -r examples/fragmentation_demo.nim outoforder 192.168.1.1
##   nim c -r examples/fragmentation_demo.nim delayed 192.168.1.1
##   nim c -r examples/fragmentation_demo.nim random 192.168.1.1
##   nim c -r examples/fragmentation_demo.nim all 192.168.1.1
##
## NOTE: For testing purposes, sending to localhost/127.0.0.1 may not show
## fragmentation in packet captures due to loopback optimization.

import ../src/[nimpacket, rawsocket, fragmentation]
import std/[os, strutils, times]

proc printUsage() =
  echo """
Fragmentation Demo - IP Fragmentation Techniques

USAGE:
  fragmentation_demo <strategy> <dest_ip>

STRATEGIES:
  tiny         - Fragment into minimum 8-byte chunks
  overlap      - Create overlapping fragments with poison data
  outoforder   - Send fragments in reverse order
  delayed      - Send fragments with time delays
  random       - Randomly select a strategy
  all          - Demonstrate all strategies

EXAMPLES:
  fragmentation_demo tiny 192.168.1.1
  fragmentation_demo overlap 10.0.0.5
  fragmentation_demo all 192.168.1.100

NOTE: Requires administrator/root privileges!
"""
  quit(1)

proc demoTinyFragments(destIP: string) =
  echo "\n=== TinyFragments Strategy ==="
  echo "Fragmenting payload into 8-byte (minimum) chunks"

  var sock = createRawSocket()
  defer: sock.close()

  var ip = IPv4Header(
    version: 4,
    headerLength: 5,
    typeOfService: 0,
    timeToLive: 64,
    protocol: IPPROTO_TCP,
    sourceIP: parseIPv4("192.168.1.100"),
    destIP: parseIPv4(destIP)
  )

  let payload = "This is a test payload for fragmentation demonstration!".toBytes()

  echo "Payload size: ", payload.len, " bytes"
  echo "Sending fragments..."

  let startTime = cpuTime()
  let bytesSent = sock.sendFragmented(ip, payload, destIP, TinyFragments)
  let elapsed = cpuTime() - startTime

  echo "Total bytes sent: ", bytesSent
  echo "Time elapsed: ", elapsed.formatFloat(ffDecimal, 3), " seconds"
  echo "Strategy: TinyFragments (8-byte fragments)"

proc demoOverlapPoison(destIP: string) =
  echo "\n=== OverlapPoison Strategy ==="
  echo "Creating overlapping fragments with conflicting data"

  var sock = createRawSocket()
  defer: sock.close()

  var ip = IPv4Header(
    version: 4,
    headerLength: 5,
    typeOfService: 0,
    timeToLive: 64,
    protocol: IPPROTO_TCP,
    sourceIP: parseIPv4("192.168.1.100"),
    destIP: parseIPv4(destIP)
  )

  let payload = "Overlap test with poison data in fragments!".toBytes()

  echo "Payload size: ", payload.len, " bytes"
  echo "Sending overlapping fragments..."

  var config = createDefaultConfig(OverlapPoison)
  config.overlapOffset = 8
  config.poisonData = "DEADBEEF".toBytes()

  let startTime = cpuTime()
  let bytesSent = sock.sendFragmentedWithConfig(ip, payload, destIP, config)
  let elapsed = cpuTime() - startTime

  echo "Total bytes sent: ", bytesSent
  echo "Time elapsed: ", elapsed.formatFloat(ffDecimal, 3), " seconds"
  echo "Strategy: OverlapPoison (fragments overlap at offset 8)"

proc demoOutOfOrder(destIP: string) =
  echo "\n=== OutOfOrder Strategy ==="
  echo "Sending fragments in reverse order"

  var sock = createRawSocket()
  defer: sock.close()

  var ip = IPv4Header(
    version: 4,
    headerLength: 5,
    typeOfService: 0,
    timeToLive: 64,
    protocol: IPPROTO_TCP,
    sourceIP: parseIPv4("192.168.1.100"),
    destIP: parseIPv4(destIP)
  )

  let payload = "Out-of-order fragment test payload data".toBytes()

  echo "Payload size: ", payload.len, " bytes"
  echo "Sending fragments in reverse order..."

  let startTime = cpuTime()
  let bytesSent = sock.sendFragmented(ip, payload, destIP, OutOfOrder)
  let elapsed = cpuTime() - startTime

  echo "Total bytes sent: ", bytesSent
  echo "Time elapsed: ", elapsed.formatFloat(ffDecimal, 3), " seconds"
  echo "Strategy: OutOfOrder (last fragment sent first)"

proc demoTimeDelayed(destIP: string) =
  echo "\n=== TimeDelayed Strategy ==="
  echo "Sending fragments with delays between them"

  var sock = createRawSocket()
  defer: sock.close()

  var ip = IPv4Header(
    version: 4,
    headerLength: 5,
    typeOfService: 0,
    timeToLive: 64,
    protocol: IPPROTO_TCP,
    sourceIP: parseIPv4("192.168.1.100"),
    destIP: parseIPv4(destIP)
  )

  let payload = "Time-delayed fragmentation test".toBytes()

  echo "Payload size: ", payload.len, " bytes"
  echo "Sending fragments with 200ms delay..."

  let startTime = cpuTime()
  let bytesSent = sock.sendFragmented(ip, payload, destIP, TimeDelayed, delayMs = 200)
  let elapsed = cpuTime() - startTime

  echo "Total bytes sent: ", bytesSent
  echo "Time elapsed: ", elapsed.formatFloat(ffDecimal, 3), " seconds"
  echo "Strategy: TimeDelayed (200ms between fragments)"

proc demoPolymorphicRandom(destIP: string) =
  echo "\n=== PolymorphicRandom Strategy ==="
  echo "Randomly selecting fragmentation strategy"

  var sock = createRawSocket()
  defer: sock.close()

  var ip = IPv4Header(
    version: 4,
    headerLength: 5,
    typeOfService: 0,
    timeToLive: 64,
    protocol: IPPROTO_TCP,
    sourceIP: parseIPv4("192.168.1.100"),
    destIP: parseIPv4(destIP)
  )

  let payload = "Polymorphic random strategy test".toBytes()

  echo "Payload size: ", payload.len, " bytes"
  echo "Sending with random strategy selection..."

  let startTime = cpuTime()
  let bytesSent = sock.sendFragmented(ip, payload, destIP, PolymorphicRandom)
  let elapsed = cpuTime() - startTime

  echo "Total bytes sent: ", bytesSent
  echo "Time elapsed: ", elapsed.formatFloat(ffDecimal, 3), " seconds"
  echo "Strategy: PolymorphicRandom (randomly selected)"

proc demoFragmentInfo(destIP: string) =
  echo "\n=== Fragment Information Demo ==="
  echo "Showing detailed fragment information"

  var ip = IPv4Header(
    version: 4,
    headerLength: 5,
    typeOfService: 0,
    timeToLive: 64,
    protocol: IPPROTO_TCP,
    sourceIP: parseIPv4("192.168.1.100"),
    destIP: parseIPv4(destIP)
  )

  let payload = "Fragment info test payload data".toBytes()
  let config = createDefaultConfig(TinyFragments)
  let fragments = applyStrategy(config, ip, payload)

  echo getFragmentInfo(fragments)

proc main() =
  echo "NimPacket - IP Fragmentation Demo"
  echo "=================================="
  echo ""

  # Auto-elevate on Windows, require sudo on Unix
  when defined(windows):
    # Windows: Auto-elevate if not admin
    if not isRunningAsAdmin():
      echo "Requesting administrator privileges..."
      elevateIfNeeded()
  else:
    # Unix: Require sudo
    if not isRunningAsAdmin():
      echo "ERROR: This demo requires root privileges!"
      echo "Please run with sudo:"
      echo "  sudo ./fragmentation_demo <strategy> <dest_ip>"
      quit(1)

  # Parse command line arguments
  if paramCount() < 2:
    printUsage()

  let strategy = paramStr(1).toLowerAscii()
  let destIP = paramStr(2)

  echo "Destination IP: ", destIP
  echo "Selected strategy: ", strategy
  echo ""

  try:
    case strategy:
    of "tiny":
      demoTinyFragments(destIP)
    of "overlap":
      demoOverlapPoison(destIP)
    of "outoforder", "ooo":
      demoOutOfOrder(destIP)
    of "delayed", "delay":
      demoTimeDelayed(destIP)
    of "random", "poly":
      demoPolymorphicRandom(destIP)
    of "all":
      echo "Running all fragmentation strategies..."
      demoTinyFragments(destIP)
      sleep(1000)
      demoOverlapPoison(destIP)
      sleep(1000)
      demoOutOfOrder(destIP)
      sleep(1000)
      demoTimeDelayed(destIP)
      sleep(1000)
      demoPolymorphicRandom(destIP)
      demoFragmentInfo(destIP)
    of "info":
      demoFragmentInfo(destIP)
    else:
      echo "ERROR: Unknown strategy '", strategy, "'"
      printUsage()

    echo ""
    echo "Demo completed successfully!"

  except Exception as e:
    echo "ERROR: ", e.msg
    quit(1)

when isMainModule:
  main()
