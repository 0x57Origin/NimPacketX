# IP Fragmentation Module

The fragmentation module provides advanced IP packet fragmentation techniques for NimPacket. This module is designed for authorized security testing, IDS/IPS evaluation, and network research.

## Features

- Multiple Fragmentation Strategies: 5 different evasion techniques
- Easy-to-use API: Simple function calls to fragment and send packets
- Full Control: Customize fragment sizes, delays, and overlap behavior
- Type-safe: Proper error handling and validation
- Well-tested: Comprehensive test suite with 22 unit tests

## Quick Start

### Running the Demo

**Windows (auto-elevates):**
```bash
nim c examples/fragmentation_demo.nim
./examples/fragmentation_demo.exe tiny 192.168.1.1
```

**Linux/macOS:**
```bash
nim c examples/fragmentation_demo.nim
sudo ./examples/fragmentation_demo tiny 192.168.1.1
```

### Available Demo Commands

```bash
# Tiny 8-byte fragments
./fragmentation_demo tiny 192.168.1.1

# Overlapping fragments with poison data
./fragmentation_demo overlap 192.168.1.1

# Out of order fragments
./fragmentation_demo outoforder 192.168.1.1

# Time delayed fragments
./fragmentation_demo delayed 192.168.1.1

# Random strategy selection
./fragmentation_demo random 192.168.1.1

# Run ALL strategies
./fragmentation_demo all 192.168.1.1
```

### Basic Code Example

```nim
import nimpacket, fragmentation, rawsocket

# Create socket (auto-elevates on Windows)
var sock = createRawSocket()
defer: sock.close()

# Create IP header
var ip = IPv4Header(
  version: 4,
  headerLength: 5,
  timeToLive: 64,
  protocol: IPPROTO_TCP,
  sourceIP: parseIPv4("192.168.1.100"),
  destIP: parseIPv4("192.168.1.1")
)

# Send with tiny fragments strategy
sock.sendFragmented(ip, "Test".toBytes(), "192.168.1.1", TinyFragments)
```

### Running Tests

```bash
nim c -r tests/test_fragmentation.nim
```

All 22 tests should pass.

## Fragmentation Strategies

### 1. TinyFragments
Fragments packets into the minimum allowed size (8 bytes). This can help evade certain IDS/IPS systems that don't properly reassemble small fragments.

```nim
sock.sendFragmented(ip, payload, destIP, TinyFragments)
```

### 2. OverlapPoison
Creates overlapping fragments with conflicting data. Different systems may reassemble overlapping fragments differently, leading to evasion.

```nim
var config = createDefaultConfig(OverlapPoison)
config.overlapOffset = 8
config.poisonData = "DEADBEEF".toBytes()
sock.sendFragmentedWithConfig(ip, payload, destIP, config)
```

### 3. OutOfOrder
Sends fragments in reverse order. Some systems may not properly handle out-of-order fragments.

```nim
sock.sendFragmented(ip, payload, destIP, OutOfOrder)
```

### 4. TimeDelayed
Sends fragments with configurable delays between them. This can bypass timeout-based reassembly.

```nim
sock.sendFragmented(ip, payload, destIP, TimeDelayed, delayMs = 200)
```

### 5. PolymorphicRandom
Randomly selects a fragmentation strategy for each packet, making detection harder.

```nim
sock.sendFragmented(ip, payload, destIP, PolymorphicRandom)
```

## Quick Start

### Basic Example

```nim
import nimpacket, fragmentation, rawsocket

# Create a raw socket (requires admin/root)
var sock = createRawSocket()
defer: sock.close()

# Create IP header
var ip = IPv4Header(
  version: 4,
  headerLength: 5,
  timeToLive: 64,
  protocol: IPPROTO_TCP,
  sourceIP: parseIPv4("192.168.1.100"),
  destIP: parseIPv4("192.168.1.1")
)

# Prepare payload
let payload = "Test data".toBytes()

# Send with tiny fragments strategy
sock.sendFragmented(ip, payload, "192.168.1.1", TinyFragments)
```

### Advanced Configuration

```nim
import nimpacket, fragmentation, rawsocket

var sock = createRawSocket()
defer: sock.close()

var ip = IPv4Header(...)

# Create custom configuration
var config = createDefaultConfig(OverlapPoison)
config.fragmentSize = 16
config.overlapOffset = 8
config.poisonData = @[0xDE'u8, 0xAD, 0xBE, 0xEF]

# Send with custom config
sock.sendFragmentedWithConfig(ip, payload, "192.168.1.1", config)
```

### Examining Fragments

```nim
# Generate fragments without sending
let fragments = applyStrategy(config, ip, payload)

# Print fragment information
echo getFragmentInfo(fragments)

# Manually send each fragment
for frag in fragments:
  var packet = frag.header.toBytes()
  packet &= frag.payload
  sock.sendPacket(packet, destIP)
```

## API Reference

### Types

```nim
type
  FragmentationStrategy* = enum
    TinyFragments
    OverlapPoison
    OutOfOrder
    TimeDelayed
    PolymorphicRandom

  FragmentConfig* = object
    strategy*: FragmentationStrategy
    fragmentSize*: int
    delayMs*: int
    overlapOffset*: int
    poisonData*: seq[byte]

  IPFragment* = object
    header*: IPv4Header
    payload*: seq[byte]
```

### Functions

#### sendFragmented
```nim
proc sendFragmented*(sock: RawSocket, baseHeader: IPv4Header,
                    payload: seq[byte], destIP: string,
                    strategy: FragmentationStrategy,
                    delayMs: int = 100): int
```
Sends a fragmented packet using the specified strategy. Returns total bytes sent.

#### sendFragmentedWithConfig
```nim
proc sendFragmentedWithConfig*(sock: RawSocket, baseHeader: IPv4Header,
                               payload: seq[byte], destIP: string,
                               config: FragmentConfig): int
```
Sends fragmented packet with custom configuration.

#### applyStrategy
```nim
proc applyStrategy*(config: FragmentConfig, baseHeader: IPv4Header,
                   payload: seq[byte]): seq[IPFragment]
```
Generates fragments according to strategy without sending.

#### createDefaultConfig
```nim
proc createDefaultConfig*(strategy: FragmentationStrategy): FragmentConfig
```
Creates a default configuration for the given strategy.

#### getFragmentInfo
```nim
proc getFragmentInfo*(fragments: seq[IPFragment]): string
```
Returns human-readable information about fragments.

## Running the Demo

The fragmentation demo shows all strategies in action:

```bash
# Compile the demo
nim c examples/fragmentation_demo.nim

# Run with a specific strategy (requires admin/root)
./fragmentation_demo tiny 192.168.1.1
./fragmentation_demo overlap 192.168.1.1
./fragmentation_demo outoforder 192.168.1.1
./fragmentation_demo delayed 192.168.1.1
./fragmentation_demo random 192.168.1.1

# Run all strategies
./fragmentation_demo all 192.168.1.1
```

## Testing

Run the comprehensive test suite:

```bash
nim c -r tests/test_fragmentation.nim
```

All 22 tests should pass, covering:
- Fragment offset calculation
- Flag setting
- Payload fragmentation
- All 5 strategies
- Checksum validation
- Error handling

## Security Considerations

### Legal Use Only

This module is for **authorized security testing only**:
- Penetration testing with proper authorization
- Security research in controlled environments
- IDS/IPS testing and evaluation
- Network forensics and analysis
- Educational purposes

### Prohibited Uses

- Unauthorized network scanning or intrusion
- Bypassing security controls for malicious purposes
- Any illegal activity
- Causing network disruption without authorization

### Requirements

- **Privileges**: Requires administrator (Windows) or root (Linux/macOS)
- **Authorization**: Only use on networks you own or have explicit permission to test
- **Responsibility**: You are responsible for complying with applicable laws

## Implementation Details

### Fragment Offset Units

IP fragment offsets are specified in 8-byte units. The module handles this automatically:

```nim
# Fragment at byte offset 16 = offset field value 2
let offset = calculateFragmentOffset(16)  # Returns 2
```

### IP Flags

The module properly sets IP fragmentation flags:
- **MF (More Fragments)**: Set for all fragments except the last
- **DF (Don't Fragment)**: Never set during fragmentation
- **Reserved**: Always zero

### Checksum Recalculation

Each fragment gets a properly recalculated IP header checksum:

```nim
result.header.checksum = 0
result.header.checksum = calculateIPv4Checksum(result.header)
```

## Troubleshooting

### "Cannot fragment empty payload"
Ensure your payload has data before fragmenting.

### "Fragment size must be at least 8 bytes"
IP fragments must be at least 8 bytes (the minimum fragment offset unit).

### "Fragment size must be a multiple of 8 bytes"
Choose fragment sizes that are multiples of 8 (8, 16, 24, 32, etc.).

### "Requires administrator/root privileges"
Raw socket operations require elevated privileges. Run as Administrator (Windows) or with sudo (Linux/macOS).

## Performance

Fragmentation adds overhead:
- **Tiny fragments**: ~3-5x more packets
- **Overlap**: ~1.5-2x more packets
- **Out of order**: Same packet count, minimal overhead
- **Time delayed**: Same packet count, added latency
- **Random**: Variable overhead

## Examples in the Wild

### Firewall Evasion
```nim
# Evade stateful inspection with tiny fragments
sock.sendFragmented(ip, payload, target, TinyFragments)
```

### IDS Testing
```nim
# Test IDS reassembly with overlapping fragments
var config = createDefaultConfig(OverlapPoison)
config.poisonData = maliciousPattern.toBytes()
sock.sendFragmentedWithConfig(ip, benignPayload, target, config)
```

### Network Research
```nim
# Study fragment reassembly behavior
for strategy in [TinyFragments, OutOfOrder, TimeDelayed]:
  sock.sendFragmented(ip, testData, target, strategy)
  # Capture and analyze responses
```

## Contributing

When contributing fragmentation strategies:
1. Add the strategy to the `FragmentationStrategy` enum
2. Implement the fragmentation logic
3. Add to `applyStrategy` case statement
4. Write comprehensive tests
5. Document the strategy and use cases

## License

Part of NimPacket. See main project license.
