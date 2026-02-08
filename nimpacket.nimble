# Package

version       = "0.1.0"
author        = "0x57Origin"
description   = "Low-level packet manipulation library for Nim with Python bindings"
license       = "MIT"
srcDir        = "src"

# Dependencies

requires "nim >= 1.6.0"
requires "nimpy >= 0.2.0"

# Tasks

task test, "Run all tests":
  exec "nim c -r tests/test_ipv4.nim"
  exec "nim c -r tests/test_tcp.nim"
  exec "nim c -r tests/test_udp.nim"
  exec "nim c -r tests/test_icmp.nim"
  exec "nim c -r tests/test_ethernet.nim"
  exec "nim c -r tests/test_arp.nim"
  exec "nim c -r tests/test_ipv6.nim"
  exec "nim c -r tests/test_icmpv6.nim"
  exec "nim c -r tests/test_dns.nim"
  exec "nim c -r tests/test_dhcp.nim"
  exec "nim c -r tests/test_integration.nim"

task test_ipv4, "Run IPv4 tests":
  exec "nim c -r tests/test_ipv4.nim"

task test_tcp, "Run TCP tests":
  exec "nim c -r tests/test_tcp.nim"

task test_udp, "Run UDP tests":
  exec "nim c -r tests/test_udp.nim"

task test_icmp, "Run ICMP tests":
  exec "nim c -r tests/test_icmp.nim"

task test_ethernet, "Run Ethernet tests":
  exec "nim c -r tests/test_ethernet.nim"

task test_arp, "Run ARP tests":
  exec "nim c -r tests/test_arp.nim"

task test_ipv6, "Run IPv6 tests":
  exec "nim c -r tests/test_ipv6.nim"

task test_icmpv6, "Run ICMPv6 tests":
  exec "nim c -r tests/test_icmpv6.nim"

task test_dns, "Run DNS tests":
  exec "nim c -r tests/test_dns.nim"

task test_dhcp, "Run DHCP tests":
  exec "nim c -r tests/test_dhcp.nim"

task test_rawsocket, "Run raw socket tests (requires admin/root)":
  exec "nim c -r tests/test_rawsocket.nim"

task test_integration, "Run integration tests":
  exec "nim c -r tests/test_integration.nim"

task docs, "Generate documentation":
  exec "nim doc --project --index:on --git.url:https://github.com/0x57Origin/NimPacket --outdir:docs src/nimpacket.nim"

task examples, "Build examples":
  exec "nim c -d:release examples/scanner.nim"
  exec "nim c -d:release examples/packet_builder.nim"

task python, "Build Python extension":
  when defined(windows):
    exec "nim c --app:lib --out:python/nimpacket/nimpacket_py.pyd -d:release src/nimpacket_py.nim"
  else:
    exec "nim c --app:lib --out:python/nimpacket/nimpacket_py.so -d:release src/nimpacket_py.nim"

task python_install, "Build and install Python package":
  exec "nimble python"
  exec "pip install -e python/"
