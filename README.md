# cpp-synscan — Educational C++ SYN Scanner

A from-scratch TCP SYN scanner (nmap `-sS` style) written in modern C++20 for
**educational purposes only**.  The project is structured as a guided learning
exercise: foundational modules (argument parsing, port-spec parsing, output
formatting) are fully implemented, while the networking core is left as clearly
documented TODO stubs for you to complete.

---

## Legal Warning

**This software is provided strictly for educational and authorized security
testing purposes.**

- **Never** scan networks or hosts you do not own or have explicit written
  permission to test.
- Unauthorized port scanning may violate local, state, and federal laws
  (e.g., the Computer Fraud and Abuse Act in the US, the Computer Misuse Act
  in the UK).
- The authors accept **no liability** for misuse.

---

## Prerequisites

| Requirement | Why |
|---|---|
| Linux | Uses raw sockets (`AF_INET`, `SOCK_RAW`) — Linux-only API |
| g++ 12+ or clang++ 15+ | C++20 features (`std::span`, `<charconv>`, etc.) |
| CMake 3.20+ | Build system |
| **root** or `CAP_NET_RAW` | Raw sockets require elevated privileges |

### Granting CAP_NET_RAW (recommended over running as root)

After building, you can grant the binary the minimal capability it needs
instead of running the entire program as root:

```bash
sudo setcap cap_net_raw=eip build/synscan
```

---

## Build Instructions

```bash
# Configure (from project root)
cmake -B build -DCMAKE_BUILD_TYPE=Debug

# Build
cmake --build build

# Run tests
ctest --test-dir build --output-on-failure

# Run the scanner (once you implement packet.cpp / scanner.cpp)
sudo ./build/synscan -p 22,80,443 192.168.1.1
```

---

## Project Structure

```
cpp-synscan/
├── CMakeLists.txt              # Top-level build configuration
├── README.md                   # You are here
├── include/synscan/
│   ├── args.h                  # CLI argument parsing interface
│   ├── output.h                # Result formatting interface
│   ├── packet.h                # ★ Raw packet crafting/send/recv (TODO)
│   ├── port_spec.h             # Port specification parser interface
│   └── scanner.h               # ★ High-level scan orchestrator (TODO)
├── src/
│   ├── main.cpp                # CLI entry point
│   ├── args.cpp                # ✓ Argument parsing (implemented)
│   ├── output.cpp              # ✓ Output formatting (implemented)
│   ├── packet.cpp              # ★ Packet functions (TODO stubs)
│   ├── port_spec.cpp           # ✓ Port-spec parser (implemented)
│   └── scanner.cpp             # ★ Scan orchestrator (TODO stub)
├── tests/
│   ├── test_helpers.h          # Minimal assertion macros
│   ├── test_args.cpp           # Tests for argument parsing
│   ├── test_output.cpp         # Tests for output formatting
│   └── test_port_spec.cpp      # Tests for port-spec parser
└── docs/                       # (future) Design notes, protocol references
```

**Legend:** ✓ = implemented, ★ = your TODO

---

## Learning Path

Complete the files below **in order**.  Each step builds on the previous one.

### Step 1: `src/packet.cpp` — `build_syn_packet()`

Craft a raw IPv4 + TCP SYN packet from scratch.

**You will learn:**
- IPv4 header layout (RFC 791)
- TCP header layout (RFC 793)
- Network byte order (`htons`, `htonl`)
- IP and TCP checksum algorithms (ones-complement sum)

**Key headers:** `<netinet/ip.h>`, `<netinet/tcp.h>`, `<arpa/inet.h>`

**Test yourself:** Write a test that builds a packet and verifies the IP
version, protocol field, TCP SYN flag, and checksums.

### Step 2: `src/packet.cpp` — `send_packet()`

Transmit your crafted packet using a raw socket.

**You will learn:**
- `socket(AF_INET, SOCK_RAW, IPPROTO_RAW)`
- `IP_HDRINCL` socket option
- `sendto()` with raw buffers
- Linux capability model (`CAP_NET_RAW`)

**Test yourself:** Send a SYN to a known-open port on localhost and capture
it with `tcpdump -i lo`.

### Step 3: `src/packet.cpp` — `receive_responses()`

Listen for SYN-ACK / RST replies.

**You will learn:**
- `socket(AF_INET, SOCK_RAW, IPPROTO_TCP)` for receiving
- `poll()` / `select()` for timeout-based I/O
- Parsing incoming IP + TCP headers
- Distinguishing SYN-ACK (open) vs RST (closed) vs no reply (filtered)

**Test yourself:** Combine send + receive against localhost ports.

### Step 4: `src/scanner.cpp` — `run_scan()`

Wire everything together: resolve the target, send probes, collect replies,
classify ports, return results.

**You will learn:**
- `getaddrinfo()` for DNS resolution
- Scan timing and batching strategies
- Stealth: sending RST after SYN-ACK to avoid completing the handshake

### Step 5 (stretch): Enhancements

- Randomise scan order to reduce IDS detection
- Rate-limiting (token bucket or simple sleep)
- Service name lookup from `/etc/services`
- JSON / XML output modes
- IPv6 support
- Multi-threaded scanning with `std::jthread`

---

## References

- [RFC 791 — Internet Protocol](https://www.rfc-editor.org/rfc/rfc791)
- [RFC 793 — Transmission Control Protocol](https://www.rfc-editor.org/rfc/rfc793)
- [Linux raw(7) man page](https://man7.org/linux/man-pages/man7/raw.7.html)
- [nmap SYN scan documentation](https://nmap.org/book/synscan.html)
- [Beej's Guide to Network Programming](https://beej.us/guide/bgnet/)
