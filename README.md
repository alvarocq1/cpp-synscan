# cpp-synscan

TCP SYN scanner (`nmap -sS` style) written in C++20.

A personal project for learning low-level networking, raw-socket programming, and comparing implementations across languages and platforms. Not intended as a production tool — the goal is understanding how SYN scanning works at the packet level.

---

## Features

- Raw TCP SYN probing with hand-crafted IPv4/TCP headers
- Port state classification:
  - `open` (SYN/ACK)
  - `closed` (RST)
  - `filtered` (no response)
- Port ranges and mixed specs (`22,80,443,8000-8100`)
- Deterministic output with service-name lookup from `/etc/services`
- Unit tests for parser, packet logic, and scanner behavior
- Cross-platform: Linux and macOS (see status matrix below)

---

## Cross-Platform Status

| Feature | Linux | macOS | Windows |
|---|---|---|---|
| Build + unit tests | Yes | Yes | No |
| Raw packet crafting | Yes | Yes | — |
| Send SYN probes | Yes (`IPPROTO_RAW`) | Yes (`IPPROTO_TCP`, root) | — |
| Receive responses | Yes (raw socket) | Yes (BPF, root) | — |
| Source IP resolution (UDP trick) | Yes | Yes | — |
| Service name lookup (`/etc/services`) | Yes | Yes | — |
| Capability grant (`setcap`) | Yes | N/A | — |
| Loopback scanning (`127.0.0.1`) | Yes | Yes | — |

**Linux**: Full support. Grant `CAP_NET_RAW` or run as root. Sends via `IPPROTO_RAW` + `IP_HDRINCL`; receives via raw `IPPROTO_TCP` socket.

**macOS**: Full support. Requires root (`sudo`). macOS raw sockets differ from Linux in several ways:
- `IPPROTO_RAW` silently drops packets on loopback (and often on physical interfaces).
- `IP_HDRINCL` with any protocol also fails silently on loopback.
- Raw `IPPROTO_TCP` sockets do not deliver loopback TCP packets.

The macOS backend therefore uses:
- **Send**: `IPPROTO_TCP` raw socket *without* `IP_HDRINCL` — the kernel builds the IP header; we supply only the TCP segment.
- **Receive**: BPF (`/dev/bpfN`) bound to the correct interface (`lo0` for loopback, auto-detected for other destinations). This is the same mechanism nmap/libpcap uses on macOS.

**Windows**: Not supported. Raw-socket SYN scanning on Windows requires Npcap or WinPcap, which is a fundamentally different API surface. CMake will fail at configure time with a clear message. Architecture hooks (`platform.h`) are in place for future contributors.

---

## Requirements

- Linux or macOS
- C++20 compiler (`g++` 12+ or `clang++` 15+)
- CMake 3.20+
- Raw socket permissions:
  - **Linux**: `sudo`, or `CAP_NET_RAW` on the binary
  - **macOS**: `sudo`

Grant capability (Linux only, recommended over full root execution):

```bash
sudo setcap cap_net_raw=eip build/synscan
```

---

## Build

```bash
cmake -S . -B build
cmake --build build -j
```

## Test

```bash
ctest --test-dir build --output-on-failure
```

## Run

```bash
# Linux (with CAP_NET_RAW or root)
sudo ./build/synscan -p 22,53,80,443 127.0.0.1

# macOS (requires root)
sudo ./build/synscan -p 22,53,80,443 127.0.0.1
```

### macOS-specific notes

- Always run with `sudo` — there is no capability-based alternative on macOS.
- The scanner uses BPF for packet capture, which requires `/dev/bpf*` access (root).
- Loopback scanning works. The scanner auto-detects the correct interface (`lo0` for `127.0.0.0/8`, the LAN interface for other targets).

### Known limitations

- **Single-target only**: scans one IPv4 address per invocation (no CIDR ranges).
- **IPv4 only**: no IPv6 support.
- **No retry logic**: ports that don't respond within the 2-second timeout are marked "filtered".
- **macOS Ethernet scanning**: the Ethernet BPF filter path is implemented but less tested than loopback. External-host scanning may require firewall configuration.

---

## Project Layout

```text
cpp-synscan/
├── CMakeLists.txt
├── include/synscan/
│   ├── args.h
│   ├── output.h
│   ├── packet.h
│   ├── platform.h          ← platform detection + cross-platform headers
│   ├── port_spec.h
│   └── scanner.h
├── src/
│   ├── main.cpp
│   ├── args.cpp
│   ├── output.cpp
│   ├── packet.cpp           ← portable byte-level packet crafting
│   ├── port_spec.cpp
│   └── scanner.cpp
└── tests/
    ├── test_args.cpp
    ├── test_output.cpp
    ├── test_packet.cpp      ← portable byte-level assertions
    ├── test_port_spec.cpp
    ├── test_scanner.cpp
    └── test_helpers.h
```

---

## Architecture Notes

### Platform abstraction strategy

The codebase uses a three-layer approach:

1. **`platform.h`** — Detects the OS at compile time (`SYNSCAN_LINUX`, `SYNSCAN_MACOS`), includes the correct POSIX and platform-specific headers (BPF on macOS), and blocks unsupported platforms with `#error`.

2. **Portable byte writes** — `build_syn_packet()` and `parse_reply()` operate on raw byte arrays at RFC-defined offsets instead of overlaying platform-specific structs (`struct iphdr` on Linux vs `struct ip` on BSD). This eliminates the most common source of Linux/macOS incompatibility in raw-socket code.

3. **Platform-specific I/O** — `send_packet()`, `open_receiver()`, and `receive_responses()` use `#ifdef SYNSCAN_MACOS` to select the correct send/receive mechanism. Linux uses raw sockets; macOS uses raw TCP sockets (send) and BPF (receive).

### Future: Windows support

Windows raw sockets (`Winsock2`) do not allow sending TCP SYN packets. A Windows implementation would need:
- Npcap/WinPcap for packet injection and capture
- `Packet.dll` or the Npcap SDK instead of `socket(AF_INET, SOCK_RAW, ...)`
- A separate send/receive backend behind the platform abstraction

The `platform.h` header already defines `SYNSCAN_WINDOWS` and provides a clear `#error` — a future contributor can gate a Npcap backend behind that macro.

---

## Notes

- Use only on systems and networks you own or are explicitly authorized to test.
- This is a personal learning project — emphasis is on understanding raw sockets and packet mechanics, not on being a complete scanning tool.
