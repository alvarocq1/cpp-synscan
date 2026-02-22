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
| Raw socket send (`IPPROTO_RAW`) | Yes | Yes (root) | — |
| Raw socket receive (`IPPROTO_TCP`) | Yes | Yes (root) | — |
| Source IP resolution (UDP trick) | Yes | Yes | — |
| Service name lookup (`/etc/services`) | Yes | Yes | — |
| Capability grant (`setcap`) | Yes | N/A | — |

**Linux**: Full support. Grant `CAP_NET_RAW` or run as root.

**macOS**: Full support. Requires root (`sudo`). No capability-based permission model — macOS raw sockets require superuser. Header construction uses portable byte writes (no Linux-specific `struct iphdr`/`struct tcphdr` overlays).

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
sudo ./build/synscan -p 22,53,80,443 127.0.0.1
```

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

Rather than `#ifdef`-branching every socket call, the codebase uses a two-layer approach:

1. **`platform.h`** — Detects the OS at compile time (`SYNSCAN_LINUX`, `SYNSCAN_MACOS`), includes the correct POSIX headers, and blocks unsupported platforms with `#error`.

2. **Portable byte writes** — `build_syn_packet()` and `parse_reply()` operate on raw byte arrays at RFC-defined offsets instead of overlaying platform-specific structs (`struct iphdr` on Linux vs `struct ip` on BSD). This eliminates the most common source of Linux/macOS incompatibility in raw-socket code.

The POSIX socket API (`socket()`, `sendto()`, `recv()`, `poll()`, `connect()`, `getsockname()`) is identical on both platforms.

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
