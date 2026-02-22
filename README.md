# cpp-synscan

TCP SYN scanner (`nmap -sS` style) written in C++20.

This is a personal project focused on performance, control over low-level networking, and comparing implementations across languages.

---

## Features

- Raw TCP SYN probing
- Port state classification:
  - `open` (SYN/ACK)
  - `closed` (RST)
  - `filtered` (no response)
- Port ranges and mixed specs (`22,80,443,8000-8100`)
- Deterministic output with service-name lookup from `/etc/services`
- Unit tests for parser, packet logic, and scanner behavior

---

## Requirements

- Linux
- C++20 compiler (`g++` 12+ or `clang++` 15+)
- CMake 3.20+
- Raw socket permissions:
  - `sudo`, or
  - `CAP_NET_RAW` on the binary

Grant capability (recommended over full root execution):

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
│   ├── port_spec.h
│   └── scanner.h
├── src/
│   ├── main.cpp
│   ├── args.cpp
│   ├── output.cpp
│   ├── packet.cpp
│   ├── port_spec.cpp
│   └── scanner.cpp
└── tests/
    ├── test_args.cpp
    ├── test_output.cpp
    ├── test_packet.cpp
    ├── test_port_spec.cpp
    ├── test_scanner.cpp
    └── test_helpers.h
```

---

## Notes

- Use only on systems and networks you own or are explicitly authorized to test.
- Raw-socket behavior can differ across platforms; this implementation targets Linux.
