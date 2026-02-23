#pragma once
// ---------------------------------------------------------------------------
// platform.h — Platform detection and cross-platform compatibility
//
// Abstracts the differences between Linux and macOS/BSD raw-socket APIs
// so the rest of the codebase can use a single set of conventions.
//
// Linux uses struct iphdr / struct tcphdr with GNU-specific field names.
// macOS/BSD uses struct ip / struct tcphdr with different field names and
// a flags bitmask instead of individual bitfields.
//
// Rather than wrapping every struct access, this header provides:
//   1.  Platform detection macros (SYNSCAN_LINUX, SYNSCAN_MACOS, etc.)
//   2.  A compile-time gate that blocks unsupported platforms.
// ---------------------------------------------------------------------------

// ---- Platform detection ---------------------------------------------------

#if defined(__linux__)
#   define SYNSCAN_LINUX 1
#elif defined(__APPLE__) && defined(__MACH__)
#   define SYNSCAN_MACOS 1
#elif defined(_WIN32) || defined(_WIN64)
#   define SYNSCAN_WINDOWS 1
#else
#   define SYNSCAN_UNKNOWN_PLATFORM 1
#endif

// ---- Windows: explicit compile-time rejection -----------------------------
//
// Full Windows support would require Npcap/WinPcap or raw Winsock2, which is
// a fundamentally different API surface.  Rather than shipping broken stubs,
// we fail early with a clear message and leave architecture hooks for future
// work.

#ifdef SYNSCAN_WINDOWS
#   error "Windows is not yet supported.  Raw-socket SYN scanning requires " \
          "Npcap or WinPcap — see README for the cross-platform status "     \
          "matrix and architecture notes for future contributors."
#endif

#ifdef SYNSCAN_UNKNOWN_PLATFORM
#   error "Unsupported platform.  cpp-synscan currently targets Linux and "  \
          "macOS only."
#endif

// ---- Common POSIX headers (Linux + macOS) ---------------------------------

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <poll.h>

// ---- Platform-specific raw-socket headers ---------------------------------

#ifdef SYNSCAN_LINUX
#   include <netinet/ip.h>
#   include <netinet/tcp.h>
#   include <linux/filter.h>
#endif

#ifdef SYNSCAN_MACOS
#   include <netinet/ip.h>
#   include <netinet/tcp.h>
#   include <net/bpf.h>
#   include <net/if.h>
#   include <sys/ioctl.h>
#   include <fcntl.h>
#   include <ifaddrs.h>
//  macOS note: IPPROTO_RAW does not transmit packets on the loopback
//  interface.  We use IPPROTO_TCP + IP_HDRINCL for sending and BPF
//  (Berkeley Packet Filter) for receiving — the same approach nmap/libpcap
//  uses on macOS.
#endif
