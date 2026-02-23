#pragma once
// ---------------------------------------------------------------------------
// packet.h — Raw-packet crafting, sending, and receiving
//
// This is the heart of the SYN scanner.  Functions provided:
//
//   1. build_syn_packet()  — construct a raw TCP SYN segment inside an
//                            IPv4 datagram, computing the IP and TCP
//                            checksums correctly.
//
//   2. open_sender() / send_on_socket()
//                          — open a raw send socket once and reuse it
//                            for all probes.  Requires CAP_NET_RAW or root.
//
//   3. open_receiver()     — create a raw socket for capturing TCP replies.
//                            Must be called BEFORE sending probes so that
//                            fast responses (e.g. localhost) are not lost.
//
//   4. receive_responses() — read TCP replies from an already-open receiver
//                            socket and return only those that match our
//                            target (SYN-ACK or RST).
//
// Recommended reading:
//   • RFC 793  — TCP specification
//   • RFC 791  — IP specification
//   • Linux raw(7) man page
//   • netinet/ip.h and netinet/tcp.h system headers
// ---------------------------------------------------------------------------

#include <cstdint>
#include <netinet/in.h>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace synscan {

// ---- Data types -----------------------------------------------------------

/// Raw bytes of a network packet.
using RawPacket = std::vector<uint8_t>;

/// A reply captured from the wire.
struct ProbeReply {
    uint16_t source_port;   // the remote port that replied
    bool     is_syn_ack;    // true → port open;  false → RST (closed)
};

// ---- Testable helpers (no sockets needed) ---------------------------------

/// Internet checksum (RFC 1071): ones-complement sum over `data`.
[[nodiscard]] uint16_t ip_checksum(const void* data, std::size_t len);

/// Determine the local source IP the OS would use to reach `dst_ip`.
/// Uses a connected UDP socket + getsockname (no traffic sent).
[[nodiscard]] std::string resolve_source_ip(std::string_view dst_ip);

/// Parse a raw IP+TCP packet and extract a ProbeReply if the packet
/// originates from `expected_src_ip` and contains SYN-ACK or RST.
/// Returns std::nullopt for non-matching or malformed packets.
[[nodiscard]] std::optional<ProbeReply> parse_reply(
    std::span<const uint8_t> raw,
    std::string_view expected_src_ip);

/// Fast overload: takes a pre-parsed network-order IPv4 address to avoid
/// repeated inet_pton() calls in hot loops (critical for 65K-port scans).
[[nodiscard]] std::optional<ProbeReply> parse_reply(
    std::span<const uint8_t> raw,
    uint32_t expected_src_addr);

// ---- Core packet functions ------------------------------------------------

/// Build a raw IPv4/TCP SYN packet targeting `dst_ip:dst_port`.
/// Uses `src_ip` as the source address for correct TCP checksumming.
/// Uses a random ephemeral source port (49152-65535).
[[nodiscard]] RawPacket build_syn_packet(std::string_view dst_ip,
                                         uint16_t dst_port,
                                         std::string_view src_ip);

/// Fast overload: build a SYN packet into a caller-supplied buffer using
/// pre-parsed network-order addresses.  Avoids heap allocation and
/// inet_pton() per packet (critical for 65K-port scans).
/// `buf` must point to at least 40 bytes.  Returns 40 (packet size).
std::size_t build_syn_packet_fast(uint8_t* buf,
                                   uint32_t src_addr, uint32_t dst_addr,
                                   uint16_t dst_port);

/// Open a raw socket suitable for sending SYN packets.
/// On Linux: IPPROTO_RAW + IP_HDRINCL.
/// On macOS: IPPROTO_TCP (kernel builds IP header for loopback).
/// Returns the file descriptor, or -1 on failure.
[[nodiscard]] int open_sender();

/// Send a pre-built raw packet on an already-open send socket.
/// Returns true on success.
[[nodiscard]] bool send_on_socket(int send_fd, const RawPacket& packet,
                                   std::string_view dst_ip);

/// Fast overload: send using a pre-built sockaddr_in (avoids inet_pton
/// per packet).
[[nodiscard]] bool send_on_socket(int send_fd, const uint8_t* data,
                                   std::size_t len,
                                   const ::sockaddr_in& addr);

/// Open a receiver for capturing TCP packets.
/// On Linux: a raw socket (AF_INET, SOCK_RAW, IPPROTO_TCP).
/// On macOS: a BPF device bound to the interface for `dst_ip`.
/// Must be called BEFORE sending probes to avoid missing fast replies.
/// Returns the file descriptor, or -1 on failure.
[[nodiscard]] int open_receiver(std::string_view dst_ip);

/// Read TCP replies from an already-open receiver fd for up to
/// `timeout_ms` milliseconds.  `expected_src_ip` filters by source.
/// The caller is responsible for closing `recv_fd` afterward.
[[nodiscard]] std::vector<ProbeReply> receive_responses(
    int recv_fd,
    std::string_view expected_src_ip,
    int timeout_ms);

/// Fast overload: takes pre-parsed address to avoid inet_pton per packet.
[[nodiscard]] std::vector<ProbeReply> receive_responses(
    int recv_fd,
    uint32_t expected_src_addr,
    int timeout_ms);

} // namespace synscan
