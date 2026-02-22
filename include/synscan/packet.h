#pragma once
// ---------------------------------------------------------------------------
// packet.h — Raw-packet crafting, sending, and receiving (TODO)
//
// This is the heart of the SYN scanner.  The user must implement:
//
//   1. build_syn_packet()  — construct a raw TCP SYN segment inside an
//                            IPv4 datagram, computing the IP and TCP
//                            checksums correctly.
//
//   2. send_packet()       — open a raw socket (AF_INET, SOCK_RAW,
//                            IPPROTO_RAW) and transmit the packet.
//                            Requires CAP_NET_RAW or root.
//
//   3. receive_responses() — listen on a raw socket for incoming TCP
//                            packets and return only those that are
//                            replies to our probes (SYN-ACK or RST).
//
// Recommended reading before implementing:
//   • RFC 793  — TCP specification
//   • RFC 791  — IP specification
//   • Linux raw(7) man page
//   • netinet/ip.h and netinet/tcp.h system headers
// ---------------------------------------------------------------------------

#include <cstdint>
#include <span>
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

// ---- Functions the user should implement ----------------------------------

/// Build a raw IPv4/TCP SYN packet targeting `dst_ip:dst_port`.
///
/// TODO(user): Fill in the IP header (version, IHL, total length, TTL,
///             protocol, checksum, src/dst addresses) and the TCP header
///             (src port, dst port, seq number, SYN flag, window, checksum).
///
/// Hint: Use a random ephemeral source port (49152-65535).
///       The TCP checksum covers a pseudo-header — don't forget it!
[[nodiscard]] RawPacket build_syn_packet(std::string_view dst_ip,
                                         uint16_t dst_port);

/// Send a pre-built raw packet to the network.
///
/// TODO(user): Create a raw socket with socket(AF_INET, SOCK_RAW, IPPROTO_RAW),
///             set IP_HDRINCL, and call sendto().
///
/// Returns true on success.
[[nodiscard]] bool send_packet(const RawPacket& packet,
                                std::string_view dst_ip);

/// Listen for TCP replies for up to `timeout_ms` milliseconds.
///
/// TODO(user): Open a raw socket bound to IPPROTO_TCP, use poll()/select()
///             to wait for incoming packets, parse IP+TCP headers, and
///             filter for replies that match our scan (check source IP and
///             that the destination port matches one of our ephemeral
///             source ports).
///
/// `expected_src_ip` is the target we're scanning — ignore packets from
/// other hosts.
[[nodiscard]] std::vector<ProbeReply> receive_responses(
    std::string_view expected_src_ip,
    int timeout_ms);

} // namespace synscan
