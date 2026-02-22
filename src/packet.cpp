#include "synscan/packet.h"

#include <stdexcept>

// ---------------------------------------------------------------------------
// packet.cpp — PLACEHOLDER implementations
//
// Every function here throws "not implemented" so the project compiles and
// links, but the real work is left for the user.  Search for TODO(user) in
// the header (include/synscan/packet.h) for detailed guidance.
// ---------------------------------------------------------------------------

namespace synscan {

RawPacket build_syn_packet(std::string_view /*dst_ip*/,
                            uint16_t /*dst_port*/) {
    // -----------------------------------------------------------------------
    // TODO(user): Build a 40-byte raw packet (20 IP + 20 TCP, no options).
    //
    // Step-by-step:
    //   1. Allocate a vector<uint8_t> of size 40.
    //   2. Fill in the IPv4 header fields:
    //        - version=4, ihl=5, total_length=40, ttl=64
    //        - protocol=6 (TCP)
    //        - source address = your local IP (or 0 — kernel fills it
    //          if IP_HDRINCL is set and src is 0.0.0.0 on some systems)
    //        - destination address = dst_ip parsed with inet_pton()
    //        - compute IP header checksum (ones-complement sum)
    //   3. Fill in the TCP header fields:
    //        - source port = random ephemeral port (49152–65535)
    //        - destination port = dst_port
    //        - sequence number = random uint32
    //        - data offset = 5 (no options), flags = SYN (0x02)
    //        - window = htons(65535)
    //        - compute TCP checksum over the pseudo-header + TCP header
    //   4. Return the packet.
    //
    // Useful headers: <netinet/ip.h>, <netinet/tcp.h>, <arpa/inet.h>
    // -----------------------------------------------------------------------
    throw std::runtime_error("build_syn_packet() not yet implemented — "
                             "see include/synscan/packet.h for instructions");
}

bool send_packet(const RawPacket& /*packet*/,
                  std::string_view /*dst_ip*/) {
    // -----------------------------------------------------------------------
    // TODO(user): Transmit a raw packet.
    //
    //   1. int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    //   2. int on = 1; setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));
    //   3. Build a sockaddr_in with dst_ip and port 0.
    //   4. sendto(fd, packet.data(), packet.size(), 0, ...);
    //   5. close(fd);
    //   6. Return true on success.
    //
    // Remember to check every syscall return value!
    // -----------------------------------------------------------------------
    throw std::runtime_error("send_packet() not yet implemented — "
                             "see include/synscan/packet.h for instructions");
}

std::vector<ProbeReply> receive_responses(
    std::string_view /*expected_src_ip*/,
    int /*timeout_ms*/) {
    // -----------------------------------------------------------------------
    // TODO(user): Listen for TCP replies.
    //
    //   1. int fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    //   2. Use poll() with the given timeout.
    //   3. On each readable event, recv() the packet.
    //   4. Parse the IP header to check source address matches expected_src_ip.
    //   5. Parse the TCP header:
    //        - SYN+ACK flags (0x12) → port is open
    //        - RST flag (0x04)      → port is closed
    //   6. Collect results into a vector<ProbeReply>.
    //   7. close(fd) and return.
    //
    // Tip: Set a total deadline (e.g. clock_gettime + timeout_ms) and
    //      subtract elapsed time from each poll() call.
    // -----------------------------------------------------------------------
    throw std::runtime_error("receive_responses() not yet implemented — "
                             "see include/synscan/packet.h for instructions");
}

} // namespace synscan
