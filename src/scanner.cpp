#include "synscan/scanner.h"
#include "synscan/packet.h"

#include <stdexcept>

namespace synscan {

std::vector<PortResult> run_scan(const ScanConfig& /*config*/) {
    // -----------------------------------------------------------------------
    // TODO(user): Orchestrate the full scan.
    //
    // Suggested implementation:
    //
    //   1. Resolve config.target → IPv4 string using getaddrinfo().
    //   2. For each port in config.ports:
    //        auto pkt = build_syn_packet(ip, port);
    //        send_packet(pkt, ip);
    //      Consider batching: send all probes first, then receive.
    //   3. auto replies = receive_responses(ip, /*timeout_ms=*/2000);
    //   4. Build a map<uint16_t, PortState> from replies:
    //        - is_syn_ack → Open
    //        - !is_syn_ack (RST) → Closed
    //   5. Any port with no reply → Filtered.
    //   6. Convert the map to vector<PortResult> and return.
    //
    // Stretch goals:
    //   • Send RST after receiving SYN-ACK to stay stealthy.
    //   • Retry up to N times for filtered ports.
    //   • Randomise scan order to reduce detection.
    //   • Throttle send rate (e.g. max N packets/sec).
    //   • Resolve service names from /etc/services or getservbyport().
    // -----------------------------------------------------------------------
    throw std::runtime_error("run_scan() not yet implemented — "
                             "complete packet.cpp first, then come back here");
}

} // namespace synscan
