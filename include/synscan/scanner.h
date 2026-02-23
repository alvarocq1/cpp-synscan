#pragma once
// ---------------------------------------------------------------------------
// scanner.h — High-level scan orchestrator (TODO)
//
// Ties together argument parsing, packet crafting, sending, receiving, and
// output formatting into a single "run a scan" entry point.
//
// The user should implement run_scan() once the packet module is ready.
// ---------------------------------------------------------------------------

#include "synscan/args.h"
#include "synscan/output.h"

#include <vector>

namespace synscan {

/// Execute a full SYN scan according to `config`.
///
/// TODO(user): Implement the scan loop:
///   1. Resolve config.target to an IPv4 address (use getaddrinfo).
///   2. For each port in config.ports:
///        a. build_syn_packet(ip, port)
///        b. send_on_socket(send_fd, packet, ip)
///      (Batch sends for speed, then collect replies.)
///   3. receive_responses(ip, timeout) to gather replies.
///   4. Classify each port:
///        - Got SYN-ACK → Open
///        - Got RST      → Closed
///        - No reply      → Filtered
///   5. Return the results.
///
/// Stretch goals:
///   • Send a RST after receiving SYN-ACK (stealth — don't complete the
///     handshake, just like nmap -sS).
///   • Retry ports that got no reply.
///   • Randomise the scan order.
///   • Rate-limit sends to avoid flooding.
[[nodiscard]] std::vector<PortResult> run_scan(const ScanConfig& config);

} // namespace synscan
