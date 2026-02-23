#pragma once
// ---------------------------------------------------------------------------
// output.h — Scan result formatting
//
// Provides simple helpers to format per-port scan results in a style similar
// to nmap's table output:
//
//   PORT     STATE    SERVICE
//   22/tcp   open     ssh
//   80/tcp   open     http
//   443/tcp  closed   https
//
// The user can later extend this with JSON / XML output, colour support, etc.
// ---------------------------------------------------------------------------

#include <cstdint>
#include <iosfwd>
#include <string>
#include <string_view>
#include <vector>

namespace synscan {

/// Possible states a port can be in after scanning.
enum class PortState {
    Open,
    Closed,
    Filtered,
    Unknown,
};

/// Human-readable label for a port state.
[[nodiscard]] std::string_view port_state_label(PortState state);

/// Single scan result for one port.
struct PortResult {
    uint16_t port;
    PortState state;
    std::string service; // e.g. "http" — can be empty if unknown
};

/// Print the header row.
void print_header(std::ostream& os);

/// Print one result row.
void print_result(std::ostream& os, const PortResult& result);

/// Print a full table (header + all rows + timing).
/// When filter_closed is true, closed ports are omitted from the output.
void print_results(std::ostream& os, const std::vector<PortResult>& results,
                   double elapsed_seconds, bool filter_closed = false);

} // namespace synscan
