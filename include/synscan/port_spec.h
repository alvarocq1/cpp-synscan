#pragma once
// ---------------------------------------------------------------------------
// port_spec.h — Port specification parser
//
// Converts nmap-style port strings into a sorted, deduplicated vector of
// port numbers.  Supported formats:
//
//   "80"          → single port
//   "20-25"       → inclusive range
//   "80,443"      → comma-separated list
//   "22,80-85,443" → mixed
//
// Ports must be in [1, 65535].  Invalid input throws std::invalid_argument.
// ---------------------------------------------------------------------------

#include <cstdint>
#include <string_view>
#include <vector>

namespace synscan {

/// Parse an nmap-style port specification string into a sorted, unique list.
/// Throws std::invalid_argument on bad input (port 0, inverted range, etc.).
[[nodiscard]] std::vector<uint16_t> parse_port_spec(std::string_view spec);

} // namespace synscan
