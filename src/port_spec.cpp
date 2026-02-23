#include "synscan/port_spec.h"

#include <algorithm>
#include <charconv>
#include <stdexcept>
#include <string>

namespace synscan {
namespace {

// Parse a single unsigned integer from a string_view.  Throws on failure.
uint16_t parse_u16(std::string_view s) {
    if (s.empty()) {
        throw std::invalid_argument("empty port token");
    }
    uint32_t value = 0;
    auto [ptr, ec] = std::from_chars(s.data(), s.data() + s.size(), value);
    if (ec != std::errc{} || ptr != s.data() + s.size()) {
        throw std::invalid_argument(
            "invalid port number: '" + std::string(s) + "'");
    }
    if (value == 0 || value > 65535) {
        throw std::invalid_argument(
            "port out of range [1-65535]: " + std::to_string(value));
    }
    return static_cast<uint16_t>(value);
}

} // anonymous namespace

std::vector<uint16_t> parse_port_spec(std::string_view spec) {
    if (spec.empty()) {
        throw std::invalid_argument("port spec must not be empty");
    }

    // "-" means all ports (1-65535), like nmap's -p-
    if (spec == "-") {
        std::vector<uint16_t> ports(65535);
        for (uint32_t p = 1; p <= 65535; ++p) {
            ports[p - 1] = static_cast<uint16_t>(p);
        }
        return ports;
    }

    if (spec.front() == ',' || spec.back() == ',') {
        throw std::invalid_argument("invalid port list: leading/trailing comma");
    }

    std::vector<uint16_t> ports;

    // Split on commas, then handle ranges within each token.
    while (!spec.empty()) {
        // Find next comma (or end of string).
        auto comma = spec.find(',');
        auto token = spec.substr(0, comma);
        spec = (comma == std::string_view::npos)
                   ? std::string_view{}
                   : spec.substr(comma + 1);

        // Check for a range (dash).
        auto dash = token.find('-');
        if (dash == std::string_view::npos) {
            // Single port.
            ports.push_back(parse_u16(token));
        } else {
            // Range: start-end (inclusive).
            auto start = parse_u16(token.substr(0, dash));
            auto end   = parse_u16(token.substr(dash + 1));
            if (start > end) {
                throw std::invalid_argument(
                    "inverted range: " + std::to_string(start) + "-" +
                    std::to_string(end));
            }
            for (uint32_t p = start; p <= end; ++p) {
                ports.push_back(static_cast<uint16_t>(p));
            }
        }
    }

    // Sort and deduplicate.
    std::sort(ports.begin(), ports.end());
    ports.erase(std::unique(ports.begin(), ports.end()), ports.end());

    return ports;
}

} // namespace synscan
