#include "synscan/output.h"

#include <iomanip>
#include <iostream>

namespace synscan {

std::string_view port_state_label(PortState state) {
    switch (state) {
        case PortState::Open:     return "open";
        case PortState::Closed:   return "closed";
        case PortState::Filtered: return "filtered";
        case PortState::Unknown:  return "unknown";
    }
    return "unknown"; // unreachable, but silences warnings
}

void print_header(std::ostream& os) {
    os << std::left
       << std::setw(10) << "PORT"
       << std::setw(12) << "STATE"
       << "SERVICE\n";
}

void print_result(std::ostream& os, const PortResult& result) {
    // Format port as "80/tcp" (we only do TCP SYN scanning).
    std::string port_str = std::to_string(result.port) + "/tcp";

    os << std::left
       << std::setw(10) << port_str
       << std::setw(12) << port_state_label(result.state)
       << (result.service.empty() ? "-" : result.service)
       << '\n';
}

void print_results(std::ostream& os, const std::vector<PortResult>& results) {
    print_header(os);
    for (const auto& r : results) {
        print_result(os, r);
    }
    os << "\n" << results.size() << " port(s) scanned.\n";
}

} // namespace synscan
