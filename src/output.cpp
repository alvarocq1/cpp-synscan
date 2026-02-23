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

void print_results(std::ostream& os, const std::vector<PortResult>& results,
                   double elapsed_seconds) {
    // Count non-open ports to decide whether to filter output.
    std::size_t closed_count = 0;
    std::size_t filtered_count = 0;
    for (const auto& r : results) {
        if (r.state == PortState::Closed)        ++closed_count;
        else if (r.state == PortState::Filtered) ++filtered_count;
    }

    // When scanning many ports, only show open ports (like nmap).
    bool filter = results.size() > 100;

    // Summary of hidden ports (before the table).
    if (filter && (closed_count > 0 || filtered_count > 0)) {
        os << "Not shown: ";
        bool need_comma = false;
        if (closed_count > 0) {
            os << closed_count << " closed";
            need_comma = true;
        }
        if (filtered_count > 0) {
            if (need_comma) os << ", ";
            os << filtered_count << " filtered";
        }
        os << "\n";
    }

    print_header(os);
    for (const auto& r : results) {
        if (filter && r.state != PortState::Open) continue;
        print_result(os, r);
    }
    os << "\n" << results.size() << " port(s) scanned in "
       << std::fixed << std::setprecision(2) << elapsed_seconds << "s\n";
}

} // namespace synscan
