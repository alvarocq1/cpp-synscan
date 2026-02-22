#include "synscan/scanner.h"
#include "synscan/packet.h"
#include "synscan/platform.h"

#include <netdb.h>

#include <algorithm>
#include <cstring>
#include <random>
#include <stdexcept>
#include <string>
#include <unordered_map>

namespace synscan {

/// Resolve a hostname or IP string to a dotted-quad IPv4 address.
static std::string resolve_target(const std::string& target) {
    struct addrinfo hints{};
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_RAW;

    struct addrinfo* res = nullptr;
    int err = getaddrinfo(target.c_str(), nullptr, &hints, &res);
    if (err != 0 || res == nullptr) {
        throw std::runtime_error("cannot resolve target '" + target +
                                 "': " + gai_strerror(err));
    }

    char ip_str[INET_ADDRSTRLEN];
    auto* sa = reinterpret_cast<struct sockaddr_in*>(res->ai_addr);
    inet_ntop(AF_INET, &sa->sin_addr, ip_str, sizeof(ip_str));

    freeaddrinfo(res);
    return ip_str;
}

/// Look up /etc/services for a well-known service name.
static std::string lookup_service(uint16_t port) {
    auto* ent = getservbyport(htons(port), "tcp");
    return ent ? ent->s_name : "";
}

std::vector<PortResult> run_scan(const ScanConfig& config) {
    std::string ip = resolve_target(config.target);

    // Determine the source IP the OS would use for this destination.
    std::string src_ip = resolve_source_ip(ip);

    // Open the receiver socket BEFORE sending any probes.
    // On localhost, responses arrive in microseconds — if we open the
    // socket after sending, we miss them and every port looks "filtered".
    int recv_fd = open_receiver();
    if (recv_fd < 0) {
        throw std::runtime_error(
            "cannot open raw receive socket — "
            "do you have CAP_NET_RAW or root?");
    }

    // Randomise scan order to reduce detection signatures.
    std::vector<uint16_t> ports = config.ports;
    {
        std::mt19937 rng{std::random_device{}()};
        std::shuffle(ports.begin(), ports.end(), rng);
    }

    // Batch-send all SYN probes.
    for (uint16_t port : ports) {
        auto pkt = build_syn_packet(ip, port, src_ip);
        if (!send_packet(pkt, ip)) {
            close(recv_fd);
            throw std::runtime_error(
                "send_packet failed — do you have CAP_NET_RAW or root?");
        }
    }

    // Collect replies from the already-listening socket.
    auto replies = receive_responses(recv_fd, ip, /*timeout_ms=*/2000);
    close(recv_fd);

    // Classify ports from replies.
    std::unordered_map<uint16_t, PortState> state_map;
    for (const auto& r : replies) {
        state_map[r.source_port] =
            r.is_syn_ack ? PortState::Open : PortState::Closed;
    }

    // Build results for every requested port (sorted by port number).
    std::vector<uint16_t> sorted_ports = config.ports; // already sorted
    std::vector<PortResult> results;
    results.reserve(sorted_ports.size());

    for (uint16_t port : sorted_ports) {
        PortState st = PortState::Filtered; // default: no reply
        if (auto it = state_map.find(port); it != state_map.end()) {
            st = it->second;
        }
        results.push_back({port, st, lookup_service(port)});
    }

    return results;
}

} // namespace synscan
