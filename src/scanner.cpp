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
#include <cstdio>

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

    // Pre-parse the expected source address to avoid per-packet inet_pton()
    // in the hot drain loop (~65K calls for a full-range scan).
    uint32_t expected_addr = 0;
    inet_pton(AF_INET, ip.c_str(), &expected_addr);

    // Open the receiver socket BEFORE sending any probes.
    // On localhost, responses arrive in microseconds — if we open the
    // socket after sending, we miss them and every port looks "filtered".
    int recv_fd = open_receiver(ip);
    if (recv_fd < 0) {
        throw std::runtime_error(
            "cannot open raw receive socket — "
            "do you have CAP_NET_RAW or root?");
    }

    // Open a single send socket (reused for all probes).
    int send_fd = open_sender();
    if (send_fd < 0) {
        close(recv_fd);
        throw std::runtime_error(
            "cannot open raw send socket — "
            "do you have CAP_NET_RAW or root?");
    }

    // Classify replies into a state map as they arrive.
    std::unordered_map<uint16_t, PortState> state_map;

    // Helper: drain all currently-available packets without blocking.
    // Uses pre-parsed address to avoid inet_pton() per packet.
    auto drain_replies = [&]() {
        uint8_t buf[65536];
        for (;;) {
            auto n = recv(recv_fd, buf, sizeof(buf), MSG_DONTWAIT);
            if (n < 0) break;
            if (n < 40) continue;
            auto reply = parse_reply(
                std::span<const uint8_t>(buf, static_cast<std::size_t>(n)),
                expected_addr);
            if (reply) {
                state_map[reply->source_port] =
                    reply->is_syn_ack ? PortState::Open : PortState::Closed;
            }
        }
    };

    std::mt19937 rng{std::random_device{}()};

    // Retry loop: on localhost, the kernel's network backlog queue can
    // overflow when we blast 65K+ SYN packets at full speed, causing
    // responses to be silently dropped.  Re-probing "filtered" ports
    // recovers these losses reliably.
    constexpr int kMaxRetries = 2;
    constexpr std::size_t kBatchSize = 256;
    constexpr int kBatchPauseUs = 100; // microseconds between batches

    std::vector<uint16_t> pending = config.ports;

    for (int attempt = 0; attempt <= kMaxRetries && !pending.empty();
         ++attempt) {
        // Randomise scan order each round.
        std::shuffle(pending.begin(), pending.end(), rng);

        // Send SYN probes in small batches, draining the receive buffer
        // and yielding briefly between batches so the kernel's softirq
        // can process loopback responses before the backlog overflows.
        for (std::size_t i = 0; i < pending.size(); i += kBatchSize) {
            std::size_t end = std::min(i + kBatchSize, pending.size());
            for (std::size_t j = i; j < end; ++j) {
                auto pkt = build_syn_packet(ip, pending[j], src_ip);
                if (!send_on_socket(send_fd, pkt, ip)) {
                    close(send_fd);
                    close(recv_fd);
                    throw std::runtime_error(
                        "send_packet failed — "
                        "do you have CAP_NET_RAW or root?");
                }
            }
            drain_replies();
            if (i + kBatchSize < pending.size()) {
                usleep(kBatchPauseUs);
            }
        }

        // Timed receive to catch stragglers.  Use a shorter timeout for
        // intermediate rounds; the final round gets the full timeout so
        // remote (non-localhost) hosts with real latency are handled.
        int timeout = (attempt < kMaxRetries) ? 500 : 2000;
        auto replies = receive_responses(recv_fd, ip, timeout);
        for (const auto& r : replies) {
            state_map[r.source_port] =
                r.is_syn_ack ? PortState::Open : PortState::Closed;
        }

        // Collect ports that still have no response (filtered).
        pending.clear();
        for (uint16_t port : config.ports) {
            if (state_map.find(port) == state_map.end()) {
                pending.push_back(port);
            }
        }
    }

    close(send_fd);
    close(recv_fd);

    // Build results for every requested port (sorted by port number).
    std::vector<PortResult> results;
    results.reserve(config.ports.size());

    for (uint16_t port : config.ports) {
        PortState st = PortState::Filtered; // default: no reply
        if (auto it = state_map.find(port); it != state_map.end()) {
            st = it->second;
        }
        results.push_back({port, st, lookup_service(port)});
    }

    return results;
}

} // namespace synscan
