#include "synscan/scanner.h"
#include "synscan/packet.h"
#include "synscan/platform.h"

#include <netdb.h>

#include <algorithm>
#include <cstring>
#include <ctime>
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

/// Look up /etc/services for a well-known service name (cached).
static const std::string& lookup_service(uint16_t port) {
    // Build the cache once on first call.  65536 entries × small string
    // is cheap and avoids getservbyport() per port in the results loop.
    static const auto cache = []() {
        std::unordered_map<uint16_t, std::string> m;
        m.reserve(1024);
        struct servent* ent;
        setservent(0);
        while ((ent = getservent()) != nullptr) {
            if (std::strcmp(ent->s_proto, "tcp") == 0) {
                uint16_t p = ntohs(static_cast<uint16_t>(ent->s_port));
                m.emplace(p, ent->s_name);
            }
        }
        endservent();
        return m;
    }();
    static const std::string empty;
    auto it = cache.find(port);
    return it != cache.end() ? it->second : empty;
}

std::vector<PortResult> run_scan(const ScanConfig& config) {
    std::string ip = resolve_target(config.target);

    // Determine the source IP the OS would use for this destination.
    std::string src_ip = resolve_source_ip(ip);

    // Pre-parse addresses ONCE to avoid inet_pton() in hot loops.
    uint32_t expected_addr = 0;
    inet_pton(AF_INET, ip.c_str(), &expected_addr);

    uint32_t src_addr = 0;
    inet_pton(AF_INET, src_ip.c_str(), &src_addr);

    uint32_t dst_addr = expected_addr;

    // Pre-build the destination sockaddr_in once.
    struct sockaddr_in dst_sockaddr{};
    dst_sockaddr.sin_family = AF_INET;
    dst_sockaddr.sin_addr.s_addr = dst_addr;

    // Open the receiver socket BEFORE sending any probes.
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
    state_map.reserve(config.ports.size());

    // Helper: drain all currently-available packets without blocking.
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

    // Stack-allocated packet buffer — no heap alloc per packet.
    uint8_t pkt_buf[40];

    constexpr int kMaxRetries = 2;
    constexpr std::size_t kBatchSize = 512;
    constexpr int kBatchPauseUs = 50; // microseconds between batches

    std::vector<uint16_t> pending = config.ports;

    for (int attempt = 0; attempt <= kMaxRetries && !pending.empty();
         ++attempt) {
        // Randomise scan order each round.
        std::shuffle(pending.begin(), pending.end(), rng);

        // Send SYN probes in batches, draining the receive buffer
        // between batches so the kernel's backlog doesn't overflow.
        for (std::size_t i = 0; i < pending.size(); i += kBatchSize) {
            std::size_t end = std::min(i + kBatchSize, pending.size());
            for (std::size_t j = i; j < end; ++j) {
                auto len = build_syn_packet_fast(pkt_buf, src_addr,
                                                  dst_addr, pending[j]);
                if (!send_on_socket(send_fd, pkt_buf, len, dst_sockaddr)) {
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

        // Adaptive timed receive: use shorter initial poll, then extend
        // only if we're still receiving replies.  On localhost most
        // replies arrive within a few ms; we don't need to wait 500ms.
        int max_timeout = (attempt < kMaxRetries) ? 500 : 2000;
        int poll_step = 50; // check in 50ms increments
        // Be more patient on final attempt to catch late stragglers.
        int max_idle = (attempt < kMaxRetries) ? 3 : 6;

        struct timespec t_start{};
        clock_gettime(CLOCK_MONOTONIC, &t_start);

        auto time_elapsed = [&]() -> int {
            struct timespec now{};
            clock_gettime(CLOCK_MONOTONIC, &now);
            return static_cast<int>(
                (now.tv_sec - t_start.tv_sec) * 1000 +
                (now.tv_nsec - t_start.tv_nsec) / 1'000'000);
        };

        std::size_t prev_count = state_map.size();
        int idle_polls = 0;

        while (time_elapsed() < max_timeout) {
            int remaining = max_timeout - time_elapsed();
            int this_timeout = std::min(poll_step, remaining);
            if (this_timeout <= 0) break;

            auto batch = receive_responses(recv_fd, expected_addr,
                                           this_timeout);
            for (const auto& r : batch) {
                state_map[r.source_port] =
                    r.is_syn_ack ? PortState::Open : PortState::Closed;
            }

            if (state_map.size() == prev_count) {
                ++idle_polls;
                if (idle_polls >= max_idle) break;
            } else {
                idle_polls = 0;
                prev_count = state_map.size();
            }
        }

        // Collect ports that still have no response (filtered).
        pending.clear();
        for (uint16_t port : config.ports) {
            if (state_map.find(port) == state_map.end()) {
                pending.push_back(port);
            }
        }
    }

    // Final sweep: if ports remain unresolved after all retries, resend
    // probes one-at-a-time with immediate draining.  This eliminates
    // buffer pressure entirely and reliably recovers ports whose RST
    // responses were dropped from the kernel receive queue during the
    // initial high-speed burst.  Only runs for the (small) set of
    // remaining ports, so the overhead is negligible.
    if (state_map.size() < config.ports.size()) {
        for (uint16_t port : config.ports) {
            if (state_map.find(port) != state_map.end()) continue;
            auto len = build_syn_packet_fast(pkt_buf, src_addr,
                                              dst_addr, port);
            if (send_on_socket(send_fd, pkt_buf, len, dst_sockaddr)) {
                drain_replies();
            }
        }
        // Brief patient wait for the last batch of responses.
        struct pollfd pfd{};
        pfd.fd     = recv_fd;
        pfd.events = POLLIN;
        for (int i = 0; i < 6; ++i) {        // up to 6 × 50 ms = 300 ms
            if (poll(&pfd, 1, 50) <= 0) break;
            drain_replies();
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
