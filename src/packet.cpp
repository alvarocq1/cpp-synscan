#include "synscan/packet.h"

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>
#include <ctime>
#include <random>
#include <stdexcept>
#include <string>

namespace synscan {

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

uint16_t ip_checksum(const void* data, std::size_t len) {
    auto* p = static_cast<const uint8_t*>(data);
    uint32_t sum = 0;
    for (std::size_t i = 0; i + 1 < len; i += 2) {
        sum += static_cast<uint16_t>(p[i] << 8 | p[i + 1]);
    }
    if (len & 1) {
        sum += static_cast<uint16_t>(p[len - 1] << 8);
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return static_cast<uint16_t>(~sum & 0xFFFF);
}

static uint16_t rand_u16(uint16_t lo, uint16_t hi) {
    static thread_local std::mt19937 gen{std::random_device{}()};
    std::uniform_int_distribution<uint16_t> dist(lo, hi);
    return dist(gen);
}

static uint32_t rand_u32() {
    static thread_local std::mt19937 gen{std::random_device{}()};
    std::uniform_int_distribution<uint32_t> dist;
    return dist(gen);
}

/// TCP checksum including IPv4 pseudo-header (RFC 793 section 3.1).
static uint16_t tcp_checksum(uint32_t src_addr, uint32_t dst_addr,
                              const void* tcp_hdr, std::size_t tcp_len) {
    std::vector<uint8_t> buf(12 + tcp_len, 0);
    std::memcpy(&buf[0], &src_addr, 4);
    std::memcpy(&buf[4], &dst_addr, 4);
    buf[8] = 0;
    buf[9] = IPPROTO_TCP;
    uint16_t tlen = htons(static_cast<uint16_t>(tcp_len));
    std::memcpy(&buf[10], &tlen, 2);
    std::memcpy(&buf[12], tcp_hdr, tcp_len);
    return ip_checksum(buf.data(), buf.size());
}

// ---------------------------------------------------------------------------
// resolve_source_ip — determine local IP for a given destination
// ---------------------------------------------------------------------------

std::string resolve_source_ip(std::string_view dst_ip) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        throw std::runtime_error("cannot create UDP socket for source IP lookup");
    }

    struct sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(80); // arbitrary port — no traffic is sent
    if (inet_pton(AF_INET, std::string(dst_ip).c_str(), &dst.sin_addr) != 1) {
        close(fd);
        throw std::runtime_error("invalid destination IP: " +
                                 std::string(dst_ip));
    }

    if (connect(fd, reinterpret_cast<struct sockaddr*>(&dst), sizeof(dst)) < 0) {
        close(fd);
        throw std::runtime_error("connect() failed during source IP lookup");
    }

    struct sockaddr_in local{};
    socklen_t len = sizeof(local);
    if (getsockname(fd, reinterpret_cast<struct sockaddr*>(&local), &len) < 0) {
        close(fd);
        throw std::runtime_error("getsockname() failed during source IP lookup");
    }

    close(fd);

    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &local.sin_addr, ip_str, sizeof(ip_str));
    return ip_str;
}

// ---------------------------------------------------------------------------
// parse_reply — testable without sockets
// ---------------------------------------------------------------------------

std::optional<ProbeReply> parse_reply(std::span<const uint8_t> raw,
                                       std::string_view expected_src_ip) {
    if (raw.size() < 40) return std::nullopt;

    auto version = (raw[0] >> 4) & 0x0F;
    if (version != 4) return std::nullopt;

    auto ihl = static_cast<std::size_t>(raw[0] & 0x0F) * 4u;
    if (ihl < 20 || raw.size() < ihl + 20) return std::nullopt;
    if (raw[9] != IPPROTO_TCP) return std::nullopt;

    uint32_t expected_addr = 0;
    if (inet_pton(AF_INET, std::string(expected_src_ip).c_str(),
                  &expected_addr) != 1) {
        return std::nullopt;
    }
    uint32_t pkt_src_addr = 0;
    std::memcpy(&pkt_src_addr, &raw[12], 4);
    if (pkt_src_addr != expected_addr) return std::nullopt;

    const uint8_t* tcp = raw.data() + ihl;
    uint16_t src_port = static_cast<uint16_t>(tcp[0] << 8 | tcp[1]);
    uint8_t flags = tcp[13];

    bool syn = (flags & 0x02) != 0;
    bool ack = (flags & 0x10) != 0;
    bool rst = (flags & 0x04) != 0;

    if (syn && ack) return ProbeReply{src_port, true};
    if (rst)        return ProbeReply{src_port, false};
    return std::nullopt;
}

// ---------------------------------------------------------------------------
// build_syn_packet
// ---------------------------------------------------------------------------

RawPacket build_syn_packet(std::string_view dst_ip, uint16_t dst_port,
                            std::string_view src_ip) {
    constexpr std::size_t kIpLen  = 20;
    constexpr std::size_t kTcpLen = 20;
    constexpr std::size_t kTotal  = kIpLen + kTcpLen;

    RawPacket pkt(kTotal, 0);

    // -- IPv4 header (struct iphdr from <netinet/ip.h>) --
    auto* ip = reinterpret_cast<struct iphdr*>(pkt.data());
    ip->version  = 4;
    ip->ihl      = 5;
    ip->tos      = 0;
    ip->tot_len  = htons(kTotal);
    ip->id       = htons(rand_u16(1, 65535));
    ip->frag_off = 0;
    ip->ttl      = 64;
    ip->protocol = IPPROTO_TCP;
    ip->check    = 0;

    // Set source address so TCP checksum is computed correctly.
    // The kernel will NOT fix the TCP checksum when it fills/overwrites saddr.
    uint32_t src_addr = 0;
    if (inet_pton(AF_INET, std::string(src_ip).c_str(), &src_addr) != 1) {
        throw std::runtime_error("invalid source IP: " + std::string(src_ip));
    }
    ip->saddr = src_addr;

    uint32_t dst_addr = 0;
    if (inet_pton(AF_INET, std::string(dst_ip).c_str(), &dst_addr) != 1) {
        throw std::runtime_error("invalid destination IP: " +
                                 std::string(dst_ip));
    }
    ip->daddr = dst_addr;
    ip->check = htons(ip_checksum(pkt.data(), kIpLen));

    // -- TCP header (struct tcphdr from <netinet/tcp.h>) --
    auto* tcp = reinterpret_cast<struct tcphdr*>(pkt.data() + kIpLen);
    tcp->source  = htons(rand_u16(49152, 65535));
    tcp->dest    = htons(dst_port);
    tcp->seq     = htonl(rand_u32());
    tcp->ack_seq = 0;
    tcp->doff    = 5;
    tcp->syn     = 1;
    tcp->window  = htons(65535);
    tcp->check   = 0;
    tcp->urg_ptr = 0;
    tcp->check   = htons(tcp_checksum(ip->saddr, ip->daddr, tcp, kTcpLen));

    return pkt;
}

// ---------------------------------------------------------------------------
// send_packet — requires CAP_NET_RAW or root
// ---------------------------------------------------------------------------

bool send_packet(const RawPacket& packet, std::string_view dst_ip) {
    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd < 0) return false;

    int on = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
        close(fd);
        return false;
    }

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    inet_pton(AF_INET, std::string(dst_ip).c_str(), &addr.sin_addr);

    auto sent = sendto(fd, packet.data(), packet.size(), 0,
                       reinterpret_cast<struct sockaddr*>(&addr),
                       sizeof(addr));
    close(fd);
    return sent >= 0;
}

// ---------------------------------------------------------------------------
// open_receiver — create a raw socket for capturing TCP replies
// ---------------------------------------------------------------------------

int open_receiver() {
    return socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
}

// ---------------------------------------------------------------------------
// receive_responses — read from an already-open receiver socket
// ---------------------------------------------------------------------------

std::vector<ProbeReply> receive_responses(int recv_fd,
                                           std::string_view expected_src_ip,
                                           int timeout_ms) {
    if (recv_fd < 0) return {};

    std::vector<ProbeReply> replies;
    uint8_t buf[65536];

    struct timespec start{};
    clock_gettime(CLOCK_MONOTONIC, &start);

    auto elapsed_ms = [&]() -> int {
        struct timespec now{};
        clock_gettime(CLOCK_MONOTONIC, &now);
        return static_cast<int>(
            (now.tv_sec - start.tv_sec) * 1000 +
            (now.tv_nsec - start.tv_nsec) / 1'000'000);
    };

    while (true) {
        int remaining = timeout_ms - elapsed_ms();
        if (remaining <= 0) break;

        struct pollfd pfd{};
        pfd.fd     = recv_fd;
        pfd.events = POLLIN;

        int ret = poll(&pfd, 1, remaining);
        if (ret <= 0) break;

        auto n = recv(recv_fd, buf, sizeof(buf), 0);
        if (n < 40) continue;

        auto reply = parse_reply(
            std::span<const uint8_t>(buf, static_cast<std::size_t>(n)),
            expected_src_ip);
        if (reply) {
            replies.push_back(*reply);
        }
    }

    return replies;
}

} // namespace synscan
