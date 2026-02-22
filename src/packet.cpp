#include "synscan/packet.h"
#include "synscan/platform.h"

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
// Portable byte-write helpers for IP and TCP headers
//
// We avoid struct iphdr (Linux) / struct ip (BSD) overlays entirely.
// Instead we write each field at its RFC-defined byte offset.  This is
// portable across Linux, macOS, and any future POSIX target.
// ---------------------------------------------------------------------------

/// Write a 16-bit value in network byte order at `buf + offset`.
static inline void put_u16(uint8_t* buf, std::size_t offset, uint16_t val) {
    uint16_t n = htons(val);
    std::memcpy(buf + offset, &n, 2);
}

/// Write a 32-bit value in network byte order at `buf + offset`.
[[maybe_unused]]
static inline void put_u32(uint8_t* buf, std::size_t offset, uint32_t val) {
    uint32_t n = htonl(val);
    std::memcpy(buf + offset, &n, 4);
}

/// Read a 32-bit value in network byte order from `buf + offset`.
static inline uint32_t get_u32_net(const uint8_t* buf, std::size_t offset) {
    uint32_t val;
    std::memcpy(&val, buf + offset, 4);
    return val; // stays in network byte order
}

// IPv4 header field offsets (RFC 791)
namespace ip {
    constexpr std::size_t VER_IHL    = 0;   // version (4 bits) + IHL (4 bits)
    constexpr std::size_t TOS        = 1;
    constexpr std::size_t TOT_LEN    = 2;   // 16-bit
    constexpr std::size_t ID         = 4;   // 16-bit
    constexpr std::size_t FRAG_OFF   = 6;   // 16-bit
    constexpr std::size_t TTL        = 8;
    constexpr std::size_t PROTOCOL   = 9;
    constexpr std::size_t CHECKSUM   = 10;  // 16-bit
    constexpr std::size_t SRC_ADDR   = 12;  // 32-bit
    constexpr std::size_t DST_ADDR   = 16;  // 32-bit
    constexpr std::size_t HDR_LEN    = 20;
}

// TCP header field offsets (RFC 793)
namespace tcp {
    constexpr std::size_t SRC_PORT   = 0;   // 16-bit
    constexpr std::size_t DST_PORT   = 2;   // 16-bit
    constexpr std::size_t SEQ        = 4;   // 32-bit
    [[maybe_unused]] constexpr std::size_t ACK = 8;  // 32-bit
    constexpr std::size_t DATA_OFF   = 12;  // upper 4 bits = data offset
    constexpr std::size_t FLAGS      = 13;  // 8-bit flags field
    constexpr std::size_t WINDOW     = 14;  // 16-bit
    constexpr std::size_t CHECKSUM   = 16;  // 16-bit
    [[maybe_unused]] constexpr std::size_t URG_PTR = 18; // 16-bit
    constexpr std::size_t HDR_LEN    = 20;
}

// TCP flag bits
namespace tcp_flags {
    [[maybe_unused]] constexpr uint8_t FIN = 0x01;
    constexpr uint8_t SYN = 0x02;
    constexpr uint8_t RST = 0x04;
    constexpr uint8_t ACK = 0x10;
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

    auto version = (raw[ip::VER_IHL] >> 4) & 0x0F;
    if (version != 4) return std::nullopt;

    auto ihl = static_cast<std::size_t>(raw[ip::VER_IHL] & 0x0F) * 4u;
    if (ihl < 20 || raw.size() < ihl + 20) return std::nullopt;
    if (raw[ip::PROTOCOL] != IPPROTO_TCP) return std::nullopt;

    uint32_t expected_addr = 0;
    if (inet_pton(AF_INET, std::string(expected_src_ip).c_str(),
                  &expected_addr) != 1) {
        return std::nullopt;
    }
    uint32_t pkt_src_addr = 0;
    std::memcpy(&pkt_src_addr, &raw[ip::SRC_ADDR], 4);
    if (pkt_src_addr != expected_addr) return std::nullopt;

    const uint8_t* tcp_ptr = raw.data() + ihl;
    uint16_t src_port = static_cast<uint16_t>(tcp_ptr[0] << 8 | tcp_ptr[1]);
    uint8_t flags = tcp_ptr[tcp::FLAGS];

    bool syn = (flags & tcp_flags::SYN) != 0;
    bool ack = (flags & tcp_flags::ACK) != 0;
    bool rst = (flags & tcp_flags::RST) != 0;

    if (syn && ack) return ProbeReply{src_port, true};
    if (rst)        return ProbeReply{src_port, false};
    return std::nullopt;
}

// ---------------------------------------------------------------------------
// build_syn_packet — portable byte-level construction
// ---------------------------------------------------------------------------

RawPacket build_syn_packet(std::string_view dst_ip, uint16_t dst_port,
                            std::string_view src_ip) {
    constexpr std::size_t kIpLen  = ip::HDR_LEN;
    constexpr std::size_t kTcpLen = tcp::HDR_LEN;
    constexpr std::size_t kTotal  = kIpLen + kTcpLen;

    RawPacket pkt(kTotal, 0);
    uint8_t* p = pkt.data();

    // -- IPv4 header (direct byte writes, no struct overlay) --
    p[ip::VER_IHL]  = 0x45;               // version=4, ihl=5
    p[ip::TOS]      = 0;
    put_u16(p, ip::TOT_LEN, static_cast<uint16_t>(kTotal));
    put_u16(p, ip::ID, rand_u16(1, 65535));
    put_u16(p, ip::FRAG_OFF, 0);
    p[ip::TTL]      = 64;
    p[ip::PROTOCOL] = IPPROTO_TCP;
    // checksum field initially zero — computed after all fields are set.

    uint32_t src_addr = 0;
    if (inet_pton(AF_INET, std::string(src_ip).c_str(), &src_addr) != 1) {
        throw std::runtime_error("invalid source IP: " + std::string(src_ip));
    }
    std::memcpy(p + ip::SRC_ADDR, &src_addr, 4);

    uint32_t dst_addr = 0;
    if (inet_pton(AF_INET, std::string(dst_ip).c_str(), &dst_addr) != 1) {
        throw std::runtime_error("invalid destination IP: " +
                                 std::string(dst_ip));
    }
    std::memcpy(p + ip::DST_ADDR, &dst_addr, 4);

    // IP checksum — stored in network byte order.
    uint16_t ip_ck = ip_checksum(p, kIpLen);
    uint16_t ip_ck_net = htons(ip_ck);
    std::memcpy(p + ip::CHECKSUM, &ip_ck_net, 2);

    // -- TCP header (direct byte writes, no struct overlay) --
    uint8_t* t = p + kIpLen;

    uint16_t src_port_val = rand_u16(49152, 65535);
    put_u16(t, tcp::SRC_PORT, src_port_val);
    put_u16(t, tcp::DST_PORT, dst_port);

    uint32_t seq = rand_u32();
    uint32_t seq_net = htonl(seq);
    std::memcpy(t + tcp::SEQ, &seq_net, 4);
    // ack_seq stays zero

    t[tcp::DATA_OFF] = 0x50;             // data offset = 5 (5 << 4)
    t[tcp::FLAGS]    = tcp_flags::SYN;    // SYN only
    put_u16(t, tcp::WINDOW, 65535);
    // checksum and urg_ptr initially zero

    uint16_t tcp_ck = tcp_checksum(
        get_u32_net(p, ip::SRC_ADDR),
        get_u32_net(p, ip::DST_ADDR),
        t, kTcpLen);
    uint16_t tcp_ck_net = htons(tcp_ck);
    std::memcpy(t + tcp::CHECKSUM, &tcp_ck_net, 2);

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
