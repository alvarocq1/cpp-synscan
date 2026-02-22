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
#ifdef SYNSCAN_MACOS
    // macOS: both IPPROTO_RAW and IPPROTO_TCP+IP_HDRINCL silently drop
    // packets on the loopback interface.  The only reliable approach is
    // IPPROTO_TCP *without* IP_HDRINCL — the kernel builds the IP header
    // and we supply only the TCP segment.
    //
    // build_syn_packet() produces a full 40-byte IP+TCP packet.  We send
    // only the TCP portion (bytes 20..39).
    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (fd < 0) return false;

    // Extract the TCP header (skip the 20-byte IP header).
    if (packet.size() < ip::HDR_LEN + tcp::HDR_LEN) {
        close(fd);
        return false;
    }
    const uint8_t* tcp_data = packet.data() + ip::HDR_LEN;
    std::size_t tcp_len = packet.size() - ip::HDR_LEN;

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    inet_pton(AF_INET, std::string(dst_ip).c_str(), &addr.sin_addr);

    auto sent = sendto(fd, tcp_data, tcp_len, 0,
                       reinterpret_cast<struct sockaddr*>(&addr),
                       sizeof(addr));
    close(fd);
    return sent >= 0;
#else
    // Linux: IPPROTO_RAW + IP_HDRINCL works as expected.
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
#endif
}

// ---------------------------------------------------------------------------
// open_receiver — platform-specific packet capture
// ---------------------------------------------------------------------------

#ifdef SYNSCAN_MACOS

/// Determine the network interface used to reach `dst_ip`.
/// For 127.0.0.0/8 returns "lo0"; otherwise uses a connected UDP socket
/// and getifaddrs to match the source IP to an interface name.
static std::string resolve_interface(std::string_view dst_ip) {
    // Loopback shortcut
    if (dst_ip.starts_with("127.")) return "lo0";

    // Determine which source IP the OS would use
    std::string src = resolve_source_ip(dst_ip);

    uint32_t src_addr = 0;
    inet_pton(AF_INET, src.c_str(), &src_addr);

    // Walk interface addresses to find the matching interface
    struct ifaddrs* ifa_list = nullptr;
    if (getifaddrs(&ifa_list) < 0) return "lo0";

    std::string result = "lo0";
    for (auto* ifa = ifa_list; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr) continue;
        if (ifa->ifa_addr->sa_family != AF_INET) continue;
        auto* sa = reinterpret_cast<struct sockaddr_in*>(ifa->ifa_addr);
        if (sa->sin_addr.s_addr == src_addr) {
            result = ifa->ifa_name;
            break;
        }
    }
    freeifaddrs(ifa_list);
    return result;
}

int open_receiver(std::string_view dst_ip) {
    std::string iface = resolve_interface(dst_ip);

    // Find an available BPF device
    int fd = -1;
    for (int i = 0; i < 128; ++i) {
        std::string dev = "/dev/bpf" + std::to_string(i);
        fd = open(dev.c_str(), O_RDWR);
        if (fd >= 0) break;
    }
    if (fd < 0) return -1;

    // Set buffer size
    int bufsize = 524288;
    ioctl(fd, BIOCSBLEN, &bufsize);

    // Bind to interface
    struct ifreq ifr{};
    std::strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ - 1);
    if (ioctl(fd, BIOCSETIF, &ifr) < 0) {
        close(fd);
        return -1;
    }

    // Immediate mode — deliver packets as soon as they arrive
    int imm = 1;
    ioctl(fd, BIOCIMMEDIATE, &imm);

    // Promiscuous mode (needed for loopback capture)
    ioctl(fd, BIOCPROMISC, nullptr);

    // BPF filter: accept only TCP (IPv4, protocol 6)
    // Loopback link header is 4 bytes (AF family in host byte order).
    // We skip the AF check (endianness-dependent) and verify IPv4 by
    // masking the version nibble of the IP header at offset 4.
    struct bpf_insn filter[] = {
        BPF_STMT(BPF_LD + BPF_B + BPF_ABS, 4),           // ver_ihl byte
        BPF_STMT(BPF_ALU + BPF_AND + BPF_K, 0xF0),       // mask version nibble
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0x40, 0, 3), // version == 4?
        BPF_STMT(BPF_LD + BPF_B + BPF_ABS, 4 + 9),       // ip.protocol
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, IPPROTO_TCP, 0, 1),
        BPF_STMT(BPF_RET + BPF_K, 65536),                 // accept
        BPF_STMT(BPF_RET + BPF_K, 0),                     // reject
    };
    // For Ethernet interfaces, the link header is 14 bytes.
    // Adjust offsets if not loopback.
    struct bpf_insn filter_eth[] = {
        BPF_STMT(BPF_LD + BPF_H + BPF_ABS, 12),          // ethertype
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0x0800, 0, 3), // must be IPv4
        BPF_STMT(BPF_LD + BPF_B + BPF_ABS, 14 + 9),      // ip.protocol
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, IPPROTO_TCP, 0, 1),
        BPF_STMT(BPF_RET + BPF_K, 65536),                 // accept
        BPF_STMT(BPF_RET + BPF_K, 0),                     // reject
    };

    // Determine link type to choose the right filter
    uint32_t dlt = 0;
    ioctl(fd, BIOCGDLT, &dlt);

    struct bpf_program prog{};
    if (dlt == DLT_NULL) {
        // Loopback (BSD NULL encapsulation)
        prog.bf_len = sizeof(filter) / sizeof(filter[0]);
        prog.bf_insns = filter;
    } else {
        // Ethernet
        prog.bf_len = sizeof(filter_eth) / sizeof(filter_eth[0]);
        prog.bf_insns = filter_eth;
    }
    ioctl(fd, BIOCSETF, &prog);

    return fd;
}

#else // Linux

int open_receiver([[maybe_unused]] std::string_view dst_ip) {
    return socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
}

#endif

// ---------------------------------------------------------------------------
// receive_responses — read from an already-open receiver fd
// ---------------------------------------------------------------------------

std::vector<ProbeReply> receive_responses(int recv_fd,
                                           std::string_view expected_src_ip,
                                           int timeout_ms) {
    if (recv_fd < 0) return {};

    std::vector<ProbeReply> replies;

    struct timespec start{};
    clock_gettime(CLOCK_MONOTONIC, &start);

    auto elapsed_ms = [&]() -> int {
        struct timespec now{};
        clock_gettime(CLOCK_MONOTONIC, &now);
        return static_cast<int>(
            (now.tv_sec - start.tv_sec) * 1000 +
            (now.tv_nsec - start.tv_nsec) / 1'000'000);
    };

#ifdef SYNSCAN_MACOS
    // macOS: read BPF frames.  Each read may return multiple packets,
    // each prefixed by a bpf_hdr.  The IP packet follows the link-layer
    // header (4 bytes for loopback NULL, 14 for Ethernet).

    // Determine link header length from the BPF fd.
    uint32_t dlt = 0;
    ioctl(recv_fd, BIOCGDLT, &dlt);
    std::size_t link_hdr_len = (dlt == DLT_NULL) ? 4 : 14;

    int blen = 0;
    ioctl(recv_fd, BIOCGBLEN, &blen);
    if (blen <= 0) blen = 524288;

    std::vector<uint8_t> buf(static_cast<std::size_t>(blen));

    while (true) {
        int remaining = timeout_ms - elapsed_ms();
        if (remaining <= 0) break;

        struct pollfd pfd{};
        pfd.fd     = recv_fd;
        pfd.events = POLLIN;

        int ret = poll(&pfd, 1, remaining);
        if (ret <= 0) break;

        auto n = read(recv_fd, buf.data(), buf.size());
        if (n <= 0) continue;

        // Walk the BPF buffer — it may contain multiple packets.
        auto* ptr = buf.data();
        auto* end = buf.data() + n;
        while (ptr < end) {
            auto* bh = reinterpret_cast<struct bpf_hdr*>(ptr);
            auto* pkt = ptr + bh->bh_hdrlen;
            auto caplen = static_cast<std::size_t>(bh->bh_caplen);

            if (caplen > link_hdr_len + 40) {
                auto* ip_data = pkt + link_hdr_len;
                auto ip_len = caplen - link_hdr_len;
                auto reply = parse_reply(
                    std::span<const uint8_t>(ip_data, ip_len),
                    expected_src_ip);
                if (reply) {
                    replies.push_back(*reply);
                }
            }

            ptr += BPF_WORDALIGN(bh->bh_hdrlen + bh->bh_caplen);
        }
    }
#else
    // Linux: read raw IP packets from the IPPROTO_TCP socket.
    uint8_t buf[65536];

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
#endif

    return replies;
}

} // namespace synscan
