#include "synscan/packet.h"
#include "test_helpers.h"

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <cstring>
#include <vector>

using namespace synscan;

// ---------------------------------------------------------------------------
// ip_checksum tests
// ---------------------------------------------------------------------------

static void test_checksum_rfc_example() {
    // A known 20-byte IP header (from RFC 1071 style checks):
    // all zeros → checksum should be 0xFFFF.
    uint8_t zeros[20] = {};
    ASSERT_EQ(ip_checksum(zeros, sizeof(zeros)), 0xFFFFu);
}

static void test_checksum_round_trip() {
    // Build any header, compute checksum, then verify the whole thing
    // checksums to zero.
    uint8_t hdr[20] = {};
    hdr[0] = 0x45;  // version=4, ihl=5
    hdr[8] = 64;    // TTL
    hdr[9] = 6;     // protocol=TCP
    // Set some addresses.
    uint32_t src = htonl(0x0A000001);
    uint32_t dst = htonl(0xC0A80001);
    std::memcpy(&hdr[12], &src, 4);
    std::memcpy(&hdr[16], &dst, 4);
    // Total length.
    hdr[2] = 0; hdr[3] = 40;

    // Compute and store checksum in network byte order.
    uint16_t cksum = ip_checksum(hdr, 20);
    hdr[10] = static_cast<uint8_t>(cksum >> 8);
    hdr[11] = static_cast<uint8_t>(cksum & 0xFF);

    // Now the full header should checksum to zero.
    ASSERT_EQ(ip_checksum(hdr, 20), 0u);
}

static void test_checksum_odd_length() {
    uint8_t data[] = {0x01, 0x02, 0x03};
    // Just verify it doesn't crash and returns something non-trivial.
    auto ck = ip_checksum(data, 3);
    ASSERT_TRUE(ck != 0);
}

// ---------------------------------------------------------------------------
// build_syn_packet tests
// ---------------------------------------------------------------------------

static void test_build_packet_size() {
    auto pkt = build_syn_packet("10.0.0.1", 80, "10.0.0.2");
    ASSERT_EQ(pkt.size(), 40u);
}

static void test_build_ip_fields() {
    auto pkt = build_syn_packet("192.168.1.100", 443, "192.168.1.1");
    auto* ip = reinterpret_cast<const struct iphdr*>(pkt.data());

    ASSERT_EQ(ip->version, 4u);
    ASSERT_EQ(ip->ihl, 5u);
    ASSERT_EQ(ntohs(ip->tot_len), 40u);
    ASSERT_EQ(ip->ttl, 64u);
    ASSERT_EQ(ip->protocol, static_cast<unsigned>(IPPROTO_TCP));

    // Destination address should match.
    uint32_t expected_dst = 0;
    inet_pton(AF_INET, "192.168.1.100", &expected_dst);
    ASSERT_EQ(ip->daddr, expected_dst);
}

static void test_build_ip_checksum_valid() {
    auto pkt = build_syn_packet("10.0.0.1", 22, "10.0.0.2");
    // Verify checksum: compute over IP header → should be zero.
    auto ck = ip_checksum(pkt.data(), 20);
    ASSERT_EQ(ck, 0u);
}

static void test_build_tcp_syn_flag() {
    auto pkt = build_syn_packet("10.0.0.1", 80, "10.0.0.2");
    auto* tcp = reinterpret_cast<const struct tcphdr*>(pkt.data() + 20);

    ASSERT_EQ(tcp->syn, 1u);
    ASSERT_EQ(tcp->ack, 0u);
    ASSERT_EQ(tcp->rst, 0u);
    ASSERT_EQ(tcp->fin, 0u);
}

static void test_build_tcp_dst_port() {
    auto pkt = build_syn_packet("10.0.0.1", 8080, "10.0.0.2");
    auto* tcp = reinterpret_cast<const struct tcphdr*>(pkt.data() + 20);

    ASSERT_EQ(ntohs(tcp->dest), 8080u);
}

static void test_build_ephemeral_src_port() {
    auto pkt = build_syn_packet("10.0.0.1", 80, "10.0.0.2");
    auto* tcp = reinterpret_cast<const struct tcphdr*>(pkt.data() + 20);
    uint16_t src = ntohs(tcp->source);

    ASSERT_TRUE(src >= 49152);
    ASSERT_TRUE(src <= 65535);
}

static void test_build_invalid_ip_throws() {
    ASSERT_THROWS((void)build_syn_packet("not.an.ip", 80, "10.0.0.1"),
                  std::runtime_error);
}

static void test_build_source_addr_set() {
    auto pkt = build_syn_packet("10.0.0.1", 80, "192.168.1.50");
    auto* ip = reinterpret_cast<const struct iphdr*>(pkt.data());

    uint32_t expected_src = 0;
    inet_pton(AF_INET, "192.168.1.50", &expected_src);
    ASSERT_EQ(ip->saddr, expected_src);
}

// ---------------------------------------------------------------------------
// parse_reply tests — craft fake packets and verify classification
// ---------------------------------------------------------------------------

/// Build a minimal 40-byte fake IP+TCP reply for testing parse_reply.
static std::vector<uint8_t> make_fake_reply(const char* src_ip,
                                             uint16_t src_port,
                                             uint8_t tcp_flags) {
    std::vector<uint8_t> pkt(40, 0);

    // IP header.
    pkt[0] = 0x45;               // version=4, ihl=5
    pkt[2] = 0; pkt[3] = 40;    // tot_len
    pkt[8] = 64;                 // TTL
    pkt[9] = IPPROTO_TCP;        // protocol

    uint32_t saddr = 0;
    inet_pton(AF_INET, src_ip, &saddr);
    std::memcpy(&pkt[12], &saddr, 4);

    // TCP header at offset 20.
    pkt[20] = static_cast<uint8_t>(src_port >> 8);
    pkt[21] = static_cast<uint8_t>(src_port & 0xFF);
    pkt[32] = 0x50;             // data offset = 5 (5 << 4)
    pkt[33] = tcp_flags;

    return pkt;
}

static void test_parse_syn_ack() {
    auto pkt = make_fake_reply("10.0.0.1", 80, 0x12); // SYN+ACK
    auto reply = parse_reply(pkt, "10.0.0.1");
    ASSERT_TRUE(reply.has_value());
    ASSERT_EQ(reply->source_port, 80u);
    ASSERT_TRUE(reply->is_syn_ack);
}

static void test_parse_rst() {
    auto pkt = make_fake_reply("10.0.0.1", 443, 0x04); // RST
    auto reply = parse_reply(pkt, "10.0.0.1");
    ASSERT_TRUE(reply.has_value());
    ASSERT_EQ(reply->source_port, 443u);
    ASSERT_TRUE(!reply->is_syn_ack);
}

static void test_parse_wrong_src_ip() {
    auto pkt = make_fake_reply("10.0.0.2", 80, 0x12);
    auto reply = parse_reply(pkt, "10.0.0.1");
    ASSERT_TRUE(!reply.has_value());
}

static void test_parse_non_tcp() {
    auto pkt = make_fake_reply("10.0.0.1", 80, 0x12);
    pkt[9] = IPPROTO_UDP; // not TCP
    auto reply = parse_reply(pkt, "10.0.0.1");
    ASSERT_TRUE(!reply.has_value());
}

static void test_parse_plain_ack_ignored() {
    auto pkt = make_fake_reply("10.0.0.1", 80, 0x10); // ACK only
    auto reply = parse_reply(pkt, "10.0.0.1");
    ASSERT_TRUE(!reply.has_value());
}

static void test_parse_too_short() {
    std::vector<uint8_t> tiny(20, 0);
    auto reply = parse_reply(tiny, "10.0.0.1");
    ASSERT_TRUE(!reply.has_value());
}

static void test_parse_rst_ack() {
    auto pkt = make_fake_reply("10.0.0.1", 22, 0x14); // RST+ACK
    auto reply = parse_reply(pkt, "10.0.0.1");
    ASSERT_TRUE(reply.has_value());
    ASSERT_TRUE(!reply->is_syn_ack); // RST wins
}

// ---------------------------------------------------------------------------

int main() {
    test_checksum_rfc_example();
    test_checksum_round_trip();
    test_checksum_odd_length();

    test_build_packet_size();
    test_build_ip_fields();
    test_build_ip_checksum_valid();
    test_build_tcp_syn_flag();
    test_build_tcp_dst_port();
    test_build_ephemeral_src_port();
    test_build_invalid_ip_throws();
    test_build_source_addr_set();

    test_parse_syn_ack();
    test_parse_rst();
    test_parse_wrong_src_ip();
    test_parse_non_tcp();
    test_parse_plain_ack_ignored();
    test_parse_too_short();
    test_parse_rst_ack();

    RUN_TESTS();
}
