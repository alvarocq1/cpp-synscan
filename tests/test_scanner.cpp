#include "synscan/output.h"
#include "synscan/packet.h"
#include "test_helpers.h"

#include <unordered_map>
#include <vector>

using namespace synscan;

// ---------------------------------------------------------------------------
// Test the port-classification logic that run_scan() uses internally.
// We replicate the classification here so it can run without raw sockets.
// ---------------------------------------------------------------------------

/// Classify ports given a set of probe replies — same logic as run_scan().
static std::vector<PortResult> classify_ports(
    const std::vector<uint16_t>& ports,
    const std::vector<ProbeReply>& replies) {

    std::unordered_map<uint16_t, PortState> state_map;
    for (const auto& r : replies) {
        state_map[r.source_port] =
            r.is_syn_ack ? PortState::Open : PortState::Closed;
    }

    std::vector<PortResult> results;
    for (uint16_t port : ports) {
        PortState st = PortState::Filtered;
        if (auto it = state_map.find(port); it != state_map.end()) {
            st = it->second;
        }
        results.push_back({port, st, ""});
    }
    return results;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

static void test_all_open() {
    std::vector<uint16_t> ports = {22, 80, 443};
    std::vector<ProbeReply> replies = {
        {22,  true},
        {80,  true},
        {443, true},
    };
    auto res = classify_ports(ports, replies);
    ASSERT_EQ(res.size(), 3u);
    ASSERT_EQ(res[0].state, PortState::Open);
    ASSERT_EQ(res[1].state, PortState::Open);
    ASSERT_EQ(res[2].state, PortState::Open);
}

static void test_all_closed() {
    std::vector<uint16_t> ports = {22, 80};
    std::vector<ProbeReply> replies = {
        {22, false},
        {80, false},
    };
    auto res = classify_ports(ports, replies);
    ASSERT_EQ(res[0].state, PortState::Closed);
    ASSERT_EQ(res[1].state, PortState::Closed);
}

static void test_no_reply_means_filtered() {
    std::vector<uint16_t> ports = {22, 80, 443};
    std::vector<ProbeReply> replies = {
        {80, true}, // only port 80 replied
    };
    auto res = classify_ports(ports, replies);
    ASSERT_EQ(res[0].state, PortState::Filtered); // 22
    ASSERT_EQ(res[1].state, PortState::Open);     // 80
    ASSERT_EQ(res[2].state, PortState::Filtered); // 443
}

static void test_mixed_states() {
    std::vector<uint16_t> ports = {22, 80, 443, 8080};
    std::vector<ProbeReply> replies = {
        {22,  true},   // open
        {80,  false},  // closed
        {443, true},   // open
        // 8080: no reply → filtered
    };
    auto res = classify_ports(ports, replies);
    ASSERT_EQ(res[0].state, PortState::Open);
    ASSERT_EQ(res[1].state, PortState::Closed);
    ASSERT_EQ(res[2].state, PortState::Open);
    ASSERT_EQ(res[3].state, PortState::Filtered);
}

static void test_empty_scan() {
    std::vector<uint16_t> ports = {};
    std::vector<ProbeReply> replies = {};
    auto res = classify_ports(ports, replies);
    ASSERT_EQ(res.size(), 0u);
}

static void test_duplicate_replies_last_wins() {
    std::vector<uint16_t> ports = {80};
    std::vector<ProbeReply> replies = {
        {80, true},   // SYN-ACK first
        {80, false},  // then RST
    };
    auto res = classify_ports(ports, replies);
    // Last reply overwrites — RST wins.
    ASSERT_EQ(res[0].state, PortState::Closed);
}

static void test_port_order_preserved() {
    std::vector<uint16_t> ports = {443, 22, 80};
    std::vector<ProbeReply> replies = {
        {22,  true},
        {80,  false},
        {443, true},
    };
    auto res = classify_ports(ports, replies);
    ASSERT_EQ(res[0].port, 443u);
    ASSERT_EQ(res[1].port, 22u);
    ASSERT_EQ(res[2].port, 80u);
}

int main() {
    test_all_open();
    test_all_closed();
    test_no_reply_means_filtered();
    test_mixed_states();
    test_empty_scan();
    test_duplicate_replies_last_wins();
    test_port_order_preserved();

    RUN_TESTS();
}
