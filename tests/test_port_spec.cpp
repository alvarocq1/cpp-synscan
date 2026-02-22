#include "synscan/port_spec.h"
#include "test_helpers.h"

#include <stdexcept>
#include <vector>

using synscan::parse_port_spec;

int main() {
    // --- Single port ---
    {
        auto ports = parse_port_spec("80");
        ASSERT_EQ(ports.size(), 1u);
        ASSERT_EQ(ports[0], 80);
    }

    // --- Comma-separated list ---
    {
        auto ports = parse_port_spec("22,80,443");
        ASSERT_EQ(ports.size(), 3u);
        ASSERT_EQ(ports[0], 22);
        ASSERT_EQ(ports[1], 80);
        ASSERT_EQ(ports[2], 443);
    }

    // --- Range ---
    {
        auto ports = parse_port_spec("20-25");
        std::vector<uint16_t> expected = {20, 21, 22, 23, 24, 25};
        ASSERT_EQ(ports.size(), expected.size());
        for (size_t i = 0; i < expected.size(); ++i) {
            ASSERT_EQ(ports[i], expected[i]);
        }
    }

    // --- Mixed ---
    {
        auto ports = parse_port_spec("22,80-82,443");
        std::vector<uint16_t> expected = {22, 80, 81, 82, 443};
        ASSERT_EQ(ports.size(), expected.size());
        for (size_t i = 0; i < expected.size(); ++i) {
            ASSERT_EQ(ports[i], expected[i]);
        }
    }

    // --- Deduplication ---
    {
        auto ports = parse_port_spec("80,80,80");
        ASSERT_EQ(ports.size(), 1u);
        ASSERT_EQ(ports[0], 80);
    }

    // --- Overlap between range and individual ---
    {
        auto ports = parse_port_spec("80,78-82");
        std::vector<uint16_t> expected = {78, 79, 80, 81, 82};
        ASSERT_EQ(ports.size(), expected.size());
    }

    // --- Single-port range (start == end) ---
    {
        auto ports = parse_port_spec("443-443");
        ASSERT_EQ(ports.size(), 1u);
        ASSERT_EQ(ports[0], 443);
    }

    // --- Edge: port 1 and 65535 ---
    {
        auto ports = parse_port_spec("1,65535");
        ASSERT_EQ(ports.size(), 2u);
        ASSERT_EQ(ports[0], 1);
        ASSERT_EQ(ports[1], 65535);
    }

    // --- Error cases ---
    ASSERT_THROWS((void)parse_port_spec(""), std::invalid_argument);
    ASSERT_THROWS((void)parse_port_spec("0"), std::invalid_argument);
    ASSERT_THROWS((void)parse_port_spec("65536"), std::invalid_argument);
    ASSERT_THROWS((void)parse_port_spec("100-50"), std::invalid_argument);
    ASSERT_THROWS((void)parse_port_spec("abc"), std::invalid_argument);
    ASSERT_THROWS((void)parse_port_spec("-1"), std::invalid_argument);
    ASSERT_THROWS((void)parse_port_spec("80,"), std::invalid_argument);

    RUN_TESTS();
}
