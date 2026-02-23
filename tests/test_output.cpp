#include "synscan/output.h"
#include "test_helpers.h"

#include <sstream>
#include <string>

using namespace synscan;

int main() {
    // --- port_state_label ---
    ASSERT_EQ(port_state_label(PortState::Open),     "open");
    ASSERT_EQ(port_state_label(PortState::Closed),   "closed");
    ASSERT_EQ(port_state_label(PortState::Filtered), "filtered");
    ASSERT_EQ(port_state_label(PortState::Unknown),  "unknown");

    // --- print_results produces expected table ---
    {
        std::vector<PortResult> results = {
            {22,  PortState::Open,   "ssh"},
            {80,  PortState::Open,   "http"},
            {443, PortState::Closed, "https"},
        };
        std::ostringstream oss;
        print_results(oss, results, 1.23);
        std::string output = oss.str();

        // Verify header is present.
        ASSERT_TRUE(output.find("PORT") != std::string::npos);
        ASSERT_TRUE(output.find("STATE") != std::string::npos);
        ASSERT_TRUE(output.find("SERVICE") != std::string::npos);

        // Verify each result row.
        ASSERT_TRUE(output.find("22/tcp") != std::string::npos);
        ASSERT_TRUE(output.find("80/tcp") != std::string::npos);
        ASSERT_TRUE(output.find("443/tcp") != std::string::npos);
        ASSERT_TRUE(output.find("open") != std::string::npos);
        ASSERT_TRUE(output.find("closed") != std::string::npos);

        // Verify summary line with timing.
        ASSERT_TRUE(output.find("3 port(s) scanned in 1.23s") != std::string::npos);
    }

    // --- Empty service shows dash ---
    {
        std::ostringstream oss;
        print_result(oss, {8080, PortState::Filtered, ""});
        std::string line = oss.str();
        ASSERT_TRUE(line.find("8080/tcp") != std::string::npos);
        ASSERT_TRUE(line.find("filtered") != std::string::npos);
        ASSERT_TRUE(line.find("-") != std::string::npos);
    }

    RUN_TESTS();
}
