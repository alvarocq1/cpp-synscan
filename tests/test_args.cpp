#include "synscan/args.h"
#include "test_helpers.h"

#include <stdexcept>

using synscan::parse_args;

// Helper: build an argv-style array from string literals.
// The first element is the "program name".
template <size_t N>
std::optional<synscan::ScanConfig> call_parse(const char* (&args)[N]) {
    return parse_args(static_cast<int>(N), const_cast<char**>(args));
}

int main() {
    // --- Basic valid invocation ---
    {
        const char* args[] = {"synscan", "-p", "80,443", "192.168.1.1"};
        auto cfg = call_parse(args);
        ASSERT_TRUE(cfg.has_value());
        ASSERT_EQ(cfg->target, "192.168.1.1");
        ASSERT_EQ(cfg->ports.size(), 2u);
        ASSERT_EQ(cfg->verbose, false);
        ASSERT_TRUE(!cfg->output_file.has_value());
    }

    // --- Verbose and output file ---
    {
        const char* args[] = {"synscan", "-v", "-p", "22", "-o", "out.txt",
                              "10.0.0.1"};
        auto cfg = call_parse(args);
        ASSERT_TRUE(cfg.has_value());
        ASSERT_EQ(cfg->verbose, true);
        ASSERT_TRUE(cfg->output_file.has_value());
        ASSERT_EQ(*cfg->output_file, "out.txt");
    }

    // --- Help returns nullopt ---
    {
        const char* args[] = {"synscan", "--help"};
        auto cfg = call_parse(args);
        ASSERT_TRUE(!cfg.has_value());
    }

    // --- Missing ports ---
    {
        const char* args[] = {"synscan", "192.168.1.1"};
        ASSERT_THROWS(call_parse(args), std::runtime_error);
    }

    // --- Missing target ---
    {
        const char* args[] = {"synscan", "-p", "80"};
        ASSERT_THROWS(call_parse(args), std::runtime_error);
    }

    // --- Unknown option ---
    {
        const char* args[] = {"synscan", "-p", "80", "--bad", "host"};
        ASSERT_THROWS(call_parse(args), std::runtime_error);
    }

    // --- "-p-" (single token) sets all_ports ---
    {
        const char* args[] = {"synscan", "-p-", "10.0.0.1"};
        auto cfg = call_parse(args);
        ASSERT_TRUE(cfg.has_value());
        ASSERT_EQ(cfg->all_ports, true);
        ASSERT_EQ(cfg->ports.size(), 65535u);
    }

    // --- "-p -" (two tokens) sets all_ports ---
    {
        const char* args[] = {"synscan", "-p", "-", "10.0.0.1"};
        auto cfg = call_parse(args);
        ASSERT_TRUE(cfg.has_value());
        ASSERT_EQ(cfg->all_ports, true);
        ASSERT_EQ(cfg->ports.size(), 65535u);
    }

    // --- Normal -p does not set all_ports ---
    {
        const char* args[] = {"synscan", "-p", "80", "10.0.0.1"};
        auto cfg = call_parse(args);
        ASSERT_TRUE(cfg.has_value());
        ASSERT_EQ(cfg->all_ports, false);
    }

    RUN_TESTS();
}
