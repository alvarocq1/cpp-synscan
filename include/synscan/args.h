#pragma once
// ---------------------------------------------------------------------------
// args.h — Command-line argument parsing
//
// Parses argv into a ScanConfig struct that the rest of the program consumes.
// Current skeleton supports:
//   -p <port-spec>    ports to scan  (required)
//   <target>          target host    (positional, required)
//   -o <file>         output file    (optional, default: stdout)
//   -v                verbose mode
//   -h / --help       print usage
//
// The user will extend this as new features are added (timeouts, interface
// selection, decoy addresses, etc.).
// ---------------------------------------------------------------------------

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace synscan {

struct ScanConfig {
    std::string target;                    // hostname or IP
    std::vector<uint16_t> ports;           // parsed port list
    std::optional<std::string> output_file;// write results here (nullopt → stdout)
    bool verbose = false;
    bool all_ports = false;               // true when -p- (all 65535 ports)
};

/// Parse command-line arguments into a ScanConfig.
/// Returns std::nullopt when --help is requested (caller should exit 0).
/// Throws std::runtime_error on invalid / missing arguments.
[[nodiscard]] std::optional<ScanConfig> parse_args(int argc, char* argv[]);

/// Print a short usage message to stderr.
void print_usage(const char* program_name);

} // namespace synscan
