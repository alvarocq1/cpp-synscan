#include "synscan/args.h"
#include "synscan/port_spec.h"

#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>

namespace synscan {

void print_usage(const char* program_name) {
    std::cerr
        << "Usage: " << program_name
        << " -p <port-spec> [-o <file>] [-v] <target>\n"
        << "\n"
        << "Options:\n"
        << "  -p <ports>   Port specification (e.g. 22,80,443 or 1-1024 or -p- for all)\n"
        << "  -o <file>    Write output to file (default: stdout)\n"
        << "  -v           Verbose output\n"
        << "  -h, --help   Show this help message\n"
        << "\n"
        << "Example:\n"
        << "  sudo " << program_name << " -p 22,80,443 192.168.1.1\n";
}

std::optional<ScanConfig> parse_args(int argc, char* argv[]) {
    ScanConfig config;
    bool got_ports = false;

    for (int i = 1; i < argc; ++i) {
        std::string_view arg = argv[i];

        if (arg == "-h" || arg == "--help") {
            print_usage(argv[0]);
            return std::nullopt; // caller should exit(0)
        }

        if (arg == "-v") {
            config.verbose = true;
            continue;
        }

        if (arg == "-p-") {
            config.ports = parse_port_spec("-");
            config.all_ports = true;
            got_ports = true;
            continue;
        }

        if (arg == "-p") {
            if (++i >= argc) {
                throw std::runtime_error("-p requires a port specification");
            }
            std::string_view port_spec = argv[i];
            config.ports = parse_port_spec(port_spec);
            if (port_spec == "-") {
                config.all_ports = true;
            }
            got_ports = true;
            continue;
        }

        // Handle combined form: -p<spec> (e.g. -p- or -p80 or -p22,80,443)
        if (arg.substr(0, 2) == "-p" && arg.size() > 2) {
            config.ports = parse_port_spec(arg.substr(2));
            got_ports = true;
            continue;
        }

        if (arg == "-o") {
            if (++i >= argc) {
                throw std::runtime_error("-o requires a filename");
            }
            config.output_file = argv[i];
            continue;
        }

        // Anything that doesn't start with '-' is the target.
        if (!arg.empty() && arg[0] != '-') {
            if (!config.target.empty()) {
                throw std::runtime_error(
                    "multiple targets not supported (got '" + config.target +
                    "' and '" + std::string(arg) + "')");
            }
            config.target = std::string(arg);
            continue;
        }

        throw std::runtime_error(
            "unknown option: '" + std::string(arg) + "'");
    }

    if (!got_ports) {
        throw std::runtime_error("missing required -p <port-spec>");
    }
    if (config.target.empty()) {
        throw std::runtime_error("missing target host");
    }

    return config;
}

} // namespace synscan
