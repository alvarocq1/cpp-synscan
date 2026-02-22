#include "synscan/args.h"
#include "synscan/output.h"
#include "synscan/scanner.h"

#include <fstream>
#include <iostream>

int main(int argc, char* argv[]) {
    try {
        auto config = synscan::parse_args(argc, argv);
        if (!config) {
            return 0; // --help was requested
        }

        if (config->verbose) {
            std::cerr << "[*] Target: " << config->target << "\n"
                      << "[*] Ports:  " << config->ports.size()
                      << " port(s)\n";
        }

        auto results = synscan::run_scan(*config);

        // Direct output to file or stdout.
        if (config->output_file) {
            std::ofstream ofs(*config->output_file);
            if (!ofs) {
                std::cerr << "error: cannot open output file: "
                          << *config->output_file << "\n";
                return 1;
            }
            synscan::print_results(ofs, results);
        } else {
            synscan::print_results(std::cout, results);
        }

        return 0;

    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    }
}
