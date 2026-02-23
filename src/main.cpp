#include "synscan/args.h"
#include "synscan/output.h"
#include "synscan/scanner.h"

#include <chrono>
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

        auto t_start = std::chrono::steady_clock::now();
        auto results = synscan::run_scan(*config);
        auto t_end = std::chrono::steady_clock::now();
        double elapsed = std::chrono::duration<double>(t_end - t_start).count();

        // Direct output to file or stdout.
        if (config->output_file) {
            std::ofstream ofs(*config->output_file);
            if (!ofs) {
                std::cerr << "error: cannot open output file: "
                          << *config->output_file << "\n";
                return 1;
            }
            synscan::print_results(ofs, results, elapsed, config->all_ports);
        } else {
            synscan::print_results(std::cout, results, elapsed, config->all_ports);
        }

        return 0;

    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    }
}
