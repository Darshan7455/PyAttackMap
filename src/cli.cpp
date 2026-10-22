#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "pyattackmap/analyzer.hpp"
#include "pyattackmap/config.hpp"
#include "pyattackmap/exceptions.hpp"
#include "pyattackmap/pyattackmap.hpp"
#include "pyattackmap/reporting.hpp"
#include "pyattackmap/rules/registry.hpp"

namespace pyattackmap {

constexpr int EXIT_CODE_SUCCESS = 0;
constexpr int EXIT_CODE_FINDINGS_FOUND = 1;
constexpr int EXIT_CODE_USAGE_ERROR = 2;
constexpr int EXIT_CODE_EXECUTION_ERROR = 3;

static void print_usage(const char* prog) {
    std::cout << "Usage: " << prog << " [options] <command> [args...]\n\n"
              << "PyAttackMap: Explainable Static Security Analysis and Data-Flow Visualization for Python\n\n"
              << "Commands:\n"
              << "  scan <target>     Scan Python files or directories for security vulnerabilities\n"
              << "  rules             List all available static security rules\n\n"
              << "Options:\n"
              << "  -h, --help        Show this help message and exit\n"
              << "  -v, --version     Show version information and exit\n\n"
              << "Scan Options:\n"
              << "  -s, --severity <LEVEL>   Minimum severity threshold: CRITICAL, HIGH, MEDIUM, LOW, INFO (default: LOW)\n"
              << "  -f, --format <FORMAT>    Output format: text, json (default: text)\n"
              << "  -o, --output <PATH>      Write report to specified output file path\n"
              << "  -e, --exclude <PAT>      Path or directory pattern to exclude (can be specified multiple times)\n"
              << "  -j, --jobs <N>           Number of worker threads (default: hardware concurrency)\n"
              << "  --no-dataflow            Disable dataflow graph generation in findings\n";
}

static int run_rules() {
    std::cout << "============================================================\n"
              << "Registered PyAttackMap Security Rules\n"
              << "============================================================\n";

    auto rules = RuleRegistry::default_registry().get_all_rules();
    for (const auto& r : rules) {
        std::string cwe_str = r->cwe() ? (" | " + std::string(*r->cwe())) : "";
        std::cout << "[" << r->rule_id() << "] " << r->title() << "\n"
                  << "  Severity: " << to_string(r->severity())
                  << " | Default Confidence: " << to_string(r->default_confidence())
                  << cwe_str << "\n"
                  << "  Description: " << r->description() << "\n\n";
    }
    return EXIT_CODE_SUCCESS;
}

static int run_scan(int argc, char* argv[]) {
    std::string target;
    std::string severity_str = "LOW";
    std::string format = "text";
    std::string output_file;
    std::vector<std::string> extra_excludes;
    bool show_dataflow = true;
    size_t jobs = 0;

    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") {
            print_usage(argv[0]);
            return EXIT_CODE_SUCCESS;
        } else if (arg == "-s" || arg == "--severity") {
            if (++i >= argc) {
                std::cerr << "Error: " << arg << " requires a severity argument.\n";
                return EXIT_CODE_USAGE_ERROR;
            }
            severity_str = argv[i];
        } else if (arg == "-f" || arg == "--format") {
            if (++i >= argc) {
                std::cerr << "Error: " << arg << " requires a format argument (text or json).\n";
                return EXIT_CODE_USAGE_ERROR;
            }
            format = argv[i];
        } else if (arg == "-o" || arg == "--output") {
            if (++i >= argc) {
                std::cerr << "Error: " << arg << " requires an output path.\n";
                return EXIT_CODE_USAGE_ERROR;
            }
            output_file = argv[i];
        } else if (arg == "-e" || arg == "--exclude") {
            if (++i >= argc) {
                std::cerr << "Error: " << arg << " requires an exclude pattern.\n";
                return EXIT_CODE_USAGE_ERROR;
            }
            extra_excludes.push_back(argv[i]);
        } else if (arg == "-j" || arg == "--jobs") {
            if (++i >= argc) {
                std::cerr << "Error: " << arg << " requires a number.\n";
                return EXIT_CODE_USAGE_ERROR;
            }
            try {
                jobs = std::stoul(argv[i]);
            } catch (...) {
                std::cerr << "Error: invalid jobs argument: " << argv[i] << "\n";
                return EXIT_CODE_USAGE_ERROR;
            }
        } else if (arg == "--no-dataflow") {
            show_dataflow = false;
        } else if (arg.empty() || arg[0] == '-') {
            std::cerr << "Error: unrecognized option: " << arg << "\n";
            return EXIT_CODE_USAGE_ERROR;
        } else {
            if (!target.empty()) {
                std::cerr << "Error: unexpected extra argument: " << arg << "\n";
                return EXIT_CODE_USAGE_ERROR;
            }
            target = arg;
        }
    }

    if (target.empty()) {
        std::cerr << "Error: target path is required for scan command.\n";
        return EXIT_CODE_USAGE_ERROR;
    }

    Severity min_sev;
    try {
        min_sev = severity_from_string(severity_str);
    } catch (const ConfigException& ce) {
        std::cerr << "Configuration error: " << ce.what() << "\n";
        return EXIT_CODE_USAGE_ERROR;
    }

    ScanConfig config;
    config.min_severity = min_sev;
    config.show_dataflow = show_dataflow;
    config.jobs = jobs;
    for (const auto& ex : extra_excludes) {
        config.exclude.push_back(ex);
    }

    Analyzer analyzer(config);
    AnalysisResult result;

    try {
        std::filesystem::path p(target);
        if (std::filesystem::is_regular_file(p)) {
            result = analyzer.scan_file(p);
        } else {
            result = analyzer.scan(p);
        }
    } catch (const FileAccessException& fae) {
        std::cerr << "Error: " << fae.what() << "\n";
        return EXIT_CODE_EXECUTION_ERROR;
    } catch (const PyAttackMapException& pme) {
        std::cerr << "Scan error: " << pme.what() << "\n";
        return EXIT_CODE_EXECUTION_ERROR;
    } catch (const std::exception& exc) {
        std::cerr << "Unexpected error: " << exc.what() << "\n";
        return EXIT_CODE_EXECUTION_ERROR;
    }

    // Output formatting
    std::string output_content;
    if (format == "json") {
        output_content = JsonReporter::serialize(result);
    } else {
        output_content = TextReporter::format_result(result);
    }

    if (!output_file.empty()) {
        std::filesystem::path out_path(output_file);
        if (out_path.has_parent_path()) {
            std::filesystem::create_directories(out_path.parent_path());
        }
        std::ofstream out(out_path);
        if (!out.is_open()) {
            std::cerr << "Error: failed to open output file: " << output_file << "\n";
            return EXIT_CODE_EXECUTION_ERROR;
        }
        out << output_content << "\n";
    } else {
        std::cout << output_content << "\n";
    }

    if (!result.empty()) {
        return EXIT_CODE_FINDINGS_FOUND;
    }
    return EXIT_CODE_SUCCESS;
}

} // namespace pyattackmap

int main(int argc, char* argv[]) {
    if (argc < 2) {
        pyattackmap::print_usage(argv[0]);
        return pyattackmap::EXIT_CODE_SUCCESS;
    }

    std::string cmd = argv[1];
    if (cmd == "-h" || cmd == "--help") {
        pyattackmap::print_usage(argv[0]);
        return pyattackmap::EXIT_CODE_SUCCESS;
    }

    if (cmd == "-v" || cmd == "--version") {
        std::cout << "pyattackmap " << pyattackmap::version << "\n";
        return pyattackmap::EXIT_CODE_SUCCESS;
    }

    if (cmd == "rules") {
        return pyattackmap::run_rules();
    }

    if (cmd == "scan") {
        return pyattackmap::run_scan(argc, argv);
    }

    std::cerr << "Error: unknown command '" << cmd << "'. Use --help for usage.\n";
    return pyattackmap::EXIT_CODE_USAGE_ERROR;
}

