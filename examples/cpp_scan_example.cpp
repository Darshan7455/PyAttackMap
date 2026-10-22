#include <iostream>
#include <pyattackmap/pyattackmap.hpp>

int main(int argc, char* argv[]) {
    std::filesystem::path target = (argc > 1) ? argv[1] : ".";

    pyattackmap::ScanConfig config;
    config.min_severity = pyattackmap::Severity::Low;
    config.show_dataflow = true;

    pyattackmap::Analyzer analyzer(config);
    const auto result = analyzer.scan(target);

    std::cout << result.summary() << '\n';

    for (const auto& finding : result.findings()) {
        std::cout << "[" << pyattackmap::to_string(finding.severity) << "] "
                  << finding.rule_id << " - "
                  << finding.title << "\n  at "
                  << finding.location.file << ":"
                  << finding.location.line << ":"
                  << finding.location.col << '\n';
    }

    result.to_json("pyattackmap-report.json");
    std::cout << "\nReport written to pyattackmap-report.json\n";
    return 0;
}

