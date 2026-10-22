#include "pyattackmap/reporting.hpp"

#include <fstream>
#include <sstream>

#include "pyattackmap/exceptions.hpp"

namespace pyattackmap {

std::string TextReporter::format_finding(const Finding& finding) {
    std::ostringstream ss;
    ss << "[" << to_string(finding.severity) << "] "
       << finding.rule_id << ": " << finding.title << "\n";
    ss << "  Location  : " << finding.location.file << ":"
       << finding.location.line << ":" << finding.location.col << "\n";
    ss << "  Confidence: " << to_string(finding.confidence)
       << " | CWE: " << (finding.cwe ? *finding.cwe : "N/A") << "\n";

    if (!finding.snippet.empty()) {
        ss << "  Code Snippet:\n";
        std::istringstream lines(finding.snippet);
        std::string line;
        while (std::getline(lines, line)) {
            ss << "    | " << line << "\n";
        }
    }

    if (!finding.evidence.empty()) {
        ss << "  Evidence  : " << finding.evidence << "\n";
    }

    if (finding.dataflow && !finding.dataflow->nodes.empty()) {
        ss << "  Data-Flow Trace:\n";
        for (const auto& node : finding.dataflow->nodes) {
            std::filesystem::path p(node.location.file);
            ss << "    --> [" << to_string(node.kind) << "] " << node.label
               << " (" << p.filename().string() << ":" << node.location.line << ")\n";
        }
    }

    if (!finding.remediation.empty()) {
        ss << "  Remediation:\n";
        std::istringstream rlines(finding.remediation);
        std::string line;
        while (std::getline(rlines, line)) {
            ss << "    " << line << "\n";
        }
    }

    return ss.str();
}

std::string TextReporter::format_result(const AnalysisResult& result) {
    std::string out = result.summary() + "\n";

    if (!result.errors().empty()) {
        out += "\n============================================================\n";
        out += "Analysis / Parse Errors\n";
        out += "============================================================\n";
        for (const auto& err : result.errors()) {
            std::string loc = err.file;
            if (err.line) {
                loc += ":" + std::to_string(*err.line);
            }
            out += "  [" + err.error_type + "] " + loc + ": " + err.message + "\n";
        }
    }

    if (!result.findings().empty()) {
        out += "\n============================================================\n";
        out += "Security Findings\n";
        out += "============================================================\n";
        for (const auto& finding : result.findings()) {
            out += format_finding(finding);
            out += "------------------------------------------------------------\n";
        }
    }

    return out;
}

void TextReporter::render(const AnalysisResult& result, std::ostream& os) {
    os << format_result(result);
}

std::string JsonReporter::serialize(const AnalysisResult& result, int indent) {
    return result.to_json(std::nullopt, indent);
}

std::string JsonReporter::write_to_file(const AnalysisResult& result, const std::filesystem::path& path, int indent) {
    return result.to_json(path, indent);
}

} // namespace pyattackmap

