#pragma once

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <nlohmann/json.hpp>
#include "pyattackmap/exceptions.hpp"

namespace pyattackmap {

enum class Severity : uint8_t {
    Info = 1,
    Low = 2,
    Medium = 3,
    High = 4,
    Critical = 5
};

[[nodiscard]] inline std::string to_string(Severity s) {
    switch (s) {
        case Severity::Critical: return "CRITICAL";
        case Severity::High:     return "HIGH";
        case Severity::Medium:   return "MEDIUM";
        case Severity::Low:      return "LOW";
        case Severity::Info:     return "INFO";
    }
    return "UNKNOWN";
}

[[nodiscard]] inline Severity severity_from_string(std::string_view val) {
    std::string upper;
    upper.reserve(val.size());
    for (char c : val) {
        upper.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(c))));
    }
    if (upper == "CRITICAL") return Severity::Critical;
    if (upper == "HIGH")     return Severity::High;
    if (upper == "MEDIUM")   return Severity::Medium;
    if (upper == "LOW")      return Severity::Low;
    if (upper == "INFO")     return Severity::Info;
    throw ConfigException("Invalid severity: " + std::string(val));
}

enum class Confidence : uint8_t {
    Low = 1,
    Medium = 2,
    High = 3
};

[[nodiscard]] inline std::string to_string(Confidence c) {
    switch (c) {
        case Confidence::High:   return "HIGH";
        case Confidence::Medium: return "MEDIUM";
        case Confidence::Low:    return "LOW";
    }
    return "UNKNOWN";
}

[[nodiscard]] inline Confidence confidence_from_string(std::string_view val) {
    std::string upper;
    upper.reserve(val.size());
    for (char c : val) {
        upper.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(c))));
    }
    if (upper == "HIGH")   return Confidence::High;
    if (upper == "MEDIUM") return Confidence::Medium;
    if (upper == "LOW")    return Confidence::Low;
    throw ConfigException("Invalid confidence: " + std::string(val));
}

enum class DataFlowNodeKind : uint8_t {
    Source,
    Propagation,
    Sanitizer,
    Sink
};

[[nodiscard]] inline std::string to_string(DataFlowNodeKind k) {
    switch (k) {
        case DataFlowNodeKind::Source:      return "SOURCE";
        case DataFlowNodeKind::Propagation: return "PROPAGATION";
        case DataFlowNodeKind::Sanitizer:   return "SANITIZER";
        case DataFlowNodeKind::Sink:        return "SINK";
    }
    return "UNKNOWN";
}

struct SourceLocation {
    std::string file;
    size_t line = 0;
    size_t col = 0;
    size_t end_line = 0;
    size_t end_col = 0;

    [[nodiscard]] nlohmann::json to_json() const {
        return {
            {"file", file},
            {"line", line},
            {"col", col},
            {"end_line", end_line},
            {"end_col", end_col}
        };
    }
};

struct DataFlowNode {
    std::string id;
    DataFlowNodeKind kind = DataFlowNodeKind::Propagation;
    SourceLocation location;
    std::string label;
    std::string snippet;

    [[nodiscard]] nlohmann::json to_json() const {
        return {
            {"id", id},
            {"kind", to_string(kind)},
            {"file", location.file},
            {"line", location.line},
            {"col", location.col},
            {"label", label},
            {"snippet", snippet}
        };
    }
};

struct DataFlowEdge {
    std::string source_id;
    std::string target_id;
    std::string label;

    [[nodiscard]] nlohmann::json to_json() const {
        return {
            {"source_id", source_id},
            {"target_id", target_id},
            {"label", label}
        };
    }
};

struct DataFlowGraph {
    std::vector<DataFlowNode> nodes;
    std::vector<DataFlowEdge> edges;

    [[nodiscard]] nlohmann::json to_json() const {
        nlohmann::json j_nodes = nlohmann::json::array();
        for (const auto& n : nodes) j_nodes.push_back(n.to_json());
        nlohmann::json j_edges = nlohmann::json::array();
        for (const auto& e : edges) j_edges.push_back(e.to_json());
        return {
            {"nodes", j_nodes},
            {"edges", j_edges}
        };
    }

    [[nodiscard]] std::string to_mermaid() const {
        std::string out = "flowchart TD\n";
        for (const auto& node : nodes) {
            std::string clean = node.label;
            std::replace(clean.begin(), clean.end(), '"', '\'');
            out += "    " + node.id + "[\"[" + to_string(node.kind) + "] " + clean +
                   " (L" + std::to_string(node.location.line) + ")\"]\n";
        }
        for (const auto& edge : edges) {
            if (!edge.label.empty()) {
                out += "    " + edge.source_id + " -->|" + edge.label + "| " + edge.target_id + "\n";
            } else {
                out += "    " + edge.source_id + " --> " + edge.target_id + "\n";
            }
        }
        return out;
    }
};

struct Finding {
    std::string id;
    std::string rule_id;
    std::string title;
    std::string description;
    Severity severity = Severity::Medium;
    Confidence confidence = Confidence::Medium;
    SourceLocation location;
    std::string snippet;
    std::string evidence;
    std::string remediation;
    std::optional<std::string> cwe;
    std::optional<DataFlowGraph> dataflow;
    std::map<std::string, std::string> metadata;

    [[nodiscard]] nlohmann::json to_json() const {
        nlohmann::json j = {
            {"id", id},
            {"rule_id", rule_id},
            {"title", title},
            {"description", description},
            {"severity", to_string(severity)},
            {"confidence", to_string(confidence)},
            {"file", location.file},
            {"line", location.line},
            {"end_line", location.end_line},
            {"col", location.col},
            {"end_col", location.end_col},
            {"snippet", snippet},
            {"evidence", evidence},
            {"remediation", remediation},
            {"cwe", cwe ? nlohmann::json(*cwe) : nlohmann::json(nullptr)},
            {"dataflow", dataflow ? dataflow->to_json() : nlohmann::json(nullptr)},
            {"metadata", metadata}
        };
        return j;
    }
};

struct ScanStatistics {
    size_t files_scanned = 0;
    size_t files_skipped = 0;
    size_t parse_errors = 0;
    size_t total_findings = 0;
    std::map<std::string, size_t> findings_by_severity = {
        {"CRITICAL", 0}, {"HIGH", 0}, {"MEDIUM", 0}, {"LOW", 0}, {"INFO", 0}
    };
    double duration_seconds = 0.0;

    [[nodiscard]] nlohmann::json to_json() const {
        return {
            {"files_scanned", files_scanned},
            {"files_skipped", files_skipped},
            {"parse_errors", parse_errors},
            {"total_findings", total_findings},
            {"findings_by_severity", findings_by_severity},
            {"duration_seconds", duration_seconds}
        };
    }
};

struct AnalysisError {
    std::string file;
    std::string error_type;
    std::string message;
    std::optional<size_t> line;

    [[nodiscard]] nlohmann::json to_json() const {
        return {
            {"file", file},
            {"error_type", error_type},
            {"message", message},
            {"line", line ? nlohmann::json(*line) : nlohmann::json(nullptr)}
        };
    }
};

class AnalysisResult {
public:
    AnalysisResult() = default;
    AnalysisResult(std::vector<Finding> findings, ScanStatistics stats, std::vector<AnalysisError> errors)
        : findings_(std::move(findings)), statistics_(stats), errors_(std::move(errors)) {}

    [[nodiscard]] const std::vector<Finding>& findings() const noexcept { return findings_; }
    [[nodiscard]] const ScanStatistics& statistics() const noexcept { return statistics_; }
    [[nodiscard]] const std::vector<AnalysisError>& errors() const noexcept { return errors_; }

    [[nodiscard]] size_t size() const noexcept { return findings_.size(); }
    [[nodiscard]] bool empty() const noexcept { return findings_.empty(); }

    [[nodiscard]] const Finding& operator[](size_t index) const { return findings_.at(index); }

    [[nodiscard]] std::vector<Finding> filter(
        std::optional<Severity> min_severity = std::nullopt,
        std::optional<std::string_view> rule_id = std::nullopt) const {
        std::vector<Finding> matched;
        for (const auto& f : findings_) {
            if (min_severity && static_cast<uint8_t>(f.severity) < static_cast<uint8_t>(*min_severity)) {
                continue;
            }
            if (rule_id && f.rule_id != *rule_id) {
                continue;
            }
            matched.push_back(f);
        }
        return matched;
    }

    [[nodiscard]] std::string summary() const {
        std::string s = "============================================================\n";
        s += "PyAttackMap Security Scan Summary\n";
        s += "============================================================\n";
        s += "Files Scanned : " + std::to_string(statistics_.files_scanned) + "\n";
        s += "Files Skipped : " + std::to_string(statistics_.files_skipped) + "\n";
        s += "Parse Errors  : " + std::to_string(statistics_.parse_errors) + "\n";
        char buf[64];
        std::snprintf(buf, sizeof(buf), "%.3fs", statistics_.duration_seconds);
        s += "Scan Duration : " + std::string(buf) + "\n";
        s += "------------------------------------------------------------\n";
        s += "Total Findings: " + std::to_string(findings_.size()) + "\n";
        for (const auto& sev : {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}) {
            auto it = statistics_.findings_by_severity.find(sev);
            size_t count = (it != statistics_.findings_by_severity.end()) ? it->second : 0;
            char line[64];
            std::snprintf(line, sizeof(line), "  - %-10s: %zu\n", sev, count);
            s += line;
        }
        s += "============================================================";
        return s;
    }

    [[nodiscard]] nlohmann::json to_json_obj() const {
        nlohmann::json j_findings = nlohmann::json::array();
        for (const auto& f : findings_) j_findings.push_back(f.to_json());

        nlohmann::json j_errors = nlohmann::json::array();
        for (const auto& e : errors_) j_errors.push_back(e.to_json());

        return {
            {"tool", "PyAttackMap"},
            {"version", "0.2.0"},
            {"statistics", statistics_.to_json()},
            {"findings", j_findings},
            {"errors", j_errors}
        };
    }

    [[nodiscard]] std::string to_json(const std::optional<std::filesystem::path>& path = std::nullopt, int indent = 2) const {
        nlohmann::json j = to_json_obj();
        std::string serialized = j.dump(indent);
        if (path) {
            std::filesystem::create_directories(path->parent_path());
            std::ofstream out(*path);
            if (!out.is_open()) {
                throw FileAccessException("Cannot write report to file: " + path->string());
            }
            out << serialized;
            return path->string();
        }
        return serialized;
    }

private:
    std::vector<Finding> findings_;
    ScanStatistics statistics_;
    std::vector<AnalysisError> errors_;
};

} // namespace pyattackmap
