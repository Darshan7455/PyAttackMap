#pragma once

#include "pyattackmap/analyzer.hpp"
#include "pyattackmap/config.hpp"
#include "pyattackmap/exceptions.hpp"
#include "pyattackmap/models.hpp"
#include "pyattackmap/parser.hpp"
#include "pyattackmap/reporting.hpp"
#include "pyattackmap/rules/registry.hpp"
#include "pyattackmap/rules/rule.hpp"

namespace pyattackmap {

inline constexpr std::string_view version = "0.2.0";

inline AnalysisResult scan(const std::filesystem::path& target, ScanConfig config = {}) {
    Analyzer analyzer(std::move(config));
    return analyzer.scan(target);
}

inline AnalysisResult scan_file(const std::filesystem::path& file_path, ScanConfig config = {}) {
    Analyzer analyzer(std::move(config));
    return analyzer.scan_file(file_path);
}

inline AnalysisResult scan_code(std::string_view code, std::string_view file_path = "<string>", ScanConfig config = {}) {
    Analyzer analyzer(std::move(config));
    return analyzer.scan_code(code, file_path);
}

} // namespace pyattackmap

