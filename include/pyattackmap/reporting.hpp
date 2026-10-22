#pragma once

#include <filesystem>
#include <iostream>
#include <string>

#include "pyattackmap/models.hpp"

namespace pyattackmap {

class TextReporter {
public:
    static void render(const AnalysisResult& result, std::ostream& os = std::cout);
    [[nodiscard]] static std::string format_result(const AnalysisResult& result);
    [[nodiscard]] static std::string format_finding(const Finding& finding);
};

class JsonReporter {
public:
    [[nodiscard]] static std::string serialize(const AnalysisResult& result, int indent = 2);
    static std::string write_to_file(const AnalysisResult& result, const std::filesystem::path& path, int indent = 2);
};

} // namespace pyattackmap

