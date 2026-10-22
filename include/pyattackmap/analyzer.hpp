#pragma once

#include <filesystem>
#include <string_view>
#include <vector>

#include "pyattackmap/config.hpp"
#include "pyattackmap/models.hpp"
#include "pyattackmap/rules/registry.hpp"

namespace pyattackmap {

class Analyzer {
public:
    explicit Analyzer(ScanConfig config = {}, RuleRegistry* registry = nullptr);

    [[nodiscard]] AnalysisResult scan(const std::filesystem::path& target) const;
    [[nodiscard]] AnalysisResult scan_file(const std::filesystem::path& file_path) const;
    [[nodiscard]] AnalysisResult scan_code(std::string_view code, std::string_view file_path = "<string>") const;

    [[nodiscard]] const ScanConfig& config() const noexcept { return config_; }

    [[nodiscard]] static std::vector<std::filesystem::path>
    discover_python_files(const std::filesystem::path& target, const ScanConfig& config);

    [[nodiscard]] static bool
    should_exclude(std::string_view rel_path, const std::vector<std::string>& patterns);

private:
    ScanConfig config_;
    RuleRegistry* registry_;
};

} // namespace pyattackmap

