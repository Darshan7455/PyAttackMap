#pragma once

#include <algorithm>
#include <cctype>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "pyattackmap/exceptions.hpp"
#include "pyattackmap/models.hpp"

namespace pyattackmap {

inline std::string to_upper(std::string_view str) {
    std::string res;
    res.reserve(str.size());
    for (char c : str) {
        res.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(c))));
    }
    return res;
}

struct ScanConfig {
    std::vector<std::string> exclude = {
        ".git", ".hg", ".svn", ".venv", "venv", "env",
        "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
        ".tox", "dist", "build", "*.egg-info", "site-packages", "node_modules"
    };
    Severity min_severity = Severity::Low;
    std::optional<std::vector<std::string>> enabled_rules = std::nullopt;
    std::vector<std::string> disabled_rules;
    size_t max_file_size_kb = 2048;
    std::vector<std::string> custom_sources;
    std::vector<std::string> custom_sinks;
    std::vector<std::string> custom_sanitizers;
    bool show_dataflow = true;
    size_t thread_count = 0; // 0 = hardware concurrency, 1 = single-threaded
    size_t jobs = 0; // alias for thread_count

    void validate() const {
        if (max_file_size_kb == 0) {
            throw ConfigException("max_file_size_kb must be greater than 0");
        }
    }

    [[nodiscard]] bool is_rule_enabled(std::string_view rule_id) const {
        std::string upper_id = to_upper(rule_id);
        for (const auto& disabled : disabled_rules) {
            if (to_upper(disabled) == upper_id) {
                return false;
            }
        }
        if (enabled_rules.has_value()) {
            for (const auto& enabled : *enabled_rules) {
                if (to_upper(enabled) == upper_id) {
                    return true;
                }
            }
            return false;
        }
        return true;
    }
};

} // namespace pyattackmap

