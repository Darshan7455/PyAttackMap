#pragma once

#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

#include <tree_sitter/api.h>

namespace pyattackmap {

class SanitizerDetector {
public:
    explicit SanitizerDetector(const std::vector<std::string>& custom_sanitizers = {});

    [[nodiscard]] std::pair<bool, std::string> is_sanitizer_call(TSNode call_node, std::string_view source) const;

private:
    std::unordered_set<std::string> sanitizers_;
};

} // namespace pyattackmap

