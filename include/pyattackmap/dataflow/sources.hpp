#pragma once

#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

#include <tree_sitter/api.h>

namespace pyattackmap {

std::string get_call_expression_name(TSNode node, std::string_view source);

class SourceDetector {
public:
    explicit SourceDetector(const std::vector<std::string>& custom_sources = {});

    [[nodiscard]] std::pair<bool, std::string> is_source(TSNode node, std::string_view source) const;

private:
    std::unordered_set<std::string> call_sources_;
    std::unordered_set<std::string> attr_sources_;
};

} // namespace pyattackmap

