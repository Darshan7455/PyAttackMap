#pragma once

#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

#include <tree_sitter/api.h>

namespace pyattackmap {

class SinkDetector {
public:
    explicit SinkDetector(const std::vector<std::string>& custom_sinks = {});

    [[nodiscard]] std::pair<bool, std::string> is_sql_sink(TSNode call_node, std::string_view source) const;
    [[nodiscard]] std::pair<bool, std::string> is_command_sink(TSNode call_node, std::string_view source) const;
    [[nodiscard]] std::pair<bool, std::string> is_deserialization_sink(TSNode call_node, std::string_view source) const;

private:
    std::unordered_set<std::string> sql_sinks_;
    std::unordered_set<std::string> command_sinks_;
    std::unordered_set<std::string> deserialization_sinks_;
    std::unordered_set<std::string> custom_sinks_;
};

} // namespace pyattackmap

