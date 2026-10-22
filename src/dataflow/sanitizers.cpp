#include "pyattackmap/dataflow/sanitizers.hpp"

#include "pyattackmap/dataflow/sources.hpp"

namespace pyattackmap {

SanitizerDetector::SanitizerDetector(const std::vector<std::string>& custom_sanitizers) {
    sanitizers_ = {
        "shlex.quote",
        "int",
        "float",
        "bool",
        "sql.Literal",
        "psycopg2.sql.Literal",
        "escape_string"
    };

    for (const auto& s : custom_sanitizers) {
        sanitizers_.insert(s);
    }
}

std::pair<bool, std::string> SanitizerDetector::is_sanitizer_call(TSNode call_node, std::string_view source) const {
    TSNode func = ts_node_child_by_field_name(call_node, "function", 8);
    if (ts_node_is_null(func)) {
        func = ts_node_child(call_node, 0);
    }
    std::string call_name = get_call_expression_name(func, source);
    if (call_name.empty()) {
        return {false, ""};
    }

    if (sanitizers_.count(call_name)) {
        return {true, call_name};
    }

    for (const auto& s : sanitizers_) {
        if (call_name == s || (call_name.size() > s.size() && call_name.ends_with("." + s))) {
            return {true, call_name};
        }
    }
    return {false, ""};
}

} // namespace pyattackmap

