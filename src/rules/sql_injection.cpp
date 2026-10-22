#include "pyattackmap/rules/sql_injection.hpp"

#include <queue>
#include <unordered_map>
#include <unordered_set>

#include "pyattackmap/dataflow/engine.hpp"
#include "pyattackmap/dataflow/sanitizers.hpp"
#include "pyattackmap/dataflow/sinks.hpp"
#include "pyattackmap/dataflow/sources.hpp"

namespace pyattackmap {

static std::pair<bool, std::string> is_dynamic_string_construction(TSNode node) {
    if (ts_node_is_null(node)) {
        return {false, ""};
    }
    std::string_view type = ts_node_type(node);
    if (type == "string") {
        uint32_t count = ts_node_child_count(node);
        for (uint32_t i = 0; i < count; ++i) {
            if (std::string_view(ts_node_type(ts_node_child(node, i))) == "interpolation") {
                return {true, "f-string formatting"};
            }
        }
    }
    if (type == "binary_operator") {
        TSNode op = ts_node_child(node, 1);
        std::string_view op_sym = ts_node_type(op);
        if (op_sym == "+") {
            return {true, "string concatenation (+)"};
        }
        if (op_sym == "%") {
            return {true, "percent formatting (%)"};
        }
    }
    if (type == "call") {
        TSNode func = ts_node_child_by_field_name(node, "function", 8);
        if (ts_node_is_null(func)) func = ts_node_child(node, 0);
        if (std::string_view(ts_node_type(func)) == "attribute") {
            TSNode attr = ts_node_child_by_field_name(func, "attribute", 9);
            (void)attr;
            return {true, "str.format() method"};
        }
    }
    return {false, ""};
}

static std::unordered_set<std::string> get_referenced_names(TSNode node, std::string_view source) {
    std::unordered_set<std::string> names;
    std::vector<TSNode> stack;
    stack.reserve(16);
    stack.push_back(node);

    while (!stack.empty()) {
        TSNode cur = stack.back();
        stack.pop_back();

        if (std::string_view(ts_node_type(cur)) == "identifier") {
            uint32_t s = ts_node_start_byte(cur);
            uint32_t e = ts_node_end_byte(cur);
            names.emplace(source.substr(s, e - s));
        }

        uint32_t count = ts_node_child_count(cur);
        for (uint32_t i = 0; i < count; ++i) {
            stack.push_back(ts_node_child(cur, i));
        }
    }
    return names;
}

static SourceLocation get_loc(TSNode node, const std::string& file) {
    TSPoint s = ts_node_start_point(node);
    TSPoint e = ts_node_end_point(node);
    return SourceLocation{
        .file = file,
        .line = s.row + 1,
        .col = s.column,
        .end_line = e.row + 1,
        .end_col = e.column
    };
}

std::vector<Finding> SqlInjectionRule::run(const ParsedSource& parsed, const ScanConfig& config) const {
    std::vector<Finding> findings;
    SinkDetector sink_detector(config.custom_sinks);
    SanitizerDetector sanitizer_detector(config.custom_sanitizers);

    // 1. Discover variables assigned from sanitizer functions
    std::unordered_set<std::string> sanitized_vars;
    TSNode root = parsed.root_node();
    if (ts_node_is_null(root)) {
        return findings;
    }

    std::vector<TSNode> stack;
    stack.reserve(64);
    stack.push_back(root);

    // Also track variables assigned dynamic constructions
    std::unordered_map<std::string, std::pair<std::string, size_t>> assigned_dynamic;

    while (!stack.empty()) {
        TSNode node = stack.back();
        stack.pop_back();

        std::string_view type = ts_node_type(node);
        if (type == "assignment") {
            TSNode left = ts_node_child_by_field_name(node, "left", 4);
            TSNode right = ts_node_child_by_field_name(node, "right", 5);
            if (ts_node_is_null(left)) left = ts_node_child(node, 0);
            if (ts_node_is_null(right)) {
                uint32_t c = ts_node_child_count(node);
                if (c >= 3) right = ts_node_child(node, c - 1);
            }

            if (!ts_node_is_null(left) && !ts_node_is_null(right) &&
                std::string_view(ts_node_type(left)) == "identifier") {
                std::string var_name = std::string(parsed.get_node_text(left));

                // Check sanitizer assignment
                if (std::string_view(ts_node_type(right)) == "call") {
                    auto [is_san, _] = sanitizer_detector.is_sanitizer_call(right, parsed.source_code);
                    if (is_san) {
                        sanitized_vars.insert(var_name);
                    }
                }

                // Check dynamic construction
                auto [is_dyn, dyn_kind] = is_dynamic_string_construction(right);
                if (is_dyn) {
                    auto refs = get_referenced_names(right, parsed.source_code);
                    bool all_sanitized = !refs.empty();
                    for (const auto& r : refs) {
                        if (!sanitized_vars.count(r)) {
                            all_sanitized = false;
                            break;
                        }
                    }
                    if (!all_sanitized) {
                        TSPoint pt = ts_node_start_point(node);
                        assigned_dynamic[var_name] = {dyn_kind, pt.row + 1};
                    }
                }
            }
        }

        uint32_t count = ts_node_child_count(node);
        for (uint32_t i = 0; i < count; ++i) {
            stack.push_back(ts_node_child(node, i));
        }
    }

    // 2. Intra-procedural taint analysis
    IntraProceduralTaintTracker tracker(parsed, config);
    std::vector<TaintTrace> traces = tracker.analyze();

    std::unordered_map<uintptr_t, const TaintTrace*> taint_by_call;
    for (const auto& trace : traces) {
        auto [is_sql, _] = sink_detector.is_sql_sink(trace.sink_call, parsed.source_code);
        if (is_sql) {
            taint_by_call[reinterpret_cast<uintptr_t>(trace.sink_call.id)] = &trace;
        }
    }

    // 3. Inspect SQL sink calls in AST
    stack.clear();
    stack.push_back(root);
    while (!stack.empty()) {
        TSNode node = stack.back();
        stack.pop_back();

        if (std::string_view(ts_node_type(node)) == "call") {
            auto [is_sql, call_name] = sink_detector.is_sql_sink(node, parsed.source_code);
            if (is_sql) {
                TSNode args = ts_node_child_by_field_name(node, "arguments", 9);
                if (ts_node_is_null(args)) {
                    uint32_t c = ts_node_child_count(node);
                    if (c >= 2) args = ts_node_child(node, 1);
                }

                if (!ts_node_is_null(args)) {
                    // First argument is SQL statement
                    TSNode query_arg = TSNode{};
                    uint32_t arg_count = ts_node_child_count(args);
                    for (uint32_t i = 0; i < arg_count; ++i) {
                        TSNode child = ts_node_child(args, i);
                        std::string_view ct = ts_node_type(child);
                        if (ct != "(" && ct != ")" && ct != ",") {
                            query_arg = child;
                            break;
                        }
                    }

                    if (!ts_node_is_null(query_arg)) {
                        SourceLocation loc = get_loc(node, parsed.file_path);
                        std::string snippet = parsed.get_snippet(loc.line, loc.end_line);

                        // Check verified taint trace
                        auto it = taint_by_call.find(reinterpret_cast<uintptr_t>(node.id));
                        if (it != taint_by_call.end()) {
                            const TaintTrace* trace = it->second;
                            std::string finding_id = std::string(rule_id()) + "-" + parsed.file_path + "-" +
                                                     std::to_string(loc.line) + "-" + std::to_string(loc.col);
                            findings.push_back(Finding{
                                .id = finding_id,
                                .rule_id = std::string(rule_id()),
                                .title = std::string(title()),
                                .description = "Call to '" + call_name + "' executes a SQL query receiving tainted input from " +
                                               trace->source_node.label + " at line " + std::to_string(trace->source_node.location.line) + ".",
                                .severity = severity(),
                                .confidence = Confidence::High,
                                .location = loc,
                                .snippet = snippet,
                                .evidence = "Tainted data reaches query argument in '" + call_name + "()'.",
                                .remediation = "Use parameterized queries with database driver place-holders instead of string formatting.\n"
                                               "Example (Safe Parameterization):\n"
                                               "    cursor.execute('SELECT * FROM accounts WHERE username = %s', (username,))",
                                .cwe = "CWE-89",
                                .dataflow = config.show_dataflow ? std::optional<DataFlowGraph>(trace->graph) : std::nullopt,
                                .metadata = {{"sink", call_name}, {"pattern", "taint_flow"}}
                            });
                            goto next_node;
                        }

                        // Check inline dynamic construction
                        auto [is_dyn, dyn_kind] = is_dynamic_string_construction(query_arg);
                        if (is_dyn) {
                            auto refs = get_referenced_names(query_arg, parsed.source_code);
                            bool all_san = !refs.empty();
                            for (const auto& r : refs) {
                                if (!sanitized_vars.count(r)) {
                                    all_san = false;
                                    break;
                                }
                            }
                            if (all_san) {
                                goto next_node;
                            }

                            std::string finding_id = std::string(rule_id()) + "-" + parsed.file_path + "-" +
                                                     std::to_string(loc.line) + "-" + std::to_string(loc.col);
                            findings.push_back(Finding{
                                .id = finding_id,
                                .rule_id = std::string(rule_id()),
                                .title = std::string(title()),
                                .description = "Call to '" + call_name + "' executes an inline query constructed via " + dyn_kind + ".",
                                .severity = severity(),
                                .confidence = Confidence::Medium,
                                .location = loc,
                                .snippet = snippet,
                                .evidence = "Dynamic SQL constructed using " + dyn_kind + ".",
                                .remediation = "Use parameterized queries with database driver place-holders instead of string formatting.\n"
                                               "Example (Safe Parameterization):\n"
                                               "    cursor.execute('SELECT * FROM accounts WHERE username = %s', (username,))",
                                .cwe = "CWE-89",
                                .dataflow = std::nullopt,
                                .metadata = {{"sink", call_name}, {"pattern", dyn_kind}}
                            });
                            goto next_node;
                        }

                        // Check variable referencing assigned dynamic string
                        if (std::string_view(ts_node_type(query_arg)) == "identifier") {
                            std::string var_name = std::string(parsed.get_node_text(query_arg));
                            auto var_it = assigned_dynamic.find(var_name);
                            if (var_it != assigned_dynamic.end()) {
                                std::string finding_id = std::string(rule_id()) + "-" + parsed.file_path + "-" +
                                                         std::to_string(loc.line) + "-" + std::to_string(loc.col);
                                findings.push_back(Finding{
                                    .id = finding_id,
                                    .rule_id = std::string(rule_id()),
                                    .title = std::string(title()),
                                    .description = "Call to '" + call_name + "' executes query variable '" + var_name +
                                                   "', constructed dynamically via " + var_it->second.first +
                                                   " at line " + std::to_string(var_it->second.second) + ".",
                                    .severity = severity(),
                                    .confidence = Confidence::Medium,
                                    .location = loc,
                                    .snippet = snippet,
                                    .evidence = "Query variable '" + var_name + "' built via " + var_it->second.first + ".",
                                    .remediation = "Use parameterized queries with database driver place-holders instead of string formatting.",
                                    .cwe = "CWE-89",
                                    .dataflow = std::nullopt,
                                    .metadata = {{"sink", call_name}, {"variable", var_name}, {"pattern", var_it->second.first}}
                                });
                            }
                        }
                    }
                }
            }
        }

    next_node:
        uint32_t count = ts_node_child_count(node);
        for (uint32_t i = 0; i < count; ++i) {
            stack.push_back(ts_node_child(node, i));
        }
    }

    return findings;
}

} // namespace pyattackmap

