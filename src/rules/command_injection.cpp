#include "pyattackmap/rules/command_injection.hpp"

#include <queue>
#include <unordered_map>
#include <unordered_set>

#include "pyattackmap/dataflow/engine.hpp"
#include "pyattackmap/dataflow/sanitizers.hpp"
#include "pyattackmap/dataflow/sinks.hpp"

namespace pyattackmap {

static const char* CMD_INJECTION_REMEDIATION =
    "Pass arguments as a sequence (list of strings) and avoid using 'shell=True' or 'os.system()'.\n"
    "Example (Safe Sequence Execution):\n"
    "    # Safe: arguments are passed directly without shell expansion:\n"
    "    subprocess.run(['ping', '-c', '1', host], shell=False, check=True)";

static std::pair<bool, std::string> is_dynamic_string(TSNode node) {
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
        return {true, "str.format() method"};
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

std::vector<Finding> CommandInjectionRule::run(const ParsedSource& parsed, const ScanConfig& config) const {
    std::vector<Finding> findings;
    SinkDetector sink_detector(config.custom_sinks);
    SanitizerDetector sanitizer_detector(config.custom_sanitizers);

    TSNode root = parsed.root_node();
    if (ts_node_is_null(root)) {
        return findings;
    }

    // 1. Discover variables assigned from sanitizer functions
    std::unordered_set<std::string> sanitized_vars;
    std::unordered_map<std::string, std::pair<std::string, size_t>> assigned_dynamic;

    std::vector<TSNode> stack;
    stack.reserve(64);
    stack.push_back(root);

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

                // Check sanitizer call
                if (std::string_view(ts_node_type(right)) == "call") {
                    auto [is_san, _] = sanitizer_detector.is_sanitizer_call(right, parsed.source_code);
                    if (is_san) {
                        sanitized_vars.insert(var_name);
                    }
                }

                // Check dynamic construction
                auto [is_dyn, dyn_kind] = is_dynamic_string(right);
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
        auto [is_cmd, _] = sink_detector.is_command_sink(trace.sink_call, parsed.source_code);
        if (is_cmd) {
            taint_by_call[reinterpret_cast<uintptr_t>(trace.sink_call.id)] = &trace;
        }
    }

    // 3. Inspect command sinks in AST
    stack.clear();
    stack.push_back(root);
    while (!stack.empty()) {
        TSNode node = stack.back();
        stack.pop_back();

        if (std::string_view(ts_node_type(node)) == "call") {
            auto [is_cmd, call_name] = sink_detector.is_command_sink(node, parsed.source_code);
            if (is_cmd) {
                TSNode args = ts_node_child_by_field_name(node, "arguments", 9);
                if (ts_node_is_null(args)) {
                    uint32_t c = ts_node_child_count(node);
                    if (c >= 2) args = ts_node_child(node, 1);
                }

                if (!ts_node_is_null(args)) {
                    TSNode cmd_arg = TSNode{};
                    bool shell_arg_true = false;
                    uint32_t arg_count = ts_node_child_count(args);

                    for (uint32_t i = 0; i < arg_count; ++i) {
                        TSNode child = ts_node_child(args, i);
                        std::string_view ct = ts_node_type(child);
                        if (ct == "(" || ct == ")" || ct == ",") {
                            continue;
                        }

                        if (ct == "keyword_argument") {
                            TSNode kw_name = ts_node_child_by_field_name(child, "name", 4);
                            TSNode kw_val = ts_node_child_by_field_name(child, "value", 5);
                            if (ts_node_is_null(kw_name)) kw_name = ts_node_child(child, 0);
                            if (ts_node_is_null(kw_val)) {
                                uint32_t kvc = ts_node_child_count(child);
                                if (kvc >= 2) kw_val = ts_node_child(child, kvc - 1);
                            }
                            if (!ts_node_is_null(kw_name) && !ts_node_is_null(kw_val)) {
                                std::string_view kwn = parsed.get_node_text(kw_name);
                                std::string_view kwv = parsed.get_node_text(kw_val);
                                if (kwn == "shell" && (kwv == "True" || kwv == "1")) {
                                    shell_arg_true = true;
                                }
                            }
                        } else if (ts_node_is_null(cmd_arg)) {
                            cmd_arg = child;
                        }
                    }

                    if (!ts_node_is_null(cmd_arg)) {
                        bool is_subprocess = (call_name.find("subprocess") != std::string::npos);
                        std::string_view cmd_type = ts_node_type(cmd_arg);

                        // If subprocess without shell=True and cmd_arg is a list or tuple -> safe!
                        if (is_subprocess && !shell_arg_true && (cmd_type == "list" || cmd_type == "tuple")) {
                            goto next_node;
                        }

                        SourceLocation loc = get_loc(node, parsed.file_path);
                        std::string snippet = parsed.get_snippet(loc.line, loc.end_line);

                        // Check verified taint trace
                        auto it = taint_by_call.find(reinterpret_cast<uintptr_t>(node.id));
                        if (it != taint_by_call.end()) {
                            const TaintTrace* trace = it->second;
                            Severity sev = (call_name.find("os.system") != std::string::npos || shell_arg_true)
                                               ? Severity::Critical
                                               : severity();
                            std::string finding_id = std::string(rule_id()) + "-" + parsed.file_path + "-" +
                                                     std::to_string(loc.line) + "-" + std::to_string(loc.col);
                            findings.push_back(Finding{
                                .id = finding_id,
                                .rule_id = std::string(rule_id()),
                                .title = std::string(title()),
                                .description = "Call to '" + call_name + "' executes system command receiving tainted input from " +
                                               trace->source_node.label + " at line " + std::to_string(trace->source_node.location.line) + ".",
                                .severity = sev,
                                .confidence = Confidence::High,
                                .location = loc,
                                .snippet = snippet,
                                .evidence = "Tainted data reaches command execution in '" + call_name + "()'.",
                                .remediation = CMD_INJECTION_REMEDIATION,
                                .cwe = "CWE-78",
                                .dataflow = config.show_dataflow ? std::optional<DataFlowGraph>(trace->graph) : std::nullopt,
                                .metadata = {{"sink", call_name}, {"shell_true", shell_arg_true ? "true" : "false"}}
                            });
                            goto next_node;
                        }

                        // Subprocess with shell=True
                        if (is_subprocess && shell_arg_true) {
                            auto [is_dyn, dyn_kind] = is_dynamic_string(cmd_arg);
                            auto refs = get_referenced_names(cmd_arg, parsed.source_code);
                            bool all_san = !refs.empty();
                            for (const auto& r : refs) {
                                if (!sanitized_vars.count(r)) {
                                    all_san = false;
                                    break;
                                }
                            }
                            if (is_dyn && all_san) {
                                goto next_node;
                            }

                            std::string pattern_desc = is_dyn ? dyn_kind : "shell=True invocation";
                            std::string finding_id = std::string(rule_id()) + "-" + parsed.file_path + "-" +
                                                     std::to_string(loc.line) + "-" + std::to_string(loc.col);
                            findings.push_back(Finding{
                                .id = finding_id,
                                .rule_id = std::string(rule_id()),
                                .title = std::string(title()),
                                .description = "Subprocess call '" + call_name + "' uses 'shell=True' with " + pattern_desc + ".",
                                .severity = Severity::High,
                                .confidence = Confidence::Medium,
                                .location = loc,
                                .snippet = snippet,
                                .evidence = "Subprocess invoked with shell=True (" + pattern_desc + ").",
                                .remediation = CMD_INJECTION_REMEDIATION,
                                .cwe = "CWE-78",
                                .dataflow = std::nullopt,
                                .metadata = {{"sink", call_name}, {"shell_true", "true"}, {"pattern", pattern_desc}}
                            });
                            goto next_node;
                        }

                        // os.system or os.popen
                        if (call_name.find("os.system") != std::string::npos ||
                            call_name.find("os.popen") != std::string::npos ||
                            call_name == "system" || call_name == "popen") {
                            auto [is_dyn, dyn_kind] = is_dynamic_string(cmd_arg);
                            auto refs = get_referenced_names(cmd_arg, parsed.source_code);
                            bool all_san = !refs.empty();
                            for (const auto& r : refs) {
                                if (!sanitized_vars.count(r)) {
                                    all_san = false;
                                    break;
                                }
                            }
                            if (is_dyn && all_san) {
                                goto next_node;
                            }

                            if (is_dyn) {
                                std::string finding_id = std::string(rule_id()) + "-" + parsed.file_path + "-" +
                                                         std::to_string(loc.line) + "-" + std::to_string(loc.col);
                                findings.push_back(Finding{
                                    .id = finding_id,
                                    .rule_id = std::string(rule_id()),
                                    .title = std::string(title()),
                                    .description = "Call to '" + call_name + "' passes command constructed via " + dyn_kind + ".",
                                    .severity = Severity::High,
                                    .confidence = Confidence::Medium,
                                    .location = loc,
                                    .snippet = snippet,
                                    .evidence = "Command string constructed dynamically using " + dyn_kind + ".",
                                    .remediation = CMD_INJECTION_REMEDIATION,
                                    .cwe = "CWE-78",
                                    .dataflow = std::nullopt,
                                    .metadata = {{"sink", call_name}, {"pattern", dyn_kind}}
                                });
                                goto next_node;
                            }

                            if (std::string_view(ts_node_type(cmd_arg)) == "identifier") {
                                std::string var_name = std::string(parsed.get_node_text(cmd_arg));
                                auto var_it = assigned_dynamic.find(var_name);
                                if (var_it != assigned_dynamic.end()) {
                                    std::string finding_id = std::string(rule_id()) + "-" + parsed.file_path + "-" +
                                                             std::to_string(loc.line) + "-" + std::to_string(loc.col);
                                    findings.push_back(Finding{
                                        .id = finding_id,
                                        .rule_id = std::string(rule_id()),
                                        .title = std::string(title()),
                                        .description = "Call to '" + call_name + "' passes variable '" + var_name +
                                                       "' built via " + var_it->second.first + " at line " +
                                                       std::to_string(var_it->second.second) + ".",
                                        .severity = Severity::High,
                                        .confidence = Confidence::Medium,
                                        .location = loc,
                                        .snippet = snippet,
                                        .evidence = "Command variable '" + var_name + "' built via " + var_it->second.first + ".",
                                        .remediation = CMD_INJECTION_REMEDIATION,
                                        .cwe = "CWE-78",
                                        .dataflow = std::nullopt,
                                        .metadata = {{"sink", call_name}, {"variable", var_name}, {"pattern", var_it->second.first}}
                                    });
                                    goto next_node;
                                }
                            }

                            // Static literal or unassigned variable passed to shell API
                            std::string finding_id = std::string(rule_id()) + "-" + parsed.file_path + "-" +
                                                     std::to_string(loc.line) + "-" + std::to_string(loc.col);
                            findings.push_back(Finding{
                                .id = finding_id,
                                .rule_id = std::string(rule_id()),
                                .title = "Use of Risky Shell Execution API (os.system)",
                                .description = "Call to '" + call_name + "' executes a command via system shell. Prefer subprocess.run() with an argument list.",
                                .severity = Severity::Low,
                                .confidence = Confidence::Low,
                                .location = loc,
                                .snippet = snippet,
                                .evidence = "Command executed via shell-enabled '" + call_name + "()'.",
                                .remediation = CMD_INJECTION_REMEDIATION,
                                .cwe = "CWE-78",
                                .dataflow = std::nullopt,
                                .metadata = {{"sink", call_name}, {"pattern", "shell_call"}}
                            });
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

