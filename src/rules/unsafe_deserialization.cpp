#include "pyattackmap/rules/unsafe_deserialization.hpp"

#include <queue>
#include <unordered_map>

#include "pyattackmap/dataflow/engine.hpp"
#include "pyattackmap/dataflow/sinks.hpp"

namespace pyattackmap {

static const char* DESERIALIZATION_REMEDIATION =
    "Avoid using pickle for untrusted or external input. Use safe data interchange formats "
    "such as JSON, Protocol Buffers, or HMAC-signed serializers.\n"
    "Example (Safe Serialization):\n"
    "    import json\n"
    "    # Safe structured data deserialization:\n"
    "    data = json.loads(payload)";

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

std::vector<Finding> UnsafeDeserializationRule::run(const ParsedSource& parsed, const ScanConfig& config) const {
    std::vector<Finding> findings;
    SinkDetector sink_detector(config.custom_sinks);

    TSNode root = parsed.root_node();
    if (ts_node_is_null(root)) {
        return findings;
    }

    // 1. Taint analysis to check if deserialized data originates from an untrusted source
    IntraProceduralTaintTracker tracker(parsed, config);
    std::vector<TaintTrace> traces = tracker.analyze();

    std::unordered_map<uintptr_t, const TaintTrace*> taint_by_call;
    for (const auto& trace : traces) {
        auto [is_deser, _] = sink_detector.is_deserialization_sink(trace.sink_call, parsed.source_code);
        if (is_deser) {
            taint_by_call[reinterpret_cast<uintptr_t>(trace.sink_call.id)] = &trace;
        }
    }

    // 2. Inspect deserialization calls in AST
    std::vector<TSNode> stack;
    stack.reserve(64);
    stack.push_back(root);

    while (!stack.empty()) {
        TSNode node = stack.back();
        stack.pop_back();

        if (std::string_view(ts_node_type(node)) == "call") {
            auto [is_deser, call_name] = sink_detector.is_deserialization_sink(node, parsed.source_code);
            if (is_deser) {
                TSNode args = ts_node_child_by_field_name(node, "arguments", 9);
                if (ts_node_is_null(args)) {
                    uint32_t c = ts_node_child_count(node);
                    if (c >= 2) args = ts_node_child(node, 1);
                }

                bool has_args = false;
                if (!ts_node_is_null(args)) {
                    uint32_t count = ts_node_child_count(args);
                    for (uint32_t i = 0; i < count; ++i) {
                        std::string_view ct = ts_node_type(ts_node_child(args, i));
                        if (ct != "(" && ct != ")" && ct != ",") {
                            has_args = true;
                            break;
                        }
                    }
                }

                if (has_args) {
                    SourceLocation loc = get_loc(node, parsed.file_path);
                    std::string snippet = parsed.get_snippet(loc.line, loc.end_line);

                    auto it = taint_by_call.find(reinterpret_cast<uintptr_t>(node.id));
                    std::string finding_id = std::string(rule_id()) + "-" + parsed.file_path + "-" +
                                             std::to_string(loc.line) + "-" + std::to_string(loc.col);

                    if (it != taint_by_call.end()) {
                        const TaintTrace* trace = it->second;
                        findings.push_back(Finding{
                            .id = finding_id,
                            .rule_id = std::string(rule_id()),
                            .title = std::string(title()),
                            .description = "Call to '" + call_name + "' deserializes untrusted data originating from " +
                                           trace->source_node.label + " at line " + std::to_string(trace->source_node.location.line) + ".",
                            .severity = Severity::Critical,
                            .confidence = Confidence::High,
                            .location = loc,
                            .snippet = snippet,
                            .evidence = "Untrusted tainted payload deserialized by '" + call_name + "()'.",
                            .remediation = DESERIALIZATION_REMEDIATION,
                            .cwe = "CWE-502",
                            .dataflow = config.show_dataflow ? std::optional<DataFlowGraph>(trace->graph) : std::nullopt,
                            .metadata = {{"sink", call_name}, {"taint_verified", "true"}}
                        });
                    } else {
                        findings.push_back(Finding{
                            .id = finding_id,
                            .rule_id = std::string(rule_id()),
                            .title = std::string(title()),
                            .description = "Potentially unsafe call to '" + call_name + "' without verified input isolation.",
                            .severity = severity(),
                            .confidence = Confidence::Medium,
                            .location = loc,
                            .snippet = snippet,
                            .evidence = "Call to '" + call_name + "()' may be vulnerable if input is attacker-controlled.",
                            .remediation = DESERIALIZATION_REMEDIATION,
                            .cwe = "CWE-502",
                            .dataflow = std::nullopt,
                            .metadata = {{"sink", call_name}, {"taint_verified", "false"}}
                        });
                    }
                }
            }
        }

        uint32_t count = ts_node_child_count(node);
        for (uint32_t i = 0; i < count; ++i) {
            stack.push_back(ts_node_child(node, i));
        }
    }

    return findings;
}

} // namespace pyattackmap

