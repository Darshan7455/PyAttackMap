#include "pyattackmap/dataflow/engine.hpp"

#include <iostream>
#include <queue>

namespace pyattackmap {

DataFlowNode DataFlowGraphBuilder::add_node(
    DataFlowNodeKind kind,
    SourceLocation loc,
    std::string label,
    std::string snippet) {
    node_counter_++;
    std::string id = "node_" + std::to_string(node_counter_);
    DataFlowNode node{
        .id = id,
        .kind = kind,
        .location = std::move(loc),
        .label = std::move(label),
        .snippet = std::move(snippet)
    };
    nodes_.push_back(node);
    return node;
}

DataFlowEdge DataFlowGraphBuilder::add_edge(std::string source_id, std::string target_id, std::string label) {
    DataFlowEdge edge{
        .source_id = std::move(source_id),
        .target_id = std::move(target_id),
        .label = std::move(label)
    };
    edges_.push_back(edge);
    return edge;
}

DataFlowGraph DataFlowGraphBuilder::build() const {
    return DataFlowGraph{
        .nodes = nodes_,
        .edges = edges_
    };
}

void ScopeTaintState::set_taint(std::string var_name, DataFlowNode source_node, std::vector<DataFlowNode> trace) {
    std::string key = var_name;
    tainted_vars_.insert_or_assign(std::move(key), VariableTaint{
        .name = var_name,
        .source_node = std::move(source_node),
        .trace = std::move(trace)
    });
}

void ScopeTaintState::clear_taint(const std::string& var_name) {
    tainted_vars_.erase(var_name);
}

const VariableTaint* ScopeTaintState::get_taint(const std::string& var_name) const {
    auto it = tainted_vars_.find(var_name);
    if (it != tainted_vars_.end()) {
        return &it->second;
    }
    return nullptr;
}

static SourceLocation make_location(TSNode node, const std::string& file_path) {
    TSPoint start = ts_node_start_point(node);
    TSPoint end = ts_node_end_point(node);
    return SourceLocation{
        .file = file_path,
        .line = start.row + 1,
        .col = start.column,
        .end_line = end.row + 1,
        .end_col = end.column
    };
}

IntraProceduralTaintTracker::IntraProceduralTaintTracker(const ParsedSource& parsed, const ScanConfig& config)
    : parsed_(parsed),
      config_(config),
      source_detector_(config.custom_sources),
      sink_detector_(config.custom_sinks),
      sanitizer_detector_(config.custom_sanitizers) {}

std::vector<TaintTrace> IntraProceduralTaintTracker::analyze() const {
    std::vector<TaintTrace> traces;
    TSNode root = parsed_.root_node();
    if (ts_node_is_null(root)) {
        return traces;
    }

    // 1. Analyze top-level module statements (skipping nested functions/classes)
    analyze_statements(root, traces);

    // 2. Walk AST to find all function definitions and analyze their bodies
    std::vector<TSNode> stack;
    stack.reserve(64);
    stack.push_back(root);

    while (!stack.empty()) {
        TSNode current = stack.back();
        stack.pop_back();

        std::string_view type = ts_node_type(current);
        if (type == "function_definition") {
            TSNode body = ts_node_child_by_field_name(current, "body", 4);
            if (!ts_node_is_null(body)) {
                analyze_statements(body, traces);
            }
        }

        uint32_t count = ts_node_child_count(current);
        for (uint32_t i = 0; i < count; ++i) {
            stack.push_back(ts_node_child(current, i));
        }
    }

    return traces;
}

void IntraProceduralTaintTracker::analyze_statements(TSNode block_node, std::vector<TaintTrace>& traces) const {
    DataFlowGraphBuilder builder(parsed_.file_path);
    ScopeTaintState state;

    uint32_t count = ts_node_child_count(block_node);
    for (uint32_t i = 0; i < count; ++i) {
        TSNode stmt = ts_node_child(block_node, i);
        std::string_view type = ts_node_type(stmt);

        // Do not process nested function/class definitions as statements in this scope
        if (type == "function_definition" || type == "class_definition") {
            continue;
        }

        // Handle assignment: x = ...
        if (type == "assignment") {
            handle_assignment(stmt, state, builder);
        } else if (type == "augmented_assignment") {
            handle_augmented_assignment(stmt, state, builder);
        } else if (type == "expression_statement") {
            uint32_t inner_count = ts_node_child_count(stmt);
            for (uint32_t j = 0; j < inner_count; ++j) {
                TSNode child = ts_node_child(stmt, j);
                std::string_view child_type = ts_node_type(child);
                if (child_type == "assignment") {
                    handle_assignment(child, state, builder);
                } else if (child_type == "augmented_assignment") {
                    handle_augmented_assignment(child, state, builder);
                }
            }
        }

        // Walk expressions inside statement looking for sink calls
        std::vector<TSNode> expr_stack;
        expr_stack.reserve(32);
        expr_stack.push_back(stmt);

        while (!expr_stack.empty()) {
            TSNode node = expr_stack.back();
            expr_stack.pop_back();

            if (std::string_view(ts_node_type(node)) == "call") {
                auto trace = check_call_sink(node, state, builder);
                if (trace) {
                    traces.push_back(std::move(*trace));
                }
            }

            uint32_t num_children = ts_node_child_count(node);
            for (uint32_t j = 0; j < num_children; ++j) {
                expr_stack.push_back(ts_node_child(node, j));
            }
        }
    }
}

void IntraProceduralTaintTracker::handle_assignment(
    TSNode assign_node,
    ScopeTaintState& state,
    DataFlowGraphBuilder& builder) const {
    TSNode left = ts_node_child_by_field_name(assign_node, "left", 4);
    TSNode right = ts_node_child_by_field_name(assign_node, "right", 5);

    if (ts_node_is_null(left)) left = ts_node_child(assign_node, 0);
    if (ts_node_is_null(right)) {
        uint32_t c = ts_node_child_count(assign_node);
        if (c >= 3) right = ts_node_child(assign_node, c - 1);
    }

    if (ts_node_is_null(left) || ts_node_is_null(right)) {
        return;
    }

    auto [is_tainted, src_node, trace_nodes] = evaluate_taint(right, state, builder);

    std::string_view left_type = ts_node_type(left);
    if (left_type == "identifier") {
        std::string var_name = std::string(parsed_.get_node_text(left));
        if (is_tainted && src_node) {
            SourceLocation loc = make_location(assign_node, parsed_.file_path);
            std::string snippet = parsed_.get_snippet(loc.line, loc.end_line);
            DataFlowNode prop_node = builder.add_node(
                DataFlowNodeKind::Propagation,
                loc,
                "Assign tainted expression to '" + var_name + "'",
                snippet
            );
            auto new_trace = trace_nodes;
            new_trace.push_back(prop_node);
            state.set_taint(var_name, *src_node, std::move(new_trace));
        } else {
            state.clear_taint(var_name);
        }
    }
}

void IntraProceduralTaintTracker::handle_augmented_assignment(
    TSNode aug_node,
    ScopeTaintState& state,
    DataFlowGraphBuilder& builder) const {
    TSNode left = ts_node_child_by_field_name(aug_node, "left", 4);
    TSNode right = ts_node_child_by_field_name(aug_node, "right", 5);

    if (ts_node_is_null(left)) left = ts_node_child(aug_node, 0);
    if (ts_node_is_null(right)) {
        uint32_t c = ts_node_child_count(aug_node);
        if (c >= 3) right = ts_node_child(aug_node, c - 1);
    }

    if (ts_node_is_null(left) || ts_node_is_null(right)) {
        return;
    }

    std::string_view left_type = ts_node_type(left);
    if (left_type == "identifier") {
        std::string var_name = std::string(parsed_.get_node_text(left));
        auto [is_tainted, src_node, trace_nodes] = evaluate_taint(right, state, builder);
        const auto* cur_taint = state.get_taint(var_name);

        if (is_tainted && src_node) {
            SourceLocation loc = make_location(aug_node, parsed_.file_path);
            std::string snippet = parsed_.get_snippet(loc.line, loc.end_line);
            DataFlowNode prop_node = builder.add_node(
                DataFlowNodeKind::Propagation,
                loc,
                "Augmented assign to '" + var_name + "'",
                snippet
            );
            auto new_trace = trace_nodes;
            new_trace.push_back(prop_node);
            state.set_taint(var_name, *src_node, std::move(new_trace));
        } else if (cur_taint) {
            SourceLocation loc = make_location(aug_node, parsed_.file_path);
            std::string snippet = parsed_.get_snippet(loc.line, loc.end_line);
            DataFlowNode prop_node = builder.add_node(
                DataFlowNodeKind::Propagation,
                loc,
                "Augmented assign on tainted '" + var_name + "'",
                snippet
            );
            auto new_trace = cur_taint->trace;
            new_trace.push_back(prop_node);
            state.set_taint(var_name, cur_taint->source_node, std::move(new_trace));
        }
    }
}

std::tuple<bool, std::optional<DataFlowNode>, std::vector<DataFlowNode>>
IntraProceduralTaintTracker::evaluate_taint(
    TSNode expr_node,
    const ScopeTaintState& state,
    DataFlowGraphBuilder& builder) const {
    if (ts_node_is_null(expr_node)) {
        return {false, std::nullopt, {}};
    }

    // 1. Direct source check
    auto [is_src, src_desc] = source_detector_.is_source(expr_node, parsed_.source_code);
    if (is_src) {
        SourceLocation loc = make_location(expr_node, parsed_.file_path);
        std::string snippet = parsed_.get_snippet(loc.line, loc.end_line);
        DataFlowNode src_node = builder.add_node(
            DataFlowNodeKind::Source,
            loc,
            "Taint source (" + src_desc + ")",
            snippet
        );
        return {true, src_node, {src_node}};
    }

    std::string_view type = ts_node_type(expr_node);

    // 2. Sanitizer check
    if (type == "call") {
        auto [is_san, san_name] = sanitizer_detector_.is_sanitizer_call(expr_node, parsed_.source_code);
        if (is_san) {
            // Taint is neutralized
            return {false, std::nullopt, {}};
        }
    }

    // 3. Variable reference (identifier)
    if (type == "identifier") {
        std::string var_name = std::string(parsed_.get_node_text(expr_node));
        const auto* taint = state.get_taint(var_name);
        if (taint) {
            return {true, taint->source_node, taint->trace};
        }
        return {false, std::nullopt, {}};
    }

    // 4. Binary operations (e.g. "SELECT " + var or "cmd %s" % var)
    if (type == "binary_operator") {
        TSNode left = ts_node_child_by_field_name(expr_node, "left", 4);
        TSNode right = ts_node_child_by_field_name(expr_node, "right", 5);
        if (ts_node_is_null(left)) left = ts_node_child(expr_node, 0);
        if (ts_node_is_null(right)) {
            uint32_t c = ts_node_child_count(expr_node);
            if (c >= 3) right = ts_node_child(expr_node, c - 1);
        }

        auto [l_taint, l_src, l_trace] = evaluate_taint(left, state, builder);
        if (l_taint) return {true, l_src, l_trace};

        auto [r_taint, r_src, r_trace] = evaluate_taint(right, state, builder);
        if (r_taint) return {true, r_src, r_trace};

        return {false, std::nullopt, {}};
    }

    // 5. String interpolation / f-string / formatted string
    // In Tree-sitter python, formatted strings contain `interpolation` nodes
    if (type == "string" || type == "concatenated_string") {
        uint32_t c = ts_node_child_count(expr_node);
        for (uint32_t i = 0; i < c; ++i) {
            TSNode child = ts_node_child(expr_node, i);
            if (std::string_view(ts_node_type(child)) == "interpolation") {
                uint32_t inner_c = ts_node_child_count(child);
                for (uint32_t j = 0; j < inner_c; ++j) {
                    TSNode expr = ts_node_child(child, j);
                    std::string_view inner_type = ts_node_type(expr);
                    if (inner_type != "{" && inner_type != "}") {
                        auto [t, s, tr] = evaluate_taint(expr, state, builder);
                        if (t) return {true, s, tr};
                    }
                }
            }
        }
    }

    // 6. Call to .format(...)
    if (type == "call") {
        TSNode func = ts_node_child_by_field_name(expr_node, "function", 8);
        if (ts_node_is_null(func)) func = ts_node_child(expr_node, 0);
        if (std::string_view(ts_node_type(func)) == "attribute") {
            TSNode attr = ts_node_child_by_field_name(func, "attribute", 9);
            if (parsed_.get_node_text(attr) == "format") {
                TSNode args = ts_node_child_by_field_name(expr_node, "arguments", 9);
                if (ts_node_is_null(args)) {
                    uint32_t count = ts_node_child_count(expr_node);
                    if (count >= 2) args = ts_node_child(expr_node, 1);
                }
                if (!ts_node_is_null(args)) {
                    uint32_t arg_count = ts_node_child_count(args);
                    for (uint32_t i = 0; i < arg_count; ++i) {
                        TSNode arg = ts_node_child(args, i);
                        auto [t, s, tr] = evaluate_taint(arg, state, builder);
                        if (t) return {true, s, tr};
                    }
                }
            }
        }
    }

    return {false, std::nullopt, {}};
}

std::optional<TaintTrace> IntraProceduralTaintTracker::check_call_sink(
    TSNode call_node,
    const ScopeTaintState& state,
    DataFlowGraphBuilder& builder) const {
    std::string sink_name;
    bool is_sink = false;

    auto [is_sql, sql_name] = sink_detector_.is_sql_sink(call_node, parsed_.source_code);
    if (is_sql) {
        is_sink = true;
        sink_name = sql_name;
    } else {
        auto [is_cmd, cmd_name] = sink_detector_.is_command_sink(call_node, parsed_.source_code);
        if (is_cmd) {
            is_sink = true;
            sink_name = cmd_name;
        } else {
            auto [is_deser, deser_name] = sink_detector_.is_deserialization_sink(call_node, parsed_.source_code);
            if (is_deser) {
                is_sink = true;
                sink_name = deser_name;
            }
        }
    }

    if (!is_sink) {
        return std::nullopt;
    }

    TSNode args = ts_node_child_by_field_name(call_node, "arguments", 9);
    if (ts_node_is_null(args)) {
        uint32_t count = ts_node_child_count(call_node);
        if (count >= 2) args = ts_node_child(call_node, 1);
    }
    if (ts_node_is_null(args)) {
        return std::nullopt;
    }

    uint32_t arg_count = ts_node_child_count(args);
    for (uint32_t i = 0; i < arg_count; ++i) {
        TSNode arg = ts_node_child(args, i);
        std::string_view arg_type = ts_node_type(arg);
        if (arg_type == "(" || arg_type == ")" || arg_type == ",") {
            continue;
        }

        TSNode actual_expr = arg;
        if (arg_type == "keyword_argument") {
            TSNode val = ts_node_child_by_field_name(arg, "value", 5);
            if (!ts_node_is_null(val)) {
                actual_expr = val;
            }
        }

        auto [is_t, src_node, trace] = evaluate_taint(actual_expr, state, builder);
        if (is_t && src_node) {
            SourceLocation loc = make_location(call_node, parsed_.file_path);
            std::string snippet = parsed_.get_snippet(loc.line, loc.end_line);

            DataFlowNode sink_node = builder.add_node(
                DataFlowNodeKind::Sink,
                loc,
                "Sink call '" + sink_name + "' receives tainted data",
                snippet
            );

            // Construct isolated graph for this trace
            std::vector<DataFlowNode> trace_nodes = {*src_node};
            std::vector<DataFlowNode> prop_nodes;
            std::vector<DataFlowEdge> trace_edges;
            std::unordered_set<std::string> seen_ids = {src_node->id};
            std::string current_id = src_node->id;

            for (const auto& p : trace) {
                if (!seen_ids.count(p.id)) {
                    seen_ids.insert(p.id);
                    trace_nodes.push_back(p);
                    prop_nodes.push_back(p);
                    trace_edges.push_back(DataFlowEdge{
                        .source_id = current_id,
                        .target_id = p.id,
                        .label = "propagates"
                    });
                    current_id = p.id;
                }
            }

            trace_nodes.push_back(sink_node);
            trace_edges.push_back(DataFlowEdge{
                .source_id = current_id,
                .target_id = sink_node.id,
                .label = "reaches sink"
            });

            DataFlowGraph graph{
                .nodes = std::move(trace_nodes),
                .edges = std::move(trace_edges)
            };

            return TaintTrace{
                .sink_call = call_node,
                .sink_name = std::move(sink_name),
                .source_node = *src_node,
                .propagation_nodes = std::move(prop_nodes),
                .sink_node = sink_node,
                .graph = std::move(graph),
                .tainted_arg = actual_expr
            };
        }
    }

    return std::nullopt;
}

} // namespace pyattackmap

