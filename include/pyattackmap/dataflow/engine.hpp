#pragma once

#include <string>
#include <unordered_map>
#include <vector>

#include <tree_sitter/api.h>

#include "pyattackmap/config.hpp"
#include "pyattackmap/dataflow/graph.hpp"
#include "pyattackmap/dataflow/sanitizers.hpp"
#include "pyattackmap/dataflow/sinks.hpp"
#include "pyattackmap/dataflow/sources.hpp"
#include "pyattackmap/models.hpp"
#include "pyattackmap/parser.hpp"

namespace pyattackmap {

struct TaintTrace {
    TSNode sink_call;
    std::string sink_name;
    DataFlowNode source_node;
    std::vector<DataFlowNode> propagation_nodes;
    DataFlowNode sink_node;
    DataFlowGraph graph;
    TSNode tainted_arg;
};

struct VariableTaint {
    std::string name;
    DataFlowNode source_node;
    std::vector<DataFlowNode> trace;
};

class ScopeTaintState {
public:
    void set_taint(std::string var_name, DataFlowNode source_node, std::vector<DataFlowNode> trace);
    void clear_taint(const std::string& var_name);
    [[nodiscard]] const VariableTaint* get_taint(const std::string& var_name) const;

private:
    std::unordered_map<std::string, VariableTaint> tainted_vars_;
};

class IntraProceduralTaintTracker {
public:
    IntraProceduralTaintTracker(const ParsedSource& parsed, const ScanConfig& config);

    [[nodiscard]] std::vector<TaintTrace> analyze() const;

private:
    const ParsedSource& parsed_;
    const ScanConfig& config_;
    SourceDetector source_detector_;
    SinkDetector sink_detector_;
    SanitizerDetector sanitizer_detector_;

    void analyze_statements(TSNode block_node, std::vector<TaintTrace>& traces) const;
    void handle_assignment(TSNode assign_node, ScopeTaintState& state, DataFlowGraphBuilder& builder) const;
    void handle_augmented_assignment(TSNode aug_node, ScopeTaintState& state, DataFlowGraphBuilder& builder) const;

    [[nodiscard]] std::tuple<bool, std::optional<DataFlowNode>, std::vector<DataFlowNode>>
    evaluate_taint(TSNode expr_node, const ScopeTaintState& state, DataFlowGraphBuilder& builder) const;

    [[nodiscard]] std::optional<TaintTrace>
    check_call_sink(TSNode call_node, const ScopeTaintState& state, DataFlowGraphBuilder& builder) const;
};

} // namespace pyattackmap

