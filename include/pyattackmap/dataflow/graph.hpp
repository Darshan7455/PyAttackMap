#pragma once

#include <string>
#include <vector>

#include "pyattackmap/models.hpp"

namespace pyattackmap {

class DataFlowGraphBuilder {
public:
    explicit DataFlowGraphBuilder(std::string file_path) : file_path_(std::move(file_path)) {}

    DataFlowNode add_node(DataFlowNodeKind kind, SourceLocation loc, std::string label, std::string snippet = "");
    DataFlowEdge add_edge(std::string source_id, std::string target_id, std::string label = "");

    [[nodiscard]] DataFlowGraph build() const;

private:
    std::string file_path_;
    std::vector<DataFlowNode> nodes_;
    std::vector<DataFlowEdge> edges_;
    size_t node_counter_ = 0;
};

} // namespace pyattackmap

