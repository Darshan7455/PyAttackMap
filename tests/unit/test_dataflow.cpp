#include <gtest/gtest.h>

#include "pyattackmap/config.hpp"
#include "pyattackmap/dataflow/engine.hpp"
#include "pyattackmap/models.hpp"
#include "pyattackmap/parser.hpp"

using namespace pyattackmap;

TEST(DataFlowTest, TaintPropagationLinear) {
    std::string code = R"(
import os

def handle():
    user_val = input("Name: ")
    cmd = "echo " + user_val
    os.system(cmd)
)";
    ParsedSource parsed = SafeParser::parse_string(code, "test_flow.py");
    IntraProceduralTaintTracker tracker(parsed, ScanConfig{});
    auto traces = tracker.analyze();

    ASSERT_EQ(traces.size(), 1u);
    const auto& trace = traces[0];
    EXPECT_EQ(trace.sink_name, "os.system");
    EXPECT_EQ(trace.source_node.kind, DataFlowNodeKind::Source);
    EXPECT_NE(trace.source_node.label.find("input"), std::string::npos);
    EXPECT_GE(trace.propagation_nodes.size(), 1u);
    EXPECT_EQ(trace.sink_node.kind, DataFlowNodeKind::Sink);
}

TEST(DataFlowTest, TaintClearedBySanitizer) {
    std::string code = R"(
import os
import shlex

def handle_safe():
    user_val = input("Name: ")
    safe_val = shlex.quote(user_val)
    cmd = "echo " + safe_val
    os.system(cmd)
)";
    ParsedSource parsed = SafeParser::parse_string(code, "test_sanitizer.py");
    IntraProceduralTaintTracker tracker(parsed, ScanConfig{});
    auto traces = tracker.analyze();

    EXPECT_EQ(traces.size(), 0u);
}

TEST(DataFlowTest, TaintClearedByConstantReassignment) {
    std::string code = R"(
import os

def handle_overwrite():
    val = input()
    val = "constant_safe_value"
    os.system(val)
)";
    ParsedSource parsed = SafeParser::parse_string(code, "test_overwrite.py");
    IntraProceduralTaintTracker tracker(parsed, ScanConfig{});
    auto traces = tracker.analyze();

    EXPECT_EQ(traces.size(), 0u);
}

