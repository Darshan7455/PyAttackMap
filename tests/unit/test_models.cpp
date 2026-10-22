#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>

#include "pyattackmap/models.hpp"
#include "pyattackmap/exceptions.hpp"

using namespace pyattackmap;

TEST(ModelsTest, SeverityOrderingAndParsing) {
    EXPECT_TRUE(Severity::Critical > Severity::High);
    EXPECT_TRUE(Severity::High > Severity::Medium);
    EXPECT_TRUE(Severity::Medium > Severity::Low);
    EXPECT_TRUE(Severity::Low > Severity::Info);

    EXPECT_EQ(severity_from_string("high"), Severity::High);
    EXPECT_EQ(severity_from_string("CRITICAL"), Severity::Critical);
    EXPECT_EQ(severity_from_string("medium"), Severity::Medium);
    EXPECT_EQ(severity_from_string("low"), Severity::Low);
    EXPECT_EQ(severity_from_string("info"), Severity::Info);

    EXPECT_THROW((void)severity_from_string("UNKNOWN"), ConfigException);
}

TEST(ModelsTest, ConfidenceParsing) {
    EXPECT_EQ(confidence_from_string("high"), Confidence::High);
    EXPECT_EQ(confidence_from_string("MEDIUM"), Confidence::Medium);
    EXPECT_EQ(confidence_from_string("low"), Confidence::Low);

    EXPECT_THROW((void)confidence_from_string("INVALID"), ConfigException);
}

TEST(ModelsTest, FindingAndGraphSerialization) {
    DataFlowNode n1{
        .id = "n1",
        .kind = DataFlowNodeKind::Source,
        .location = SourceLocation{.file = "app.py", .line = 10, .col = 4},
        .label = "input()",
        .snippet = "u = input()"
    };

    DataFlowNode n2{
        .id = "n2",
        .kind = DataFlowNodeKind::Sink,
        .location = SourceLocation{.file = "app.py", .line = 12, .col = 4},
        .label = "os.system()",
        .snippet = "os.system(u)"
    };

    DataFlowEdge edge{
        .source_id = "n1",
        .target_id = "n2",
        .label = "flows to"
    };

    DataFlowGraph graph{
        .nodes = {n1, n2},
        .edges = {edge}
    };

    std::string mermaid = graph.to_mermaid();
    EXPECT_NE(mermaid.find("flowchart TD"), std::string::npos);
    EXPECT_NE(mermaid.find("n1 -->|flows to| n2"), std::string::npos);

    Finding finding{
        .id = "F001",
        .rule_id = "PAM002",
        .title = "Command Injection",
        .description = "Vulnerable call",
        .severity = Severity::High,
        .confidence = Confidence::High,
        .location = SourceLocation{.file = "app.py", .line = 12, .col = 4, .end_line = 12, .end_col = 16},
        .snippet = "os.system(u)",
        .evidence = "Tainted var reaches sink",
        .remediation = "Use subprocess.run without shell",
        .cwe = "CWE-78",
        .dataflow = graph,
        .metadata = {{"sink", "os.system"}}
    };

    ScanStatistics stats;
    stats.files_scanned = 1;
    stats.total_findings = 1;

    AnalysisResult result({finding}, stats, {});

    EXPECT_EQ(result.size(), 1u);
    EXPECT_FALSE(result.empty());
    EXPECT_EQ(result[0].rule_id, "PAM002");

    auto high_findings = result.filter(Severity::High);
    EXPECT_EQ(high_findings.size(), 1u);

    auto critical_findings = result.filter(Severity::Critical);
    EXPECT_EQ(critical_findings.size(), 0u);

    auto pam002_findings = result.filter(std::nullopt, "PAM002");
    EXPECT_EQ(pam002_findings.size(), 1u);

    auto pam001_findings = result.filter(std::nullopt, "PAM001");
    EXPECT_EQ(pam001_findings.size(), 0u);

    std::string summary = result.summary();
    EXPECT_NE(summary.find("PyAttackMap Security Scan Summary"), std::string::npos);
    EXPECT_NE(summary.find("Total Findings: 1"), std::string::npos);
}

