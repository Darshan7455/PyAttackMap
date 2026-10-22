#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <nlohmann/json.hpp>

#include "pyattackmap/models.hpp"
#include "pyattackmap/reporting.hpp"

using namespace pyattackmap;

TEST(ReportingTest, TextReporterFormatting) {
    Finding finding{
        .id = "PAM001-test",
        .rule_id = "PAM001",
        .title = "SQL Injection",
        .description = "Dynamic query execution",
        .severity = Severity::High,
        .confidence = Confidence::High,
        .location = SourceLocation{.file = "app.py", .line = 15, .col = 4, .end_line = 15, .end_col = 20},
        .snippet = "cursor.execute(f'SELECT {x}')",
        .evidence = "Dynamic f-string in SQL execute",
        .remediation = "Use parameterized queries",
        .cwe = "CWE-89",
        .dataflow = std::nullopt,
        .metadata = {}
    };

    AnalysisError error{
        .file = "bad.py",
        .error_type = "ParseError",
        .message = "Syntax error at line 1",
        .line = 1
    };

    ScanStatistics stats;
    stats.files_scanned = 2;
    stats.parse_errors = 1;
    stats.total_findings = 1;

    AnalysisResult result({finding}, stats, {error});

    std::string formatted = TextReporter::format_result(result);
    EXPECT_NE(formatted.find("PyAttackMap Security Scan Summary"), std::string::npos);
    EXPECT_NE(formatted.find("Analysis / Parse Errors"), std::string::npos);
    EXPECT_NE(formatted.find("bad.py:1: Syntax error"), std::string::npos);
    EXPECT_NE(formatted.find("[HIGH] PAM001: SQL Injection"), std::string::npos);
    EXPECT_NE(formatted.find("cursor.execute"), std::string::npos);
}

TEST(ReportingTest, JsonReporterFileWrite) {
    ScanStatistics stats;
    stats.files_scanned = 5;
    stats.total_findings = 0;

    AnalysisResult result({}, stats, {});

    std::filesystem::path out_file = std::filesystem::temp_directory_path() / "pam_report_test.json";
    std::string written = JsonReporter::write_to_file(result, out_file);

    EXPECT_TRUE(std::filesystem::exists(out_file));
    EXPECT_EQ(written, out_file.string());

    std::ifstream in(out_file);
    nlohmann::json data;
    in >> data;

    EXPECT_EQ(data["tool"], "PyAttackMap");
    EXPECT_EQ(data["version"], "0.2.0");
    EXPECT_TRUE(data.contains("statistics"));
    EXPECT_TRUE(data.contains("findings"));
    EXPECT_TRUE(data.contains("errors"));

    std::error_code ec;
    std::filesystem::remove(out_file, ec);
}

