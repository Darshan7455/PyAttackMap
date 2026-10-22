#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>

#include "pyattackmap/analyzer.hpp"
#include "pyattackmap/config.hpp"
#include "pyattackmap/models.hpp"

using namespace pyattackmap;

static std::filesystem::path find_fixtures_dir() {
    std::vector<std::filesystem::path> candidates = {
        "tests/fixtures",
        "../tests/fixtures",
        "../../tests/fixtures",
        "../../../tests/fixtures"
    };
    for (const auto& p : candidates) {
        if (std::filesystem::is_directory(p)) {
            return std::filesystem::canonical(p);
        }
    }
    return "tests/fixtures";
}

TEST(AnalyzerTest, ScanDirectory) {
    auto fixtures = find_fixtures_dir();
    ASSERT_TRUE(std::filesystem::exists(fixtures));

    ScanConfig config;
    config.min_severity = Severity::Low;
    Analyzer analyzer(config);

    AnalysisResult result = analyzer.scan(fixtures);

    EXPECT_GE(result.statistics().files_scanned, 6u);
    EXPECT_GE(result.findings().size(), 6u);
    EXPECT_EQ(result.statistics().parse_errors, 0u);
    EXPECT_GT(result.statistics().duration_seconds, 0.0);
}

TEST(AnalyzerTest, ScanFile) {
    auto fixtures = find_fixtures_dir();
    auto vuln_sql = fixtures / "vulnerable" / "sql_injection.py";
    ASSERT_TRUE(std::filesystem::exists(vuln_sql));

    Analyzer analyzer;
    AnalysisResult result = analyzer.scan_file(vuln_sql);

    EXPECT_EQ(result.statistics().files_scanned, 1u);
    EXPECT_GE(result.findings().size(), 2u);
}

TEST(AnalyzerTest, FileExclusions) {
    auto fixtures = find_fixtures_dir();
    ASSERT_TRUE(std::filesystem::exists(fixtures));

    ScanConfig config;
    config.min_severity = Severity::Low;
    config.exclude = {"vulnerable", "vulnerable/*"};

    Analyzer analyzer(config);
    AnalysisResult result = analyzer.scan(fixtures);

    // Only safe fixtures scanned, 0 findings
    EXPECT_EQ(result.findings().size(), 0u);
    EXPECT_GE(result.statistics().files_scanned, 3u);
}

TEST(AnalyzerTest, HandlesSyntaxErrorGracefully) {
    std::filesystem::path tmp_dir = std::filesystem::temp_directory_path() / "pam_syntax_err_test";
    std::filesystem::create_directories(tmp_dir);

    std::filesystem::path good = tmp_dir / "good.py";
    std::filesystem::path bad = tmp_dir / "bad.py";

    {
        std::ofstream og(good);
        og << "import os\nos.system('ls')\n";
    }
    {
        std::ofstream ob(bad);
        ob << "def broken(:\n    pass\n";
    }

    Analyzer analyzer;
    AnalysisResult result = analyzer.scan(tmp_dir);

    EXPECT_EQ(result.statistics().files_scanned, 2u);
    EXPECT_EQ(result.statistics().parse_errors, 1u);
    EXPECT_EQ(result.errors().size(), 1u);
    EXPECT_EQ(result.errors()[0].error_type, "ParseError");
    EXPECT_GE(result.findings().size(), 1u);

    std::error_code ec;
    std::filesystem::remove_all(tmp_dir, ec);
}

