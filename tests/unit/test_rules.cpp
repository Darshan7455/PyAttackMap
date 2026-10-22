#include <gtest/gtest.h>

#include <filesystem>
#include <iostream>

#include "pyattackmap/config.hpp"
#include "pyattackmap/parser.hpp"
#include "pyattackmap/rules/command_injection.hpp"
#include "pyattackmap/rules/sql_injection.hpp"
#include "pyattackmap/rules/unsafe_deserialization.hpp"

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

TEST(RulesTest, Pam001SqlInjectionVulnerableAndSafe) {
    auto fixtures = find_fixtures_dir();
    auto vuln_path = fixtures / "vulnerable" / "sql_injection.py";
    auto safe_path = fixtures / "safe" / "parameterized_sql.py";

    ASSERT_TRUE(std::filesystem::exists(vuln_path));
    ASSERT_TRUE(std::filesystem::exists(safe_path));

    SqlInjectionRule rule;
    ScanConfig config;
    config.min_severity = Severity::Low;

    // Vulnerable fixture
    ParsedSource vuln_parsed = SafeParser::parse_file(vuln_path);
    auto findings = rule.run(vuln_parsed, config);
    EXPECT_GE(findings.size(), 2u);
    for (const auto& f : findings) {
        EXPECT_EQ(f.rule_id, "PAM001");
        EXPECT_EQ(f.severity, Severity::High);
        EXPECT_EQ(f.cwe, "CWE-89");
    }

    // Safe fixture
    ParsedSource safe_parsed = SafeParser::parse_file(safe_path);
    auto safe_findings = rule.run(safe_parsed, config);
    EXPECT_EQ(safe_findings.size(), 0u);
}

TEST(RulesTest, Pam002CommandInjectionVulnerableAndSafe) {
    auto fixtures = find_fixtures_dir();
    auto vuln_path = fixtures / "vulnerable" / "command_injection.py";
    auto safe_path = fixtures / "safe" / "safe_subprocess.py";

    ASSERT_TRUE(std::filesystem::exists(vuln_path));
    ASSERT_TRUE(std::filesystem::exists(safe_path));

    CommandInjectionRule rule;
    ScanConfig config;
    config.min_severity = Severity::Low;

    // Vulnerable fixture
    ParsedSource vuln_parsed = SafeParser::parse_file(vuln_path);
    auto findings = rule.run(vuln_parsed, config);
    EXPECT_GE(findings.size(), 2u);
    for (const auto& f : findings) {
        EXPECT_EQ(f.rule_id, "PAM002");
        EXPECT_EQ(f.cwe, "CWE-78");
    }

    // Safe fixture
    ParsedSource safe_parsed = SafeParser::parse_file(safe_path);
    auto safe_findings = rule.run(safe_parsed, config);
    EXPECT_EQ(safe_findings.size(), 0u);
}

TEST(RulesTest, Pam003UnsafeDeserializationVulnerableAndSafe) {
    auto fixtures = find_fixtures_dir();
    auto vuln_path = fixtures / "vulnerable" / "unsafe_deserialization.py";
    auto safe_path = fixtures / "safe" / "safe_json.py";

    ASSERT_TRUE(std::filesystem::exists(vuln_path));
    ASSERT_TRUE(std::filesystem::exists(safe_path));

    UnsafeDeserializationRule rule;
    ScanConfig config;
    config.min_severity = Severity::Low;

    // Vulnerable fixture
    ParsedSource vuln_parsed = SafeParser::parse_file(vuln_path);
    auto findings = rule.run(vuln_parsed, config);
    EXPECT_GE(findings.size(), 2u);

    bool has_high_confidence = false;
    for (const auto& f : findings) {
        EXPECT_EQ(f.rule_id, "PAM003");
        EXPECT_EQ(f.cwe, "CWE-502");
        if (f.confidence == Confidence::High) {
            has_high_confidence = true;
        }
    }
    EXPECT_TRUE(has_high_confidence);

    // Safe fixture
    ParsedSource safe_parsed = SafeParser::parse_file(safe_path);
    auto safe_findings = rule.run(safe_parsed, config);
    EXPECT_EQ(safe_findings.size(), 0u);
}

