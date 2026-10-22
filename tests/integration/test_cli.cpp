#include <gtest/gtest.h>

#include <array>
#include <cstdio>
#include <filesystem>
#include <iostream>
#include <memory>
#include <string>

static std::filesystem::path find_binary() {
    std::vector<std::filesystem::path> candidates = {
        "pyattackmap.exe",
        "../pyattackmap.exe",
        "../../pyattackmap.exe",
        "build/release/pyattackmap.exe",
        "./pyattackmap",
        "../pyattackmap",
        "../../pyattackmap",
        "build/release/pyattackmap"
    };
    for (const auto& p : candidates) {
        if (std::filesystem::is_regular_file(p)) {
            return std::filesystem::canonical(p);
        }
    }
    return "pyattackmap.exe";
}

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

struct ExecResult {
    int exit_code;
    std::string output;
};

static ExecResult run_cli(const std::string& args) {
    std::filesystem::path bin = find_binary();
#if defined(_WIN32)
    std::string cmd = "\"\"" + bin.string() + "\" " + args + " 2>&1\"";
    FILE* pipe = _popen(cmd.c_str(), "r");
#else
    std::string cmd = "\"" + bin.string() + "\" " + args + " 2>&1";
    FILE* pipe = popen(cmd.c_str(), "r");
#endif

    if (!pipe) {
        return {-1, "Failed to run command"};
    }
    std::array<char, 256> buffer;
    std::string result;
    while (fgets(buffer.data(), static_cast<int>(buffer.size()), pipe) != nullptr) {
        result += buffer.data();
    }
#if defined(_WIN32)
    int status = _pclose(pipe);
#else
    int status = pclose(pipe);
    if (WIFEXITED(status)) {
        status = WEXITSTATUS(status);
    }
#endif
    return {status, result};
}

TEST(CliTest, RulesCommand) {
    auto res = run_cli("rules");
    EXPECT_EQ(res.exit_code, 0);
    EXPECT_NE(res.output.find("PAM001"), std::string::npos);
    EXPECT_NE(res.output.find("PAM002"), std::string::npos);
    EXPECT_NE(res.output.find("PAM003"), std::string::npos);
}

TEST(CliTest, ScanClean) {
    auto fixtures = find_fixtures_dir();
    auto safe_dir = fixtures / "safe";
    ASSERT_TRUE(std::filesystem::exists(safe_dir));

    auto res = run_cli("scan \"" + safe_dir.string() + "\"");
    EXPECT_EQ(res.exit_code, 0);
    EXPECT_NE(res.output.find("Total Findings: 0"), std::string::npos);
}

TEST(CliTest, ScanFindings) {
    auto fixtures = find_fixtures_dir();
    auto vuln_dir = fixtures / "vulnerable";
    ASSERT_TRUE(std::filesystem::exists(vuln_dir));

    auto res = run_cli("scan \"" + vuln_dir.string() + "\"");
    EXPECT_EQ(res.exit_code, 1); // EXIT_FINDINGS_FOUND
    EXPECT_NE(res.output.find("PAM001"), std::string::npos);
}

TEST(CliTest, ScanInvalidPath) {
    auto res = run_cli("scan \"nonexistent_path_xyz_123\"");
    EXPECT_EQ(res.exit_code, 3); // EXIT_EXECUTION_ERROR
    EXPECT_NE(res.output.find("Error:"), std::string::npos);
}

TEST(CliTest, ScanJsonOutput) {
    auto fixtures = find_fixtures_dir();
    auto safe_dir = fixtures / "safe";
    ASSERT_TRUE(std::filesystem::exists(safe_dir));

    auto res = run_cli("scan \"" + safe_dir.string() + "\" --format json");
    EXPECT_EQ(res.exit_code, 0);
    EXPECT_NE(res.output.find("\"statistics\""), std::string::npos);
    EXPECT_NE(res.output.find("\"findings\": []"), std::string::npos);
}

