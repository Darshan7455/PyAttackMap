#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>

#include "pyattackmap/exceptions.hpp"
#include "pyattackmap/parser.hpp"

using namespace pyattackmap;

TEST(ParserTest, ParseValidString) {
    std::string code = "def add(a, b):\n    return a + b\n";
    ParsedSource parsed = SafeParser::parse_string(code, "math.py");

    EXPECT_EQ(parsed.file_path, "math.py");
    EXPECT_EQ(parsed.lines.size(), 2u);
    EXPECT_EQ(parsed.get_snippet(1, 2), "def add(a, b):\n    return a + b");
    EXPECT_FALSE(ts_node_is_null(parsed.root_node()));
    EXPECT_EQ(std::string_view(ts_node_type(parsed.root_node())), "module");
}

TEST(ParserTest, ParseSyntaxError) {
    std::string broken = "def broken(:\n    pass";
    EXPECT_THROW({
        try {
            SafeParser::parse_string(broken, "bad.py");
        } catch (const ParseException& pe) {
            EXPECT_EQ(pe.file_path(), "bad.py");
            EXPECT_EQ(pe.line(), 1u);
            throw;
        }
    }, ParseException);
}

TEST(ParserTest, ParseFileNotFound) {
    std::filesystem::path missing = "this_file_does_not_exist_at_all.py";
    EXPECT_THROW(SafeParser::parse_file(missing), FileAccessException);
}

TEST(ParserTest, ParseMaxFileSize) {
    std::filesystem::path tmp_file = std::filesystem::temp_directory_path() / "pam_test_large.py";
    {
        std::ofstream out(tmp_file);
        for (int i = 0; i < 1000; ++i) {
            out << "x = 1\n";
        }
    }

    // Limit to 0.1 KB (~102 bytes)
    EXPECT_THROW(SafeParser::parse_file(tmp_file, 0.1), FileAccessException);

    std::error_code ec;
    std::filesystem::remove(tmp_file, ec);
}

