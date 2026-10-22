#pragma once

#include <filesystem>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include <tree_sitter/api.h>

namespace pyattackmap {

struct TSTreeDeleter {
    void operator()(TSTree* tree) const noexcept {
        if (tree) ts_tree_delete(tree);
    }
};

struct TSParserDeleter {
    void operator()(TSParser* parser) const noexcept {
        if (parser) ts_parser_delete(parser);
    }
};

using ScopedTSTree = std::unique_ptr<TSTree, TSTreeDeleter>;
using ScopedTSParser = std::unique_ptr<TSParser, TSParserDeleter>;

class ParsedSource {
public:
    std::string file_path;
    std::string source_code;
    std::vector<std::string_view> lines;
    std::shared_ptr<TSTree> tree;

    [[nodiscard]] std::string get_snippet(size_t start_line, size_t end_line) const;
    [[nodiscard]] std::string_view get_node_text(TSNode node) const noexcept;
    [[nodiscard]] TSNode root_node() const noexcept;
};

class SafeParser {
public:
    static ScopedTSParser make_parser();
    static ParsedSource parse_string(std::string_view code, std::string_view file_path = "<string>", TSParser* reusable_parser = nullptr);
    static ParsedSource parse_file(const std::filesystem::path& path, size_t max_size_kb = 2048, TSParser* reusable_parser = nullptr);
};

} // namespace pyattackmap

