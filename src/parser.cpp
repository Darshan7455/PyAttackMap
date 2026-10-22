#include "pyattackmap/parser.hpp"

#include <fstream>
#include <sstream>

#include "pyattackmap/exceptions.hpp"

extern "C" const TSLanguage* tree_sitter_python(void);

namespace pyattackmap {

std::string ParsedSource::get_snippet(size_t start_line, size_t end_line) const {
    if (lines.empty() || start_line == 0) {
        return "";
    }
    size_t end = (end_line >= start_line) ? end_line : start_line;
    size_t idx_start = (start_line > 0) ? start_line - 1 : 0;
    size_t idx_end = std::min(lines.size(), end);

    size_t total_len = 0;
    for (size_t i = idx_start; i < idx_end; ++i) {
        total_len += lines[i].size() + 1;
    }

    std::string snippet;
    if (total_len > 0) {
        snippet.reserve(total_len);
    }
    for (size_t i = idx_start; i < idx_end; ++i) {
        if (!snippet.empty()) snippet += "\n";
        snippet.append(lines[i]);
    }
    return snippet;
}

std::string_view ParsedSource::get_node_text(TSNode node) const noexcept {
    uint32_t start = ts_node_start_byte(node);
    uint32_t end = ts_node_end_byte(node);
    if (start >= source_code.size() || end > source_code.size() || start > end) {
        return "";
    }
    return std::string_view(source_code.data() + start, end - start);
}

TSNode ParsedSource::root_node() const noexcept {
    if (!tree) {
        return TSNode{};
    }
    return ts_tree_root_node(tree.get());
}

ScopedTSParser SafeParser::make_parser() {
    ScopedTSParser parser(ts_parser_new());
    if (parser) {
        ts_parser_set_language(parser.get(), tree_sitter_python());
    }
    return parser;
}

ParsedSource SafeParser::parse_string(std::string_view code, std::string_view file_path, TSParser* reusable_parser) {
    ScopedTSParser local_parser;
    TSParser* parser = reusable_parser;
    if (!parser) {
        local_parser = make_parser();
        if (!local_parser) {
            throw ParseException(std::string(file_path), "Failed to allocate tree-sitter parser");
        }
        parser = local_parser.get();
    } else {
        ts_parser_reset(parser);
    }

    TSTree* raw_tree = ts_parser_parse_string(
        parser,
        nullptr,
        code.data(),
        static_cast<uint32_t>(code.size())
    );

    if (!raw_tree) {
        throw ParseException(std::string(file_path), "Parsing failed unexpectedly");
    }

    std::shared_ptr<TSTree> tree(raw_tree, TSTreeDeleter{});

    ParsedSource parsed;
    parsed.file_path = std::string(file_path);
    parsed.source_code = std::string(code);
    parsed.tree = tree;

    // Index line views
    const std::string& src = parsed.source_code;
    parsed.lines.reserve(src.size() / 32 + 8);
    size_t start = 0;
    while (start < src.size()) {
        size_t next_newline = src.find('\n', start);
        if (next_newline == std::string::npos) {
            parsed.lines.emplace_back(src.data() + start, src.size() - start);
            break;
        }
        size_t len = next_newline - start;
        if (len > 0 && src[start + len - 1] == '\r') {
            len--;
        }
        parsed.lines.emplace_back(src.data() + start, len);
        start = next_newline + 1;
    }

    // Check for syntax errors
    TSNode root = ts_tree_root_node(raw_tree);
    if (ts_node_has_error(root)) {
        TSPoint error_point = ts_node_start_point(root);
        // BFS to find the exact error node for precise line location
        std::vector<TSNode> stack = {root};
        stack.reserve(64);
        while (!stack.empty()) {
            TSNode cur = stack.back();
            stack.pop_back();

            if (ts_node_is_error(cur) || ts_node_is_missing(cur)) {
                error_point = ts_node_start_point(cur);
                break;
            }

            uint32_t cnt = ts_node_child_count(cur);
            for (uint32_t i = 0; i < cnt; ++i) {
                stack.push_back(ts_node_child(cur, i));
            }
        }
        throw ParseException(parsed.file_path, "Syntax error in Python source", error_point.row + 1);
    }

    return parsed;
}

ParsedSource SafeParser::parse_file(const std::filesystem::path& path, size_t max_size_kb, TSParser* reusable_parser) {
    std::error_code ec;
    auto file_size = std::filesystem::file_size(path, ec);
    if (ec) {
        if (!std::filesystem::exists(path, ec)) {
            throw FileAccessException("Target file does not exist: " + path.string());
        }
        throw FileAccessException("Cannot determine size of file: " + path.string());
    }

    double size_kb = static_cast<double>(file_size) / 1024.0;
    if (size_kb > static_cast<double>(max_size_kb)) {
        throw FileAccessException(
            "File '" + path.string() + "' exceeds maximum allowed size (" +
            std::to_string(static_cast<size_t>(size_kb)) + " KB > " + std::to_string(max_size_kb) + " KB)"
        );
    }

    std::ifstream in(path, std::ios::binary);
    if (!in.is_open()) {
        throw FileAccessException("Cannot read file: " + path.string());
    }

    std::string content;
    content.resize(file_size);
    if (file_size > 0) {
        in.read(content.data(), static_cast<std::streamsize>(file_size));
        content.resize(in.gcount());
    }

    return parse_string(content, path.string(), reusable_parser);
}

} // namespace pyattackmap

