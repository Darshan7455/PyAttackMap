#include "pyattackmap/dataflow/sources.hpp"

namespace pyattackmap {

std::string get_call_expression_name(TSNode node, std::string_view source) {
    if (ts_node_is_null(node)) {
        return "";
    }
    std::string_view type = ts_node_type(node);
    if (type == "identifier") {
        uint32_t start = ts_node_start_byte(node);
        uint32_t end = ts_node_end_byte(node);
        return std::string(source.substr(start, end - start));
    }
    if (type == "attribute") {
        TSNode obj = ts_node_child_by_field_name(node, "object", 6);
        TSNode attr = ts_node_child_by_field_name(node, "attribute", 9);
        if (ts_node_is_null(obj)) {
            obj = ts_node_child(node, 0);
        }
        if (ts_node_is_null(attr)) {
            uint32_t count = ts_node_child_count(node);
            if (count >= 3) attr = ts_node_child(node, count - 1);
        }
        std::string obj_name = get_call_expression_name(obj, source);
        uint32_t attr_start = ts_node_start_byte(attr);
        uint32_t attr_end = ts_node_end_byte(attr);
        std::string attr_name = (attr_end > attr_start) ? std::string(source.substr(attr_start, attr_end - attr_start)) : "";
        if (!obj_name.empty() && !attr_name.empty()) {
            return obj_name + "." + attr_name;
        }
        return attr_name;
    }
    return "";
}

SourceDetector::SourceDetector(const std::vector<std::string>& custom_sources) {
    call_sources_ = {
        "input",
        "sys.argv",
        "os.getenv",
        "os.environ.get"
    };

    attr_sources_ = {
        "request.args",
        "request.form",
        "request.values",
        "request.data",
        "request.json",
        "request.params",
        "request.GET",
        "request.POST",
        "request.body",
        "os.environ",
        "sys.argv"
    };

    for (const auto& s : custom_sources) {
        call_sources_.insert(s);
        attr_sources_.insert(s);
    }
}

std::pair<bool, std::string> SourceDetector::is_source(TSNode node, std::string_view source) const {
    if (ts_node_is_null(node)) {
        return {false, ""};
    }

    std::string_view type = ts_node_type(node);

    // 1. Call expression: e.g. input(), os.getenv()
    if (type == "call") {
        TSNode func = ts_node_child_by_field_name(node, "function", 8);
        if (ts_node_is_null(func)) {
            func = ts_node_child(node, 0);
        }
        std::string call_name = get_call_expression_name(func, source);
        if (!call_name.empty()) {
            if (call_sources_.count(call_name)) {
                return {true, "call to " + call_name + "()"};
            }
            for (const auto& src : call_sources_) {
                if (call_name == src || (call_name.size() > src.size() && call_name.ends_with("." + src))) {
                    return {true, "call to " + call_name + "()"};
                }
            }
        }
    }

    // 2. Attribute expression: e.g. request.args, request.data
    if (type == "attribute") {
        std::string attr_name = get_call_expression_name(node, source);
        if (!attr_name.empty()) {
            if (attr_sources_.count(attr_name)) {
                return {true, "access to " + attr_name};
            }
            for (const auto& src : attr_sources_) {
                if (attr_name == src || (attr_name.size() > src.size() && attr_name.ends_with("." + src))) {
                    return {true, "access to " + attr_name};
                }
            }
        }
    }

    // 3. Subscript expression: e.g. request.args['id'], os.environ['VAR'], sys.argv[1]
    if (type == "subscript") {
        TSNode val = ts_node_child_by_field_name(node, "value", 5);
        if (ts_node_is_null(val)) {
            val = ts_node_child(node, 0);
        }
        std::string target_name = get_call_expression_name(val, source);
        if (!target_name.empty()) {
            if (attr_sources_.count(target_name) || call_sources_.count(target_name) ||
                target_name == "sys.argv" || target_name == "os.environ") {
                return {true, "subscript access on " + target_name};
            }
        }
    }

    return {false, ""};
}

} // namespace pyattackmap

