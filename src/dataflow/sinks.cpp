#include "pyattackmap/dataflow/sinks.hpp"

#include "pyattackmap/dataflow/sources.hpp"

namespace pyattackmap {

SinkDetector::SinkDetector(const std::vector<std::string>& custom_sinks) {
    sql_sinks_ = {
        "execute",
        "executemany",
        "cursor.execute",
        "connection.execute",
        "session.execute",
        "engine.execute",
        "db.execute"
    };

    command_sinks_ = {
        "os.system",
        "os.popen",
        "subprocess.run",
        "subprocess.Popen",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output"
    };

    deserialization_sinks_ = {
        "pickle.load",
        "pickle.loads",
        "_pickle.load",
        "_pickle.loads",
        "cPickle.load",
        "cPickle.loads"
    };

    for (const auto& s : custom_sinks) {
        custom_sinks_.insert(s);
    }
}

std::pair<bool, std::string> SinkDetector::is_sql_sink(TSNode call_node, std::string_view source) const {
    TSNode func = ts_node_child_by_field_name(call_node, "function", 8);
    if (ts_node_is_null(func)) {
        func = ts_node_child(call_node, 0);
    }
    std::string call_name = get_call_expression_name(func, source);
    if (call_name.empty()) {
        return {false, ""};
    }

    if (sql_sinks_.count(call_name) ||
        call_name.ends_with(".execute") ||
        call_name.ends_with(".executemany") ||
        custom_sinks_.count(call_name)) {
        return {true, call_name};
    }
    return {false, ""};
}

std::pair<bool, std::string> SinkDetector::is_command_sink(TSNode call_node, std::string_view source) const {
    TSNode func = ts_node_child_by_field_name(call_node, "function", 8);
    if (ts_node_is_null(func)) {
        func = ts_node_child(call_node, 0);
    }
    std::string call_name = get_call_expression_name(func, source);
    if (call_name.empty()) {
        return {false, ""};
    }

    if (command_sinks_.count(call_name) ||
        call_name == "system" ||
        call_name == "popen" ||
        custom_sinks_.count(call_name)) {
        return {true, call_name};
    }
    return {false, ""};
}

std::pair<bool, std::string> SinkDetector::is_deserialization_sink(TSNode call_node, std::string_view source) const {
    TSNode func = ts_node_child_by_field_name(call_node, "function", 8);
    if (ts_node_is_null(func)) {
        func = ts_node_child(call_node, 0);
    }
    std::string call_name = get_call_expression_name(func, source);
    if (call_name.empty()) {
        return {false, ""};
    }

    if (deserialization_sinks_.count(call_name) || custom_sinks_.count(call_name)) {
        return {true, call_name};
    }
    return {false, ""};
}

} // namespace pyattackmap

