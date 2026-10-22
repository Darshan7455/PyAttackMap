#pragma once

#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "pyattackmap/config.hpp"
#include "pyattackmap/rules/rule.hpp"

namespace pyattackmap {

class RuleRegistry {
public:
    using RuleFactory = std::function<std::unique_ptr<Rule>()>;

    void register_rule(std::string rule_id, RuleFactory factory);

    [[nodiscard]] std::vector<std::unique_ptr<Rule>> get_enabled_rules(const ScanConfig& config) const;
    [[nodiscard]] std::vector<std::unique_ptr<Rule>> get_all_rules() const;

    static RuleRegistry& default_registry();

private:
    std::unordered_map<std::string, RuleFactory> factories_;
    std::vector<std::string> rule_order_;
};

} // namespace pyattackmap

