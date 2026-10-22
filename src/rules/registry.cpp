#include "pyattackmap/rules/registry.hpp"

#include "pyattackmap/rules/command_injection.hpp"
#include "pyattackmap/rules/sql_injection.hpp"
#include "pyattackmap/rules/unsafe_deserialization.hpp"

namespace pyattackmap {

void RuleRegistry::register_rule(std::string rule_id, RuleFactory factory) {
    std::string upper_id = to_upper(rule_id);
    if (factories_.find(upper_id) == factories_.end()) {
        rule_order_.push_back(upper_id);
    }
    factories_[upper_id] = std::move(factory);
}

std::vector<std::unique_ptr<Rule>> RuleRegistry::get_enabled_rules(const ScanConfig& config) const {
    std::vector<std::unique_ptr<Rule>> rules;
    for (const auto& id : rule_order_) {
        if (config.is_rule_enabled(id)) {
            auto it = factories_.find(id);
            if (it != factories_.end()) {
                rules.push_back(it->second());
            }
        }
    }
    return rules;
}

std::vector<std::unique_ptr<Rule>> RuleRegistry::get_all_rules() const {
    std::vector<std::unique_ptr<Rule>> rules;
    for (const auto& id : rule_order_) {
        auto it = factories_.find(id);
        if (it != factories_.end()) {
            rules.push_back(it->second());
        }
    }
    return rules;
}

RuleRegistry& RuleRegistry::default_registry() {
    static RuleRegistry registry = []() {
        RuleRegistry reg;
        reg.register_rule("PAM001", []() { return std::make_unique<SqlInjectionRule>(); });
        reg.register_rule("PAM002", []() { return std::make_unique<CommandInjectionRule>(); });
        reg.register_rule("PAM003", []() { return std::make_unique<UnsafeDeserializationRule>(); });
        return reg;
    }();
    return registry;
}

} // namespace pyattackmap

