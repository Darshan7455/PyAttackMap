#pragma once

#include "pyattackmap/rules/rule.hpp"

namespace pyattackmap {

class SqlInjectionRule : public Rule {
public:
    [[nodiscard]] std::string_view rule_id() const noexcept override { return "PAM001"; }
    [[nodiscard]] std::string_view title() const noexcept override {
        return "Potential SQL Injection via Dynamic Query Construction";
    }
    [[nodiscard]] std::string_view description() const noexcept override {
        return "Dynamically constructed SQL queries using string formatting, f-strings, "
               "or concatenation can allow attackers to alter query logic.";
    }
    [[nodiscard]] Severity severity() const noexcept override { return Severity::High; }
    [[nodiscard]] Confidence default_confidence() const noexcept override { return Confidence::High; }
    [[nodiscard]] std::optional<std::string_view> cwe() const noexcept override { return "CWE-89"; }

    [[nodiscard]] std::vector<Finding> run(const ParsedSource& parsed, const ScanConfig& config) const override;
};

} // namespace pyattackmap

