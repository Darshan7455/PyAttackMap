#pragma once

#include "pyattackmap/rules/rule.hpp"

namespace pyattackmap {

class CommandInjectionRule : public Rule {
public:
    [[nodiscard]] std::string_view rule_id() const noexcept override { return "PAM002"; }
    [[nodiscard]] std::string_view title() const noexcept override {
        return "Potential Command Injection via Unsafe Shell Execution";
    }
    [[nodiscard]] std::string_view description() const noexcept override {
        return "Invoking system commands through a shell with dynamically constructed strings "
               "can allow execution of arbitrary host commands.";
    }
    [[nodiscard]] Severity severity() const noexcept override { return Severity::High; }
    [[nodiscard]] Confidence default_confidence() const noexcept override { return Confidence::High; }
    [[nodiscard]] std::optional<std::string_view> cwe() const noexcept override { return "CWE-78"; }

    [[nodiscard]] std::vector<Finding> run(const ParsedSource& parsed, const ScanConfig& config) const override;
};

} // namespace pyattackmap

