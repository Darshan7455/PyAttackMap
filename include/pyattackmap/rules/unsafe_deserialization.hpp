#pragma once

#include "pyattackmap/rules/rule.hpp"

namespace pyattackmap {

class UnsafeDeserializationRule : public Rule {
public:
    [[nodiscard]] std::string_view rule_id() const noexcept override { return "PAM003"; }
    [[nodiscard]] std::string_view title() const noexcept override {
        return "Potential Unsafe Deserialization via pickle";
    }
    [[nodiscard]] std::string_view description() const noexcept override {
        return "Deserializing untrusted data with pickle allows arbitrary Python object construction "
               "and remote code execution via __reduce__ methods.";
    }
    [[nodiscard]] Severity severity() const noexcept override { return Severity::High; }
    [[nodiscard]] Confidence default_confidence() const noexcept override { return Confidence::Medium; }
    [[nodiscard]] std::optional<std::string_view> cwe() const noexcept override { return "CWE-502"; }

    [[nodiscard]] std::vector<Finding> run(const ParsedSource& parsed, const ScanConfig& config) const override;
};

} // namespace pyattackmap

