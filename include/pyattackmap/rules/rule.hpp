#pragma once

#include <optional>
#include <string_view>
#include <vector>

#include "pyattackmap/config.hpp"
#include "pyattackmap/models.hpp"
#include "pyattackmap/parser.hpp"

namespace pyattackmap {

class Rule {
public:
    virtual ~Rule() = default;

    [[nodiscard]] virtual std::string_view rule_id() const noexcept = 0;
    [[nodiscard]] virtual std::string_view title() const noexcept = 0;
    [[nodiscard]] virtual std::string_view description() const noexcept = 0;
    [[nodiscard]] virtual Severity severity() const noexcept = 0;
    [[nodiscard]] virtual Confidence default_confidence() const noexcept = 0;
    [[nodiscard]] virtual std::optional<std::string_view> cwe() const noexcept = 0;

    [[nodiscard]] virtual std::vector<Finding> run(const ParsedSource& parsed, const ScanConfig& config) const = 0;
};

} // namespace pyattackmap

