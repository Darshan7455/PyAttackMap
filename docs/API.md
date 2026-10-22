# PyAttackMap C++20 Library API Reference

PyAttackMap exposes a modular, modern C++20 library interface under the namespace `pyattackmap`.

Header include:
```cpp
#include <pyattackmap/pyattackmap.hpp>
```

---

## 1. Top-Level Convenience Functions

### `pyattackmap::scan`
```cpp
AnalysisResult scan(const std::filesystem::path& target, ScanConfig config = {});
```
Recursively scans a target directory or file.

### `pyattackmap::scan_file`
```cpp
AnalysisResult scan_file(const std::filesystem::path& file_path, ScanConfig config = {});
```
Scans a single Python source file.

### `pyattackmap::scan_code`
```cpp
AnalysisResult scan_code(std::string_view code, std::string_view file_path = "<string>", ScanConfig config = {});
```
Scans Python code directly from an in-memory string.

---

## 2. Core Classes & Data Models

### `pyattackmap::Severity` (Enum Class)
- `Severity::Critical`
- `Severity::High`
- `Severity::Medium`
- `Severity::Low`
- `Severity::Info`

Supports comparison operators (`Severity::Critical > Severity::High`).
Conversion helpers:
- `to_string(Severity s) -> std::string`
- `severity_from_string(std::string_view str) -> Severity`

### `pyattackmap::Confidence` (Enum Class)
- `Confidence::High`
- `Confidence::Medium`
- `Confidence::Low`

Conversion helpers:
- `to_string(Confidence c) -> std::string`
- `confidence_from_string(std::string_view str) -> Confidence`

### `pyattackmap::ScanConfig`
Configuration structure:
```cpp
struct ScanConfig {
    std::vector<std::string> exclude;         // Exclusion patterns (.git, .venv, etc.)
    Severity min_severity = Severity::Low;    // Minimum severity threshold
    std::optional<std::vector<std::string>> enabled_rules;
    std::vector<std::string> disabled_rules;
    size_t max_file_size_kb = 2048;           // Maximum file size in KB
    std::vector<std::string> custom_sources;  // Custom taint sources
    std::vector<std::string> custom_sinks;    // Custom security sinks
    std::vector<std::string> custom_sanitizers;
    bool show_dataflow = true;                // Populate DataFlowGraph
    size_t jobs = 0;                          // Worker threads (0 = hardware concurrency)
};
```

### `pyattackmap::Finding`
```cpp
struct Finding {
    std::string id;
    std::string rule_id;
    std::string title;
    std::string description;
    Severity severity;
    Confidence confidence;
    SourceLocation location;
    std::string snippet;
    std::string evidence;
    std::string remediation;
    std::optional<std::string> cwe;
    std::optional<DataFlowGraph> dataflow;
    std::map<std::string, std::string> metadata;
};
```

### `pyattackmap::DataFlowGraph`
```cpp
struct DataFlowGraph {
    std::vector<DataFlowNode> nodes;
    std::vector<DataFlowEdge> edges;

    [[nodiscard]] nlohmann::json to_json() const;
    [[nodiscard]] std::string to_mermaid() const;
};
```

### `pyattackmap::AnalysisResult`
```cpp
class AnalysisResult {
public:
    [[nodiscard]] const std::vector<Finding>& findings() const noexcept;
    [[nodiscard]] const ScanStatistics& statistics() const noexcept;
    [[nodiscard]] const std::vector<AnalysisError>& errors() const noexcept;
    [[nodiscard]] size_t size() const noexcept;
    [[nodiscard]] bool empty() const noexcept;
    [[nodiscard]] const Finding& operator[](size_t index) const;

    [[nodiscard]] std::vector<Finding> filter(
        std::optional<Severity> min_severity = std::nullopt,
        std::optional<std::string_view> rule_id = std::nullopt) const;

    [[nodiscard]] std::string summary() const;
    [[nodiscard]] std::string to_json(const std::optional<std::filesystem::path>& path = std::nullopt, int indent = 2) const;
};
```

---

## 3. Analyzer Engine

```cpp
class Analyzer {
public:
    explicit Analyzer(ScanConfig config = {}, RuleRegistry* registry = nullptr);

    [[nodiscard]] AnalysisResult scan(const std::filesystem::path& target) const;
    [[nodiscard]] AnalysisResult scan_file(const std::filesystem::path& file_path) const;
    [[nodiscard]] AnalysisResult scan_code(std::string_view code, std::string_view file_path = "<string>") const;
};
```

---

## 4. CMake Target Integration

```cmake
find_package(PyAttackMap REQUIRED)
target_link_libraries(my_tool PRIVATE pyattackmap::pyattackmap_lib)
```
