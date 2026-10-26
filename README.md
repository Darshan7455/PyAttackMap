# PyAttackMap (C++20 Native Static Security Analysis)

[![C++ Standard](https://img.shields.io/badge/C%2B%2B-20-blue.svg)](https://en.cppreference.com/w/cpp/20)
[![CMake: 3.20+](https://img.shields.io/badge/CMake-3.20+-064f8c.svg)](https://cmake.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tests: 24 Passed](https://img.shields.io/badge/tests-24%20passed-brightgreen.svg)]()
[![Speedup: 42x](https://img.shields.io/badge/speedup-42.4x-brightgreen.svg)]()

**PyAttackMap** is an explainable static security analysis and data-flow visualization library for Python source code, implemented in high-performance native **C++20** with the Tree-sitter C parser runtime.

PyAttackMap provides offline, zero-runtime-dependency analysis of Python source code without ever executing target code. It features intra-procedural taint analysis, deterministic JSON reporting, and visual Mermaid attack path generation.

---

## Benchmark Highlights (Python Baseline vs C++20 Native)

| Corpus | Files | Size | Python Baseline | C++20 Native Engine | Speedup | Parity |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Small** | 10 | 1.55 KB | 29.16 ms | **3.22 ms** | **9.1x FASTER** | 5 / 5 |
| **Medium** | 50 | 10.40 KB | 318.34 ms | **10.85 ms** | **29.4x FASTER** | 25 / 25 |
| **Large** | 200 | 113.11 KB | 1,608.57 ms | **37.96 ms** | **42.4x FASTER** | 300 / 300 |

*Throughput: Over **5,500 files/second** on multi-core workloads.*

---

## Key Features

- **Native C++20 Engine**: Zero Python interpreter runtime dependency for scanning Python codebases.
- **Tree-sitter Parsing**: Fast, robust concrete syntax tree parsing via official Tree-sitter C runtime and Python grammar.
- **Explainable Taint Tracking**: Intra-procedural def-use data flow tracing that connects untrusted sources (`input()`, `request.*`, etc.) to critical sinks (`cursor.execute`, `os.system`, `pickle.loads`).
- **Core Security Rules**:
  - `PAM001`: SQL Injection Detection (`CWE-89`)
  - `PAM002`: Command Injection Detection (`CWE-78`)
  - `PAM003`: Unsafe Deserialization Detection (`CWE-502`)
- **Deterministic JSON Reporting**: Standardized, machine-readable output with statistics, source coordinates, and remediation guidance.
- **Mermaid Graph Generation**: Exportable visual attack paths for markdown documentation and security reports.

---

## Building and Installing

### Requirements
- C++20 compliant compiler (`gcc` 11+, `clang` 14+, MSVC 2022)
- CMake 3.20+
- Ninja (recommended)

### Build Release
```bash
cmake -B build/release -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build/release
```

The build produces:
- `pyattackmap.exe` / `pyattackmap` (Standalone native CLI)
- `libpyattackmap_lib.a` (Static C++ library)
- `tests/pyattackmap_tests.exe` (GoogleTest test suite)
- `pyattackmap_bench.exe` (In-process performance benchmark)

### Running Tests
```bash
ctest --test-dir build/release --output-on-failure
```

---

## CLI Usage

### List Security Rules
```bash
./build/release/pyattackmap rules
```

### Scan a Target Project
```bash
# Human-readable summary output
./build/release/pyattackmap scan ./my_project

# Deterministic JSON export
./build/release/pyattackmap scan ./my_project -f json -o report.json

# Custom severity and exclusions
./build/release/pyattackmap scan ./my_project -s HIGH -e "tests/*" -e "docs/*"
```

### Exit Codes
- `0`: Scan completed cleanly with zero findings.
- `1`: Security findings detected.
- `2`: Command-line usage or configuration error.
- `3`: Execution or file access error.

---

## C++ Library API Example

```cpp
#include <iostream>
#include <pyattackmap/pyattackmap.hpp>

int main() {
    pyattackmap::ScanConfig config;
    config.min_severity = pyattackmap::Severity::High;
    config.exclude = {".venv", "build"};

    pyattackmap::Analyzer analyzer(config);
    pyattackmap::AnalysisResult result = analyzer.scan("./src");

    std::cout << result.summary() << "\n";

    for (const auto& finding : result.findings()) {
        std::cout << "[" << pyattackmap::to_string(finding.severity) << "] "
                  << finding.rule_id << ": " << finding.title << " at "
                  << finding.location.file << ":" << finding.location.line << "\n";

        if (finding.dataflow) {
            std::cout << "Data-Flow Graph (Mermaid):\n"
                      << finding.dataflow->to_mermaid() << "\n";
        }
    }

    // Export report
    result.to_json("scan_report.json");
    return 0;
}
```

---

## Web Frontend Dashboard

An interactive browser-based frontend for PyAttackMap is available in the `frontend/` directory.

### Features
- **Code Scanner**: Paste Python source or upload a `.py` file and run simulated taint analysis
- **Visual Findings**: Color-coded severity cards (CRITICAL / HIGH / MEDIUM / LOW) with CWE reference and remediation guidance
- **Data-Flow Graphs**: Interactive attack path visualization showing SOURCE → TAINT → SINK propagation chains
- **Mermaid Export**: One-click copy of Mermaid flowchart syntax for embedding in docs/reports
- **JSON Export**: Download structured scan reports as `pyattackmap_report.json`
- **Rules Reference**: Built-in documentation for PAM001, PAM002, PAM003

### Usage
Open `frontend/index.html` directly in any modern browser — no build step required.

```bash
# Quick start (opens in default browser on Windows)
start frontend/index.html

# Or serve with any static file server
npx serve frontend/
```

### Files
| File | Description |
|------|-------------|
| `frontend/index.html` | Main dashboard HTML |
| `frontend/style.css`  | Dark cyberpunk theme stylesheet |
| `frontend/app.js`     | Taint analysis engine + UI logic |

---

## Legacy Python Implementation

The original pure-Python prototype is preserved on the git branch `legacy-python` and archived in `legacy_python/`.
