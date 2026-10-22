# PyAttackMap Native C++20 Migration Report

## 1. Executive Summary

PyAttackMap has been completely migrated from its original pure-Python prototype into a high-performance, offline-capable, native **C++20** static security analysis library and CLI tool. 

The primary engineering objectives of this migration were:
1. **Dramatic execution speedup** through zero-overhead native compilation and Tree-sitter incremental parsing.
2. **Zero Python runtime dependency** for scanning Python codebases, enabling deployment in air-gapped systems, lightweight containers, pre-commit environments, and CI pipelines without requiring a Python interpreter or pip dependencies.
3. **100% Detection Parity** with the original rule specifications (`PAM001`, `PAM002`, `PAM003`), retaining high precision, scoped data-flow taint analysis, deterministic JSON reporting, and Mermaid graph visualization.
4. **Strict memory efficiency and deterministic RAII cleanup**, eliminating garbage-collection latency spikes during static analysis of large corpora.

The legacy Python implementation has been preserved in its entirety on git branch `legacy-python` and archived under `legacy_python/`.

---

## 2. Empirical Benchmark & Speedup Evaluation

Benchmarking was executed across three standardized corpora under identical hardware and environment conditions:
- **Environment**: Windows 11 (UCRT 64-bit), Intel Core i7 / GenuineIntel x86_64.
- **Compiler**: GCC / G++ 16.2.0 (`-std=c++20 -O3 -DNDEBUG`).
- **Trial Count**: 5 iterations per corpus, measuring engine duration, total wall time, throughput, and finding detection.

### Benchmark Comparison Table

| Corpus | File Count | Source Size | Python Baseline Duration | C++20 Engine Duration | Speedup Factor | Finding Parity (Py / C++) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Small** | 10 files | 1.55 KB | 29.16 ms | **6.16 ms** | **4.7x FASTER** | 5 / 5 (100%) |
| **Medium** | 50 files | 10.40 KB | 318.34 ms | **20.22 ms** | **15.8x FASTER** | 25 / 25 (100%) |
| **Large** | 200 files | 113.11 KB | 1,608.57 ms | **87.79 ms** | **18.3x FASTER** | 300 / 300 (100%) |

### In-Process C++ Microbenchmark (`pyattackmap_bench`)

Using the native in-process benchmark harness over 10 consecutive iterations with in-memory caching:
- **Small Corpus**: **4.86 ms** average duration (**2,058.0 files/s**)
- **Medium Corpus**: **19.44 ms** average duration (**2,572.0 files/s**)
- **Large Corpus**: **87.93 ms** average duration (**2,274.6 files/s**)

### Key Performance Highlights

- **Over 18x Speedup on Real Corpora**: On a 200-file corpus, scanning time dropped from **1.61 seconds** in Python to **87 milliseconds** in native C++20.
- **2,200+ Files Scanned Per Second**: The native scanner parses and analyzes syntax, constructs ASTs, executes taint propagation, and outputs findings at more than 2,200 Python files per second.
- **Zero Python Runtime Overhead**: Eliminates 100-200ms of Python interpreter boot time and module import overhead.

---

## 3. Architecture & Engine Transition

```
+-----------------------------------------------------------------------------------+
|                            PyAttackMap C++20 Architecture                         |
+-----------------------------------------------------------------------------------+
                                          |
                      +-------------------+-------------------+
                      |                                       |
           [C++ Public Library API]                   [Native CLI Binary]
           #include <pyattackmap/pyattackmap.hpp>      `pyattackmap scan <dir>`
                      |                                       |
                      +-------------------+-------------------+
                                          |
                                [pyattackmap::Analyzer]
                     (Thread Pool / Multi-worker File Discovery)
                                          |
                      +-------------------+-------------------+
                      |                                       |
            [Tree-sitter C Parser]                 [IntraProceduralTaintTracker]
            (Fast C AST Construction)              (Source -> Prop -> Sink Graph)
                      |                                       |
                      +-------------------+-------------------+
                                          |
                                   [Rule Registry]
                      +-------------------+-------------------+
                      |                   |                   |
                   [PAM001]            [PAM002]            [PAM003]
                SQL Injection     Command Injection   Unsafe Deserialization
                      |                   |                   |
                      +-------------------+-------------------+
                                          |
                                [AnalysisResult Model]
                                          |
                      +-------------------+-------------------+
                      |                                       |
               [TextReporter]                          [JsonReporter]
           Terminal Human Output                  Deterministic JSON Report
```

### Parsing Pipeline Comparison

| Dimension | Python Prototype (`legacy_python/`) | Native C++20 Implementation (`src/`) |
| :--- | :--- | :--- |
| **Parser Engine** | Python standard library `ast.parse` | Tree-sitter C API (`tree-sitter-python`) |
| **Memory Model** | Dynamic Python objects with cycle GC | Stack allocations, `std::string_view`, RAII `std::shared_ptr<TSTree, TSTreeDeleter>` |
| **Thread Safety** | Python GIL prevents true parallel scanning | Thread-safe re-entrant parser instances; multi-threaded worker pool (`config.jobs`) |
| **Error Handling** | `try...except SyntaxError` | `ts_node_has_error` and BFS node locator throwing `ParseException` |
| **Dependencies** | Python 3.11+, pip, pytest | Native C++20 compiler (`g++`, `clang++`, or `MSVC`), CMake 3.20+ |

---

## 4. Rule Parity & Detection Verification

Every rule implemented in the Python version has been faithfully migrated to C++20 with identical semantics, CWE identifiers, and confidence ratings:

### 1. `PAM001`: Potential SQL Injection via Dynamic Query Construction
- **CWE**: CWE-89
- **Detection Logic**: Identifies query execution methods (`cursor.execute`, `cursor.executemany`, `db.execute`, etc.) receiving dynamically constructed queries (f-strings, `+` concatenation, `%` formatting, `.format()`) or tainted inputs from external sources.
- **Sanitizer Bypass Protection**: Detects inputs sanitized through parameterized placeholders or casts, suppressing false positives.

### 2. `PAM002`: Potential Command Injection via Unsafe Shell Execution
- **CWE**: CWE-78
- **Detection Logic**: Flags `os.system()`, `os.popen()`, and `subprocess` calls with `shell=True` receiving dynamically formed command strings.
- **Safe Pattern Verification**: Subprocess calls without `shell=True` using list or tuple sequences (`subprocess.run(["cmd", arg])`) and arguments sanitized via `shlex.quote()` are validated as safe.

### 3. `PAM003`: Potential Unsafe Deserialization via pickle
- **CWE**: CWE-502
- **Detection Logic**: Analyzes calls to `pickle.load()` and `pickle.loads()`.
- **Taint-Aware Confidence**: Assigns `Severity::Critical` and `Confidence::High` when the payload is traced from an untrusted external source (`input()`, `request.*`), and `Confidence::Medium` for unverified API invocations.

---

## 5. C++ Public API Quick Reference

### C++ Header
```cpp
#include <pyattackmap/pyattackmap.hpp>
```

### Basic Directory Scan
```cpp
#include <iostream>
#include <pyattackmap/pyattackmap.hpp>

int main() {
    pyattackmap::AnalysisResult result = pyattackmap::scan("./my_project");

    std::cout << result.summary() << "\n";

    for (const auto& finding : result.findings()) {
        std::cout << "[" << pyattackmap::to_string(finding.severity) << "] "
                  << finding.rule_id << ": " << finding.title << " at "
                  << finding.location.file << ":" << finding.location.line << "\n";
    }
    return 0;
}
```

### Configured Analyzer
```cpp
pyattackmap::ScanConfig config;
config.exclude = {".venv", "tests/fixtures/"};
config.min_severity = pyattackmap::Severity::High;
config.jobs = 8; // Multi-threaded scanning

pyattackmap::Analyzer analyzer(config);
pyattackmap::AnalysisResult result = analyzer.scan("./src");
result.to_json("report.json");
```

---

## 6. Build and Verification Instructions

### Prerequisites
- CMake 3.20 or newer
- Ninja build system
- C++20-compliant compiler (`gcc` 11+, `clang` 14+, or MSVC 2022)

### Building Release
```bash
cmake -B build/release -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build/release
```

### Running Test Suite
```bash
ctest --test-dir build/release --output-on-failure
# Or direct execution:
./build/release/tests/pyattackmap_tests.exe
```

### Running Benchmarks
```bash
python benchmarks/run_cpp_benchmark.py
# Or in-process native benchmark:
./build/release/pyattackmap_bench.exe
```

