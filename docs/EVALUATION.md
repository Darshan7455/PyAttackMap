# Academic Evaluation & Benchmark Report

## 1. Static Analysis Rule Evaluation

The evaluation suite validates PyAttackMap against labeled vulnerable and safe test cases spanning SQL injection (`PAM001`), command injection (`PAM002`), and unsafe deserialization (`PAM003`).

### Labeled Test Evaluation Summary

```text
======================================================================
PyAttackMap Static Analysis Academic Evaluation
======================================================================
[TP (Hit)    ] eval-sql-01: SQL injection via direct string concatenation
[TN (Clean)  ] eval-sql-02: Safe parameterized SQL query
[TP (Hit)    ] eval-sql-03: SQL injection via f-string with tainted input
[TP (Hit)    ] eval-cmd-01: Command injection via os.system with tainted input
[TN (Clean)  ] eval-cmd-02: Safe subprocess execution with argument array
[TP (Hit)    ] eval-cmd-03: Command injection via subprocess shell=True
[TN (Clean)  ] eval-cmd-04: Sanitized shell command with shlex.quote
[TP (Hit)    ] eval-deser-01: Unsafe deserialization of tainted input
[TN (Clean)  ] eval-deser-02: Safe JSON deserialization
[TP (Hit)    ] eval-deser-03: Static pickle load with risky API
----------------------------------------------------------------------
Evaluation Metrics Summary:
  Total Samples Evaluated: 10
  True Positives (TP)    : 6
  False Positives (FP)   : 0
  True Negatives (TN)    : 4
  False Negatives (FN)   : 0
  Precision              : 1.0000 (100.0%)
  Recall                 : 1.0000 (100.0%)
  F1-Score               : 1.0000
  Taint Trace Accuracy   : 1.0000 (3/3)
======================================================================
```

### Metric Analysis

- **Recall (100%)**: Zero false negatives across evaluated vulnerability patterns. All true injections were flagged.
- **Precision (100%)**: Zero false alarms. Sanitized dynamic execution (e.g. `shlex.quote()`) is accurately distinguished from unvalidated inputs.
- **Taint Trace Accuracy (100%)**: Source-to-sink data-flow paths reconstruct propagation nodes, AST locations, and Mermaid flow diagrams with complete accuracy.

---

## 2. Native C++20 Empirical Performance Benchmarks

Benchmark comparison between the Python baseline implementation (`legacy_python/`) and the native C++20 engine (`build/release/pyattackmap.exe`) across three standardized synthetic corpora:

| Corpus | Files | Size | Python Baseline Duration | C++20 Engine Duration | Speedup Factor | Finding Parity (Py / C++) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Small** | 10 files | 1.55 KB | 29.16 ms | **3.22 ms** | **9.1x FASTER** | 5 / 5 |
| **Medium** | 50 files | 10.40 KB | 318.34 ms | **10.85 ms** | **29.4x FASTER** | 25 / 25 |
| **Large** | 200 files | 113.11 KB | 1,608.57 ms | **37.96 ms** | **42.4x FASTER** | 300 / 300 |

### In-Process C++ Microbenchmark (`pyattackmap_bench`)

- **Small Corpus (10 files)**: **2.56 ms** (3,908 files/sec)
- **Medium Corpus (50 files)**: **9.24 ms** (5,410 files/sec)
- **Large Corpus (200 files)**: **35.73 ms** (5,598 files/sec)

### Key Takeaways

1. **Over 42x Speedup**: Scans of 200 files dropped from 1.61 seconds to 37.96 milliseconds.
2. **High Throughput**: Exceeds 5,500 files/sec scanning throughput.
3. **Deterministic Latency**: Eliminates garbage collection pauses and Python interpreter startup time.
4. **100% Detection Parity**: Identical findings identified in both implementations.
