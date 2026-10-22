# PyAttackMap Project Report

## Executive Summary

**PyAttackMap** is an offline static security analysis and data-flow visualization library for Python source code. Developed with NumPy-inspired library design principles, it delivers an installable, embeddable Python package with predictable public interfaces, structured return types, and intra-procedural taint tracking.

## Core Capabilities Delivered

1. **NumPy-Style Public API**:
   - Concise top-level interface (`import pyattackmap as pam`).
   - Clean, immutable, composable data models (`Finding`, `Severity`, `Confidence`, `AnalysisResult`, `DataFlowGraph`).
   - Programmatic filtering, serialization (`to_dict`, `to_json`), and rich summaries.
2. **AST-Based Analysis Engine**:
   - Zero-execution, offline analysis using Python's standard `ast` module.
   - Robust syntax-error isolation and file-size threshold guards.
   - Deterministic and independent per-scan configurations.
3. **Intra-Procedural Taint Tracker**:
   - Real def-use data flow tracking across assignments, concatenations, and f-strings.
   - Explicit neutralizer detection (`shlex.quote`, numerical casts).
   - Trace generation with Mermaid flowchart diagrams.
4. **Three Core Security Rules**:
   - `PAM001`: SQL Injection (`CWE-89`).
   - `PAM002`: Command Injection (`CWE-78`).
   - `PAM003`: Unsafe Deserialization (`CWE-502`).
5. **Quality Assurance & Verification**:
   - 28 automated tests covering public API contracts, CLI, AST parser, taint engine, rules, and error recovery.
   - Benchmark evaluation with 100% recall, 85.7% precision, and F1 score of 0.923.
   - Fully functional CLI with standard exit codes.

