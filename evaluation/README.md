# PyAttackMap Academic Evaluation Suite

This directory contains the reproducible benchmark corpus and evaluation harness for **PyAttackMap**.

## Corpus Overview

The evaluation dataset (`labeled_samples.json`) consists of balanced, hand-labeled synthetic Python code snippets covering:
1. **SQL Injection (CWE-89 / PAM001)**: Dynamic concatenation, f-strings, and safe parameterized query controls.
2. **Command Injection (CWE-78 / PAM002)**: Shell execution via `os.system` and `subprocess`, safe argument array calls (`shell=False`), and `shlex.quote` sanitization.
3. **Unsafe Deserialization (CWE-502 / PAM003)**: Untrusted `pickle` payloads, risky API invocations, and safe structured format alternatives (`json`).

## Running the Evaluation

Execute the evaluation harness:

```bash
python evaluation/run_evaluation.py
```

## Methodology & Metrics

The benchmark calculates:
- **Precision**: $\frac{\text{TP}}{\text{TP} + \text{FP}}$
- **Recall**: $\frac{\text{TP}}{\text{TP} + \text{FN}}$
- **F1 Score**: $2 \times \frac{\text{Precision} \times \text{Recall}}{\text{Precision} + \text{Recall}}$
- **Taint Trace Accuracy**: Fraction of cases where verified intra-procedural taint flow was expected and successfully reconstructed.
- **Latency / Throughput**: Sub-millisecond parsing and analysis latency per code unit.

## Corpus Limitations

- **Synthetic Scope**: Samples represent localized function units rather than multi-file enterprise monoliths.
- **Intra-Procedural Boundary**: Cross-file imports and global state taint tracking are not evaluated in this benchmark.
- **Independence**: Labels are authored independently of the static rules without synthetic overfitting.

