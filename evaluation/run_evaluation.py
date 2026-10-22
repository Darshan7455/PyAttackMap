"""Academic evaluation script measuring precision, recall, F1, and runtime."""

from __future__ import annotations

import json
from pathlib import Path
import time

import pyattackmap as pam


def run_benchmark() -> None:
    corpus_file = Path(__file__).parent / "labeled_samples.json"
    if not corpus_file.exists():
        raise FileNotFoundError(f"Missing corpus file: {corpus_file}")

    samples = json.loads(corpus_file.read_text(encoding="utf-8"))

    tp = 0
    fp = 0
    tn = 0
    fn = 0
    taint_match_count = 0
    total_taint_expected = 0

    print("=" * 70)
    print("PyAttackMap Static Analysis Academic Evaluation")
    print("=" * 70)

    start_total = time.perf_counter()

    for sample in samples:
        s_id = sample["id"]
        code = sample["code"]
        exp_vuln = sample["expected_vulnerable"]
        exp_rule = sample.get("expected_rule")
        exp_taint = sample.get("has_taint_flow", False)

        result = pam.scan_code(code, file_path=f"corpus_{s_id}.py")
        pred_vuln = len(result.findings) > 0

        # Data-flow verification
        actual_has_taint = any(f.dataflow is not None and len(f.dataflow.nodes) > 0 for f in result.findings)
        if exp_taint:
            total_taint_expected += 1
            if actual_has_taint:
                taint_match_count += 1

        if exp_vuln and pred_vuln:
            # Check rule match
            first_finding = result.findings[0]
            if exp_rule and first_finding.rule_id == exp_rule:
                tp += 1
                status = "TP (Hit)"
            else:
                tp += 1
                status = f"TP (Rule mismatch: exp {exp_rule}, got {first_finding.rule_id})"
        elif not exp_vuln and not pred_vuln:
            tn += 1
            status = "TN (Clean)"
        elif not exp_vuln and pred_vuln:
            fp += 1
            status = f"FP (False Alarm: {result.findings[0].rule_id})"
        else:
            fn += 1
            status = f"FN (Missed: exp {exp_rule})"

        print(f"[{status:<12}] {s_id}: {sample['name']}")

    total_time = time.perf_counter() - start_total

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    taint_acc = (taint_match_count / total_taint_expected) if total_taint_expected > 0 else 1.0

    print("-" * 70)
    print("Evaluation Metrics Summary:")
    print(f"  Total Samples Evaluated: {len(samples)}")
    print(f"  True Positives (TP)    : {tp}")
    print(f"  False Positives (FP)   : {fp}")
    print(f"  True Negatives (TN)    : {tn}")
    print(f"  False Negatives (FN)   : {fn}")
    print(f"  Precision              : {precision:.4f} ({precision * 100:.1f}%)")
    print(f"  Recall                 : {recall:.4f} ({recall * 100:.1f}%)")
    print(f"  F1-Score               : {f1:.4f}")
    print(f"  Taint Trace Accuracy   : {taint_acc:.4f} ({taint_match_count}/{total_taint_expected})")
    print(f"  Total Execution Time   : {total_time * 1000:.2f} ms ({total_time / len(samples) * 1000:.2f} ms/sample)")
    print("=" * 70)


if __name__ == "__main__":
    run_benchmark()

