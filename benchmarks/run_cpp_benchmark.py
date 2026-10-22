"""Runner for benchmarking the native C++20 PyAttackMap implementation."""

from __future__ import annotations

import json
import os
import platform
import subprocess
import sys
import time
from pathlib import Path


def find_cpp_binary(root: Path) -> Path:
    candidates = [
        root / "build" / "release" / "pyattackmap.exe",
        root / "build" / "release" / "pyattackmap",
        root / "build" / "pyattackmap.exe",
        root / "build" / "pyattackmap",
    ]
    for c in candidates:
        if c.is_file():
            return c
    raise FileNotFoundError(f"Could not locate compiled pyattackmap binary in {root}")


def benchmark_corpus(binary_path: Path, corpus_path: Path, trials: int = 5) -> dict:
    files = list(corpus_path.glob("*.py"))
    total_bytes = sum(f.stat().st_size for f in files)
    file_count = len(files)

    durations = []
    engine_durations = []
    finding_counts = []

    for t in range(trials):
        start = time.perf_counter()
        proc = subprocess.run(
            [str(binary_path), "scan", str(corpus_path), "--format", "json"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        elapsed = time.perf_counter() - start

        try:
            report = json.loads(proc.stdout)
            engine_dur = report.get("statistics", {}).get("duration_seconds", elapsed)
            findings_cnt = len(report.get("findings", []))
        except Exception:
            engine_dur = elapsed
            findings_cnt = -1

        durations.append(elapsed)
        engine_durations.append(engine_dur)
        finding_counts.append(findings_cnt)

    avg_wall_time = sum(durations) / len(durations)
    avg_engine_time = sum(engine_durations) / len(engine_durations)
    files_per_sec = file_count / avg_engine_time if avg_engine_time > 0 else 0
    bytes_per_sec = total_bytes / avg_engine_time if avg_engine_time > 0 else 0

    return {
        "corpus": corpus_path.name,
        "file_count": file_count,
        "total_bytes": total_bytes,
        "total_kb": round(total_bytes / 1024.0, 2),
        "trials": trials,
        "avg_wall_duration_sec": round(avg_wall_time, 6),
        "avg_engine_duration_sec": round(avg_engine_time, 6),
        "min_engine_duration_sec": round(min(engine_durations), 6),
        "max_engine_duration_sec": round(max(engine_durations), 6),
        "files_per_sec": round(files_per_sec, 2),
        "kb_per_sec": round(bytes_per_sec / 1024.0, 2),
        "mb_per_sec": round(bytes_per_sec / (1024.0 * 1024.0), 3),
        "findings_detected": finding_counts[0],
    }


def main():
    root = Path(__file__).resolve().parent.parent
    corpora_dir = root / "benchmarks" / "corpora"
    binary_path = find_cpp_binary(root)

    print("=" * 75)
    print("PyAttackMap Native C++20 Implementation Benchmark")
    print("=" * 75)
    print(f"Platform: {platform.platform()}")
    print(f"Binary:   {binary_path}")
    print("-" * 75)

    baseline_path = root / "benchmarks" / "baseline_python.json"
    baseline_data = {}
    if baseline_path.exists():
        baseline_data = json.loads(baseline_path.read_text(encoding="utf-8")).get("benchmarks", {})

    if not (corpora_dir / "large").exists():
        sys.path.insert(0, str(root / "benchmarks"))
        from generate_corpus import generate_benchmark_corpora
        print("Generating benchmark corpora...")
        generate_benchmark_corpora(root)

    results = {}
    comparison = {}

    for corpus_name in ["small", "medium", "large"]:
        c_path = corpora_dir / corpus_name
        if not c_path.exists():
            continue
        print(f"Benchmarking '{corpus_name}' ({len(list(c_path.glob('*.py')))} files)...")
        res = benchmark_corpus(binary_path, c_path, trials=5)
        results[corpus_name] = res

        py_res = baseline_data.get(corpus_name, {})
        py_time = py_res.get("avg_duration_sec", 0.0)
        cpp_time = res["avg_engine_duration_sec"]

        speedup = (py_time / cpp_time) if cpp_time > 0 and py_time > 0 else 0.0

        comparison[corpus_name] = {
            "file_count": res["file_count"],
            "total_kb": res["total_kb"],
            "python_findings": py_res.get("findings_detected", 0),
            "cpp_findings": res["findings_detected"],
            "python_duration_ms": round(py_time * 1000.0, 2),
            "cpp_duration_ms": round(cpp_time * 1000.0, 2),
            "speedup_factor": round(speedup, 2),
            "python_files_per_sec": py_res.get("files_per_sec", 0.0),
            "cpp_files_per_sec": res["files_per_sec"],
        }

        print(f"  Avg Engine Duration : {cpp_time * 1000.0:.2f} ms (Wall: {res['avg_wall_duration_sec'] * 1000.0:.2f} ms)")
        print(f"  Throughput          : {res['files_per_sec']:.1f} files/s ({res['kb_per_sec']:.2f} KB/s)")
        print(f"  Findings            : {res['findings_detected']} (Python: {py_res.get('findings_detected')})")
        if speedup > 0:
            print(f"  >>> SPEEDUP         : {speedup:.1f}x FASTER than Python baseline!")

    # Write output files
    out_file = root / "benchmarks" / "cpp_benchmark.json"
    out_file.write_text(json.dumps({"system_info": {"platform": platform.platform()}, "benchmarks": results}, indent=2), encoding="utf-8")

    comp_file = root / "benchmarks" / "benchmark_comparison.json"
    comp_file.write_text(json.dumps(comparison, indent=2), encoding="utf-8")

    # Print markdown comparison table
    print("\n" + "=" * 75)
    print("BENCHMARK COMPARISON TABLE: Python Baseline vs C++20 Native")
    print("=" * 75)
    print("| Corpus | Files | Size (KB) | Python Time | C++20 Time | Speedup | Parity (Py/C++) |")
    print("|---|---|---|---|---|---|---|")
    for k, v in comparison.items():
        print(f"| {k:6} | {v['file_count']:5} | {v['total_kb']:9.2f} | {v['python_duration_ms']:9.2f} ms | {v['cpp_duration_ms']:8.2f} ms | **{v['speedup_factor']:5.1f}x** | {v['python_findings']}/{v['cpp_findings']} |")
    print("=" * 75)


if __name__ == "__main__":
    main()

