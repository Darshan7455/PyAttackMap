"""Runner for benchmarking the baseline Python implementation."""

from __future__ import annotations

import json
import os
import platform
import sys
import time
import tracemalloc
from pathlib import Path

import pyattackmap as pam


def benchmark_corpus(corpus_path: Path, trials: int = 5) -> dict:
    files = list(corpus_path.glob("*.py"))
    total_bytes = sum(f.stat().st_size for f in files)
    file_count = len(files)

    durations = []
    peak_memories = []
    finding_counts = []

    for t in range(trials):
        tracemalloc.start()
        start = time.perf_counter()
        
        result = pam.scan(corpus_path)
        
        elapsed = time.perf_counter() - start
        current_mem, peak_mem = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        durations.append(elapsed)
        peak_memories.append(peak_mem)
        finding_counts.append(len(result.findings))

    avg_time = sum(durations) / len(durations)
    avg_peak_mem = sum(peak_memories) / len(peak_memories)
    files_per_sec = file_count / avg_time if avg_time > 0 else 0
    bytes_per_sec = total_bytes / avg_time if avg_time > 0 else 0

    return {
        "corpus": corpus_path.name,
        "file_count": file_count,
        "total_bytes": total_bytes,
        "total_kb": round(total_bytes / 1024.0, 2),
        "trials": trials,
        "avg_duration_sec": round(avg_time, 5),
        "min_duration_sec": round(min(durations), 5),
        "max_duration_sec": round(max(durations), 5),
        "files_per_sec": round(files_per_sec, 2),
        "kb_per_sec": round(bytes_per_sec / 1024.0, 2),
        "mb_per_sec": round(bytes_per_sec / (1024.0 * 1024.0), 3),
        "avg_peak_memory_kb": round(avg_peak_mem / 1024.0, 2),
        "findings_detected": finding_counts[0],
    }


def main():
    root = Path(__file__).resolve().parent.parent
    corpora_dir = root / "benchmarks" / "corpora"

    system_info = {
        "platform": platform.platform(),
        "processor": platform.processor(),
        "python_version": sys.version.split()[0],
        "pyattackmap_version": pam.__version__,
    }

    print("=" * 70)
    print("PyAttackMap Python Implementation Baseline Benchmark")
    print("=" * 70)
    print(f"Platform: {system_info['platform']}")
    print(f"Processor: {system_info['processor']}")
    print(f"Python: {system_info['python_version']}")
    print("-" * 70)

    results = {}
    for corpus_name in ["small", "medium", "large"]:
        c_path = corpora_dir / corpus_name
        if not c_path.exists():
            print(f"Skipping missing corpus: {corpus_name}")
            continue
        print(f"Benchmarking '{corpus_name}' ({len(list(c_path.glob('*.py')))} files)...")
        res = benchmark_corpus(c_path, trials=5)
        results[corpus_name] = res
        print(f"  Avg Duration : {res['avg_duration_sec'] * 1000:.2f} ms")
        print(f"  Throughput   : {res['files_per_sec']:.1f} files/s ({res['kb_per_sec']:.2f} KB/s)")
        print(f"  Peak Memory  : {res['avg_peak_memory_kb']:.2f} KB")
        print(f"  Findings     : {res['findings_detected']}")

    output_data = {
        "system_info": system_info,
        "benchmarks": results,
    }

    out_file = root / "benchmarks" / "baseline_python.json"
    out_file.write_text(json.dumps(output_data, indent=2), encoding="utf-8")
    print("-" * 70)
    print(f"Baseline results saved to {out_file}")
    print("=" * 70)


if __name__ == "__main__":
    main()

