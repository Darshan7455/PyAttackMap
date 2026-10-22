"""Generator for reproducible benchmark corpora (small, medium, large)."""

from __future__ import annotations

import os
from pathlib import Path


def generate_benchmark_corpora(base_dir: Path) -> dict[str, Path]:
    corpora_dir = base_dir / "benchmarks" / "corpora"
    corpora_dir.mkdir(parents=True, exist_ok=True)

    # 1. Small corpus (10 files)
    small_dir = corpora_dir / "small"
    small_dir.mkdir(parents=True, exist_ok=True)

    templates = [
        # Vulnerable SQL
        """
import sqlite3

def query_user(cursor: sqlite3.Cursor, user_id: str):
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    cursor.execute(query)

def list_users(cursor: sqlite3.Cursor):
    cursor.execute("SELECT id, name FROM users")
""",
        # Safe SQL
        """
import sqlite3

def query_user_safe(cursor: sqlite3.Cursor, user_id: int):
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
""",
        # Vulnerable Command
        """
import os

def ping_target():
    host = input("Host: ")
    cmd = "ping -c 1 " + host
    os.system(cmd)
""",
        # Safe Subprocess
        """
import subprocess

def run_ping(host: str):
    subprocess.run(["ping", "-c", "1", host], shell=False, check=True)
""",
        # Deserialization
        """
import pickle

def load_data(raw_data: bytes):
    return pickle.loads(raw_data)
""",
        # Complex multi-step
        """
import os
import sqlite3
import shlex

def handle_workflow(val: str):
    clean = shlex.quote(val)
    os.system("echo " + clean)
    conn = sqlite3.connect(":memory:")
    c = conn.cursor()
    c.execute("SELECT 1")
""",
    ]

    for i in range(10):
        tmpl = templates[i % len(templates)]
        (small_dir / f"module_{i:02d}.py").write_text(tmpl, encoding="utf-8")

    # 2. Medium corpus (50 files)
    medium_dir = corpora_dir / "medium"
    medium_dir.mkdir(parents=True, exist_ok=True)
    for i in range(50):
        tmpl = templates[i % len(templates)]
        content = tmpl + f"\n# Variant {i}\ndef helper_{i}():\n    return {i} * 2\n"
        (medium_dir / f"module_{i:02d}.py").write_text(content, encoding="utf-8")

    # 3. Large corpus (200 files)
    large_dir = corpora_dir / "large"
    large_dir.mkdir(parents=True, exist_ok=True)
    for i in range(200):
        tmpl = templates[i % len(templates)]
        repeated = tmpl * 3 + f"\n# Large module padding {i}\ndef process_batch_{i}(items):\n    return [x for x in items if x > {i}]\n"
        (large_dir / f"module_{i:03d}.py").write_text(repeated, encoding="utf-8")

    return {
        "small": small_dir,
        "medium": medium_dir,
        "large": large_dir,
    }


if __name__ == "__main__":
    root = Path(__file__).resolve().parent.parent
    paths = generate_benchmark_corpora(root)
    for name, p in paths.items():
        count = len(list(p.glob("*.py")))
        size = sum(f.stat().st_size for f in p.glob("*.py"))
        print(f"Generated {name}: {count} files, {size / 1024:.2f} KB at {p}")

