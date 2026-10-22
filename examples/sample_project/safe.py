"""Sample safe project file demonstrating remediated and secure patterns."""

import json
import sqlite3
import subprocess


def safe_db_lookup(user_id: int) -> None:
    conn = sqlite3.connect("demo.db")
    cursor = conn.cursor()
    # Safe: Parameterized SQL query
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))


def safe_system_ping(host: str) -> None:
    # Safe: Passing arguments as a sequence without shell=True
    subprocess.run(["ping", "-c", "1", host], shell=False, check=True)


def safe_deserializer(payload: str) -> dict:
    # Safe: Using JSON format instead of pickle
    return json.loads(payload)

