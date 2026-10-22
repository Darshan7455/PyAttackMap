"""Sample project file containing intentional vulnerabilities for demonstration."""

import os
import pickle
import sqlite3


def vulnerable_db_lookup(user_id: str) -> None:
    conn = sqlite3.connect("demo.db")
    cursor = conn.cursor()
    # PAM001: SQL injection via f-string
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    cursor.execute(query)


def vulnerable_system_ping() -> None:
    host = input("Target IP: ")
    # PAM002: Command injection via tainted input to os.system
    os.system("ping -c 1 " + host)


def vulnerable_deserializer() -> None:
    token = input("Session token: ")
    # PAM003: Unsafe deserialization of untrusted input
    data = pickle.loads(token.encode("utf-8"))
    return data

