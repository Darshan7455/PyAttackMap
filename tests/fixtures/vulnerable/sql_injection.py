"""Vulnerable SQL injection samples for testing."""

import sqlite3


def get_user_by_name(cursor: sqlite3.Cursor, user_input: str) -> None:
    # Vulnerable f-string SQL query
    query = f"SELECT * FROM users WHERE username = '{user_input}'"
    cursor.execute(query)


def get_user_direct_concat(cursor: sqlite3.Cursor) -> None:
    raw_id = input("Enter user ID: ")
    # Vulnerable binary concatenation reaching execute
    cursor.execute("SELECT * FROM users WHERE id = " + raw_id)

