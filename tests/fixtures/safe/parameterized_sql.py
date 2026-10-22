"""Safe parameterized SQL query patterns."""

import sqlite3


def get_user_parameterized(cursor: sqlite3.Cursor, user_id: int) -> None:
    # Parameterized query with tuple
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))


def get_all_active_users(cursor: sqlite3.Cursor) -> None:
    # Static string query without dynamic parameters
    cursor.execute("SELECT id, username, email FROM users WHERE is_active = 1")

