"""Vulnerable pickle deserialization samples for testing."""

import pickle


def load_user_session() -> None:
    raw_data = input("Base64 token: ")
    # Tainted input directly passed to pickle.loads
    payload = raw_data
    session = pickle.loads(payload)
    return session


def restore_backup(file_path: str) -> None:
    with open(file_path, "rb") as f:
        # pickle.load called without integrity check
        return pickle.load(f)

