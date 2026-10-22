"""Safe deserialization using JSON."""

import json


def load_user_settings(payload: str) -> dict:
    # Safe structured serialization using json
    return json.loads(payload)


def read_config_file(file_path: str) -> dict:
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)

