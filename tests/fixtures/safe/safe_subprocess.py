"""Safe subprocess execution patterns."""

import subprocess


def ping_host_safe(host: str) -> None:
    # Safe argument sequence with shell=False
    subprocess.run(["ping", "-c", "1", host], shell=False, check=True)


def list_directory() -> None:
    # Subprocess without shell argument (defaults to False)
    subprocess.run(["ls", "-la"])

