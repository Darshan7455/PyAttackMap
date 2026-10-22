"""Vulnerable command injection samples for testing."""

import os
import subprocess


def ping_host_system() -> None:
    host = input("Enter host: ")
    # os.system with tainted variable
    os.system(f"ping -c 1 {host}")


def list_files_shell_true(target_dir: str) -> None:
    # subprocess with shell=True and formatting
    cmd = "ls -la " + target_dir
    subprocess.run(cmd, shell=True)

