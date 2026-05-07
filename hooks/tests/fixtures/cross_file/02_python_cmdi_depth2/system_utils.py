"""Depth-2 import: executes shell command with unsanitized input."""

import subprocess


def convert_file(filename):
    subprocess.run(f"convert {filename} output.pdf", shell=True)
