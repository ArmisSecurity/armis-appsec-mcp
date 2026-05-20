"""Depth-1 import: passes filename to system utility."""

from .system_utils import convert_file


def process_file(filename):
    convert_file(filename)
