#!/usr/bin/env python3
"""Simple configuration file parser.

This module provides ``parse_config`` which reads key-value pairs from a file.
Lines starting with ``#`` are treated as comments and ignored. Blank lines are
also skipped.

Example config::

    # Sample configuration
    host = localhost
    port = 8080

``parse_config`` will return ``{"host": "localhost", "port": "8080"}``.
"""

from __future__ import annotations

from typing import Dict


def parse_config(path: str) -> Dict[str, str]:
    """Parse a simple key=value configuration file.

    Parameters
    ----------
    path: str
        Path to the configuration file.

    Returns
    -------
    Dict[str, str]
        Dictionary mapping keys to values from the file.
    """
    config: Dict[str, str] = {}
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            stripped = line.strip()
            if not stripped or stripped.startswith('#'):
                continue
            if '=' not in stripped:
                continue
            key, value = stripped.split('=', 1)
            config[key.strip()] = value.strip()
    return config


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Parse a configuration file")
    parser.add_argument("path", help="Path to config file")
    args = parser.parse_args()
    result = parse_config(args.path)
    for k, v in result.items():
        print(f"{k}={v}")

