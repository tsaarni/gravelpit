#!/bin/bash
# Profile: Python with uv package manager.
[ "$1" = "--check" ] && { command -v uv >/dev/null; exit; }
uv run hello.py
