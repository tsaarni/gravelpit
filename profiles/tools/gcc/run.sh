#!/bin/bash
# Profile: GCC compiler.
[ "$1" = "--check" ] && { command -v gcc >/dev/null; exit; }
gcc -o hello hello.c
./hello
