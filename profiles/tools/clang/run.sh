#!/bin/bash
# Profile: Clang/LLVM compiler.
[ "$1" = "--check" ] && { command -v clang >/dev/null; exit; }
clang -o hello hello.c
./hello
