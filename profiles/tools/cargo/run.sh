#!/bin/bash
# Profile: Rust/Cargo toolchain.
[ "$1" = "--check" ] && { command -v cargo >/dev/null; exit; }
cargo build
cargo test
