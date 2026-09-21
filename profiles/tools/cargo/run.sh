#!/bin/bash
# Profile: Rust/Cargo toolchain.
[ "$1" = "--check" ] && { command -v cargo >/dev/null; exit; }
# Force cargo's auto-gc to run every time. By default it runs once per day,
# and the gc scans ~/.cargo/registry and ~/.cargo/git directories.
export CARGO_CACHE_AUTO_CLEAN_FREQUENCY=always
cargo build
cargo test
