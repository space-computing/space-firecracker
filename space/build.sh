#!/usr/bin/env bash
# Copyright 2026 Spacebox authors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Builds the release binary of the fork for the hosts: Firecracker for
# x86_64-unknown-linux-musl, with the default seccomp filters of
# resources/seccomp/x86_64-unknown-linux-musl.json compiled in.
#
# Usage: space/build.sh [--test]
#   --test  also runs the unit tests as the CI of Firecracker runs them
#           (needs root, or access to /dev/kvm and /dev/net/tun).
#
# Needs, on a Debian host: the Rust toolchain of rust-toolchain.toml with the
# target x86_64-unknown-linux-musl; the packages build-essential, musl-tools,
# clang, libseccomp-dev; the kernel headers in the musl include folder
# (/usr/include/x86_64-linux-musl/{linux,asm,asm-generic}); and, for --test,
# a static libseccomp built with musl-gcc in /usr/local/lib (as the
# development container of Firecracker builds it, tools/devctr/Dockerfile).
#
# Prints the path of the binary on its last line.
set -euo pipefail

cd "$(dirname "$0")/.."
target=x86_64-unknown-linux-musl

if [ "${1:-}" = "--test" ]; then
    RUST_TEST_THREADS=1 cargo test --target "$target" --all --no-fail-fast
fi

cargo build --release --target "$target" -p firecracker
echo "$PWD/build/cargo_target/$target/release/firecracker"
