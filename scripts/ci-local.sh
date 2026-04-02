#!/usr/bin/env bash
# Локальная проверка — аналог GitHub CI.
# Запускай перед коммитом: ./scripts/ci-local.sh
set -euo pipefail

echo "=== cargo fmt --check ==="
cargo fmt --check

echo "=== cargo test ==="
cargo test

echo "=== cargo clippy ==="
cargo clippy -- -D warnings

echo ""
echo "✓ Все проверки пройдены"
