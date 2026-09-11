#!/usr/bin/env bash
# Generate local fixtures (gitignored) and measure detector accuracy.
set -euo pipefail
cd "$(dirname "$0")/.."
N="${1:-200}"; SEED="${2:-42}"
cargo build --release --quiet
mkdir -p fixtures
./target/release/psk gen "$N" "$SEED" > fixtures/examples.jsonl
echo "generated $(wc -l < fixtures/examples.jsonl) examples -> fixtures/examples.jsonl (not committed)"
./target/release/psk eval fixtures/examples.jsonl
