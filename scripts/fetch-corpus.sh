#!/usr/bin/env bash
#
# Fetch the external detection corpus into ./corpus (gitignored).
#
# The corpus is a separate repository: it is thousands of secret-shaped strings, and keeping it out
# of this tree lets GitHub push protection stay enabled here, keeps MIT-licensed third-party data
# unmixed with Apache-2.0 source, and leaves `cargo test` hermetic and offline for anyone who has
# just cloned PSK.
#
#   ./scripts/fetch-corpus.sh
#   PSK_REQUIRE_CORPUS=1 cargo test -p psk-secrets --test corpus
#
# Without corpus/, the gate prints a hint and passes. CI sets PSK_REQUIRE_CORPUS=1 so the precision
# floor is always enforced somewhere.
set -euo pipefail

REPO="${PSK_CORPUS_REPO:-https://github.com/arthur-b-renaud/psk-corpus.git}"
# Pin the corpus, not just the upstream gitleaks commit: bumping either changes the benchmark and
# therefore the numbers PSK reports. Both are recorded in CLAUDE.md.
REF="${PSK_CORPUS_REF:-main}"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
dest="$root/corpus"

if [ -d "$dest/.git" ]; then
    echo "corpus: updating $dest"
    git -C "$dest" fetch --quiet origin "$REF"
    git -C "$dest" checkout --quiet FETCH_HEAD
else
    echo "corpus: cloning $REPO -> $dest"
    rm -rf "$dest"
    git clone --quiet --depth 1 --branch "$REF" "$REPO" "$dest"
fi

if [ ! -f "$dest/manifest.jsonl" ]; then
    echo "corpus: $dest/manifest.jsonl is missing; the corpus repo layout changed" >&2
    exit 1
fi

echo "corpus: $(wc -l < "$dest/manifest.jsonl") rows at $(git -C "$dest" rev-parse --short HEAD)"
