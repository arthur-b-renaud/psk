# Contributing

Thanks for helping improve `psk`. This is a small, focused Rust workspace; contributions that add
detection coverage, harden the proxy, or improve agent integration are especially welcome.

## Development setup

```bash
git clone https://github.com/arthur-b-renaud/psk.git
cd psk
cargo build
cargo test --workspace
```

## The CI gate (run before every push)

CI enforces all three of these. Run them locally first:

```bash
cargo fmt --all -- --check
cargo clippy --workspace -- -D warnings
cargo test --workspace
```

`clippy` runs with `-D warnings`, so warnings fail the build. `cargo fmt --all` will fix formatting.

## Workspace layout

```
crates/
  psk-core/      pipeline, redaction policy, span/entity model, vault, stats
  psk-patterns/  YAML-driven regex recognizers + validators
  psk-proxy/     axum proxy: per-provider scrub + forward, /psk/detokenize
  psk-hook/      Claude Code wiring (settings.json + PreToolUse hook)
  psk-cli/       the `psk` binary
patterns/        built-in YAML pattern packs
fixtures/        synthetic test inputs (never real secrets)
docs/            architecture, getting-started, security, patterns
```

See [docs/architecture.md](docs/architecture.md) for how the pieces fit together.

## Adding a detection pattern

1. Add an entry to the appropriate `patterns/*.yaml` (see [docs/patterns.md](docs/patterns.md)).
2. If it's a **new secret type**, add the `EntityType` variant in `crates/psk-core/src/span.rs`,
   list it in `is_secret_entity()` in `policy.rs` (so it tokenizes reversibly), and add the arm in
   `parse_entity_type()` in `crates/psk-patterns/src/recognizer.rs`.
3. Add a synthetic example to `fixtures/secrets.txt`. **Do not commit a realistic provider token** —
   GitHub push-protection will block it. Break the format with a `…REDACTED…` marker if needed and
   rely on a unit test for exact matching.
4. Add/extend a unit test in `recognizer.rs` for the new pattern.
5. `cargo run -p psk -- patterns` and `cargo run -p psk -- test` to sanity-check.

## Guardrails

- **No model, no network at detection time.** Detection stays deterministic (regex + validators).
- The vault is in-memory and session-scoped — never persist it.
- Fixtures are synthetic only; stats are counters only.
- Keep regexes linear and anchored (the `regex` crate has no backtracking, but tight patterns keep
  latency in budget — target p95 redaction under ~30–50 ms).

## Commits & PRs

- Keep commits focused; describe the *why* in the body.
- Make sure the CI gate passes locally before pushing.
