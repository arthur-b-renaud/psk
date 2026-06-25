# psk — Prompt Secret Killer

Scrub secrets and PII from LLM traffic **before it leaves your machine** — while your local files
keep the real values.

`psk` is a pure-Rust, local-first **egress filter** that sits between your coding agent (Claude
Code, Cursor, Antigravity) and external LLM providers. It detects sensitive content with
**deterministic, regex-like recognizers** (no ML model, no network at detection time) and redacts it
in-flight, so confidential data never reaches a third-party API.

## The two guarantees

1. **Nothing sensitive leaves in cleartext.** A local proxy scans every outbound request and
   redacts secrets and PII.
2. **Local actions keep the real value.** If the agent writes a `.env`, the file on disk contains
   the *real* secret — not a placeholder.

These are reconciled by **reversible tokenization**: the proxy swaps each secret for a stable token
(`__PSK_<hex>__`) before the request leaves and remembers `token → secret` in an in-memory vault.
The provider only ever sees the token. When the agent writes a file or runs a command locally, a
Claude Code `PreToolUse` hook swaps the token back to the real value — so your `.env` is correct and
your provider logs are clean.

> **Status: early / work in progress.** Detection (secrets + structured PII), the proxy, the vault,
> and Claude Code wiring are functional. Cursor and Antigravity are best-effort (see below).

## Architecture

A Cargo workspace of focused crates:

| Crate          | Role                                                              |
| -------------- | ---------------------------------------------------------------- |
| `psk-core`     | Pipeline, redaction policy, span model, **vault**, stats         |
| `psk-patterns` | Regex recognizers + validators (Luhn, IBAN, INSEE, SIRET, SIREN) |
| `psk-proxy`    | Local proxy daemon: scrubs egress, `/psk/detokenize` endpoint    |
| `psk-hook`     | Agent wiring (Claude Code base URL + PreToolUse restore hook)    |
| `psk-cli`      | `psk` command-line entrypoint + daemon lifecycle                 |

Detection layers, in order:

1. **Secrets** — broad provider catalog (`patterns/secrets.yaml`) + connection strings with embedded
   credentials (`patterns/connections.yaml`). Reversibly tokenized so agents stay functional.
2. **Structured PII** — emails, phones, cards, IBANs, IPs, national IDs, … (`patterns/*.yaml`),
   gated by validators. Irreversibly replaced.

## Build

```bash
cargo build --release
```

## Usage

```bash
# Wire up detected agents (Claude Code base URL + restore hook), then start the daemon.
psk install
psk start                      # background daemon — the token vault lives here
psk status
psk stop

# One-shot scan of stdin (no daemon; tokenization degrades to irreversible replacement).
echo "key is AKIAIOSFODNN7EXAMPLE" | psk scan
echo "..." | psk scan --json    # span details

# Inspect loaded patterns and redaction stats.
psk patterns
psk gain

# Run fixture tests.
psk test
```

`psk restore --hook` is invoked automatically by the Claude Code `PreToolUse` hook; you don't run it
by hand.

### Other agents

- **Cursor (best-effort):** set Settings → Models → "Override OpenAI Base URL" to
  `http://127.0.0.1:7878/v1`. Note that only Cursor's chat/plan panel honors this — Composer / apply
  / autocomplete bypass it, so agent traffic isn't fully covered.
- **Antigravity (experimental):** point its model endpoint at `http://127.0.0.1:7878` (Gemini
  route). Custom-endpoint support is unstable upstream.

Upstreams are overridable for Azure / self-hosted gateways via `PSK_ANTHROPIC_UPSTREAM`,
`PSK_OPENAI_UPSTREAM`, `PSK_GEMINI_UPSTREAM`.

## Documentation

- [Getting started](docs/getting-started.md) — build, install, daemon, per-tool wiring, troubleshooting
- [Architecture](docs/architecture.md) — the proxy, the vault, reversible tokenization, request lifecycle
- [Security model](docs/security.md) — what's protected, what isn't, threat model, trade-offs
- [Patterns & configuration](docs/patterns.md) — YAML pattern format, validators, custom packs, runtime files
- [Contributing](CONTRIBUTING.md) — dev setup, CI gate, adding recognizers
- [Changelog](CHANGELOG.md)

## Patterns & fixtures

- `patterns/*.yaml` — declarative recognizer definitions (name, entity, regex, confidence, optional
  validator).
- `fixtures/*.txt` — **synthetic** test inputs. Never commit real client data or real prompts.

## Security notes

- The vault holds real secrets only in the running daemon's memory (session-scoped, never on disk).
  `/psk/detokenize` is gated by a per-session auth token (`~/.psk/auth.token`).
- Restoring a token inside a `Bash` command means a command could re-expose a secret to a
  non-proxied egress (e.g. a direct `curl`). This is inherent to guarantee #2 and is by design.

## License

[MIT](LICENSE). Provided **"as is", without warranty of any kind** — see the LICENSE file for the
full disclaimer of warranty and liability.
