# PSK — Prompt Secret Killer

PSK sits between a coding agent (Claude Code, Cursor, Codex) and the LLM provider. It scrubs
secrets out of everything sent upstream and puts the real values back at the local execution
boundary, so the agent still operates on real data while the model never sees it.

> **Naming.** "PSK" collides with *pre-shared key* in security vocabulary. In this project it
> always means **Prompt Secret Killer**, and it is never abbreviated ambiguously in
> security-adjacent documentation.

## The idea in one example

Your prompt contains a real AWS key, `AKIA1234567890ABCDEF`.

1. **Outbound.** PSK's local proxy replaces it with a *format-preserving fake* — same prefix, same
   length, checksum-valid where the format implies one — say `AKIAQPSKR7T2XW9MQ4LP`. The model
   reasons about the fake and never receives the real key.
2. **Vault.** A durable `real <-> fake` mapping, derived deterministically from a salt that
   persists at `~/.psk/salt`.
3. **Restore.** The model replies "write it to `config.yaml`". A `PreToolUse` hook swaps the real
   key back in the instant before the write executes. `config.yaml` gets the real key.

This is a **bidirectional substitution loop**, not visible redaction. Nothing is starred out, so
the model's reasoning about the value stays intact.

## Why a proxy and not just hooks

Claude Code's `UserPromptSubmit` hook can *inject* context or *block* a prompt. It **cannot**
silently rewrite the outgoing prompt body, so it cannot hide a secret the user already typed. The
only place with full, silent control over what leaves the machine is a local reverse proxy that
the agent points at via `ANTHROPIC_BASE_URL`.

The `PreToolUse` hook *can* rewrite tool input, which is exactly what makes it the right place to
restore.

## Restore modes

Configured in `~/.psk/config.toml`.

| Mode | Proxy restores the response? | Real secrets in agent transcripts? |
| --- | --- | --- |
| `execution` (default) | No | **No** — they materialize only at tool execution |
| `full` | Yes, in the SSE stream | **Yes** — the agent persists them to `~/.claude/projects/*.jsonl` |

In `execution` mode you see fakes on screen. That is the feature: **what you see is what the
provider saw.** Real values appear only inside the tool call that needed them.

`full` mode exists for agents with no hook mechanism. It trades the transcript guarantee away, and
says so out loud.

**Known limitation:** MCP tools and agents without `PreToolUse` support bypass the restore path.

## Authentication

Both of Claude Code's auth modes work through PSK. Verified empirically: a Pro/Max **OAuth** session
(`Authorization: Bearer`) survives `ANTHROPIC_BASE_URL` redirection to a local proxy and reaches the
upstream with a `200`, exactly as an **API key** (`x-api-key`) does. PSK passes auth headers through
untouched and never logs them.

## Status

M1 is **in progress**. This is not yet a working binary — building in the brief's order, with each
layer proven before the next is written.

| Component | State |
| --- | --- |
| `psk-vault` — deterministic fakes, salt, guard, restore, near-miss | **Done**, 35 tests passing |
| `psk-secrets` / `psk-verifiers` — rules and false-positive killers | Not started |
| `psk-core` — the recognizer/engine orchestration | Not started |
| `psk-proxy` — outbound substitution, `/restore`, `/events` | Not started |
| `psk-cli`, `psk-init`, `psk-tui` | Not started |

Once the CLI lands, the quickstart will be:

```sh
cargo install psk-cli      # not yet published
psk init                   # writes the PreToolUse hook into ~/.claude/settings.json
psk proxy                  # prints the ANTHROPIC_BASE_URL line to export
```

Run the tests that exist today with:

```sh
cargo test -p psk-vault
```

## What PSK does not protect

Real secrets live in plain memory inside the vault for the whole session, and in every incoming
request buffer. `zeroize` wipes transient scratch buffers; it does not make the process memory safe
to dump, and it cannot reach bytes left behind by heap reallocation. See the honesty block at the
top of `crates/psk-vault/src/lib.rs`.

PSK never writes prompt or response content to disk. Counters and the salt only.

## License

Apache-2.0.
