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
| `psk-vault` — deterministic fakes, salt, guard, restore, near-miss | **Done** |
| `psk-verifiers` — checksums, entropy gate, allowlists | **Done** |
| `psk-secrets` — detection rules over a lazily-compiled `RegexSet` | **Done** |
| `psk-core` — recognizer trait, overlap resolution, the engine | **Done** |
| `psk-proxy` — substitution surfaces, SSE restore, `/restore`, `/events` | **Done** |
| external corpus + per-kind precision floor | **Done** |
| `psk-cli` — `scan` / `proxy` / `hook` / `init` / `uninit` / `gain` / `test` | **Done** |
| `psk-init` — manages the `PreToolUse` hook in `settings.json` | **Done** |
| `psk-tui` (`psk top`) — live inspector | **Done** |

**M1 is complete.** 178 tests pass. The full loop — detect, verify, resolve overlap, guard,
substitute, forward, restore — is proven end to end against a mock upstream; the
**execution-boundary loop** (proxy mints a fake → the `PreToolUse` hook restores it before
`Bash`/`Edit`/`Write` runs → a mangled fake is blocked → a down proxy fails open) was driven by
hand against the real binary; and `psk top` was driven live against a running proxy, rendering the
streamed request feed.

## Quickstart

```sh
cargo install --path crates/psk-cli   # builds the `psk` binary
psk init                              # installs the restore hook AND the `claude` shim
export PATH="$HOME/.psk/bin:$PATH"    # one-time; add to your shell rc (psk init prints this)
claude                                # routes through the proxy, which starts on demand
```

`psk init` installs two things: the `PreToolUse` restore **hook** in `~/.claude/settings.json`, and
a transparent `claude` **shim** at `~/.psk/bin/claude`. Once `~/.psk/bin` is on your `PATH`, typing
`claude` runs it through `psk run`, which **starts the proxy on demand** and points that session at
it — so you never have to keep a proxy terminal open, and a stopped proxy never breaks `claude`
(it just launches unprotected). You can still run `psk proxy` by hand to watch one in the
foreground. Run `psk uninit` to remove the hook and the shim cleanly.

> Upgrading from an older PSK? Earlier versions wrote `env.ANTHROPIC_BASE_URL` into
> `settings.json`, which broke `claude` whenever the proxy wasn't running. `psk init` now removes
> that automatically.

Watch traffic live with `psk top`; see savings with `psk gain`.

## Requirements

A Rust toolchain, and the C compiler it already needs in order to link. Nothing else — no
`pkg-config`, no preinstalled system library, no C++ toolchain. `cargo install` just works.

Run the tests with:

```sh
cargo test --workspace          # hermetic and offline

./scripts/fetch-corpus.sh       # optional: the external detection benchmark
PSK_REQUIRE_CORPUS=1 cargo test -p psk-secrets --test corpus
```

Detection is scored against [`psk-corpus`](https://github.com/arthur-b-renaud/psk-corpus), a
labelled corpus extracted from gitleaks (MIT). Current: **precision 1.0000, recall 1.0000** over the
71 true positives that map to an M1 rule kind. Those numbers come from a small sample, and the rules
were tuned against it — it is a regression gate and an outside opinion, not proof of general
accuracy.

## What PSK does not protect

Real secrets live in plain memory inside the vault for the whole session, and in every incoming
request buffer. `zeroize` wipes transient scratch buffers; it does not make the process memory safe
to dump, and it cannot reach bytes left behind by heap reallocation. See the honesty block at the
top of `crates/psk-vault/src/lib.rs`.

PSK never writes prompt or response content to disk. Counters and the salt only.

## License

Apache-2.0.
