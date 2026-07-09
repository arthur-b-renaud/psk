# PSK (Prompt Secret Killer) — Build Brief v2

You are building an open-source Rust tool. Read this whole brief before writing code. The maintainer is proficient in Python but new to Rust, so comment non-obvious Rust idioms (ownership, lifetimes, `Result`, traits) inline and keep the code idiomatic but readable. Do not over-engineer.

Naming note: "PSK" collides with "pre-shared key" in security vocabulary. The name stays for now, but the README must expand it as "Prompt Secret Killer" on first use and never abbreviate ambiguously in security-adjacent docs.

## 1. What PSK does

PSK sits between a coding agent (Claude Code, Cursor, Codex, etc.) and the LLM provider. It scrubs secrets and PII out of anything sent to the provider, then restores the real values at the local execution boundary, so local execution still works on the real data.

The mechanism is a **bidirectional substitution loop**, not visible redaction:

1. **Outbound:** detect each real secret in the request, replace it with a *format-preserving fake* (a plausible value of the same shape). The LLM reasons on the fake and never sees the real value.
2. **Session vault:** maintain a durable `real <-> fake` mapping (see section 7 for durability rules).
3. **Restore:** swap the real value back in before local execution acts on it. Where restore happens is an explicit architecture decision (section 2b).

Example: the prompt contains `AKIA1234567890ABCDEF`. The LLM sees `AKIAQPSKQ00000000001`. The LLM replies "write it to `config.yaml`". PSK restores the real key before the write executes, so `config.yaml` gets the real key. The LLM never saw it.

## 2. Interception architecture (read carefully, this drives the design)

Claude Code hooks are **not** sufficient for the outbound rewrite. Verified behavior:

- `UserPromptSubmit` hook: can **inject context** (stdout is appended) or **block** (exit 2). It **cannot** silently replace the outgoing prompt body. So it can't hide a secret that's already in the user's prompt.
- `PreToolUse` hook: **can** rewrite tool input (reads tool-input JSON on stdin, emits modified JSON on stdout). This is the restore point for `Write`/`Edit`/`Bash`.

Therefore the **primary outbound interception mechanism is a local reverse proxy**, not hooks:

- Run a local HTTP server that speaks the **Anthropic Messages API** (and later an OpenAI-compatible endpoint).
- The agent points at it: `ANTHROPIC_BASE_URL=http://127.0.0.1:8787`.
- PSK rewrites the request body (substitute) before forwarding to the real provider.

This is the only place we get full, silent control over what leaves the machine. Build the proxy first; it is the product.

**Auth pre-check (do this before writing proxy code):** Claude Code authenticates either with `x-api-key` (API key users) or an OAuth Bearer token (Pro/Max subscription users). Verify empirically that `ANTHROPIC_BASE_URL` redirection plus untouched header pass-through works for **both** auth modes. If the OAuth flow pins the origin or fails through a local base URL, document the limitation prominently in the README (the product would then only serve API-key users) and record the finding in `CLAUDE.md`. Do not discover this after the proxy is built.

### 2b. Restore point: execution-boundary by default (explicit decision)

Where restore happens determines where real secrets exist on the machine. If the proxy restores inbound (in the streamed response), Claude Code receives real values and **persists them to its own session transcripts on disk** (`~/.claude/projects/*.jsonl`) and displays them in terminal scrollback. That partially defeats the tool's purpose.

PSK therefore supports two restore modes, configured via `~/.psk/config.toml` (`restore_mode = "execution" | "full"`):

- **`execution` (default):** the proxy substitutes outbound only and does **not** restore inbound. Restore happens exclusively at the `PreToolUse` hook, the instant before `Bash`/`Edit`/`Write` executes. Consequences, all intentional:
  - Real secrets never appear in Claude Code transcripts, terminal output, or any agent-side state. They materialize only at execution.
  - The user sees fakes on screen. This is a feature: what you see is what the provider saw.
  - Conversation history resent by the agent contains fakes. The substitution engine must never re-substitute a known fake (see the fake-recognition guard, section 7).
  - Limitation: MCP tools and agents without hook support bypass the restore path. Document this.
- **`full`:** the proxy additionally restores fakes in the streamed response (SSE), for agents that have no hook mechanism. The README must state plainly that in this mode the agent will persist real secrets to its own local transcripts.

Both modes ship in M1. Both are tested. The hook is required in both modes (in `full` mode it is a second restore layer catching anything the stream restore missed).

The hook restores; it never rewrites prompts. `UserPromptSubmit` prompt rewriting remains impossible and is not attempted.

## 3. Scope for this milestone (M1)

Ship a single binary that does the full loop for **secrets only** (no ML, no PII NER yet), provable end to end.

Deliverables:
- Detection engine for ~30 high-value secret patterns (see section 6).
- Durable session vault with deterministic format-preserving fake generation and exact restore (section 7).
- Local proxy for the Anthropic Messages API doing outbound substitution across **all** substitution surfaces (section 8), plus inbound SSE restore when `restore_mode = "full"`.
- `PreToolUse` restore hook with **loud failure** on near-miss fakes (section 8b).
- `psk init` that writes the hook config into `~/.claude/settings.json` (and `psk uninit` to remove it).
- CLI: `psk scan`, `psk proxy`, `psk hook`, `psk init` / `psk uninit`, `psk top`, `psk gain`, `psk test`.
- Fixture corpus + tests proving substitute/restore round-trips losslessly, **plus** an external-corpus gate (section 12).
- `README.md` with a copy-pasteable quickstart, and a `CLAUDE.md` documenting the architecture for future sessions.

Explicitly **out of scope for M1** (do not build): ONNX/GLiNER NER, PII layer, Homebrew tap, Windows packaging, multi-provider (OpenAI) proxy, WASM playground. Leave clean seams (traits, feature flags) so these slot in later, but do not implement them.

## 4. Workspace layout

Cargo workspace. Keep crates small and single-purpose.

```
psk/
  Cargo.toml            # [workspace] members
  crates/
    psk-core/           # orchestrator: text in -> (substituted text, vault ops) -> text out
    psk-secrets/        # the pattern rules, compiled once into a RegexSet
    psk-verifiers/      # false-positive killers: Luhn (cards), mod-97 (IBAN), entropy gate, allowlists
    psk-vault/          # bijective real<->fake map + deterministic format-preserving fake generation
    psk-proxy/          # local HTTP server, Anthropic Messages API, request rewrite, optional response restore, restore endpoint
    psk-init/           # writes/removes the PreToolUse hook config in ~/.claude/settings.json
    psk-tui/            # terminal inspector: SSE client + ratatui UI (stats, live feed, prompt diff)
    psk-cli/            # the `psk` binary: scan / proxy / hook / init / uninit / top / gain / test subcommands
  fixtures/             # internal test corpus (dummy secrets, expected detections)
  corpus/               # vendored external detection corpus (see section 12)
  README.md
  CLAUDE.md
```

Dependency direction: `cli -> {proxy, init, tui} -> core -> {secrets, verifiers, vault}`. No cycles. `psk-tui` talks to `psk-proxy` only over its localhost HTTP endpoints (SSE + fetch), not by linking its internals. `psk-core` exposes a `Recognizer` trait so new detectors (future NER) plug in without touching the proxy.

## 5. Core abstractions

- `Recognizer` trait in `psk-core`: `fn scan(&self, text: &str) -> Vec<Match>` where `Match { start, end, kind: SecretKind, value: &str }`. The regex layer is one implementation; future NER is another.
- `Vault` in `psk-vault`: holds two `HashMap<String, String>` (real->fake, fake->real) plus a counter. Methods: `substitute(real: &str, kind: SecretKind) -> String` (idempotent and deterministic, see section 7) and `restore(text: &str) -> String`. Also `is_known_fake(&str) -> bool` and `near_miss(&str) -> Option<NearMiss>` (section 8b).
- `Engine` in `psk-core`: runs recognizers, dedups/resolves overlapping matches (longest match wins), **drops any match that `is_known_fake` accepts** (never re-substitute a fake), calls the vault, returns the rewritten string. Also exposes `restore` delegating to the vault.

Restore must be an **exact, whole-token** replacement. Use `aho-corasick` built over the set of known fakes for fast multi-pattern replacement, not N calls to `str::replace`.

## 6. Detection rules (M1 set)

Pure-Rust `regex` crate with `RegexSet` for the first cut. Do **not** pull in Hyperscan/vectorscan yet: it needs a C toolchain and breaks the "`cargo install` just works everywhere" promise. Note in `CLAUDE.md` that Hyperscan is a later throughput lever if profiling demands it.

Port these rule shapes from gitleaks/trufflehog (regex + validator):

- AWS access key id (`AKIA` + 16), AWS secret key (40-char base64-ish, entropy-gated)
- GitHub PAT (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` + 36)
- Anthropic key (`sk-ant-` prefix), OpenAI key (`sk-` + long)
- Google API key (`AIza` + 35), GCP service-account private key block
- Slack token (`xox[baprs]-`), Stripe (`sk_live_`, `rk_live_`)
- JWT (three base64url segments), generic Bearer token
- Private key blocks (`-----BEGIN ... PRIVATE KEY-----`)
- SSH private keys
- Credit card (Luhn-validated), IBAN (mod-97-validated)
- IPv4 / IPv6, email — **disabled by default in M1** (see below)

Every rule that can have a checksum **must** go through `psk-verifiers` before it's treated as a real secret. Entropy gate (Shannon, threshold configurable) for the high-false-positive generics.

### 6b. False-positive discipline (this decides whether the tool is usable)

Coding-agent traffic is full of values that pattern-match secrets but are not: loopback IPs, example emails, git SHAs, lockfile hashes. Substituting them fires constantly and actively breaks the LLM's reasoning about networking code, git operations, and dependency files. The loop tolerates false positives only if restore is perfect, and restore is not perfect (section 8b). Rules:

- **IPv4/IPv6 and email rules ship disabled by default.** Enable via config. Even when enabled, hard-allowlist: loopback (`127.0.0.0/8`, `::1`), unspecified (`0.0.0.0`), RFC 1918 private ranges, link-local, documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`), and reserved/example domains (`example.com/.org/.net`, `.test`, `.invalid`, `.localhost`, `.example`).
- **The 40-char entropy-gated generic (AWS secret key shape) must exclude pure-hex strings** (git SHA-1s are 40 hex chars) and require the base64 alphabet beyond `[0-9a-f]`. Add lockfile-typical hash shapes (`sha256-`, `sha512-` prefixed, integrity fields) to the allowlist logic in `psk-verifiers`.
- Allowlists live in `psk-verifiers` with a fixture proving each allowlisted class is *not* substituted.

## 7. Fakes and vault durability

### 7a. Deterministic fake generation (mandatory)

Claude Code resends the **full conversation history on every request**. If the proxy restarts mid-session with a randomly generated vault, the history contains fakes the new vault has never seen; worse, those fakes pattern-match as real secrets and would be substituted again, cascading into a corrupted mapping. Therefore:

- Fake generation is **deterministic**: `fake = format_preserve(HMAC-SHA256(salt, real_value), kind)`. The same real value always yields the same fake for a given salt.
- The **salt persists** at `~/.psk/salt` (0600 permissions, created on first run). A salt is not content; this does not violate the disk ban. Because the real secret reappears in the resent history (it is in the original user message or tool result every time), a restarted proxy re-derives the identical fake and rebuilds the mapping on the fly. Restart becomes a non-event.
- Determinism also protects **Anthropic prompt caching**: stable fakes keep cached prefixes byte-identical across requests and restarts. Randomized fakes would silently invalidate the cache and inflate the user's token bill. `cache_control` blocks pass through the proxy untouched; add a test.

### 7b. Fake format rules

- Same **prefix and length class** as the real value so the LLM's reasoning stays intact (`AKIA...` stays `AKIA...` and stays 20 chars).
- **Embedded marker:** every fake carries a fixed reserved 4-character marker (e.g., `QPSK`) at a deterministic, kind-specific offset. The LLM does not care; checksums are still forced to pass; but a human, `psk scan`, or the near-miss detector can instantly identify an unrestored fake in a file or diff. Indistinguishable fakes are a debugging nightmare; do not build them.
- Checksum-valid where the format implies one (fake cards pass Luhn, fake IBANs pass mod-97), so the LLM doesn't comment on an invalid value. **Collision avoidance:** generated checksum-valid values can collide with someone's real value (a Luhn-valid number can be a live card). Prefer reserved/test spaces where they exist: documentation BINs for cards, an IBAN country/structure pattern not in live use. Accept the residual risk that the LLM occasionally recognizes a test range and comments; that is cheaper than emitting plausible-live values.
- High internal entropy from the HMAC, so two different real values never collide to the same fake, and a fake is extremely unlikely to appear by chance in normal text.
- Memoized within the vault: `real -> fake` lookups hit the map before re-deriving (preserves coreference for the LLM and avoids recomputing HMACs).

### 7c. The fake-recognition guard

`Engine::substitute` must check every candidate match against the known-fake set (and the marker) **before** substituting, and skip it if it is a fake. This is required for the restart scenario, for `restore_mode = "execution"` (where history legitimately contains fakes), and as a general anti-cascade invariant. Add a test: substituting text that already contains a fake is a no-op on that span.

### 7d. Memory hygiene, scoped honestly

Real secrets necessarily live in plain `String`s inside the vault's `HashMap` for the whole session, and in every incoming request buffer. Do not pretend otherwise. `zeroize` is applied to **transient** buffers (scan scratch space, restore intermediates, the hook's stdin buffer) and the vault implements `Drop` with best-effort wipe. `CLAUDE.md` documents explicitly that the vault is the accepted in-memory residency of real values and what `zeroize` does and does not cover. A security tool with a false sense of memory hygiene is worse than one with none.

## 8. Proxy spec (`psk-proxy`)

- `axum` or `hyper` server on `127.0.0.1:8787`.
- Accept POST on the Anthropic Messages path, parse the JSON body, run `Engine::substitute` over **all substitution surfaces** (8a), forward the rewritten body to the real upstream (`https://api.anthropic.com`, base URL configurable).
- **`restore_mode = "full"` only:** stream the SSE response back, running `Vault::restore` on text deltas **and thinking deltas** (both are displayed to the user) before yielding them. A fake token can be split across two SSE chunks: buffer a small trailing window (longest known fake length) across chunk boundaries so a spanning fake is still restored. In `execution` mode, the SSE stream passes through untouched.
- Pass through auth headers untouched (`x-api-key` and OAuth `Authorization: Bearer` both; see the auth pre-check in section 2). Never log request/response bodies.
- One vault instance per proxy process for M1 (with the durability rules of section 7, this is safe across restarts). Structure it so per-session isolation is a small change. Note: Claude Code issues parallel background requests (subagents, title generation); the single shared vault must be `Send + Sync` and correct under concurrent access.
- Expose a tiny local `POST /restore` endpoint on the same server: body is a JSON string, response is the restored string plus any near-miss diagnostics (8b). The `psk hook` client calls this so the hook and the proxy share one live vault.
- Publish one event per request for the inspector: push `{ id, timestamp, upstream_url, model, entity_counts_by_kind, chars_hidden, latency_ms, rewritten_text }` onto a `tokio::sync::broadcast` channel, keep the last N (default 500) in an in-memory ring buffer, and serve them at `GET /events` (SSE). Serve the original text for a single request only at `GET /events/{id}/original`. Both endpoints bind to `127.0.0.1` only. Original text is never broadcast, only served on explicit per-id request. No event content touches disk.
- The proxy owns the stats counters and flushes them to `~/.psk/stats.json` (counters only, never content): prompts scanned, entities substituted by kind, fakes restored, fakes never restored, near-misses caught at the hook, avg latency. This file is what `psk gain` reads.

### 8a. Substitution surfaces (mandatory, all of them)

"The prompt" is the smallest leak channel. The dominant exfiltration path in agent traffic is tool output: the agent runs `cat .env`, reads `settings.py`, greps credentials, and that content goes upstream inside the request. Substitution must cover, explicitly:

- `messages[].content` as a plain string;
- `messages[].content[]` content blocks of type `text`;
- **`tool_result` blocks**, including nested content in both string and array shapes: this is the big one;
- `tool_use` input blocks echoed back in history;
- the top-level **`system`** field (string and block-array shapes).

A fixture containing a fake `.env` file inside a `tool_result` block is an acceptance criterion (section 12).

### 8b. Hook spec: restore loudly, fail open quietly

The `PreToolUse` hook (`psk hook`) reads tool-input JSON on stdin for `Bash`/`Edit`/`Write`, sends the relevant string fields to the proxy's `/restore`, and emits the modified JSON on stdout. Claude Code executes the restored input. This is the primary restore point in `execution` mode and the safety net in `full` mode.

**Loud failure on near-misses.** The LLM sometimes echoes an altered fake: changed casing, truncation, re-wrapped lines. Exact-match restore misses it, and the result would be a plausible-looking, checksum-valid fake silently written into a real config file, which is worse than no tool at all. Therefore, at the execution boundary only:

- After exact restore, run **near-miss detection** on the remaining text: case-insensitive match against known fakes, known-fake prefix match of ≥ 12 characters, and presence of the fake marker (7b) outside any exact-restored span.
- On a near-miss, the hook **blocks** (exit 2) with a clear message naming the tool input field and the suspected mangled fake, so the agent and the user see it immediately instead of three hours later. Count it in stats.
- Exact-match restore everywhere else (proxy stream, `psk scan`) stays exact; the execution boundary is where "almost" becomes damage, so it is the only place that pays the near-miss cost.

**Fail-open applies only to infrastructure, not to detection.** If the proxy is down, the hook passes input through unchanged with exit 0 (never block the agent because PSK isn't running). Down-proxy pass-through and near-miss blocking are different conditions; do not conflate them.

## 9. Inspector TUI (`psk-tui`)

A terminal UI for watching what actually leaves the machine, in the spirit of `rtk gain` but live. Launched with `psk top`. Built with `ratatui` + `crossterm`.

**Data source.** The proxy publishes one structured event per request onto an in-process `tokio::sync::broadcast` channel and exposes it as a localhost-only SSE stream at `GET /events`. The TUI is an SSE client. Each event carries **metadata + the rewritten (safe) text only**. Original (real-secret) text is **not** put on the wire by default. When the user opens a request and presses reveal, the TUI fetches the original for that one `id` from `GET /events/{id}/original`. This keeps real secrets off the event stream unless the operator explicitly asks to see one.

**Persistence.** Nothing is written to disk. The proxy keeps a bounded in-memory ring buffer (last N requests, default 500, configurable); the TUI keeps its own bounded buffer. Closing either drops the content. The disk ban from the rest of PSK still holds: counters may persist, content never does.

**Layout (three regions):**

- **Header — high-level stats, live:** uptime, prompts scanned, entities substituted (running total + per-kind breakdown), total chars hidden, near-misses blocked at the hook, avg + p95 latency. A sparkline of substitutions-per-minute is a nice-to-have, not required.
- **Main list — realtime request feed, grouped by upstream URL:** newest at top, auto-scrolling (pausable). Columns: time, upstream host+path, model, entities substituted, chars hidden, latency. A filter/group toggle collapses rows under each distinct API URL. Arrow keys move the selection.
- **Detail pane — inspectable prompt / rewritten prompt:** on select, show the request's messages. Default view is the **rewritten** text with substituted spans highlighted and a legend of `kind -> fake` for that request. Pressing `r` (reveal) fetches and shows the **original**, rendered as a diff against the rewritten version. Reveal is per-request and never cached to disk. `Esc` collapses back to the safe view.

**Keybindings (minimum):** arrows to navigate, `Enter` to open detail, `r` to reveal original, `g` to toggle group-by-URL, `space` to pause/resume the feed, `/` to filter by URL substring, `q` to quit.

**Failure behavior.** If the proxy isn't running, `psk top` prints a one-line hint to start `psk proxy` and exits cleanly. The TUI is read-only: it never modifies traffic, so it can attach/detach at any time without affecting the proxy.

## 10. CLI

- `psk scan` — read stdin (or a file arg), print detected entities with kind + span, the substituted text, **and flag any string that is or near-misses a known fake** (requires the proxy for vault access; degrade to pattern+marker detection if it is down). For manual testing: `echo 'key sk-ant-abc...' | psk scan`.
- `psk proxy` — start the local proxy (holds the vault, serves the Messages API, `POST /restore`, `GET /events`). Print the exact `export ANTHROPIC_BASE_URL=...` line the user should set, and the active `restore_mode`.
- `psk hook` — the `PreToolUse` handler per section 8b.
- `psk init` / `psk uninit` — write or remove the `PreToolUse` hook entry in `~/.claude/settings.json` (matcher `Edit|Write|Bash`, command `psk hook`). `init` should be idempotent and print what it changed.
- `psk top` — launch the inspector TUI (section 9).
- `psk gain` — print counters from `~/.psk/stats.json` (written by the proxy, section 8): prompts scanned, entities substituted by kind, fakes restored, fakes never restored, near-misses blocked, avg latency. Counters only, never content.
- `psk test` — run the engine against `fixtures/` **and** `corpus/`, report precision/recall and pass/fail per corpus. Non-zero exit on failure so it works in CI.

Use `clap` (derive API) for arg parsing. Lazily compile the `RegexSet` (first scan, not process start) so cold CLI startup stays under ~10 ms.

## 11. Dependencies (justify any additions in CLAUDE.md)

`regex`, `aho-corasick`, `serde` + `serde_json`, `axum` (or `hyper` + `tower`), `reqwest` (streaming), `tokio`, `clap`, `ratatui` + `crossterm` (the TUI), `zeroize` (transient buffers, per 7d), `hmac` + `sha2` (deterministic fake derivation), `criterion` (dev-dependency, benches). Nothing that needs a system C library in M1.

## 12. Acceptance criteria

- `cargo build` and `cargo test` pass on Linux and macOS with no system deps beyond a Rust toolchain.
- **Internal fixtures:** `psk test` reports 100% detection on `fixtures/` with zero false positives on a clean-text fixture *and* zero substitutions on the allowlist fixture (loopback IPs, example domains, git SHAs, lockfile hashes).
- **External corpus:** vendor a third-party detection corpus (gitleaks' test data or an equivalent public secrets benchmark) into `corpus/`, respecting its license. `psk test` reports precision/recall against it. Set an explicit floor (≥ 0.95 precision on the M1 rule kinds) rather than a self-graded 100%. Document corpus provenance in `CLAUDE.md`. Self-graded fixtures alone prove nothing to an open-source audience.
- **Round-trip:** a prompt with 5 distinct real secrets: substitute, assert none of the 5 real values appear outbound, assert all 5 fakes present, restore verbatim-echoed fakes, assert output equals the original.
- **Determinism/restart:** substitute a value, drop the vault, recreate it from the same salt, substitute the same value, assert the identical fake; and assert `Engine::substitute` is a no-op on text already containing that fake (the guard, 7c).
- **Tool-result surface:** a request fixture with a fake `.env` inside a `tool_result` block and a secret in the `system` field is fully substituted before forwarding.
- **Proxy integration (mock upstream):** request body substituted before forwarding; in `full` mode, streamed response restored including a fake split across two SSE chunks and a fake inside a thinking delta; in `execution` mode, the stream passes through byte-identical. `cache_control` blocks survive untouched.
- **Hook:** a `Write` tool-input JSON containing an exact fake is restored; one containing a case-mangled fake causes exit 2 with a diagnostic; with the proxy down, input passes through unchanged with exit 0.
- `zeroize` applied per the scope in 7d, with a comment block in `psk-vault` stating exactly what is and is not wiped.
- Cold startup of the `psk` binary under ~10 ms.

## 13. Conventions

- Comment ownership/borrow decisions and any `.clone()` that exists for a reason. Explain traits the first time they appear.
- Errors: use `thiserror` for library crates, `anyhow` at the binary boundary. No `.unwrap()` in library code paths that can fail on user input.
- Keep functions short. Prefer clarity over cleverness; this is a teaching codebase as much as a shipping one.
- Write `CLAUDE.md` covering: the interception architecture and *why the proxy is the outbound point and the hook is the execution-boundary restore point*, the two restore modes and the transcript-persistence trade-off, the crate graph, the vault contract (determinism, salt, marker, guard), the auth-mode findings from the 2b pre-check, the honest `zeroize` scope, the external corpus provenance, the Hyperscan-later note, and the M2+ seams (NER recognizer, PII layer, OpenAI proxy).
- License Apache-2.0.

## 14. Do not

- Do not implement NER, PII, ML, or the OpenAI proxy in M1.
- Do not add Hyperscan or any C-linked dependency in M1.
- Do not store prompt or response content on disk, ever. Counters and the salt only.
- Do not claim the `UserPromptSubmit` hook can rewrite prompts. It cannot. The proxy is the outbound rewrite point.
- Do not generate random (non-deterministic) fakes. Every fake derives from the persisted salt.
- Do not substitute a known fake (the guard is an invariant, not an optimization).
- Do not enable IP/email rules by default.
- Do not let the hook block the agent because the proxy is down; do not let it silently pass a near-miss fake into an executed tool input.

## 15. Build order

Scaffold the workspace, then in order: `psk-vault` (deterministic generation, salt handling, guard, marker, round-trip + determinism tests) → `psk-secrets` + `psk-verifiers` (rules, allowlists, external corpus wiring) → `psk-core` → the proxy (substitution surfaces, `/restore`, `/events`, both restore modes) → the CLI → `psk hook` + `psk-init` (near-miss blocking) → `psk-tui` last. Show me the vault with its passing round-trip and determinism tests first before moving on.
