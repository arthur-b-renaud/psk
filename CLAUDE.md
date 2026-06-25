# CLAUDE.md :: psk — Prompt Secret Killer

`psk` is a **pure-Rust, local-first egress filter** that sits between coding agents and external LLM
providers. It detects secrets and structured PII with **deterministic, regex-like recognizers only**
and redacts them *in flight*, so confidential data never reaches a third-party API — while the local
machine keeps the real values.

There is **no ML model and no inference at runtime**. Detection is regex + validators (Luhn, IBAN,
INSEE, SIRET, SIREN). This is a hard constraint: do not add a model, an ONNX runtime, a tokenizer
download, or any network call at detection time. If recall on free-text entities (client/org names)
is needed later, it returns as a *deterministic* `aho-corasick`/`fst` gazetteer over a user roster —
never a model.

Read this before touching `crates/`, `patterns/`, or `fixtures/`.

---

## Mission and the two guarantees

The enterprise goal is to stop **secrets and personal/company PII** from leaking to external LLM
providers, without crippling the agent locally. Two guarantees define the design:

1. **Nothing sensitive leaves the machine in cleartext.** Every outbound provider request is scanned
   and redacted by the proxy (the egress filter).
2. **Local actions keep the real value.** If the agent writes a `.env`, edits a file, or runs a
   command containing a secret, the bytes that hit the local disk/shell are the *real* secret — not
   a placeholder.

Reconciling these requires **reversible tokenization**: the proxy swaps each secret for a stable,
opaque token (`__PSK_<hex>__`), remembers `token → secret` in an in-memory vault, and a Claude Code
`PreToolUse` hook swaps tokens back to real values when the agent writes/edits/bashes locally. The
provider only ever sees tokens; the filesystem only ever sees real values.

Risk is asymmetric — a false positive (tokenizing a non-secret) is harmless because it round-trips,
a missed credential is the failure we prevent — so recognizers are **tuned for recall**.

---

## Architecture

Cargo workspace of focused crates:

| Crate          | Role                                                                          |
| -------------- | ----------------------------------------------------------------------------- |
| `psk-core`     | `Pipeline`, `RedactionPolicy`, `Span`/`EntityType`, `Vault`, stats            |
| `psk-patterns` | YAML-driven `RegexRecognizer` + validators (Luhn/IBAN/INSEE/SIRET/SIREN)      |
| `psk-proxy`    | Local HTTP proxy: scrubs egress, `/psk/detokenize` endpoint                   |
| `psk-hook`     | Agent wiring (Claude Code base-URL + `PreToolUse` restore hook)               |
| `psk-cli`      | `psk` binary: daemon lifecycle, install, scan, restore, stats                 |

Data flow:

```
agent → (ANTHROPIC_BASE_URL / OpenAI base URL / Gemini base URL) → psk proxy daemon
            scrub request body  ──tokenize secrets──▶  upstream provider (sees only tokens)
            vault: token → secret  (in daemon memory, session-scoped)

agent wants to write a file / run a command locally
            Claude Code PreToolUse hook → `psk restore --hook` → POST /psk/detokenize
            tokens in tool input → real values → tool runs with the real secret on disk
```

### Detection layers (order)

1. **Secrets** — `patterns/secrets.yaml` (broad provider catalog) + `patterns/connections.yaml`
   (DB/broker URLs with embedded creds). Default action: **`Tokenize`** (reversible).
2. **Structured PII** — `patterns/contact|financial|identity|network|generic.yaml` (emails, phones,
   cards, IBANs, IPs, national IDs, …), gated by validators. Default action: **`Replace`**
   (irreversible — PII rarely needs to round-trip into a local file).

The default action per entity is decided in `psk-core/src/policy.rs` (`is_secret_entity` →
`Tokenize`, else `Replace`); both are overridable per entity in `~/.psk/config`.

---

## The vault and token format (`psk-core/src/vault.rs`)

- Token: `__PSK_<8+ hex>__`. ASCII-delimited so model tokenizers preserve it and it round-trips
  through generation unchanged; matched by `__PSK_[0-9a-f]{8,}__`.
- Deterministic within a session (same secret → same token), so re-scrubbing resent conversation
  history is idempotent. Random across sessions (salt minted at daemon start).
- The token is **only a handle** — it reveals nothing about the secret. Restoration is impossible
  without the in-memory map, which lives only in the running daemon and dies with it. Never persist
  the vault to disk.
- `/psk/detokenize` is gated by a per-session auth token (`~/.psk/auth.token`, mode 600) that
  `psk install` embeds in the hook command.

**Accepted limitation:** restoring tokens inside a `Bash` command means a malicious command could
re-expose a secret to a *non-proxied* egress (e.g. a direct `curl`). This is inherent to guarantee
#2 (local actions get the real value); it is documented, not prevented.

---

## Egress scrubbing rule (`psk-proxy/src/scrubber.rs`)

Scrub the **entire** outgoing body every request — all `messages[*].content` (string and text
blocks) + `system` (Anthropic), all messages (OpenAI), `contents[*].parts[*].text` +
`system_instruction` (Gemini). **Not** just the last turn: agents resend full history each request
from their own un-redacted copy, so scrubbing only the latest message leaks earlier-turn secrets on
resend. Deterministic tokenization makes whole-body re-scrubbing a cheap no-op.

---

## Tool wiring (`psk-hook`, `psk-cli`)

- **Claude Code (full).** `psk install` writes `ANTHROPIC_BASE_URL=http://127.0.0.1:<port>` into
  `~/.claude/settings.json` (+ shell rc fallback) and installs a `PreToolUse` hook
  (`Write|Edit|MultiEdit|Bash`) → `psk restore --hook`. `UserPromptSubmit` is **not** used: it can
  only block/add-context, not rewrite, and the proxy already covers egress.
  - Caveat: with a custom base URL, server-side tool search is off by default — set
    `ENABLE_TOOL_SEARCH=true` if relied upon.
- **Cursor (best-effort).** Only its chat/plan panel honors "Override OpenAI Base URL"
  (`http://127.0.0.1:<port>/v1`); Composer/apply/autocomplete bypass it. No local restore hook, so
  tokens may surface in chat (secrets still never leave in cleartext).
- **Antigravity (experimental).** Point its model base URL at the proxy (Gemini route); custom
  endpoints are unstable upstream.

Daemon is required (the vault lives there): `psk start` (background, PID file `~/.psk/psk.pid`,
`setsid`-detached), `psk stop`, `psk status`. Upstreams overridable via
`PSK_{ANTHROPIC,OPENAI,GEMINI}_UPSTREAM` (Azure/self-hosted/tests).

---

## Performance targets

- p95 end-to-end redaction **under 30–50 ms** with the daemon (regex over the request body).
- Peak RSS small (single-digit to low-hundreds MB).
- Record latency/throughput per change if you touch the hot path; keep regexes anchored and avoid
  catastrophic backtracking (the `regex` crate is linear, but keep patterns tight).

---

## Agent guardrails

- **No model, no network at detection time.** Regex + validators only.
- Vault is in-memory and session-scoped; never written to disk.
- Load patterns once; daemon shares the pipeline read-only across requests.
- **Never commit real secrets or real prompts.** `fixtures/*.txt` are synthetic only. Stats
  (`~/.psk/stats.json`) are counters only — never content.
- Regex-only builds must always compile and run (there is no optional ML feature anymore).

---

## Out of scope (do not implement here)

- **Client-name gazetteer:** deterministic exact/fuzzy match (`aho-corasick`/`fst`) over a client
  roster. The real guarantee for *known* client names; bolts on as another recognizer without
  touching the vault/proxy design. Not a model.
