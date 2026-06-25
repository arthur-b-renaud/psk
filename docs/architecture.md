# Architecture

`psk` is a **local egress filter**: a small HTTP proxy that sits between your coding agent and the
LLM provider, scrubs sensitive data out of every outbound request, and restores it locally when the
agent needs the real value. Detection is **deterministic** — regex recognizers plus a few checksum
validators. There is no ML model and no network call at detection time.

## The two guarantees

1. **Nothing sensitive leaves the machine in cleartext.** Every outbound provider request passes
   through the proxy, which redacts secrets and PII before forwarding.
2. **Local actions keep the real value.** When the agent writes a file or runs a command containing
   a secret, the bytes that hit disk/shell are the *real* secret — not a placeholder.

These two pull in opposite directions: a model can only emit a value it was given, so if the proxy
simply replaced a secret with `[SECRET]`, the agent could never write the real value back to a local
`.env`. The resolution is **reversible tokenization**.

## Reversible tokenization

```
                          ┌──────────────────────────── your machine ────────────────────────────┐
                          │                                                                        │
  agent (Claude Code) ────┼──▶ psk proxy daemon ──▶ scrub request body ──▶ upstream LLM provider   │
   ANTHROPIC_BASE_URL      │         │                  (secret → __PSK_ab12cd34__)   (sees token)  │
   = http://127.0.0.1:7878 │         │                                                              │
                          │         └── vault: __PSK_ab12cd34__ → "AKIA…REAL…"  (in memory only)    │
                          │                                                                        │
  agent wants to write .env / run a command                                                        │
                          │                                                                        │
  Claude Code PreToolUse ─┼──▶ psk restore --hook ──▶ POST /psk/detokenize ──▶ vault lookup        │
   hook (Write/Edit/Bash) │         │                                                              │
                          │         └── tool input "__PSK_ab12cd34__" → "AKIA…REAL…" via updatedInput
                          │                          (real secret written to local disk)            │
                          └────────────────────────────────────────────────────────────────────────┘
```

- On **egress**, the proxy replaces each detected secret with a stable token `__PSK_<hex>__` and
  records `token → secret` in an in-memory **vault**. The provider only ever sees the token.
- On a **local action**, a Claude Code `PreToolUse` hook (`psk restore --hook`) sends the tool input
  to the daemon's `/psk/detokenize` endpoint, which swaps tokens back to real values. The hook
  returns the restored input via `updatedInput`, so the file/command runs with the real secret.

The vault lives only in the running daemon's memory, is session-scoped, and is never written to
disk. The token is just a handle — it encodes nothing about the secret, and restoration is
impossible without the in-memory map. See [security.md](security.md).

### Why a proxy and not a prompt hook?

Claude Code's `UserPromptSubmit` hook can only *block* a prompt or *add context* — it cannot rewrite
the prompt text, and it only sees the typed prompt (not tool outputs, file contents, or the full
request body). The proxy sees the actual HTTP request and can rewrite it, so it is the only place
that can guarantee *every* outbound byte is scrubbed. The `PreToolUse` hook, by contrast, *can*
rewrite tool input (`updatedInput`), which is exactly what the local-restore step needs.

## Components

| Crate          | Responsibility                                                                       |
| -------------- | ------------------------------------------------------------------------------------ |
| `psk-core`     | `Pipeline` (detect + redact), `RedactionPolicy`, `Span`/`EntityType`, `Vault`, stats |
| `psk-patterns` | `RegexRecognizer` built from YAML, plus validators (Luhn, IBAN, INSEE, SIRET, SIREN) |
| `psk-proxy`    | Axum HTTP proxy: per-provider scrub + forward, `/psk/detokenize`, `/health`          |
| `psk-hook`     | Claude Code wiring: base-URL in `settings.json` + the `PreToolUse` restore hook      |
| `psk-cli`      | `psk` binary: daemon lifecycle, install/uninstall, scan, restore, stats              |

## Request lifecycle (proxy)

1. Agent sends a request to `http://127.0.0.1:<port>/v1/messages` (or `/v1/chat/completions`, or a
   Gemini `/v1beta/...` path) because its base URL points at the proxy.
2. The proxy reads the JSON body and runs the provider-specific scrubber
   (`scrub_anthropic_request` / `scrub_openai_request` / `scrub_gemini_request`).
3. The scrubber walks **every** message (not just the last — see below) and runs the detection
   pipeline on each text field. Secrets become vault tokens; structured PII is replaced.
4. The scrubbed body is forwarded to the real upstream (overridable via `PSK_*_UPSTREAM`), and the
   response is streamed back unchanged.

### Whole-body scrubbing

Coding agents resend the **entire conversation history** on every request, from their own
un-redacted local copy. If the proxy scrubbed only the latest message, a secret introduced in an
earlier turn would be re-sent in cleartext on the next request. So the proxy scrubs the whole body
every time. Because tokenization is deterministic within a session (the same secret always maps to
the same token), re-scrubbing already-tokenized history is a cheap no-op.

## Detection pipeline

`Pipeline::redact(text)`:

1. Run every recognizer over the text, collecting candidate `Span`s.
2. Resolve overlaps (longest match wins, ties broken by confidence).
3. For each surviving span, apply the policy action for its entity type and splice the replacement
   into the output string.

Recognizers are loaded from `patterns/*.yaml` at startup (and from `~/.psk/patterns/` if present).
See [patterns.md](patterns.md).

## Detection layers

1. **Secrets** — `patterns/secrets.yaml` (broad provider catalog) and `patterns/connections.yaml`
   (DB/broker URLs with embedded credentials). Default action: `Tokenize` (reversible).
2. **Structured PII** — `patterns/contact|financial|identity|network|generic.yaml` (emails, phones,
   cards, IBANs, IPs, national IDs, …), gated by validators. Default action: `Replace`
   (irreversible — PII rarely needs to round-trip into a local file).
