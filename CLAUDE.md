# CLAUDE.md — architecture record for PSK (Prompt Secret Killer)

Written for future sessions. It records *why* the design is what it is, so the reasoning does not
have to be rediscovered. The build brief lives in `PSK_Claude_Code_Brief_v2.md`; this file records
decisions, findings, and the things that are easy to get wrong.

## 1. Interception architecture

**The proxy is the outbound rewrite point. The hook is the execution-boundary restore point.**
These are not interchangeable.

- `UserPromptSubmit` hook: can inject context (stdout is appended) or block (exit 2). It **cannot**
  silently replace the outgoing prompt body. It therefore cannot hide a secret already present in
  the user's prompt. Do not claim otherwise, and do not attempt prompt rewriting there.
- `PreToolUse` hook: **can** rewrite tool input — it reads tool-input JSON on stdin and emits
  modified JSON on stdout. This is the restore point for `Write` / `Edit` / `Bash`.

So the only place with full, silent control over what leaves the machine is a local reverse proxy
that speaks the Anthropic Messages API, which the agent reaches via `ANTHROPIC_BASE_URL`.

## 2. Restore modes and the transcript trade-off

`restore_mode` in `~/.psk/config.toml`.

- **`execution` (default).** The proxy substitutes outbound only; it does not restore inbound.
  Restore happens exclusively at the `PreToolUse` hook. Consequences, all intentional:
  - Real secrets never appear in Claude Code transcripts, terminal scrollback, or agent-side state.
  - The user sees fakes on screen. This is the feature: what you see is what the provider saw.
  - The resent conversation history contains fakes, which is precisely why the fake-recognition
    guard (§4) is an invariant and not an optimization.
  - MCP tools and hook-less agents bypass restore. Documented in the README.
- **`full`.** The proxy additionally restores fakes in the streamed SSE response. Needed for agents
  with no hook mechanism. **The agent then persists real secrets to its own local transcripts**
  (`~/.claude/projects/*.jsonl`). The README states this plainly.

Why `execution` is the default: if the proxy restores inbound, Claude Code receives real values and
writes them to disk itself, which partially defeats the tool.

The hook runs in both modes — in `full` mode as a second layer catching whatever the stream restore
missed.

## 3. Crate graph

```
cli -> {proxy, init, tui} -> core -> {secrets, verifiers, vault}
```

No cycles. `psk-tui` talks to `psk-proxy` only over its localhost HTTP endpoints (SSE + fetch),
never by linking its internals. `psk-core` exposes a `Recognizer` trait so future detectors (NER)
plug in without touching the proxy.

**`SecretKind` lives in `psk-vault`, not `psk-secrets`.** A kind's only structural obligation in
this codebase is *"what shape must a fake of me have"*, which is the vault's concern; the vault
cannot depend on the rules crate without inverting the graph. `psk-secrets` will therefore depend
on `psk-vault` for the enum. This avoids inventing a `psk-types` crate for one enum.

## 4. The vault contract

Everything in `crates/psk-vault`. Four properties, each load-bearing:

**Determinism.** `fake = format_preserve(HMAC-SHA256(salt, kind_tag || 0x00 || real), kind)`.
Claude Code resends the full conversation history on every request. A proxy that restarted with a
random vault would meet fakes it has never seen — and those fakes pattern-match as real secrets, so
they would be substituted *again*, cascading into a corrupted mapping. Deterministic derivation
makes restart a non-event: the real secret reappears in the resent history, so the new process
re-derives the identical fake and rebuilds the mapping on the fly.

Determinism also protects Anthropic **prompt caching**: stable fakes keep cached prefixes
byte-identical across requests and restarts. Randomized fakes would silently invalidate the cache
and inflate the user's token bill. `cache_control` blocks must pass through the proxy untouched.

**The salt.** 32 bytes at `~/.psk/salt`, mode `0600` inside a `0700` directory, created atomically
on first run (`create_new` + `fsync` + `hard_link`, so two racing first-runs converge on one salt).
`PSK_HOME` overrides the directory; tests use it so they never touch a developer's real salt.
A salt is a key, not content — persisting it does not violate the disk ban. A salt file of the
wrong length is a hard error, never a silent regeneration: minting a new salt mid-conversation
would invalidate every fake in the live history.

**The marker.** Every fake carries the reserved 4-character marker `QPSK` at a kind-specific offset
in its generated body. Indistinguishable fakes are a debugging nightmare; a marked fake is
instantly identifiable in a diff, by `psk scan`, or by the near-miss detector.

*The marker is not literally four bytes in every kind.* Digit-only and network formats cannot carry
letters, so they live in **reserved spaces** that serve the same "obviously not a live value"
purpose:

| Kind | Marker mechanism |
| --- | --- |
| all token kinds, JWT, PEM, IBAN | literal `QPSK` in the generated body |
| `CreditCard` | reserved Visa **test BIN** `411111`, Luhn-valid |
| `Iban` | unassigned country code `ZZ`, mod-97-valid (plus `QPSK` in the BBAN) |
| `IpV4` / `IpV6` | RFC 5737 `192.0.2.0/24` / RFC 3849 `2001:db8::/32` |
| `Email` | RFC 2606 `example.com`, local part `qpsk-…` |

Reserved spaces are chosen over plausible-live values on purpose: a checksum-valid fake card *could
otherwise be someone's live card*. The residual risk is that the LLM occasionally recognises a test
range and comments on it. That is cheaper than emitting a live-looking value.

**The guard (`is_known_fake`).** `Engine::substitute` must drop any candidate match the guard
accepts, *before* substituting. Required for: the restart scenario, `restore_mode = "execution"`
(where history legitimately contains fakes), and as a general anti-cascade invariant. The guard
recognises the map, the marker (case-insensitively), and the reserved spaces — so it accepts fakes
this process never minted.

**Restore is exact and whole-token**, via a single `aho-corasick` automaton over the known-fake set
(`MatchKind::LeftmostLongest`), rebuilt only when a new fake is minted. Never N calls to
`str::replace`.

### Near-miss detection (execution boundary only)

The LLM sometimes echoes an *altered* fake: recased, truncated, re-wrapped. Exact restore misses it
and a checksum-valid fake gets written silently into a real config file — worse than not running
PSK. So after exact restore, the hook scans for: case-insensitive matches, a 12-character
fake-signature window, and marker/reserved-space residue. On a hit it **blocks (exit 2)** naming
the field and the suspect value.

**Gotcha, learned the hard way.** The signature window is anchored at the *marker*, not at offset 0
of the fake. A PEM fake begins `-----BEGIN PRIVATE KEY-----`, which every real private key also
begins with; anchoring at offset 0 made the hook block on any legitimate key file the agent wrote.
There is a regression test (`near_miss_ignores_pem_boilerplate`).

Similarly, the IP and email reserved spaces are deliberately **not** treated as residues: a bare
`192.0.2.1` in tool input is far more likely to be documentation the user meant than an unrestored
fake. Only the card BIN and the `ZZ` IBAN are, and only when the checksum also passes.

**Fail-open applies to infrastructure, not to detection.** Proxy down → hook passes input through
unchanged, exit 0, never block the agent because PSK isn't running. Near-miss → block. These are
different conditions; do not conflate them.

## 5. `zeroize`, scoped honestly

A security tool with a false sense of memory hygiene is worse than one with none.

**Covered:** the HMAC key stream's seed, derived block, and salt copy (`KeyStream::drop`) — these
are transient scratch space holding a copy of the real secret's bytes. Plus a best-effort wipe of
the vault's maps on `Drop`.

**Not covered, and cannot be:**
- Real secrets live in plain heap `String`s inside `fwd`/`rev` for the entire session. That is the
  **accepted, deliberate residency** of real values: the vault cannot restore what it does not
  remember. Every incoming request buffer holds them too.
- `String` and `HashMap` reallocate as they grow, leaving unreferenced, unwiped copies on the heap
  that `Drop` cannot reach.
- Nothing prevents the OS from paging the vault to swap or including it in a core dump.

## 6. False-positive discipline

Coding-agent traffic is full of values that pattern-match secrets and are not: loopback IPs,
example emails, git SHAs, lockfile hashes. Substituting them fires constantly and breaks the LLM's
reasoning about networking code, git operations, and dependency files. The loop tolerates false
positives only if restore is perfect, and restore is not perfect.

- **IPv4/IPv6 and email rules ship disabled by default** (`SecretKind::enabled_by_default`). Even
  when enabled, hard-allowlist loopback, unspecified, RFC 1918, link-local, documentation ranges,
  and reserved/example domains.
- The 40-char entropy-gated generic (AWS secret key shape) **must exclude pure-hex strings** — a
  git SHA-1 is 40 hex characters — and require the base64 alphabet beyond `[0-9a-f]`. Note that our
  own AWS-secret fakes always contain `QPSK`, so they are never pure hex and can never be
  re-detected as a git SHA.
- Lockfile hash shapes (`sha256-`, `sha512-`, integrity fields) belong in the `psk-verifiers`
  allowlist, with a fixture proving each allowlisted class is *not* substituted.

**Entropy cannot reject a git SHA.** A random 40-character hex string scores ~3.9 bits per
character, comfortably over any usable floor (`DEFAULT_MIN_BITS_PER_CHAR` is 3.0 — raising it high
enough to reject hex would also reject real base64 credentials). Pure-hex exclusion is what kills
git SHAs, not the entropy gate. There is a test asserting the SHA *passes* the gate, so nobody
"fixes" this by tuning the threshold.

**Gotcha: `is_reserved_ip` returns `false` for non-addresses.** The IP regexes match shapes that
are not addresses (`999.999.999.999`, `1.2.3.4.5`, a version string). A verifier that only asked
"is it reserved?" would answer "no" and treat the garbage as a live secret. `verify` calls
`allowlist::is_valid_ip` **first**. Same class of bug as a `contains` check on an empty set.

Note also that `1.2.3.4` parses as a routable address, so with the network rules enabled a version
string is substituted. That is one more reason those rules ship off.

### Overlap resolution (`psk-core`)

Overlap between rules is normal, not exceptional: an Anthropic key's 40-character tail genuinely
has the AWS-secret shape, and a GCP service-account key matches both its own rule and the generic
PEM rule at the identical span. `psk-secrets::scan` therefore returns **raw, overlapping** matches
and `Engine::substitute` resolves them.

The rule is **longest wins**, ties broken by `SecretKind`'s *declaration order* (which is `Ord` by
derive). Specific kinds are declared before the generics they subsume — `GcpServiceAccountKey`
before `PrivateKeyBlock` — so an equal-length tie picks the more specific kind, deterministically,
rather than depending on which recognizer happened to report first. **If you reorder the
`SecretKind` variants you change tie-breaking.**

### Gotcha: PEM inside JSON

A GCP service-account key is a PEM block living inside a JSON string, so its newlines are the two
characters `\` `n`, not U+000A. The fake generator detects the escaped form and preserves it. Emit
a real newline there and the agent's own credentials file stops parsing — a corruption PSK would
have caused, in a file the user never asked us to touch. Tests: `gcp_pem_preserves_escaped_newlines`
and `gcp_key_inside_json_stays_valid_json`.

## 7. Auth findings (§2 pre-check)

**Status: DONE, 2026-07-09. OAuth works through a local base URL. PSK serves both auth modes.**

Claude Code authenticates either with `x-api-key` (API-key users) or an OAuth `Authorization:
Bearer` token (Pro/Max subscribers; `~/.claude/.credentials.json`). The open question was whether
the OAuth flow pins the origin and breaks under `ANTHROPIC_BASE_URL` redirection. It does not.

Method: a throwaway pass-through proxy on `127.0.0.1:8787` forwarding to `https://api.anthropic.com`
with headers untouched, logging header *names* and the upstream status only — never header values,
never request or response bodies. Driven with
`ANTHROPIC_BASE_URL=http://127.0.0.1:8787 claude -p "say hi"` on a Pro/Max (OAuth) account.

Observed:

- **Auth mode:** `authorization` present, `x-api-key` absent. OAuth Bearer.
- **Upstream status:** `200`. The model's reply rendered normally in the terminal, so the redirect
  is transparent end to end.
- **Request line:** `POST /v1/messages?beta=true` — note the query string; route matching in
  `psk-proxy` must not assume a bare path.
- **Headers sent:** `accept`, `accept-encoding`, `anthropic-beta`, `anthropic-dangerous-direct-
  browser-access`, `anthropic-version`, `authorization`, `connection`, `content-length`,
  `content-type`, `host`, `user-agent`, `x-app`, `x-claude-code-session-id`, and the
  `x-stainless-*` SDK telemetry family (`arch`, `lang`, `os`, `package-version`, `retry-count`,
  `runtime`, `runtime-version`, `timeout`).

Consequences for `psk-proxy`:

- Pass **all** headers through untouched except hop-by-hop ones (`host`, `content-length`,
  `connection`), which the HTTP client must recompute. In particular `anthropic-beta` and
  `anthropic-version` are load-bearing; stripping them changes API behaviour.
- Do not rewrite or normalise the path; preserve the query string.
- The probe buffered the whole response rather than streaming it, and `claude -p` still worked.
  That is *not* a licence to buffer: the real proxy must stream SSE, both for latency and because
  `restore_mode = "full"` restores across chunk boundaries.

No README limitation section is needed. Both auth modes are supported.

## 7b. The proxy

A catch-all route, not a literal `/v1/messages`: Claude Code sends `POST /v1/messages?beta=true`
and also hits other endpoints (token counting, model listing) that must keep working. The path
**and query string** are forwarded verbatim.

Headers pass through untouched except the hop-by-hop set (`host`, `content-length`, `connection`,
`transfer-encoding`) and **`accept-encoding`**, which is stripped on purpose: PSK rewrites the SSE
body and cannot rewrite what it cannot read. `authorization`, `x-api-key`, `anthropic-beta`,
`anthropic-version` and the `x-stainless-*` family all reach the upstream unmodified.

A body that is not JSON, or JSON that will not re-serialise, is forwarded **untouched** rather than
mangled. Better to break nothing than to corrupt a request shape we did not anticipate.

### The SSE restorer (`full` mode) — two layers of fragmentation

1. **HTTP chunks split SSE events.** Bytes are buffered until a complete `\n\n`-terminated event
   exists.
2. **SSE events split the text itself.** The model streams a few characters per
   `content_block_delta`, so a fake is routinely spread across several *events*. Restoring each
   delta in isolation would never match one.

The fix for (2) is a hold-back window. The naive version — always retain `longest_fake_len` bytes —
would stall the stream by the length of a PEM block on every delta. Instead
`Vault::pending_fake_prefix_len` computes *exactly* how many trailing bytes could still grow into a
fake. It is almost always 0, so deltas forward immediately with no added latency.

**Restore happens inside the parsed JSON, never on the raw bytes.** A real secret can contain
characters illegal raw inside a JSON string — a PEM key is full of newlines. Splicing those into
the SSE bytes would produce a response the agent cannot parse.

**Held-back text is flushed as a synthetic delta event**, on `content_block_stop` or at stream end,
and never as bare bytes appended after the last event — the agent's SSE parser would discard those
and the tail of the secret would vanish. A flushed `thinking_delta` keeps its type, or the agent
renders the tail of its own reasoning as assistant output.

### Events and stats

`GET /events` carries **metadata plus the rewritten (safe) text only**. The original is stashed
beside the ring buffer and served solely at `GET /events/{id}/original`, on explicit per-id demand.
Ring buffer and originals are evicted together, so the two never disagree about which ids exist.

`stats.json` holds counters only. There is a test asserting every leaf of the serialised snapshot
is numeric, so no content can slip in.

## 8. Dependencies

Justified additions beyond the brief's §11 list:

- **`getrandom`** — 32 bytes of entropy for the salt on first run. Tiny, no C toolchain. `rand`
  would be a much larger dependency for one call.
- **`futures-util`, `tokio-stream`, `bytes`** — streaming plumbing for the proxy's SSE path.
- **`toml`** — reads `~/.psk/config.toml`, which the brief specifies.

**`aws-lc-rs`, via `reqwest` → `rustls`: a deviation worth stating.** The brief says "nothing that
needs a system C library in M1". `aws-lc-rs` does not need a *system* library — it vendors its C
sources — but it does compile C during the build, so `cargo install psk-cli` needs a C compiler
present. In practice every machine with a working Rust toolchain has one (the linker path requires
it), so `cargo install` still "just works". If that ever becomes a problem, `reqwest`'s
`rustls-no-provider` feature plus an explicit `ring` provider removes the C entirely. Recorded here
so the trade-off is a choice rather than an accident.

Deliberately *not* used, despite the earlier implementation at `94aa2f4` pulling them in:
`luhn3`, `iban`, `card_validate`. Luhn and mod-97 are ~15 lines each and PSK needs to both verify
*and forge* them; the crates only verify. They live in `psk-vault/src/checksum.rs` and
`psk-verifiers` re-exports rather than reimplements.

**Hyperscan / vectorscan is a later throughput lever, not an M1 dependency.** It needs a C
toolchain and would break the "`cargo install` just works everywhere" promise. Revisit only if
profiling demands it.

## 9. History

The repo previously held a different design (`94aa2f4`): opaque `__PSK_<hex>__` tokens minted from
a **random per-session salt**. It is not a starting point. Random salts corrupt the mapping on any
proxy restart, for the reason in §4, and opaque tokens destroy the LLM's ability to reason about
the value's shape. Only the checksum validators were conceptually worth carrying forward.

## 10. M2+ seams

Left clean, not implemented:

- **NER recognizer.** `psk-core`'s `Recognizer` trait takes a second implementation (ONNX/GLiNER);
  the regex layer is just the first. Training corpora sit untracked in `data/` (ai4privacy).
- **PII layer.** New `SecretKind` variants plus their fake templates in `psk-vault/src/kind.rs`.
- **OpenAI-compatible proxy.** A second route in `psk-proxy`; the substitution surfaces differ, the
  vault does not.
- **External corpus.** `corpus/` will vendor gitleaks' test data (or an equivalent public secrets
  benchmark), license respected, provenance recorded here. `psk test` reports precision/recall
  against it with an explicit floor (≥ 0.95 precision on M1 rule kinds). Self-graded fixtures alone
  prove nothing to an open-source audience.

## 11. Conventions

- `thiserror` in library crates, `anyhow` at the binary boundary. No `.unwrap()` in library paths
  reachable from user input.
- Comment ownership/borrow decisions and any `.clone()` that exists for a reason. The maintainer is
  proficient in Python and new to Rust; this is a teaching codebase as much as a shipping one.
- Never store prompt or response content on disk. Counters and the salt only.
- Never generate random (non-deterministic) fakes.
- Never substitute a known fake.
