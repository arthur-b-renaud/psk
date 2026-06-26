# Changelog

All notable changes to this project are documented here.

## [Unreleased]

### Changed — pivot to a regex-only egress scrubber

`psk` is now a deterministic, local-first **egress filter** with reversible tokenization. The
planned ML/NER layer was dropped; detection is regex + validators only, with no model or network
call at detection time.

#### Added
- **Reversible tokenization vault** (`psk-core`): secrets are swapped for stable `__PSK_<hex>__`
  tokens on egress and restored locally on demand. New `RedactionAction::Tokenize`.
- **`/psk/detokenize` endpoint** (auth-gated, loopback-only) on the proxy.
- **`psk restore --hook`**: a Claude Code `PreToolUse` hook that restores real values into local
  `Write`/`Edit`/`MultiEdit`/`Bash` via `updatedInput`.
- **Gemini proxy route** and `scrub_gemini_request` (for Antigravity, best-effort).
- **Real daemon lifecycle**: `psk start` (detached, `setsid`), `psk stop`, `psk status` via a PID
  file; `PSK_{ANTHROPIC,OPENAI,GEMINI}_UPSTREAM` overrides.
- Expanded detection: pattern packs grown from ~33 to **60** recognizers — broad secret catalog
  plus `connections.yaml` for DB/broker URLs with embedded credentials.
- Documentation under `docs/` (architecture, getting-started, security, patterns) and
  `CONTRIBUTING.md`.

#### Changed
- The proxy now scrubs the **whole** request body on every request (not just the last message), so
  earlier-turn secrets are not leaked when the client resends history.
- Claude Code wiring writes `ANTHROPIC_BASE_URL` into `~/.claude/settings.json` and installs the
  `PreToolUse` restore hook. The `UserPromptSubmit` hook was removed (it cannot rewrite prompts).
- `CLAUDE.md` and `README.md` rewritten for the new architecture.

#### Removed
- The `psk-pii-ml` crate, `data/`, `bench/RESULTS.md`, GLiNER `scripts/*.py`, and the
  `Person`/`Organization`/`Location`/`Address` entity types.
