# Getting started

## Build & install the binary

```bash
git clone https://github.com/arthur-b-renaud/psk.git
cd psk
cargo build --release
# the binary is at target/release/psk — put it on your PATH, e.g.:
install -m755 target/release/psk ~/.local/bin/psk
psk version
```

## 1. Wire up your agent

```bash
psk install            # auto-detects Claude Code / Cursor / Antigravity
psk install --agent claude-code --port 7878   # or target one explicitly
```

For **Claude Code** this:

- writes `ANTHROPIC_BASE_URL=http://127.0.0.1:7878` into `~/.claude/settings.json` (and your shell
  rc as a fallback), so all API traffic goes through the proxy; and
- installs a `PreToolUse` hook (matching `Write|Edit|MultiEdit|Bash`) that runs `psk restore --hook`
  to put real values back into local writes/commands.

For **Cursor** and **Antigravity**, `psk install` prints the manual steps (see below).

## 2. Start the daemon

The daemon holds the token vault, so it must be running for the round-trip to work.

```bash
psk start              # runs in the background (detached), logs to ~/.psk/psk.log
psk status             # -> running (pid …, port 7878) — healthy
psk stop
```

Run `psk start --foreground` to keep it attached (useful under a process manager or for debugging).

## 3. Use your agent normally

Open Claude Code as usual. Secrets in your prompts, file contents, and tool outputs are tokenized
before they reach the provider; when the agent writes them back to a local file, the real values are
restored. Check what's being caught:

```bash
psk gain               # counters: prompts scanned, entities redacted, by type, latency
psk patterns           # list the loaded recognizers
```

## One-shot scanning (no daemon)

You can scan arbitrary text without the proxy. Note: with no daemon there is no vault, so secrets
degrade to irreversible `[TAG]` replacement.

```bash
echo "key is AKIAIOSFODNN7EXAMPLE, email jane@acme.com" | psk scan
echo "..." | psk scan --json     # structured span output
```

## Other agents (best-effort)

### Cursor

Cursor → Settings → Models → **Override OpenAI Base URL**:

```
http://127.0.0.1:7878/v1
```

Put any non-empty string in the "OpenAI API Key" field. **Limitation:** only Cursor's chat/plan
panel honors this override — Composer, inline edit, apply, and autocomplete bypass it, so agent
traffic is **not** fully covered. There is no local-restore hook for Cursor, so PSK tokens may
appear in its chat (your secrets still never leave the machine in cleartext).

### Antigravity (experimental)

Point Antigravity's model endpoint at the proxy (`http://127.0.0.1:7878`); the proxy exposes a
Gemini route. Custom-endpoint support is unstable upstream, so treat this as experimental.

## Pointing at a non-default upstream

For Azure OpenAI, self-hosted gateways, or chaining behind another proxy, override the upstream the
daemon forwards to:

```bash
PSK_ANTHROPIC_UPSTREAM=https://my-gateway.example.com \
PSK_OPENAI_UPSTREAM=https://my-azure-openai.example.com \
PSK_GEMINI_UPSTREAM=https://my-gemini-proxy.example.com \
  psk start --foreground
```

## Uninstall

```bash
psk uninstall          # removes the base-URL override + PreToolUse hook
                       # (config and stats under ~/.psk are kept)
```

## Troubleshooting

- **`psk status` says not running** right after `psk start`: give it a second; the daemon writes its
  pid file at startup. Check `~/.psk/psk.log`.
- **Claude Code can't reach the API**: ensure the daemon is running and `ANTHROPIC_BASE_URL` is set
  in `~/.claude/settings.json`. Restart Claude Code after `psk install`.
- **Server-side tool search disabled**: with a custom base URL, Claude Code turns off server-side
  tool search by default. Set `ENABLE_TOOL_SEARCH=true` if you rely on it.
- **A real secret reached the provider**: it means no recognizer matched it. Add a pattern (see
  [patterns.md](patterns.md)) — recognizers are tuned for recall, so prefer a broader pattern.
