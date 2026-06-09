# psk — Prompt Secret Killer

Scrub PII and secrets from LLM prompts **before they leave your machine**.

`psk` is a pure-Rust, local-first redaction layer that sits between your agents/tools and external
LLM providers. It detects sensitive content (secrets, structured PII, and — soon — named entities
like client and company names) and masks it in-flight, so confidential data never reaches a
third-party API.

> **Status: early / work in progress.** The regex and secrets layers are functional; the ML/NER
> layer (`psk-pii-ml`) is currently a stub. See [`CLAUDE.md`](CLAUDE.md) for the NER design and roadmap.

## Why

The risk is asymmetric: leaking a client or company name to an external provider is a real failure,
while masking an extra harmless word is just noise. `psk` is therefore tuned for **recall** on the
entities that matter, and runs entirely on your machine — no network calls at inference time.

## Architecture

A Cargo workspace of focused crates:

| Crate          | Role                                                                    | State        |
| -------------- | ----------------------------------------------------------------------- | ------------ |
| `psk-core`     | Pipeline, redaction policy, span model, stats                           | working      |
| `psk-patterns` | Regex/Hyperscan recognizers + validators (Luhn, IBAN, card)             | working      |
| `psk-pii-ml`   | ML/NER layer (GLiNER via `gline-rs`) for ORG/PERSON/LOCATION/ADDRESS    | stub         |
| `psk-proxy`    | Local proxy daemon that scrubs prompts in transit                       | working      |
| `psk-hook`     | Agent integration (e.g. Claude Code hooks)                              | working      |
| `psk-cli`      | `psk` command-line entrypoint                                           | working      |

Detection layers, in order:

1. **Secrets** — regex patterns for API keys, tokens, credentials (`patterns/secrets.yaml`).
2. **Structured PII** — regex + validators for emails, phones, IPs, IBANs, cards, SSNs
   (`patterns/*.yaml`).
3. **NER (planned)** — a small GLiNER model for the *unstructured* slice (organizations, people,
   locations, addresses). Recall-tuned, `ORGANIZATION` as the headline metric. See `CLAUDE.md`.

## Build

```bash
cargo build --release
```

## Usage

```bash
# Scan stdin and print redacted text
echo "Email me at jane@acme.com" | psk scan

# JSON output with span details
echo "..." | psk scan --json

# Run the local proxy daemon
psk start --port 7878
psk status
psk stop

# Install hooks + proxy env for a detected agent
psk install

# Inspect loaded patterns and redaction stats
psk patterns
psk gain
psk gain --history

# Run fixture tests and report precision/recall
psk test
```

## Patterns & fixtures

- `patterns/*.yaml` — declarative recognizer definitions (name, entity, regex, confidence,
  optional validator).
- `fixtures/*.txt` — **synthetic** test inputs. Never commit real client data or real prompts.

## License

[MIT](LICENSE). Provided **"as is", without warranty of any kind** — see the LICENSE file for the
full disclaimer of warranty and liability.
