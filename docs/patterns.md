# Patterns & configuration

Detection is driven by declarative YAML pattern packs. Each entry defines a regex, the entity type
it produces, a confidence, and an optional post-match validator.

## Pattern file format

`patterns/*.yaml` is a YAML array of entries:

```yaml
- name: anthropic_api_key        # unique within the pack
  entity: AnthropicApiKey        # maps to an EntityType (see below)
  pattern: 'sk-ant-[a-zA-Z0-9_-]{20,}'   # Rust `regex` crate syntax
  confidence: 0.97               # 0.0–1.0; used for overlap tie-breaking
  validator: null                # optional: luhn | iban | credit_card | insee | siret | siren
  description: "Anthropic API key (sk-ant- prefix)"
```

Notes:

- The regex uses the [`regex`](https://docs.rs/regex) crate — **no backreferences or lookarounds**.
  Patterns run in linear time; keep them anchored and specific.
- The **entire match** is what gets redacted. If you only want to redact the value (not a
  surrounding `KEY=` prefix), match only the value.
- The file stem is the "pack" name shown in `psk patterns` (e.g. `secrets`, `contact`).

## Built-in packs

| Pack                 | Examples                                                                  |
| -------------------- | ------------------------------------------------------------------------- |
| `secrets.yaml`       | AWS, OpenAI, Anthropic, GitHub, GitLab, Stripe, Google, Slack, HF, npm, PyPI, SendGrid, Twilio, Discord, Telegram, Sentry, Shopify, DigitalOcean, Cloudflare, Datadog, JWT, bearer, generic `KEY=…`, SSH/PGP private-key blocks |
| `connections.yaml`   | `postgres://`, `mysql://`, `mongodb+srv://`, `redis://`, `amqp://` with embedded credentials |
| `contact.yaml`       | emails, international / FR / US phone numbers                              |
| `financial.yaml`     | Visa/Mastercard/Amex (Luhn), IBAN, BIC/SWIFT, FR RIB                       |
| `identity.yaml`      | US SSN, FR INSEE/SIRET/SIREN, ES NIF/NIE, UK NIN                           |
| `network.yaml`       | IPv4, IPv6, MAC, URLs with embedded auth                                   |
| `generic.yaml`       | UUIDv4, long base64/hex blobs (low confidence)                            |

Run `psk patterns` to see the live list (currently 60 recognizers).

## Validators

Validators run after a regex match and reject false positives by checking structure/checksums:

- `luhn` — credit-card Luhn checksum
- `credit_card` — card brand/length validation
- `iban` — IBAN structural validation
- `insee` / `siret` / `siren` — French national identifiers (length + Luhn/key)

An unknown validator name passes by default (with a warning).

## Entity types & redaction actions

Each `entity` maps to an `EntityType` in `psk-core`. The redaction **action** is chosen per entity:

- **Secrets** default to `Tokenize` (reversible — see [architecture.md](architecture.md)).
- **Everything else** defaults to `Replace` (irreversible `[TAG]`).

The classification lives in `is_secret_entity()` in `crates/psk-core/src/policy.rs`. If you add a
new secret-type recognizer, add its `EntityType` variant there (and to `parse_entity_type` in
`crates/psk-patterns/src/recognizer.rs`) so it tokenizes reversibly. An unmapped `entity` string
becomes `EntityType::Custom(name)` and defaults to `Replace`.

## Adding your own patterns

Drop a `.yaml` file into `~/.psk/patterns/` — it is loaded at daemon startup alongside the built-in
packs, no rebuild required:

```yaml
# ~/.psk/patterns/acme.yaml
- name: acme_internal_token
  entity: GenericSecret          # reuse a secret type so it tokenizes reversibly
  pattern: 'acme_[A-Za-z0-9]{32}'
  confidence: 0.95
  description: "ACME internal service token"
```

Restart the daemon (`psk stop && psk start`) to pick up changes, then confirm with `psk patterns`.

## Tuning for recall

`psk` deliberately favors recall over precision: a false positive is tokenized and round-trips
harmlessly, while a missed credential is the failure it exists to prevent. When in doubt, prefer a
broader pattern and a moderate confidence over a tight one that misses variants.

## Runtime files & environment

| Path / variable                | Purpose                                                          |
| ------------------------------ | ---------------------------------------------------------------- |
| `~/.psk/psk.pid` / `psk.port`  | daemon pid and port (used by `status`/`stop`)                    |
| `~/.psk/psk.log`               | background daemon log                                            |
| `~/.psk/auth.token`            | per-session detokenize auth token (mode 0600)                    |
| `~/.psk/stats.json`            | counters only (never content)                                    |
| `~/.psk/patterns/*.yaml`       | user-supplied custom packs                                       |
| `ANTHROPIC_BASE_URL`           | set by `psk install` → points Claude Code at the proxy           |
| `PSK_ANTHROPIC_UPSTREAM` etc.  | override where the daemon forwards (Azure/self-hosted/tests)     |
| `RUST_LOG=psk=debug`           | increase log verbosity                                           |

> Policy overrides via `~/.psk/config.toml` are stubbed but not yet wired — per-entity action
> overrides currently require editing `policy.rs`. Custom **patterns** (above) work today.
