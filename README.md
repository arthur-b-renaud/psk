# psk

Secret-like detector for tool output: API tokens, IBAN, card numbers, phones, emails.

- `rules.toml` — token rules. Each `pattern` is a restricted regex subset that is
  **both** the detector and the fixture generator (see `src/pattern.rs`).
  Curated from [gitleaks](https://github.com/gitleaks/gitleaks) and
  [secrets-patterns-db](https://github.com/mazen160/secrets-patterns-db); only
  prefix-anchored rules (no keyword-context rules yet).
- `src/lib.rs` — `scan(text)`; PII rules validated with IBAN mod-97 / Luhn / phone shape.

```
./scripts/test.sh [n] [seed]      # generate fixtures/ (gitignored) and print accuracy
echo "token ghp_..." | psk scan   # JSON findings
psk rules                         # list token rules
```
