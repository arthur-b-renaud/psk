//! The full substitution loop, end to end: detect -> verify -> guard -> substitute -> restore.
//!
//! These are the brief's §12 acceptance criteria that need every crate at once.

use std::sync::Arc;

use psk_core::{Engine, ScanConfig, SecretKind, Vault};
use psk_vault::sample;

fn engine() -> Engine {
    Engine::new(
        Arc::new(Vault::with_salt([42u8; 32])),
        ScanConfig::default(),
    )
}

fn engine_with_network_rules() -> Engine {
    Engine::new(
        Arc::new(Vault::with_salt([42u8; 32])),
        ScanConfig {
            enable_network_rules: true,
            ..Default::default()
        },
    )
}

/// A prompt containing five real secrets of five different kinds.
fn prompt() -> String {
    format!(
        "Deploy with {} and {}.\nPush using {}.\nBill {} to the card {}.",
        sample::for_kind(SecretKind::AwsAccessKeyId),
        sample::for_kind(SecretKind::AwsSecretKey),
        sample::for_kind(SecretKind::GithubPat),
        sample::for_kind(SecretKind::AnthropicKey),
        sample::for_kind(SecretKind::CreditCard),
    )
}

/// §12 "Round-trip": none of the five real values go out, all five fakes appear, and restoring the
/// verbatim-echoed fakes reproduces the original byte for byte.
#[test]
fn round_trip_over_five_secrets_is_lossless() {
    let e = engine();
    let original = prompt();
    let (outbound, summary) = e.substitute(&original);

    for k in [
        SecretKind::AwsAccessKeyId,
        SecretKind::AwsSecretKey,
        SecretKind::GithubPat,
        SecretKind::AnthropicKey,
        SecretKind::CreditCard,
    ] {
        let real = sample::for_kind(k);
        assert!(!outbound.contains(&real), "{k:?} leaked outbound");
        assert_eq!(
            summary.by_kind.get(&k),
            Some(&1),
            "{k:?} not substituted once"
        );
    }
    assert_eq!(summary.total(), 5);
    assert!(summary.chars_hidden > 0);

    assert_eq!(e.restore(&outbound), original, "restore must be verbatim");
}

/// §7c: substituting text that already contains a fake is a no-op on that span.
///
/// This is the anti-cascade invariant. Claude Code resends the whole conversation every turn, so
/// in `execution` mode the engine sees its own fakes on every single request.
#[test]
fn substituting_an_already_substituted_prompt_is_idempotent() {
    let e = engine();
    let original = prompt();

    let (once, first) = e.substitute(&original);
    let (twice, second) = e.substitute(&once);

    assert_eq!(once, twice, "a second pass must not touch the fakes");
    assert_eq!(first.total(), 5);
    assert_eq!(second.total(), 0, "no fake may be re-substituted");
    assert_eq!(e.vault().len(), 5, "the map must not have grown");
    assert_eq!(e.restore(&twice), original);
}

/// The same invariant across a proxy restart: a brand-new engine, same salt, empty maps, meets the
/// history's fakes and must leave them alone.
#[test]
fn a_restarted_engine_does_not_re_substitute_history() {
    let outbound = {
        let e = engine();
        e.substitute(&prompt()).0
    };

    let restarted = engine(); // same salt, no map
    assert!(restarted.vault().is_empty());

    let (again, summary) = restarted.substitute(&outbound);
    assert_eq!(
        summary.total(),
        0,
        "restarted engine re-substituted its own fakes"
    );
    assert_eq!(again, outbound);
}

/// §12 "Tool-result surface" precursor: a `.env` file's worth of secrets, as tool output would
/// carry it upstream. The dominant exfiltration path is not the prompt.
#[test]
fn a_dotenv_file_is_fully_substituted() {
    let e = engine();
    let dotenv = format!(
        "AWS_ACCESS_KEY_ID={}\nAWS_SECRET_ACCESS_KEY={}\nGITHUB_TOKEN={}\nSTRIPE_KEY={}\n",
        sample::for_kind(SecretKind::AwsAccessKeyId),
        sample::for_kind(SecretKind::AwsSecretKey),
        sample::for_kind(SecretKind::GithubPat),
        sample::for_kind(SecretKind::StripeKey),
    );
    let (outbound, summary) = e.substitute(&dotenv);

    assert_eq!(summary.total(), 4);
    // The keys and the `=` structure survive; only the values change.
    for line in outbound.lines() {
        let (name, value) = line.split_once('=').expect("shape preserved");
        assert!(!value.is_empty(), "{name} lost its value");
    }
    assert_eq!(e.restore(&outbound), dotenv);
}

/// §12 "allowlist fixture": zero substitutions, even with the network rules enabled.
#[test]
fn allowlisted_values_are_never_substituted() {
    let e = engine_with_network_rules();
    let text = "\
Checkout d6cd1e2bd19e03a81132a23b2025920577f84e37 and rebase onto main.
The dev server listens on 127.0.0.1:8787 and the container on 10.0.0.5.
Docs use 192.0.2.1 and 2001:db8::1; mail alice@example.com for access.
Integrity sha512-vfNTPFNH1sBLPGDDeUXBrXXsRcMdvHtE6yHhU1cUw is fine.";

    let (outbound, summary) = e.substitute(text);
    assert_eq!(
        summary,
        Default::default(),
        "allowlisted values were substituted"
    );
    assert_eq!(outbound, text, "outbound text must be untouched");
}

/// Overlap resolution, end to end: an Anthropic key's tail also matches the AWS-secret rule, but
/// the whole key must be substituted as one unit — not shredded into two fakes.
#[test]
fn overlapping_rules_substitute_the_longest_span_once() {
    let e = engine();
    let key = sample::for_kind(SecretKind::AnthropicKey);
    let (outbound, summary) = e.substitute(&format!("key: {key}"));

    assert_eq!(
        summary.total(),
        1,
        "the key must be substituted exactly once"
    );
    assert_eq!(summary.by_kind.get(&SecretKind::AnthropicKey), Some(&1));
    assert!(
        outbound.starts_with("key: sk-ant-"),
        "prefix preserved: {outbound}"
    );
    assert_eq!(e.restore(&outbound), format!("key: {key}"));
}

/// A GCP service-account key lives inside JSON. Substituting it must not emit a real newline, or
/// the agent's own credentials file stops parsing.
#[test]
fn gcp_key_inside_json_stays_valid_json() {
    let e = engine();
    let key = sample::for_kind(SecretKind::GcpServiceAccountKey);
    let json = format!(r#"{{"type":"service_account","private_key":"{key}"}}"#);

    let (outbound, summary) = e.substitute(&json);
    assert_eq!(summary.total(), 1);
    assert_eq!(
        summary.by_kind.get(&SecretKind::GcpServiceAccountKey),
        Some(&1),
        "the specific GCP kind must win over the generic PEM rule"
    );
    assert!(
        !outbound.contains('\n'),
        "a raw newline would corrupt the JSON: {outbound}"
    );
    assert_eq!(e.restore(&outbound), json);
}

/// The engine is shared across Claude Code's parallel background requests.
#[test]
fn concurrent_substitution_is_consistent() {
    let e = Arc::new(engine());
    let original = prompt();

    let outputs: Vec<String> = std::thread::scope(|s| {
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let e = Arc::clone(&e);
                let original = original.as_str();
                s.spawn(move || e.substitute(original).0)
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });

    assert!(
        outputs.windows(2).all(|w| w[0] == w[1]),
        "concurrent substitution produced divergent outbound text"
    );
    assert_eq!(
        e.vault().len(),
        5,
        "one map entry per secret, no duplicates"
    );
}
