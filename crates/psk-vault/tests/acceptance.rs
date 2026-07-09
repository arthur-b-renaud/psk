//! The vault half of the brief's M1 acceptance criteria (§12), exercised through the public API
//! exactly as `psk-core` and the proxy will use it.

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use psk_vault::kind::MARKER;
use psk_vault::{NearMissReason, SecretKind, Vault, salt, sample};

/// Five distinct real secrets of five different kinds, as they might appear in one prompt.
///
/// Assembled by `psk_vault::sample`, never written as literals: PSK's fixtures are secret-shaped
/// by definition, and a literal here trips GitHub push protection and every credential scanner
/// pointed at this repo. See that module for the full reasoning.
const KINDS: [SecretKind; 5] = [
    SecretKind::AwsAccessKeyId,
    SecretKind::AwsSecretKey,
    SecretKind::GithubPat,
    SecretKind::AnthropicKey,
    SecretKind::CreditCard,
];

fn secrets() -> Vec<(SecretKind, String)> {
    KINDS.iter().map(|&k| (k, sample::for_kind(k))).collect()
}

/// A prompt with all five secrets embedded, as a user might actually paste it.
fn prompt() -> String {
    let s = secrets();
    format!(
        "Deploy with {} and {}.\nPush using {}.\nBill {} to {}.",
        s[0].1, s[1].1, s[2].1, s[3].1, s[4].1
    )
}

fn vault() -> Vault {
    Vault::with_salt([42u8; 32])
}

/// Substitute every secret in `text`, returning the outbound text and the fakes minted.
fn substitute_all(v: &Vault, text: &str) -> (String, Vec<String>) {
    let mut out = text.to_string();
    let mut fakes = Vec::new();
    for (kind, real) in secrets() {
        let fake = v.substitute(&real, kind);
        out = out.replace(&real, &fake);
        fakes.push(fake);
    }
    (out, fakes)
}

/// §12 "Round-trip": five real secrets, none leave, all fakes present, restore is verbatim.
#[test]
fn round_trip_is_lossless() {
    let v = vault();
    let (outbound, fakes) = substitute_all(&v, &prompt());

    for (_, real) in secrets() {
        assert!(
            !outbound.contains(&real),
            "real secret leaked outbound: {real}"
        );
    }
    for fake in &fakes {
        assert!(outbound.contains(fake), "fake missing outbound: {fake}");
    }

    // The LLM echoes the fakes back verbatim; the hook restores them before execution.
    assert_eq!(v.restore(&outbound), prompt(), "restore must be verbatim");
}

/// §12 "Determinism/restart": drop the vault, rebuild from the same salt, get identical fakes —
/// and recognise the old fakes as fakes *before* the map is rebuilt.
#[test]
fn determinism_survives_a_restart() {
    let (outbound, fakes) = {
        let v = vault();
        substitute_all(&v, &prompt())
    }; // the vault is dropped here, taking both maps with it

    let restarted = vault(); // same salt, empty maps
    assert!(restarted.is_empty(), "a restarted vault starts with no map");

    // The guard (§7c) must hold on a vault that has never seen these fakes. This is the whole
    // reason the salt persists: the resent conversation history is full of them.
    for fake in &fakes {
        assert!(
            restarted.is_known_fake(fake),
            "restarted vault failed to recognise its own fake: {fake}"
        );
    }

    // Re-deriving the same secrets rebuilds the identical mapping on the fly.
    let (outbound_again, fakes_again) = substitute_all(&restarted, &prompt());
    assert_eq!(fakes, fakes_again, "fakes must be stable across a restart");
    assert_eq!(outbound, outbound_again);
    assert_eq!(restarted.restore(&outbound), prompt());
}

/// A different salt must yield different fakes, or the salt is not doing anything.
#[test]
fn a_different_salt_yields_different_fakes() {
    let (_, a) = substitute_all(&vault(), &prompt());
    let (_, b) = substitute_all(&Vault::with_salt([1u8; 32]), &prompt());
    assert_ne!(a, b);
}

/// §7c: the guard accepts every fake the vault mints, so `Engine::substitute` will skip them.
#[test]
fn guard_accepts_every_minted_fake() {
    let v = vault();
    for k in SecretKind::ALL {
        let real = sample::for_kind(k);
        let fake = v.substitute(&real, k);
        assert!(v.is_known_fake(&fake), "{k:?}: guard missed {fake}");
    }
}

/// The guard must not fire on ordinary text, or the engine would stop substituting real secrets.
#[test]
fn guard_rejects_ordinary_values() {
    let v = vault();
    for s in [
        &sample::for_kind(SecretKind::AwsAccessKeyId), // a real-shaped AWS key
        "hello world",
        "d6cd1e2bd19e03a81132a23b2025920577f84e37", // a git SHA-1
        "5500005555555559",                         // a Luhn-valid card outside the reserved BIN
        "GB82WEST12345698765432",                   // a valid IBAN in a live country
    ]
    .map(|s| s.to_string())
    {
        assert!(!v.is_known_fake(&s), "guard falsely accepted {s}");
    }
}

/// Substituting text that already contains a fake must be a no-op on that span (§7c).
///
/// The vault half of the invariant: the engine consults `is_known_fake` before substituting, and
/// the vault answers correctly for a fake it minted *and* for one from a previous process.
#[test]
fn substitution_is_a_no_op_on_an_existing_fake() {
    let v = vault();
    let fake = v.substitute(
        &sample::for_kind(SecretKind::AwsAccessKeyId),
        SecretKind::AwsAccessKeyId,
    );

    // The engine's decision, simulated: the fake matches the AWS pattern, but the guard vetoes.
    assert!(v.is_known_fake(&fake));

    // Had the engine substituted it anyway, the fake would map to a fake and the real value
    // would be unreachable. Assert the map still holds exactly one secret.
    assert_eq!(v.len(), 1);
    assert_eq!(
        v.restore(&fake),
        sample::for_kind(SecretKind::AwsAccessKeyId)
    );
}

/// §8b: exact fakes are clean; mangled ones are not.
#[test]
fn near_miss_catches_mangled_fakes_only() {
    let v = vault();
    let fake = v.substitute(
        &sample::for_kind(SecretKind::AwsAccessKeyId),
        SecretKind::AwsAccessKeyId,
    );

    // Exact fake: exact restore handles it, so the *restored* text is clean.
    assert_eq!(v.near_miss(&v.restore(&format!("key = {fake}"))), None);

    // Case-mangled: exact restore misses it, near-miss must not.
    let mangled = fake.to_ascii_lowercase();
    let nm = v
        .near_miss(&v.restore(&format!("key = {mangled}")))
        .expect("case-mangled fake must be caught");
    assert_eq!(nm.reason, NearMissReason::CaseMangled);
    assert_eq!(nm.resembles.as_deref(), Some(fake.as_str()));

    // Truncated at the tail, keeping the fake's signature window intact.
    let truncated = format!("{}ZZ", &fake[..18]);
    let nm = v
        .near_miss(&v.restore(&format!("key = {truncated}")))
        .expect("truncated fake must be caught");
    assert_eq!(nm.reason, NearMissReason::TruncatedPrefix);
    assert_eq!(nm.resembles.as_deref(), Some(fake.as_str()));

    // Truncated so hard that even the signature window is gone. The reason changes, but the hook
    // must still block: the marker is what gives it away. Blocking is the invariant; the reason
    // is only ever a diagnostic in the message.
    let butchered = format!("{}ZZZZ", &fake[..12]);
    assert!(
        v.near_miss(&v.restore(&format!("key = {butchered}")))
            .is_some(),
        "a fake truncated past its signature window must still block"
    );

    // A marker from a *previous* proxy process: no known fake matches, but it must still block.
    let orphan = format!("AKIA{MARKER}ZZZZZZZZZZZZ");
    let nm = v
        .near_miss(&v.restore(&orphan))
        .expect("orphaned marker must be caught");
    assert_eq!(nm.reason, NearMissReason::MarkerResidue);

    // Ordinary tool input must pass cleanly, or the hook blocks the agent for nothing.
    assert_eq!(v.near_miss("cargo build --release"), None);
    assert_eq!(
        v.near_miss("git checkout d6cd1e2bd19e03a81132a23b2025920577f84e37"),
        None
    );
}

/// Regression: the truncated-prefix rule must key on fake-specific entropy, not on boilerplate.
///
/// A PEM fake opens with `-----BEGIN PRIVATE KEY-----`, and so does every real private key. An
/// earlier version anchored the prefix window at offset 0, which made the hook block on any
/// legitimate key file the agent wrote — fail-closed on ordinary work, the one thing §8b says the
/// hook must never do.
#[test]
fn near_miss_ignores_pem_boilerplate() {
    let v = vault();
    let _ = v.substitute(
        &sample::for_kind(SecretKind::PrivateKeyBlock),
        SecretKind::PrivateKeyBlock,
    );

    let innocent = "-----BEGIN PRIVATE KEY-----\nAAAAB3NzaC1yc2EAAAA\n-----END PRIVATE KEY-----";
    assert_eq!(
        v.near_miss(&v.restore(innocent)),
        None,
        "an unrelated real PEM must not look like a mangled fake"
    );

    // The rule still fires when the fake's own high-entropy body shows up mangled.
    let fake = v.substitute(
        &sample::for_kind(SecretKind::PrivateKeyBlock),
        SecretKind::PrivateKeyBlock,
    );
    let body: String = fake.lines().filter(|l| !l.contains("-----")).collect();
    let rewrapped = format!("-----BEGIN PRIVATE KEY-----\n{body}  \n-----END PRIVATE KEY-----");
    assert!(
        v.near_miss(&v.restore(&rewrapped)).is_some(),
        "a re-wrapped fake body must still be caught"
    );
}

/// An unrestored fake *card* carries no alphabetic marker, so the reserved BIN has to catch it.
#[test]
fn near_miss_catches_reserved_space_residue() {
    let v = vault();
    let fake = v.substitute(
        &sample::for_kind(SecretKind::CreditCard),
        SecretKind::CreditCard,
    );
    let mangled = fake.replace(' ', "-"); // re-formatted by the LLM; exact restore misses it

    let nm = v
        .near_miss(&v.restore(&mangled))
        .expect("a Luhn-valid fake in the reserved BIN must be caught");
    assert_eq!(nm.reason, NearMissReason::MarkerResidue);
}

/// §8: the proxy shares one vault across Claude Code's parallel background requests.
#[test]
fn concurrent_substitution_mints_one_fake() {
    let v = Arc::new(vault());
    let real = sample::for_kind(SecretKind::AwsAccessKeyId);
    // `&str` rather than `String`: it is `Copy`, so each `move` closure gets its own reference
    // into the one buffer that outlives the scope, instead of fighting over ownership.
    let real: &str = &real;

    let fakes: Vec<String> = std::thread::scope(|s| {
        let handles: Vec<_> = (0..16)
            .map(|_| {
                let v = Arc::clone(&v);
                s.spawn(move || v.substitute(real, SecretKind::AwsAccessKeyId))
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });

    assert!(
        fakes.windows(2).all(|w| w[0] == w[1]),
        "concurrent substitution produced different fakes"
    );
    assert_eq!(v.len(), 1, "one secret must yield exactly one map entry");
    assert_eq!(v.restore(&fakes[0]), real);
}

/// The salt on disk is created once and reused, which is what makes the restart test above true
/// of a real process and not just of `with_salt`.
#[test]
fn vault_opened_twice_from_disk_derives_identical_fakes() {
    let dir = scratch_dir("open-twice");
    let a = Vault::with_salt(salt::load_or_create(&dir).unwrap());
    let b = Vault::with_salt(salt::load_or_create(&dir).unwrap());
    let real = sample::for_kind(SecretKind::AwsAccessKeyId);
    assert_eq!(
        a.substitute(&real, SecretKind::AwsAccessKeyId),
        b.substitute(&real, SecretKind::AwsAccessKeyId),
    );
    let _ = fs::remove_dir_all(&dir);
}

fn scratch_dir(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("psk-acceptance-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&p);
    p
}
