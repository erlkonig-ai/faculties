//! secrets — an encrypted secret-store faculty (a 1Password replacement, owned,
//! pile-native). The model: admins distribute company secrets to users by
//! sealing them to recipients' public keys; the pile gives storage, sync, and a
//! signed audit trail for free; authorization is relationship-tuples queried
//! with `path!` (design captured in the `authz`-tagged wiki).
//!
//! MVP (this slice): the dryoc *envelope* — a random data key (DEK) encrypts the
//! body once, and the DEK is sealed-boxed to each recipient's public key —
//! validated by a seal -> open round-trip. The trible schema, `identity init`,
//! `secret add/get`, and the `path!` membership queries land on top of this.

use dryoc::dryocbox::{DryocBox, KeyPair, PublicKey};
use dryoc::dryocsecretbox::{DryocSecretBox, Key, Nonce};
use dryoc::types::*;

/// Seal a secret: a fresh DEK encrypts the body once (secretbox); the DEK is
/// sealed-boxed to each recipient public key. Returns (nonce, ciphertext, wraps).
fn seal(recipients: &[&PublicKey], secret: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<Vec<u8>>) {
    let dek = Key::gen();
    let nonce = Nonce::gen();
    let ciphertext = DryocSecretBox::encrypt_to_vecbox(secret, &nonce, &dek).to_vec();
    let wraps = recipients
        .iter()
        .map(|pk| {
            DryocBox::seal_to_vecbox(&dek, *pk)
                .expect("seal DEK")
                .to_vec()
        })
        .collect();
    (nonce.as_slice().to_vec(), ciphertext, wraps)
}

/// Open: unseal the DEK with the recipient keypair, then open the body.
fn open(kp: &KeyPair, nonce: &[u8], ciphertext: &[u8], wrap: &[u8]) -> Vec<u8> {
    let dek_bytes = DryocBox::from_sealed_bytes(wrap)
        .expect("parse sealed box")
        .unseal_to_vec(kp)
        .expect("unseal DEK");
    let dek = Key::try_from(dek_bytes.as_slice()).expect("DEK length");
    let nonce = Nonce::try_from(nonce).expect("nonce length");
    DryocSecretBox::from_bytes(ciphertext)
        .expect("parse secretbox")
        .decrypt_to_vec(&nonce, &dek)
        .expect("decrypt body")
}

fn main() {
    // MVP gate: envelope round-trip to two distinct recipients.
    let alice = KeyPair::gen_with_defaults();
    let bob = KeyPair::gen_with_defaults();
    let secret = b"the prod database password is hunter2";

    let (nonce, ciphertext, wraps) = seal(&[&alice.public_key, &bob.public_key], secret);
    let a = open(&alice, &nonce, &ciphertext, &wraps[0]);
    let b = open(&bob, &nonce, &ciphertext, &wraps[1]);

    assert_eq!(a.as_slice(), secret, "alice must recover the secret");
    assert_eq!(b.as_slice(), secret, "bob must recover the secret");
    // a wrong recipient must NOT open a wrap meant for another
    assert!(
        DryocBox::from_sealed_bytes(&wraps[0])
            .unwrap()
            .unseal_to_vec(&bob)
            .is_err(),
        "bob must not open alice's wrap"
    );
    println!(
        "✓ envelope round-trip: 1 body, {} wraps, both recipients opened identically; cross-open refused",
        wraps.len()
    );
}
