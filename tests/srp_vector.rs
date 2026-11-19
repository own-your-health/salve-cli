//! salve's SRP against a vector made with AWS's reference Cognito client
//! (amazon-cognito-identity-js 6.1.2) over synthetic inputs: a fixed `a`,
//! a server `B` made from a known password, salt and `b`, a secret block
//! and a timestamp. The vector's README entry says how it was made.

use num_bigint::BigUint;
use salve::srp::{self, Client, Group};
use serde_json::Value;

fn vector() -> Value {
    serde_json::from_str(include_str!("fixtures/srp-vector.json")).unwrap()
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v[k].as_str().unwrap()
}

#[test]
fn the_group_multiplier_matches() {
    let v = vector();
    assert_eq!(Group::new().k.to_str_radix(16), s(&v, "k"));
}

#[test]
fn the_sign_in_signature_matches_the_reference_client() {
    let v = vector();
    let a = BigUint::parse_bytes(s(&v, "small_a").as_bytes(), 16).unwrap();
    let c = Client::with_secret(s(&v, "pool_name"), a).unwrap();
    assert_eq!(c.large_a_hex(), s(&v, "large_a"));
    let key = c
        .password_key(s(&v, "user_id"), s(&v, "password"), s(&v, "srp_b"), s(&v, "salt"))
        .unwrap();
    let hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(hex, s(&v, "hkdf"));
    let sig = srp::signature(
        &key,
        s(&v, "pool_name"),
        s(&v, "user_id"),
        s(&v, "challenge_block"),
        s(&v, "timestamp"),
    )
    .unwrap();
    assert_eq!(sig, s(&v, "signature"));
}

#[test]
fn a_wrong_password_signs_differently() {
    let v = vector();
    let a = BigUint::parse_bytes(s(&v, "small_a").as_bytes(), 16).unwrap();
    let c = Client::with_secret(s(&v, "pool_name"), a).unwrap();
    let key = c
        .password_key(s(&v, "user_id"), "wrong-password", s(&v, "srp_b"), s(&v, "salt"))
        .unwrap();
    let sig = srp::signature(
        &key,
        s(&v, "pool_name"),
        s(&v, "user_id"),
        s(&v, "challenge_block"),
        s(&v, "timestamp"),
    )
    .unwrap();
    assert_ne!(sig, s(&v, "signature"));
}
