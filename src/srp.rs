//! The client half of Cognito's SRP sign-in (`USER_SRP_AUTH`), written from
//! the protocol: SRP-6a over the 3072-bit group of RFC 5054, SHA-256, and
//! Cognito's own key derivation and claim signature.
//!
//! The password never leaves this module: Cognito gets `A`, then a
//! signature over its secret block made with a key derived from the
//! password, the salt and `B` it answered.
//!
//! Every hex value Cognito hashes is "padded" the way its own clients pad
//! it ([`pad_hex`]): an even number of digits, with `00` in front when the
//! first digit has the high bit set. `tests/srp_vector.rs` checks the whole
//! exchange against a vector made with AWS's reference client.

use base64::Engine;
use hmac::{Hmac, Mac};
use num_bigint::BigUint;
use pk_cli_core::CliError;
use sha2::{Digest, Sha256};

/// RFC 5054's 3072-bit prime, the group Cognito uses.
pub const N_HEX: &str =
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF\
9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F241\
17C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED52907709\
6966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817\
183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB\
3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE1\
17577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF";

/// Cognito's label for the derived key.
const INFO: &[u8] = b"Caldera Derived Key";

type HmacSha256 = Hmac<Sha256>;

/// The group: `N`, `g` and the multiplier `k = H(N | g)`.
pub struct Group {
    pub n: BigUint,
    pub g: BigUint,
    pub k: BigUint,
}

impl Group {
    pub fn new() -> Group {
        let n = BigUint::parse_bytes(N_HEX.as_bytes(), 16).expect("N is hex");
        let g = BigUint::from(2u32);
        let k = from_hex(&hex_hash(&format!("{}{}", pad_hex(&n), pad_hex(&g)))).expect("a hash is hex");
        Group { n, g, k }
    }
}

impl Default for Group {
    fn default() -> Self {
        Group::new()
    }
}

/// One sign-in's client values: the secret `a` and the public `A = g^a`.
pub struct Client {
    group: Group,
    /// The user pool's name: what follows `_` in its id.
    pool_name: String,
    a: BigUint,
    large_a: BigUint,
}

impl Client {
    /// A sign-in with a fresh random `a` (128 bytes).
    pub fn random(pool_name: &str) -> Result<Client, CliError> {
        let mut bytes = [0u8; 128];
        getrandom::fill(&mut bytes).map_err(|e| CliError::Other(format!("no randomness for the sign-in: {e}")))?;
        Client::with_secret(pool_name, BigUint::from_bytes_be(&bytes))
    }

    /// A sign-in with a given `a`: the tests' vector.
    pub fn with_secret(pool_name: &str, a: BigUint) -> Result<Client, CliError> {
        let group = Group::new();
        let large_a = group.g.modpow(&a, &group.n);
        if large_a == BigUint::ZERO {
            return Err(CliError::Other("the sign-in's public value came out zero".into()));
        }
        Ok(Client {
            group,
            pool_name: pool_name.to_string(),
            a,
            large_a,
        })
    }

    /// `SRP_A`, as Cognito's clients send it: lowercase hex, unpadded.
    pub fn large_a_hex(&self) -> String {
        self.large_a.to_str_radix(16)
    }

    /// The 16-byte key Cognito expects the claim to be signed with, from the
    /// password and the challenge's `SRP_B` and `SALT` (hex). `user_id` is
    /// the challenge's `USER_ID_FOR_SRP`. A `B` that is zero modulo `N`, or a
    /// scrambler `u` of zero, is refused: either would let the server learn
    /// the password's key.
    pub fn password_key(
        &self,
        user_id: &str,
        password: &str,
        b_hex: &str,
        salt_hex: &str,
    ) -> Result<[u8; 16], CliError> {
        let Group { n, g, k } = &self.group;
        let bad = || CliError::Upstream("Cognito answered a sign-in challenge this client cannot use".into());
        let b = from_hex(b_hex).ok_or_else(bad)?;
        let salt = from_hex(salt_hex).ok_or_else(bad)?;
        if &b % n == BigUint::ZERO {
            return Err(bad());
        }
        let u = from_hex(&hex_hash(&format!("{}{}", pad_hex(&self.large_a), pad_hex(&b)))).ok_or_else(bad)?;
        if u == BigUint::ZERO {
            return Err(bad());
        }
        let user_password = hash_hex(format!("{}{user_id}:{password}", self.pool_name).as_bytes());
        let x = from_hex(&hex_hash(&format!("{}{user_password}", pad_hex(&salt)))).ok_or_else(bad)?;
        let g_x = g.modpow(&x, n);
        let k_g_x = (k * g_x) % n;
        let base = ((&b % n) + n - k_g_x) % n;
        let exponent = &self.a + &u * &x;
        let s = base.modpow(&exponent, n);
        let ikm = decode_hex(&pad_hex(&s)).ok_or_else(bad)?;
        let salt_bytes = decode_hex(&pad_hex(&u)).ok_or_else(bad)?;
        Ok(hkdf(&salt_bytes, &ikm))
    }
}

/// HKDF-SHA256 as Cognito uses it: one block, the first 16 bytes.
pub fn hkdf(salt: &[u8], ikm: &[u8]) -> [u8; 16] {
    let prk = hmac(salt, &[ikm]);
    let okm = hmac(&prk, &[INFO, &[1u8]]);
    let mut out = [0u8; 16];
    out.copy_from_slice(&okm[..16]);
    out
}

fn hmac(key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC takes a key of any length");
    for p in parts {
        mac.update(p);
    }
    mac.finalize().into_bytes().to_vec()
}

/// `PASSWORD_CLAIM_SIGNATURE`: base64 of the HMAC, under the password key,
/// of the pool name, the user id, the secret block's bytes and the
/// timestamp.
pub fn signature(
    key: &[u8; 16],
    pool_name: &str,
    user_id: &str,
    secret_block: &str,
    timestamp: &str,
) -> Result<String, CliError> {
    let block = base64::engine::general_purpose::STANDARD
        .decode(secret_block.trim())
        .map_err(|_| CliError::Upstream("Cognito's secret block is not base64".into()))?;
    let mac = hmac(
        key,
        &[pool_name.as_bytes(), user_id.as_bytes(), &block, timestamp.as_bytes()],
    );
    Ok(base64::engine::general_purpose::STANDARD.encode(mac))
}

/// Cognito's timestamp for the claim: `Thu Nov 5 09:07:03 UTC 2026`, in
/// English, the day of the month unpadded.
pub fn timestamp(unix: u64) -> String {
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let days = unix / 86_400;
    let secs = unix % 86_400;
    let (y, m, d) = civil(days as i64);
    format!(
        "{} {} {} {:02}:{:02}:{:02} UTC {}",
        DAYS[(days % 7) as usize],
        MONTHS[(m - 1) as usize],
        d,
        secs / 3600,
        secs % 3600 / 60,
        secs % 60,
        y
    )
}

/// The civil date of a day count from 1970-01-01 (Howard Hinnant's
/// algorithm).
fn civil(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

/// A number's hex as Cognito hashes it: even length, and `00` in front when
/// the first digit is 8 or more.
pub fn pad_hex(n: &BigUint) -> String {
    let mut s = n.to_str_radix(16);
    if s.len() % 2 == 1 {
        s.insert(0, '0');
    }
    if s.as_bytes()
        .first()
        .is_some_and(|c| matches!(c, b'8'..=b'9' | b'a'..=b'f'))
    {
        s.insert_str(0, "00");
    }
    s
}

/// SHA-256 of `bytes`, as 64 lowercase hex digits.
pub fn hash_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

/// SHA-256 of the bytes a hex string spells.
pub fn hex_hash(hex: &str) -> String {
    hash_hex(&decode_hex(hex).unwrap_or_default())
}

pub fn from_hex(hex: &str) -> Option<BigUint> {
    let hex = hex.trim();
    if hex.is_empty() {
        return None;
    }
    BigUint::parse_bytes(hex.as_bytes(), 16)
}

pub fn decode_hex(hex: &str) -> Option<Vec<u8>> {
    if hex.len() % 2 == 1 {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(hex.get(i..i + 2)?, 16).ok())
        .collect()
}

/// The verifier `ConfirmDevice` takes for a device, made the way AWS's
/// reference client makes it (`generateHashDevice`): a random password
/// hashed with the device's group and key, under a random salt, both
/// base64. The password is then dropped: salve never signs in as the
/// device, so the device never stands in for the texted code.
pub struct DeviceVerifier {
    pub salt: String,
    pub verifier: String,
}

/// A [`DeviceVerifier`] with a fresh random password and salt.
pub fn device_verifier(group_key: &str, device_key: &str) -> Result<DeviceVerifier, CliError> {
    let mut password = [0u8; 40];
    let mut salt = [0u8; 16];
    getrandom::fill(&mut password)
        .and_then(|()| getrandom::fill(&mut salt))
        .map_err(|e| CliError::Other(format!("no randomness for the device: {e}")))?;
    let password = base64::engine::general_purpose::STANDARD.encode(password);
    Ok(device_verifier_with(group_key, device_key, &password, &salt))
}

/// A [`DeviceVerifier`] from a given password and salt.
pub fn device_verifier_with(group_key: &str, device_key: &str, password: &str, salt: &[u8]) -> DeviceVerifier {
    let group = Group::new();
    let hashed = hash_hex(format!("{group_key}{device_key}:{password}").as_bytes());
    let salt_hex = pad_hex(&BigUint::from_bytes_be(salt));
    let x = from_hex(&hex_hash(&format!("{salt_hex}{hashed}"))).unwrap_or_default();
    let verifier = pad_hex(&group.g.modpow(&x, &group.n));
    let b64 = |hex: &str| base64::engine::general_purpose::STANDARD.encode(decode_hex(hex).unwrap_or_default());
    DeviceVerifier {
        salt: b64(&salt_hex),
        verifier: b64(&verifier),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padding_follows_the_high_bit() {
        let n = |h: &str| BigUint::parse_bytes(h.as_bytes(), 16).unwrap();
        assert_eq!(pad_hex(&n("2")), "02");
        assert_eq!(pad_hex(&n("7f")), "7f");
        assert_eq!(pad_hex(&n("80")), "0080");
        assert_eq!(pad_hex(&n("abc")), "0abc");
        assert_eq!(pad_hex(&n("fabc")), "00fabc");
        assert!(pad_hex(&Group::new().n).starts_with("00ffff"));
    }

    #[test]
    fn the_timestamp_is_cognitos_spelling() {
        assert_eq!(timestamp(0), "Thu Jan 1 00:00:00 UTC 1970");
        // 5 November 2026, 09:07:03 UTC, a Thursday.
        assert_eq!(timestamp(1_793_869_623), "Thu Nov 5 09:07:03 UTC 2026");
        // 29 February 2024, 23:59:59 UTC, a Thursday too.
        assert_eq!(timestamp(1_709_251_199), "Thu Feb 29 23:59:59 UTC 2024");
        assert_eq!(timestamp(1_709_251_200), "Fri Mar 1 00:00:00 UTC 2024");
    }

    #[test]
    fn a_challenge_that_would_leak_is_refused() {
        let c = Client::with_secret("TestPool1", BigUint::from(12345u32)).unwrap();
        let n = Group::new().n.to_str_radix(16);
        assert!(c.password_key("u", "p", &n, "01").is_err(), "B = N");
        assert!(c.password_key("u", "p", "0", "01").is_err(), "B = 0");
        assert!(c.password_key("u", "p", "zz", "01").is_err(), "not hex");
        assert!(c.password_key("u", "p", "1234", "01").is_ok());
    }

    #[test]
    fn hex_round_trips() {
        assert_eq!(decode_hex("00ff10").unwrap(), vec![0, 255, 16]);
        assert!(decode_hex("abc").is_none());
        assert!(decode_hex("zz").is_none());
        assert_eq!(
            hash_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
