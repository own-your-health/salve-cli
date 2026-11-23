//! Where a profile's Salve sign-in is kept: the one seam that knows.
//!
//! A [`Session`] is the three Cognito tokens a sign-in answered (the ID
//! token Salve's APIs take, the access token and the refresh token that
//! renews them), when the first two lapse, and what the sign-in read about
//! the patient and their clinic. The password is never kept.
//!
//! The entries are the vault's (`pk_cli_auth::vault`, cli-common DESIGN.md
//! §2.5): `<profile>/<clinic>/<patient>` ([`Key`]), each in its own
//! encrypted owner-only file under `~/.config/salve/vault/`, all under one
//! key, the keychain item `vault-key` in `piekstra.salve`. A sign-in
//! waiting on its texted code is parked in the same vault
//! ([`VaultSlot`]). A run with nothing stored reads no keychain item.
//!
//! [`KEYCHAIN_SERVICE_ENV`] names another keychain service for the key, for
//! the tests and the smoke run, and moves the vault under
//! `$XDG_CONFIG_HOME/salve/vault`, which must then be set: a test's vault
//! is never the owner's. While it is set ([`hermetic`]) nothing touches the
//! real browser profiles either.

use std::path::PathBuf;

use base64::Engine;
use pk_cli_auth::otp::{ParkedLogin, ParkingSlot};
use pk_cli_auth::vault::{self, Vault};
use pk_cli_config::profile::ProfileName;
use pk_cli_core::{CliError, Reason};
use pk_cli_secrets::{CredentialStore, Secret};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::cli::BIN;
use crate::cognito::Tokens;

/// Names the keychain service holding the vault's key instead of
/// `piekstra.salve`, and moves the vault under `$XDG_CONFIG_HOME`. For the
/// tests and the smoke run only.
pub const KEYCHAIN_SERVICE_ENV: &str = "SALVE_KEYCHAIN_SERVICE";

/// Renew the tokens when they have less than this left.
pub const RENEW_BEFORE_SECS: u64 = 120;

pub struct Session {
    pub id_token: Secret,
    pub access_token: Secret,
    pub refresh_token: Secret,
    /// Unix seconds when the ID and access tokens lapse.
    pub expires_at: u64,
    /// Salve's patient id.
    pub patient_id: String,
    pub full_name: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    /// `YYYY-MM-DD`, from the ID token.
    pub birth_date: Option<String>,
    /// The clinic the account reads, as Salve names it.
    pub clinic_id: String,
    pub clinic_name: Option<String>,
    /// A stub's address, for a session made against one.
    pub stub: Option<String>,
    /// RFC 3339, UTC.
    pub signed_in_at: String,
}

impl Session {
    /// The clinic's token, from the ID token's `custom:clinictoken` claim:
    /// the patient API takes it beside the sign-in.
    pub fn clinic_token(&self) -> Option<String> {
        claims(self.id_token.expose())?["custom:clinictoken"]
            .as_str()
            .map(str::to_string)
    }

    /// The device Cognito tracks this sign-in as: the access token's
    /// `device_key` claim. Salve's pool tracks devices, and refuses a
    /// renewal that does not name the device ("Invalid Refresh Token").
    pub fn device_key(&self) -> Option<String> {
        claims(self.access_token.expose())?["device_key"]
            .as_str()
            .map(str::to_string)
    }

    /// Whether the tokens lapse within [`RENEW_BEFORE_SECS`].
    pub fn lapsing(&self, now: u64) -> bool {
        self.expires_at <= now + RENEW_BEFORE_SECS
    }

    /// The tokens a renewal answered, in place of the old ones.
    pub fn renewed(&mut self, t: Tokens, now: u64) {
        self.expires_at = expiry(&t, now);
        self.id_token = t.id_token;
        self.access_token = t.access_token;
        if let Some(r) = t.refresh_token {
            self.refresh_token = r;
        }
    }

    fn entry(&self) -> Entry {
        Entry {
            id_token: self.id_token.expose().to_string(),
            access_token: self.access_token.expose().to_string(),
            refresh_token: self.refresh_token.expose().to_string(),
            expires_at: self.expires_at,
            patient_id: self.patient_id.clone(),
            full_name: self.full_name.clone(),
            first_name: self.first_name.clone(),
            last_name: self.last_name.clone(),
            birth_date: self.birth_date.clone(),
            clinic_id: self.clinic_id.clone(),
            clinic_name: self.clinic_name.clone(),
            stub: self.stub.clone(),
            signed_in_at: self.signed_in_at.clone(),
        }
    }

    fn from_entry(e: Entry) -> Option<Session> {
        let ok = !e.id_token.is_empty() && !e.refresh_token.is_empty() && !e.patient_id.is_empty();
        ok.then(|| Session {
            id_token: Secret::new(e.id_token),
            access_token: Secret::new(e.access_token),
            refresh_token: Secret::new(e.refresh_token),
            expires_at: e.expires_at,
            patient_id: e.patient_id,
            full_name: e.full_name,
            first_name: e.first_name,
            last_name: e.last_name,
            birth_date: e.birth_date,
            clinic_id: e.clinic_id,
            clinic_name: e.clinic_name,
            stub: e.stub,
            signed_in_at: e.signed_in_at,
        })
    }
}

/// When tokens answered at `now` lapse: the ID token's own `exp`, else
/// `expires_in` from now.
pub fn expiry(t: &Tokens, now: u64) -> u64 {
    claims(t.id_token.expose())
        .and_then(|c| c["exp"].as_u64())
        .unwrap_or(now + t.expires_in)
}

/// A JSON Web Token's claims, read without checking its signature: salve
/// reads only what the token says about the patient and their clinic, and
/// Salve checks the token itself on every call.
pub fn claims(token: &str) -> Option<Value> {
    let payload = token.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload.trim_end_matches('='))
        .ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// A session's vault entry: `<profile>/<clinic>/<patient>`, the clinic
/// being Salve's id for it and the patient the household's label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Key {
    pub profile: ProfileName,
    pub org: String,
    pub patient: String,
}

impl std::fmt::Display for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}/{}", self.profile, self.org, self.patient)
    }
}

#[derive(Serialize, Deserialize)]
struct Entry {
    id_token: String,
    access_token: String,
    refresh_token: String,
    expires_at: u64,
    patient_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    full_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    first_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    birth_date: Option<String>,
    clinic_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    clinic_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    stub: Option<String>,
    signed_in_at: String,
}

/// The sessions, one per profile.
pub struct SessionStore {
    vault: Vault,
}

impl SessionStore {
    /// The store every command uses: the vault of `piekstra.salve`, or with
    /// [`KEYCHAIN_SERVICE_ENV`] a test's ([`hermetic`]).
    pub fn open() -> Result<SessionStore, CliError> {
        let vault = match service_override(service_env().as_deref()) {
            None => Vault::for_binary(BIN)?,
            Some(service) => Vault::new(CredentialStore::new(service), test_vault_dir()?),
        };
        Ok(SessionStore { vault })
    }

    /// A store over `vault`: the tests' in-memory one.
    pub fn with_vault(vault: Vault) -> SessionStore {
        SessionStore { vault }
    }

    /// The session stored under `key`, `None` when none is. An entry this
    /// salve cannot read is an error naming the profile and the command
    /// that removes it, never what it holds.
    pub fn get(&self, key: &Key) -> Result<Option<Session>, CliError> {
        let profile = &key.profile;
        let Some(raw) = self.vault.get(&key.to_string()).map_err(|e| remedied(e, profile))? else {
            return Ok(None);
        };
        let read: Entry = serde_json::from_str(raw.expose()).map_err(|_| unreadable(profile))?;
        Session::from_entry(read).map(Some).ok_or_else(|| unreadable(profile))
    }

    /// The session, for a command that reads Salve: none stored is exit 3,
    /// with the sign-in that stores one.
    pub fn load(&self, key: &Key) -> Result<Session, CliError> {
        self.get(key)?.ok_or_else(|| not_signed_in(&key.profile))
    }

    pub fn put(&self, key: &Key, session: &Session) -> Result<(), CliError> {
        self.vault
            .put_json(&key.to_string(), &session.entry())
            .map_err(|e| remedied(e, &key.profile))
    }

    /// Whether there was a session to remove. Reads no keychain item.
    pub fn delete(&self, key: &Key) -> Result<bool, CliError> {
        self.vault.delete(&key.to_string())
    }

    /// Remove every profile's session and the vault's key (`auth reset`).
    /// How many entries were removed.
    pub fn clear(&self) -> Result<usize, CliError> {
        self.vault.clear()
    }

    /// Where a profile's sign-in waits for its texted code.
    pub fn slot<'a>(&'a self, profile: &ProfileName) -> VaultSlot<'a> {
        VaultSlot {
            vault: &self.vault,
            name: format!("pending/{profile}"),
        }
    }
}

/// A sign-in waiting on its code, as a vault entry: no keychain item of its
/// own, so parking it asks for nothing more than the vault's key.
pub struct VaultSlot<'a> {
    vault: &'a Vault,
    name: String,
}

impl ParkingSlot for VaultSlot<'_> {
    fn load(&self) -> Result<Option<ParkedLogin>, CliError> {
        match self.vault.get(&self.name) {
            Ok(None) => Ok(None),
            Ok(Some(raw)) => Ok(serde_json::from_str(raw.expose()).ok()),
            // A parked sign-in that cannot be read is no sign-in waiting.
            Err(e) if e.reason() == Some(Reason::CredentialUnreadable) => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn save(&self, parked: &ParkedLogin) -> Result<(), CliError> {
        self.vault.put_json(&self.name, parked)
    }

    fn clear(&self) -> Result<(), CliError> {
        self.vault.delete(&self.name).map(|_| ())
    }
}

/// A profile with no session: exit 3, naming the sign-in.
pub fn not_signed_in(profile: &ProfileName) -> CliError {
    CliError::Auth(format!("no Salve sign-in is stored for profile `{profile}`"))
        .because(Reason::NoCredential)
        .with_remedy(format!(
            "{BIN} auth login --profile {profile} --op-item op://VAULT/ITEM (or --stdin, or --browser)"
        ))
}

/// The vault's errors with salve's own commands as their remedies.
fn remedied(e: CliError, profile: &ProfileName) -> CliError {
    match e.remedy() {
        Some(vault::REMEDY_DELETE_ENTRY) => e
            .with_remedy(format!("{BIN} auth logout --profile {profile}, then sign in again"))
            .because(Reason::CredentialUnreadable),
        Some(vault::REMEDY_CLEAR) => e.with_remedy(format!(
            "{BIN} auth reset removes every profile's sign-in and the key; then sign in again"
        )),
        _ => e,
    }
}

fn unreadable(profile: &ProfileName) -> CliError {
    CliError::Keychain(format!(
        "the sign-in stored for profile `{profile}` is not the shape this salve writes"
    ))
    .because(Reason::CredentialUnreadable)
    .with_remedy(format!("{BIN} auth logout --profile {profile}, then sign in again"))
}

/// Whether [`KEYCHAIN_SERVICE_ENV`] points the store elsewhere: a test or
/// the smoke run, under which nothing reads or removes the owner's kept
/// browser profiles.
pub fn hermetic() -> bool {
    service_override(service_env().as_deref()).is_some()
}

/// A test's vault: under `$XDG_CONFIG_HOME/salve`, which must be set, so a
/// test never opens the owner's `~/.config/salve/vault`.
fn test_vault_dir() -> Result<PathBuf, CliError> {
    match std::env::var_os("XDG_CONFIG_HOME").filter(|v| !v.is_empty()) {
        Some(base) => Ok(PathBuf::from(base).join(BIN).join("vault")),
        None => Err(CliError::Usage(format!(
            "{KEYCHAIN_SERVICE_ENV} is for tests and goes with XDG_CONFIG_HOME, so a test's vault is never the \
             owner's"
        ))),
    }
}

/// The variable's value. One that is not UTF-8 still counts as set, so it
/// never falls back to the real service.
fn service_env() -> Option<String> {
    std::env::var_os(KEYCHAIN_SERVICE_ENV).map(|v| v.to_string_lossy().into_owned())
}

/// A blank value names no service.
fn service_override(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pk_cli_auth::otp::check_slot_contract;
    use pk_cli_auth::vault::MemoryKeys;
    use std::sync::Arc;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("salve-session-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn key(profile: &str) -> Key {
        Key {
            profile: ProfileName::parse(profile).unwrap(),
            org: "clinic-0001".into(),
            patient: profile.into(),
        }
    }

    /// A token-shaped dummy with these claims.
    fn token(claims: &Value) -> String {
        let b = |v: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v);
        format!(
            "{}.{}.dummy",
            b(b"{\"alg\":\"none\"}"),
            b(claims.to_string().as_bytes())
        )
    }

    fn dummy() -> Session {
        Session {
            id_token: Secret::new(token(
                &serde_json::json!({ "custom:clinictoken": "dummy-clinic-token", "exp": 2000 }),
            )),
            access_token: Secret::new("dummy-access"),
            refresh_token: Secret::new("dummy-refresh"),
            expires_at: 2000,
            patient_id: "1001".into(),
            full_name: Some("Jane Example".into()),
            first_name: Some("Jane".into()),
            last_name: Some("Example".into()),
            birth_date: Some("1990-01-02".into()),
            clinic_id: "clinic-0001".into(),
            clinic_name: Some("Example Fertility".into()),
            stub: None,
            signed_in_at: "2026-01-02T03:04:05Z".into(),
        }
    }

    #[test]
    fn the_device_is_the_access_tokens_device_key() {
        let mut s = dummy();
        assert_eq!(s.device_key(), None, "an opaque access token names none");
        s.access_token = Secret::new(token(&serde_json::json!({ "device_key": "eu-west-2_dummy-device" })));
        assert_eq!(s.device_key().as_deref(), Some("eu-west-2_dummy-device"));
        s.access_token = Secret::new(token(&serde_json::json!({ "token_use": "access" })));
        assert_eq!(s.device_key(), None);
    }

    #[test]
    fn a_blank_service_names_none() {
        assert_eq!(service_override(None), None);
        assert_eq!(service_override(Some("  ")), None);
        assert_eq!(
            service_override(Some("piekstra.salve.hermetic-tests")),
            Some("piekstra.salve.hermetic-tests")
        );
    }

    #[test]
    fn the_clinic_token_and_expiry_come_from_the_id_token() {
        let s = dummy();
        assert_eq!(s.clinic_token().as_deref(), Some("dummy-clinic-token"));
        assert!(s.lapsing(1900));
        assert!(!s.lapsing(1000));
        let t = Tokens {
            id_token: Secret::new(token(&serde_json::json!({ "exp": 5000 }))),
            access_token: Secret::new("a"),
            refresh_token: None,
            expires_in: 3600,
            new_device: None,
        };
        assert_eq!(expiry(&t, 100), 5000);
        let opaque = Tokens {
            id_token: Secret::new("not-a-token"),
            access_token: Secret::new("a"),
            refresh_token: None,
            expires_in: 3600,
            new_device: None,
        };
        assert_eq!(expiry(&opaque, 100), 3700);
        let mut s = dummy();
        s.renewed(t, 100);
        assert_eq!(s.expires_at, 5000);
        assert_eq!(
            s.refresh_token.expose(),
            "dummy-refresh",
            "a renewal keeps the refresh token"
        );
    }

    #[test]
    fn each_profile_has_its_own_entry() {
        let dir = temp_dir("entries");
        let keys = Arc::new(MemoryKeys::new());
        let store = SessionStore::with_vault(Vault::new(keys.clone(), &dir));
        assert!(store.get(&key("adult1")).unwrap().is_none());
        assert_eq!(keys.reads(), 0, "nothing stored, nothing read");
        assert_eq!(key("adult1").to_string(), "adult1/clinic-0001/adult1");

        store.put(&key("adult1"), &dummy()).unwrap();
        let read = store.get(&key("adult1")).unwrap().unwrap();
        assert_eq!(read.refresh_token.expose(), "dummy-refresh");
        assert_eq!(read.patient_id, "1001");
        assert_eq!(read.birth_date.as_deref(), Some("1990-01-02"));
        assert!(store.get(&key("adult2")).unwrap().is_none());
        for file in std::fs::read_dir(&dir).unwrap() {
            let bytes = std::fs::read(file.unwrap().path()).unwrap();
            assert!(!String::from_utf8_lossy(&bytes).contains("dummy-refresh"));
        }
        assert!(store.delete(&key("adult1")).unwrap());
        assert!(!store.delete(&key("adult1")).unwrap());
        assert!(store.load(&key("adult1")).err().unwrap().is_auth());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_parked_sign_in_keeps_to_its_slot() {
        let dir = temp_dir("slot");
        let store = SessionStore::with_vault(Vault::new(MemoryKeys::new(), &dir));
        let p = ProfileName::parse("adult1").unwrap();
        check_slot_contract(&store.slot(&p));
        store.put(&key("adult1"), &dummy()).unwrap();
        let slot = store.slot(&p);
        slot.save(&ParkedLogin::new("dummy-parked", 1)).unwrap();
        slot.clear().unwrap();
        assert!(
            store.get(&key("adult1")).unwrap().is_some(),
            "clearing the slot spares the session"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_unreadable_entry_is_named_not_quoted() {
        let dir = temp_dir("unreadable");
        let vault = Vault::new(MemoryKeys::new(), &dir);
        vault
            .put("adult1/clinic-0001/adult1", &Secret::new(r#"{"token":"dummy_secret"}"#))
            .unwrap();
        let store = SessionStore::with_vault(vault);
        let e = store.get(&key("adult1")).err().unwrap();
        assert_eq!(e.reason(), Some(Reason::CredentialUnreadable));
        assert!(!e.to_string().contains("dummy"), "{e}");
        assert!(e.remedy().unwrap().contains("auth logout --profile adult1"), "{e}");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
