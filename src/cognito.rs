//! Salve's sign-in: Amazon Cognito's user-pool API, as Salve's web app
//! calls it.
//!
//! Every call is `POST https://cognito-idp.eu-west-2.amazonaws.com/` with
//! `X-Amz-Target: AWSCognitoIdentityProviderService.<Action>` and a JSON
//! body. Salve's web client allows the SRP flow only (`USER_SRP_AUTH`;
//! `USER_PASSWORD_AUTH` answers "flow not enabled for this client"), so the
//! password is proved, never sent ([`crate::srp`]). The pool then asks for a
//! code sent by text message (`SMS_MFA`).
//!
//! A completed sign-in answers three tokens: the ID token, which Salve's
//! APIs take as their `authorization` header, the access token, and a
//! refresh token, which renews the other two (`REFRESH_TOKEN_AUTH`) with no
//! password or code until it lapses or is revoked.
//!
//! The pool tracks devices. A sign-in also names a new device
//! (`NewDeviceMetadata`), and a renewal is refused ("Invalid Refresh
//! Token") unless it names that device and the device was confirmed
//! (`ConfirmDevice`), as Salve's web app does after every sign-in.
//!
//! Each call is one request, never retried: a refused password is spent
//! once.

use std::time::Duration;

use pk_cli_core::{transport, CliError, Reason};
use pk_cli_secrets::Secret;
use serde_json::{json, Value};

use crate::cli::BIN;
use crate::endpoints::{Endpoints, CLIENT_ID, USER_POOL_ID};
use crate::srp;

const TIMEOUT: Duration = Duration::from_secs(60);

/// What a sign-in's tokens are.
pub struct Tokens {
    pub id_token: Secret,
    pub access_token: Secret,
    /// Answered by a sign-in; a renewal answers none unless the pool
    /// rotates them.
    pub refresh_token: Option<Secret>,
    /// Seconds the ID and access tokens last.
    pub expires_in: u64,
    /// The device the sign-in was tracked as, to confirm; a renewal names
    /// none.
    pub new_device: Option<NewDevice>,
}

/// A device a sign-in was tracked as (`NewDeviceMetadata`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewDevice {
    pub key: String,
    pub group_key: String,
}

/// The name a confirmed device has in the account's list of devices.
const DEVICE_NAME: &str = "salve (command line)";

/// The step a sign-in is at after the password's proof.
pub enum Step {
    Done(Tokens),
    /// A code was texted. `session` is Cognito's handle for the waiting
    /// sign-in, `user_id` the pool's name for the user, `sent_to` the masked
    /// number Cognito reports.
    SmsCode {
        session: Secret,
        user_id: String,
        sent_to: Option<String>,
    },
}

pub struct Cognito {
    url: String,
    http: reqwest::blocking::Client,
}

pub(crate) fn http_client() -> Result<reqwest::blocking::Client, CliError> {
    reqwest::blocking::Client::builder()
        .timeout(TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(format!("{BIN}/{}", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| CliError::Other(format!("building the HTTP client: {e}")))
}

/// The pool's name, as its SRP hashes it: what follows `_` in its id.
pub fn pool_name() -> &'static str {
    USER_POOL_ID.split_once('_').map_or(USER_POOL_ID, |(_, n)| n)
}

impl Cognito {
    pub fn new(ep: &Endpoints) -> Result<Cognito, CliError> {
        transport::require_secure_url(&ep.cognito)?;
        Ok(Cognito {
            url: ep.cognito.clone(),
            http: http_client()?,
        })
    }

    fn call(&self, action: &str, body: &Value) -> Result<Value, CliError> {
        let resp = self
            .http
            .post(&self.url)
            .header("content-type", "application/x-amz-json-1.1")
            .header("x-amz-target", format!("AWSCognitoIdentityProviderService.{action}"))
            .body(body.to_string())
            .send()
            .map_err(|e| net_error(&e))?;
        let status = resp.status().as_u16();
        let text = resp.text().map_err(|e| net_error(&e))?;
        let v: Value = serde_json::from_str(&text).map_err(|_| {
            CliError::Upstream(format!(
                "Cognito answered HTTP {status} with something that is not JSON"
            ))
        })?;
        if (200..300).contains(&status) {
            return Ok(v);
        }
        Err(refused(action, status, &v))
    }

    /// The sign-in up to the password's proof and past it: `InitiateAuth`
    /// with `A`, then `RespondToAuthChallenge` with the signed claim.
    pub fn sign_in(&self, email: &Secret, password: &Secret, now_unix: u64) -> Result<Step, CliError> {
        let client = srp::Client::random(pool_name())?;
        let started = self.call(
            "InitiateAuth",
            &json!({
                "AuthFlow": "USER_SRP_AUTH",
                "ClientId": CLIENT_ID,
                "AuthParameters": { "USERNAME": email.expose().trim(), "SRP_A": client.large_a_hex() },
            }),
        )?;
        if started["ChallengeName"].as_str() != Some("PASSWORD_VERIFIER") {
            return Err(unexpected(&started, "its sign-in"));
        }
        let p = &started["ChallengeParameters"];
        let field = |k: &str| {
            p[k].as_str()
                .map(str::to_string)
                .ok_or_else(|| CliError::Upstream(format!("Cognito's sign-in challenge has no {k}")))
        };
        let user_id = field("USER_ID_FOR_SRP")?;
        let secret_block = field("SECRET_BLOCK")?;
        let key = client.password_key(&user_id, password.expose(), &field("SRP_B")?, &field("SALT")?)?;
        let stamp = srp::timestamp(now_unix);
        let signature = srp::signature(&key, pool_name(), &user_id, &secret_block, &stamp)?;
        let mut body = json!({
            "ChallengeName": "PASSWORD_VERIFIER",
            "ClientId": CLIENT_ID,
            "ChallengeResponses": {
                "USERNAME": user_id,
                "PASSWORD_CLAIM_SECRET_BLOCK": secret_block,
                "TIMESTAMP": stamp,
                "PASSWORD_CLAIM_SIGNATURE": signature,
            },
        });
        if let Some(s) = started["Session"].as_str() {
            body["Session"] = json!(s);
        }
        let answered = self.call("RespondToAuthChallenge", &body)?;
        step(&answered, &user_id)
    }

    /// The texted code, for the sign-in waiting on it.
    pub fn sms_code(&self, session: &Secret, user_id: &str, code: &str) -> Result<Tokens, CliError> {
        let answered = self.call(
            "RespondToAuthChallenge",
            &json!({
                "ChallengeName": "SMS_MFA",
                "ClientId": CLIENT_ID,
                "Session": session.expose(),
                "ChallengeResponses": { "USERNAME": user_id, "SMS_MFA_CODE": code },
            }),
        )?;
        match step(&answered, user_id)? {
            Step::Done(t) => Ok(t),
            Step::SmsCode { .. } => Err(CliError::Auth("Cognito asked for another code".into())),
        }
    }

    /// New ID and access tokens from the refresh token, naming the device
    /// the sign-in was tracked as, when it was.
    pub fn refresh(&self, refresh_token: &Secret, device_key: Option<&str>) -> Result<Tokens, CliError> {
        let mut parameters = json!({ "REFRESH_TOKEN": refresh_token.expose() });
        if let Some(device) = device_key {
            parameters["DEVICE_KEY"] = json!(device);
        }
        let answered = self.call(
            "InitiateAuth",
            &json!({
                "AuthFlow": "REFRESH_TOKEN_AUTH",
                "ClientId": CLIENT_ID,
                "AuthParameters": parameters,
            }),
        )?;
        tokens(&answered["AuthenticationResult"]).ok_or_else(|| unexpected(&answered, "its renewal"))
    }

    /// `ConfirmDevice` for the device a sign-in was tracked as, so that
    /// renewals naming it are taken. The device's verifier is made from a
    /// password salve drops at once ([`srp::device_verifier`]).
    pub fn confirm_device(&self, access_token: &Secret, device: &NewDevice) -> Result<(), CliError> {
        let v = srp::device_verifier(&device.group_key, &device.key)?;
        self.call(
            "ConfirmDevice",
            &json!({
                "AccessToken": access_token.expose(),
                "DeviceKey": device.key,
                "DeviceName": DEVICE_NAME,
                "DeviceSecretVerifierConfig": { "PasswordVerifier": v.verifier, "Salt": v.salt },
            }),
        )
        .map(|_| ())
    }

    /// `ForgetDevice`: the device leaves the account's list, and renewals
    /// naming it stop. Takes a live access token, so it goes before
    /// [`Cognito::revoke`].
    pub fn forget_device(&self, access_token: &Secret, device_key: &str) -> Result<(), CliError> {
        self.call(
            "ForgetDevice",
            &json!({ "AccessToken": access_token.expose(), "DeviceKey": device_key }),
        )
        .map(|_| ())
    }

    /// `RevokeToken`: the refresh token, and the tokens it issued, stop
    /// working. Signs out this sign-in only, not the patient's other
    /// devices.
    pub fn revoke(&self, refresh_token: &Secret) -> Result<(), CliError> {
        self.call(
            "RevokeToken",
            &json!({ "ClientId": CLIENT_ID, "Token": refresh_token.expose() }),
        )
        .map(|_| ())
    }
}

fn step(answered: &Value, user_id: &str) -> Result<Step, CliError> {
    if let Some(t) = tokens(&answered["AuthenticationResult"]) {
        return Ok(Step::Done(t));
    }
    match answered["ChallengeName"].as_str() {
        Some("SMS_MFA") => {
            let session = answered["Session"]
                .as_str()
                .ok_or_else(|| CliError::Upstream("Cognito asked for a code but named no sign-in to finish".into()))?;
            let p = &answered["ChallengeParameters"];
            Ok(Step::SmsCode {
                session: Secret::new(session),
                user_id: p["USER_ID_FOR_SRP"].as_str().unwrap_or(user_id).to_string(),
                sent_to: p["CODE_DELIVERY_DESTINATION"].as_str().map(str::to_string),
            })
        }
        Some("NEW_PASSWORD_REQUIRED") => Err(
            CliError::Auth("Salve asks this account to choose a new password".into())
                .because(Reason::CredentialRefused)
                .with_remedy("set it in Salve's app, update the 1Password item, then sign in again".to_string()),
        ),
        Some(other) => Err(
            CliError::Auth(format!("Cognito asked for a step salve does not take ({other})")).with_remedy(format!(
                "sign in on Salve's own page: `{BIN} auth login --browser --profile <NAME>`"
            )),
        ),
        None => Err(unexpected(answered, "the sign-in")),
    }
}

fn tokens(r: &Value) -> Option<Tokens> {
    let id = r["IdToken"].as_str()?;
    let access = r["AccessToken"].as_str()?;
    Some(Tokens {
        id_token: Secret::new(id),
        access_token: Secret::new(access),
        refresh_token: r["RefreshToken"].as_str().map(Secret::new),
        expires_in: r["ExpiresIn"].as_u64().unwrap_or(3600),
        new_device: match (
            r["NewDeviceMetadata"]["DeviceKey"].as_str(),
            r["NewDeviceMetadata"]["DeviceGroupKey"].as_str(),
        ) {
            (Some(key), Some(group)) => Some(NewDevice {
                key: key.to_string(),
                group_key: group.to_string(),
            }),
            _ => None,
        },
    })
}

fn unexpected(v: &Value, what: &str) -> CliError {
    let named = v["ChallengeName"].as_str().unwrap_or("nothing salve reads");
    CliError::Upstream(format!("Cognito answered {what} with {named}"))
}

/// Cognito's error, by its `__type`, as salve's exit code. Its message is
/// Cognito's own (no account data); the request's values are never quoted.
fn refused(action: &str, status: u16, v: &Value) -> CliError {
    let kind = v["__type"].as_str().unwrap_or_default();
    let kind = kind.rsplit('#').next().unwrap_or(kind);
    let said = one_line(v["message"].as_str().or(v["Message"].as_str()).unwrap_or_default());
    let lower = said.to_ascii_lowercase();
    let refresh = action == "InitiateAuth" && lower.contains("refresh token");
    match kind {
        "NotAuthorizedException" if refresh => CliError::Auth(format!("Salve no longer accepts the sign-in ({said})"))
            .because(Reason::CredentialRefused)
            .with_remedy(format!("{BIN} auth login --overwrite --profile <NAME> signs in again")),
        "NotAuthorizedException" if lower.contains("session") && lower.contains("expired") => CliError::Auth(
            "the sign-in waited too long for its code; Cognito keeps a waiting sign-in about 3 minutes".into(),
        )
        .because(Reason::CredentialRefused)
        .with_remedy(format!(
            "{BIN} auth login --profile <NAME> ... starts again and texts a new code"
        )),
        "NotAuthorizedException" | "UserNotFoundException" => {
            CliError::Auth(format!("Salve refused the sign-in: {said}")).because(Reason::CredentialRefused)
        }
        "CodeMismatchException" | "ExpiredCodeException" => {
            CliError::Auth(format!("the code was refused: {said}")).because(Reason::CredentialRefused)
        }
        "PasswordResetRequiredException" | "UserNotConfirmedException" => CliError::Auth(format!(
            "Salve asks this account to finish a step in its app first: {said}"
        ))
        .because(Reason::CredentialRefused),
        "TooManyRequestsException" | "LimitExceededException" | "TooManyFailedAttemptsException" => CliError::Upstream(
            format!("Cognito is limiting sign-ins: {said}; wait before trying again"),
        ),
        "UnsupportedOperationException" | "UnsupportedTokenTypeException" => {
            CliError::Upstream(format!("Cognito does not offer {action} here: {said}"))
        }
        "" => CliError::Upstream(format!("Cognito answered {action} with HTTP {status}")),
        other => CliError::Upstream(format!("Cognito refused {action} ({other}): {said}")),
    }
}

pub(crate) fn net_error(e: &reqwest::Error) -> CliError {
    // reqwest's message can carry the URL; the host is all that is said.
    let host = e.url().and_then(|u| u.host_str()).unwrap_or("Salve").to_string();
    let what = if e.is_timeout() {
        "timed out"
    } else if e.is_connect() {
        "could not connect"
    } else if e.is_redirect() {
        "was redirected, which salve does not follow"
    } else {
        "failed"
    };
    CliError::Upstream(format!("the request to {host} {what}"))
}

/// One line, at most 200 characters, of a message.
pub(crate) fn one_line(s: &str) -> String {
    let flat = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if flat.chars().count() > 200 {
        format!("{}…", flat.chars().take(200).collect::<String>())
    } else {
        flat
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_pool_name_is_after_the_region() {
        assert_eq!(pool_name(), "PS2EMAFqC");
    }

    #[test]
    fn cognito_errors_read_as_exit_codes() {
        let e = |t: &str, m: &str| refused("RespondToAuthChallenge", 400, &json!({ "__type": t, "message": m }));
        assert_eq!(
            e("NotAuthorizedException", "Incorrect username or password.").exit_code(),
            3
        );
        assert_eq!(e("UserNotFoundException", "User does not exist.").exit_code(), 3);
        assert_eq!(
            e("CodeMismatchException", "Invalid code received for user").exit_code(),
            3
        );
        assert_eq!(e("TooManyRequestsException", "Rate exceeded").exit_code(), 5);
        assert_eq!(e("InternalErrorException", "x").exit_code(), 5);
        let expired = e(
            "NotAuthorizedException",
            "Invalid session for the user, session is expired.",
        );
        assert!(expired.message().contains("3 minutes"), "{expired}");
        let lapsed = refused(
            "InitiateAuth",
            400,
            &json!({ "__type": "NotAuthorizedException", "message": "Refresh Token has expired" }),
        );
        assert!(lapsed.remedy().unwrap().contains("--overwrite"), "{lapsed}");
        let prefixed = e("com.amazonaws.cognito#NotAuthorizedException", "x");
        assert_eq!(prefixed.exit_code(), 3);
    }

    #[test]
    fn a_challenge_reads_as_its_step() {
        let s = step(
            &json!({ "ChallengeName": "SMS_MFA", "Session": "dummy-session", "ChallengeParameters": {
                "CODE_DELIVERY_DESTINATION": "+*******0000", "USER_ID_FOR_SRP": "test-user-0001" } }),
            "x",
        )
        .unwrap();
        match s {
            Step::SmsCode {
                session,
                user_id,
                sent_to,
            } => {
                assert_eq!(session.expose(), "dummy-session");
                assert_eq!(user_id, "test-user-0001");
                assert_eq!(sent_to.as_deref(), Some("+*******0000"));
            }
            Step::Done(_) => panic!("a code is asked for"),
        }
        let done = step(
            &json!({ "AuthenticationResult": { "IdToken": "a", "AccessToken": "b", "RefreshToken": "c", "ExpiresIn": 60 } }),
            "x",
        )
        .unwrap();
        assert!(matches!(done, Step::Done(Tokens { expires_in: 60, .. })));
        assert_eq!(
            step(&json!({ "ChallengeName": "NEW_PASSWORD_REQUIRED" }), "x")
                .err()
                .unwrap()
                .exit_code(),
            3
        );
    }
}
