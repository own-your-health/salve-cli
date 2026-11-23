//! A stub Salve on 127.0.0.1: Cognito's sign-in, the app API, the patient
//! API, the file-link service and the file host, answering from
//! `tests/fixtures/salve`.
//!
//! The sign-in is checked as Cognito checks it: the stub holds the SRP
//! verifier of one user and password, answers `InitiateAuth` with `B`, and
//! accepts `RespondToAuthChallenge` only with the claim signed by the key
//! that password derives. The password never reaches the stub, and a test
//! can assert so from the request bodies. A code is then "texted"
//! ([`CODE`]) unless the scenario signs in without one.
//!
//! Every read needs an ID token the stub issued and has not lapsed or
//! revoked, sent as `authorization` with no scheme; the patient API also
//! needs the clinic's token. Every request is logged, so a test can say
//! what was and was not sent.

#![allow(dead_code)]

use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use base64::Engine;
use num_bigint::BigUint;
use salve::srp::{self, Group};
use serde_json::{json, Value};

pub const EMAIL: &str = "patient@example.com";
pub const PASSWORD: &str = "right-password";
pub const CODE: &str = "123456";
/// Cognito's name for the user (`USER_ID_FOR_SRP`).
pub const USER_ID: &str = "test-user-0001";
pub const CLINIC_TOKEN: &str = "dummy-clinic-token-0001";
pub const CLINIC_ID: &str = "clinic-0001";
pub const PATIENT_ID: &str = "100001";
const SALT: &str = "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd";

/// A PDF small enough to read, whole enough to pass `verify_pdf`.
pub fn pdf(label: &str) -> Vec<u8> {
    format!("%PDF-1.4\n1 0 obj << /Type /Catalog >> endobj\n% {label}\ntrailer << /Root 1 0 R >>\n%%EOF\n").into_bytes()
}

/// The first bytes of a PNG, which is what the checks read.
pub fn png() -> Vec<u8> {
    let mut b = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR".to_vec();
    b.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 1, 8, 2, 0, 0, 0]);
    b
}

pub fn fixture(name: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/salve")
        .join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// What the stub answers, beyond the fixtures.
#[derive(Clone, Debug, Default)]
pub struct Scenario {
    /// The sign-in completes with no texted code.
    pub no_mfa: bool,
    /// The newer messaging has no conversation, so the first one is read.
    pub v0_messaging: bool,
    /// The patient API answers HTTP 502 with a web page.
    pub patient_api_fails: bool,
    /// The files list answers an error of Salve's own.
    pub files_fail: bool,
    /// The consent PDF is served as a web page.
    pub bad_pdf: bool,
    /// The file link service has no file for the treatment plan.
    pub missing_file: bool,
    /// Every ID token lapses after this many reads.
    pub expire_after: Option<usize>,
    /// ID tokens are issued with a minute left, so a run renews first.
    pub short_tokens: bool,
    /// A renewal is refused: the refresh token was revoked.
    pub refresh_revoked: bool,
    /// `RevokeToken` answers that revocation is not enabled.
    pub revoke_unsupported: bool,
    /// The account answers `errorCode: AwaitingSync`.
    pub awaiting_sync: bool,
    /// The conversation's messages are this many synthetic ones, read a
    /// page at a time.
    pub long_conversation: Option<usize>,
    /// A second conversation, whose messages Salve fails to fetch.
    pub broken_conversation: bool,
    /// This many more conversations, each with no messages.
    pub more_conversations: Option<usize>,
    /// The account answers `AwaitingSync` (HTTP 412, as Salve does) to
    /// this many reads of the patient and clinic, then its records.
    pub sync_after: Option<usize>,
    /// The pool tracks no devices: a sign-in names none, and a renewal
    /// needs none. Salve's pool tracks them.
    pub untracked_devices: bool,
    /// `ConfirmDevice` is refused.
    pub confirm_device_fails: bool,
}

#[derive(Default)]
struct State {
    /// SECRET_BLOCK of a started sign-in, with its A, b and B.
    srp: HashMap<String, (BigUint, BigUint, BigUint)>,
    /// Sign-ins waiting on a code.
    waiting: HashSet<String>,
    ids: HashSet<String>,
    refresh: HashSet<String>,
    /// The refresh token each ID token was issued under.
    issued_under: HashMap<String, String>,
    issued: usize,
    reads: usize,
    log: Vec<String>,
    cognito_bodies: Vec<String>,
    sign_ins: usize,
    codes_sent: usize,
    refreshes: usize,
    revokes: usize,
    /// A read that carried `Bearer `, or the clinic's token to the app API,
    /// or any credential to the file host.
    leaks: Vec<String>,
    mutations: usize,
    /// Reads of the patient and clinic so far.
    account_reads: usize,
    /// Each refresh token's device, and whether it was confirmed.
    devices: HashMap<String, (String, bool)>,
    /// The refresh token each access token was issued under.
    access: HashMap<String, String>,
    confirms: usize,
    forgets: usize,
}

pub struct Stub {
    pub port: u16,
    state: Arc<Mutex<State>>,
}

impl Stub {
    pub fn start(scenario: Scenario) -> Stub {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let state = Arc::new(Mutex::new(State::default()));
        let shared = state.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let state = shared.clone();
                let scenario = scenario.clone();
                std::thread::spawn(move || {
                    let _ = serve(stream, port, &state, &scenario);
                });
            }
        });
        Stub { port, state }
    }

    pub fn origin(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    /// Every request, in order (`cognito InitiateAuth:USER_SRP_AUTH`, `app
    /// GetDocuments`, `presign documents/2001.pdf`, `s3 doc-2001.pdf`).
    pub fn log(&self) -> Vec<String> {
        self.state.lock().unwrap().log.clone()
    }

    pub fn cognito_bodies(&self) -> Vec<String> {
        self.state.lock().unwrap().cognito_bodies.clone()
    }

    pub fn sign_ins(&self) -> usize {
        self.state.lock().unwrap().sign_ins
    }

    pub fn codes_sent(&self) -> usize {
        self.state.lock().unwrap().codes_sent
    }

    pub fn refreshes(&self) -> usize {
        self.state.lock().unwrap().refreshes
    }

    pub fn revokes(&self) -> usize {
        self.state.lock().unwrap().revokes
    }

    /// Devices confirmed with `ConfirmDevice`.
    pub fn confirms(&self) -> usize {
        self.state.lock().unwrap().confirms
    }

    /// Devices forgotten with `ForgetDevice`.
    pub fn forgets(&self) -> usize {
        self.state.lock().unwrap().forgets
    }

    pub fn leaks(&self) -> Vec<String> {
        self.state.lock().unwrap().leaks.clone()
    }

    pub fn mutations(&self) -> usize {
        self.state.lock().unwrap().mutations
    }

    /// Whether any refresh token the stub issued still works.
    pub fn holds_sign_in(&self) -> bool {
        !self.state.lock().unwrap().refresh.is_empty()
    }

    /// Every waiting sign-in lapses, as Cognito's do after about 3 minutes.
    pub fn expire_waiting(&self) {
        self.state.lock().unwrap().waiting.clear();
    }

    /// Every ID token lapses.
    pub fn expire_ids(&self) {
        self.state.lock().unwrap().ids.clear();
    }

    /// Every sign-in is revoked, as signing out on another device can.
    pub fn revoke_all(&self) {
        let mut s = self.state.lock().unwrap();
        s.ids.clear();
        s.refresh.clear();
    }
}

struct Request {
    method: String,
    path: String,
    query: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

fn read_request(stream: &TcpStream) -> std::io::Result<Request> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let target = parts.next().unwrap_or_default().to_string();
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (target, String::new()),
    };
    let mut headers = HashMap::new();
    loop {
        let mut h = String::new();
        reader.read_line(&mut h)?;
        let h = h.trim_end();
        if h.is_empty() {
            break;
        }
        if let Some((k, v)) = h.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    let len: usize = headers.get("content-length").and_then(|v| v.parse().ok()).unwrap_or(0);
    let mut body = vec![0; len];
    reader.read_exact(&mut body)?;
    Ok(Request {
        method,
        path,
        query,
        headers,
        body,
    })
}

fn respond(mut stream: &TcpStream, status: u16, ctype: &str, body: &[u8]) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        502 => "Bad Gateway",
        _ => "Internal Server Error",
    };
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    stream.write_all(body)?;
    stream.flush()
}

const JSON: &str = "application/json; charset=utf-8";
const AMZ: &str = "application/x-amz-json-1.1";

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn b64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// An ID token: a JWT with Cognito's claims for the dummy patient. The stub
/// checks it by holding it, not by its signature.
fn id_token(n: usize, exp: u64) -> String {
    let header = b64url(br#"{"alg":"RS256","kid":"dummy-key"}"#);
    let claims = json!({
        "sub": USER_ID,
        "token_use": "id",
        "exp": exp,
        "given_name": "Jane",
        "family_name": "Example",
        "birthdate": "1990-01-01",
        "email": EMAIL,
        "phone_number": "+15555550100",
        "custom:clinictoken": CLINIC_TOKEN,
        "custom:consentid": "dummy-consent",
        "n": n,
    });
    format!("{header}.{}.dummy-signature", b64url(claims.to_string().as_bytes()))
}

/// An access token: a JWT naming the device the sign-in was tracked as,
/// as Cognito's do (`device_key`) when the pool tracks devices.
fn access_token(n: usize, exp: u64, device: Option<&str>) -> String {
    let header = b64url(br#"{"alg":"RS256","kid":"dummy-key"}"#);
    let mut claims = json!({ "sub": USER_ID, "token_use": "access", "exp": exp, "n": n });
    if let Some(d) = device {
        claims["device_key"] = json!(d);
    }
    format!("{header}.{}.dummy-signature", b64url(claims.to_string().as_bytes()))
}

fn verifier(group: &Group) -> BigUint {
    let pool = salve::cognito::pool_name();
    let user_password = srp::hash_hex(format!("{pool}{USER_ID}:{PASSWORD}").as_bytes());
    let salt = srp::from_hex(SALT).unwrap();
    let x = srp::from_hex(&srp::hex_hash(&format!("{}{user_password}", srp::pad_hex(&salt)))).unwrap();
    group.g.modpow(&x, &group.n)
}

fn cognito(req: &Request, state: &Mutex<State>, scenario: &Scenario) -> (u16, String) {
    let action = req
        .headers
        .get("x-amz-target")
        .and_then(|t| t.strip_prefix("AWSCognitoIdentityProviderService."))
        .unwrap_or_default()
        .to_string();
    let body: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
    let flow = body["AuthFlow"]
        .as_str()
        .or(body["ChallengeName"].as_str())
        .unwrap_or_default()
        .to_string();
    {
        let mut s = state.lock().unwrap();
        s.log.push(format!("cognito {action}:{flow}"));
        s.cognito_bodies.push(String::from_utf8_lossy(&req.body).into_owned());
    }
    let err = |name: &str| (400, fixture(name));
    let tokens = |with_refresh: bool, under: Option<String>| -> (u16, String) {
        let mut s = state.lock().unwrap();
        s.issued += 1;
        let n = s.issued;
        let exp = now() + if scenario.short_tokens { 60 } else { 3600 };
        let id = id_token(n, exp);
        let refresh = under.unwrap_or_else(|| format!("dummy-refresh-{n}"));
        s.ids.insert(id.clone());
        s.issued_under.insert(id.clone(), refresh.clone());
        s.reads = 0;
        let device = if scenario.untracked_devices {
            None
        } else if with_refresh {
            let d = format!("eu-west-2_dummy-device-{n}");
            s.devices.insert(refresh.clone(), (d.clone(), false));
            Some(d)
        } else {
            s.devices.get(&refresh).map(|(d, _)| d.clone())
        };
        let access = access_token(n, exp, device.as_deref());
        s.access.insert(access.clone(), refresh.clone());
        let text = if with_refresh {
            s.refresh.insert(refresh.clone());
            fixture("cognito-tokens.json").replace("{REFRESH}", &refresh)
        } else {
            fixture("cognito-refreshed.json")
        };
        let mut answer: Value = serde_json::from_str(&text.replace("{ID}", &id).replace("{ACCESS}", &access)).unwrap();
        if let (true, Some(d)) = (with_refresh, device) {
            answer["AuthenticationResult"]["NewDeviceMetadata"] =
                json!({ "DeviceGroupKey": format!("-dummyGroup{n}"), "DeviceKey": d });
        }
        (200, answer.to_string())
    };
    // ConfirmDevice and ForgetDevice name no client: the access token says
    // whose device it is.
    let by_access_token = matches!(action.as_str(), "ConfirmDevice" | "ForgetDevice");
    if !by_access_token && body["ClientId"].as_str() != Some(salve::endpoints::CLIENT_ID) {
        return (
            400,
            json!({ "__type": "ResourceNotFoundException", "message": "User pool client does not exist." }).to_string(),
        );
    }
    let group = Group::new();
    match (action.as_str(), flow.as_str()) {
        ("InitiateAuth", "USER_SRP_AUTH") => {
            let p = &body["AuthParameters"];
            if p["USERNAME"].as_str() != Some(EMAIL) {
                return err("cognito-user-not-found.json");
            }
            let Some(a) = p["SRP_A"].as_str().and_then(srp::from_hex) else {
                return (
                    400,
                    json!({ "__type": "InvalidParameterException", "message": "SRP_A is missing." }).to_string(),
                );
            };
            if &a % &group.n == BigUint::ZERO {
                return (
                    400,
                    json!({ "__type": "InvalidParameterException", "message": "SRP_A is invalid." }).to_string(),
                );
            }
            let mut s = state.lock().unwrap();
            s.issued += 1;
            let b = BigUint::from_bytes_be(format!("stub-secret-b-{}", s.issued).as_bytes());
            let large_b = (&group.k * verifier(&group) + group.g.modpow(&b, &group.n)) % &group.n;
            let block = base64::engine::general_purpose::STANDARD.encode(format!("dummy-secret-block-{}", s.issued));
            s.srp.insert(block.clone(), (a, b, large_b.clone()));
            let text = fixture("cognito-password-verifier.json")
                .replace("{SALT}", SALT)
                .replace("{SRP_B}", &large_b.to_str_radix(16))
                .replace("{SECRET_BLOCK}", &block)
                .replace("{USER_ID}", USER_ID);
            (200, text)
        }
        ("RespondToAuthChallenge", "PASSWORD_VERIFIER") => {
            let r = &body["ChallengeResponses"];
            let block = r["PASSWORD_CLAIM_SECRET_BLOCK"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            let started = state.lock().unwrap().srp.remove(&block);
            let Some((a, b, large_b)) = started else {
                return err("cognito-incorrect-password.json");
            };
            let u = srp::from_hex(&srp::hex_hash(&format!(
                "{}{}",
                srp::pad_hex(&a),
                srp::pad_hex(&large_b)
            )))
            .unwrap();
            let v = verifier(&group);
            let base = (&a * v.modpow(&u, &group.n)) % &group.n;
            let shared = base.modpow(&b, &group.n);
            let key = srp::hkdf(
                &srp::decode_hex(&srp::pad_hex(&u)).unwrap(),
                &srp::decode_hex(&srp::pad_hex(&shared)).unwrap(),
            );
            let stamp = r["TIMESTAMP"].as_str().unwrap_or_default();
            let expected = srp::signature(&key, salve::cognito::pool_name(), USER_ID, &block, stamp).unwrap();
            let ok = r["USERNAME"].as_str() == Some(USER_ID)
                && r["PASSWORD_CLAIM_SIGNATURE"].as_str() == Some(expected.as_str())
                && stamp.contains(" UTC ");
            if !ok {
                return err("cognito-incorrect-password.json");
            }
            if scenario.no_mfa {
                state.lock().unwrap().sign_ins += 1;
                return tokens(true, None);
            }
            let mut s = state.lock().unwrap();
            s.issued += 1;
            let session = format!("dummy-mfa-session-{}", s.issued);
            s.waiting.insert(session.clone());
            s.codes_sent += 1;
            (
                200,
                fixture("cognito-sms-mfa.json")
                    .replace("{SESSION}", &session)
                    .replace("{USER_ID}", USER_ID),
            )
        }
        ("RespondToAuthChallenge", "SMS_MFA") => {
            let session = body["Session"].as_str().unwrap_or_default();
            if !state.lock().unwrap().waiting.contains(session) {
                return err("cognito-session-expired.json");
            }
            if body["ChallengeResponses"]["SMS_MFA_CODE"].as_str() != Some(CODE)
                || body["ChallengeResponses"]["USERNAME"].as_str() != Some(USER_ID)
            {
                return err("cognito-code-mismatch.json");
            }
            {
                let mut s = state.lock().unwrap();
                s.waiting.remove(session);
                s.sign_ins += 1;
            }
            tokens(true, None)
        }
        ("InitiateAuth", "REFRESH_TOKEN_AUTH") => {
            let token = body["AuthParameters"]["REFRESH_TOKEN"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            let held = state.lock().unwrap().refresh.contains(&token);
            if scenario.refresh_revoked || !held {
                return err("cognito-refresh-revoked.json");
            }
            // A tracked pool takes a renewal only for the confirmed device
            // it was issued to, as Salve's does.
            let named = body["AuthParameters"]["DEVICE_KEY"].as_str();
            let device_ok = state
                .lock()
                .unwrap()
                .devices
                .get(&token)
                .is_none_or(|(d, confirmed)| *confirmed && named == Some(d.as_str()));
            if !device_ok {
                return err("cognito-refresh-invalid.json");
            }
            state.lock().unwrap().refreshes += 1;
            tokens(false, Some(token))
        }
        ("ConfirmDevice", _) => {
            if scenario.confirm_device_fails {
                return (
                    400,
                    json!({ "__type": "InvalidParameterException", "message": "Invalid device secret verifier." })
                        .to_string(),
                );
            }
            let base64 = |k: &str| {
                body["DeviceSecretVerifierConfig"][k]
                    .as_str()
                    .and_then(|v| base64::engine::general_purpose::STANDARD.decode(v).ok())
                    .is_some_and(|b| !b.is_empty())
            };
            let mut s = state.lock().unwrap();
            let refresh = s.access.get(body["AccessToken"].as_str().unwrap_or_default()).cloned();
            let key = body["DeviceKey"].as_str().unwrap_or_default().to_string();
            let well_formed = base64("PasswordVerifier") && base64("Salt") && body["DeviceName"].is_string();
            match refresh.and_then(|r| s.devices.get_mut(&r)) {
                Some((d, confirmed)) if *d == key && well_formed => {
                    *confirmed = true;
                    s.confirms += 1;
                    (200, json!({ "UserConfirmationNecessary": false }).to_string())
                }
                _ => (
                    400,
                    json!({ "__type": "ResourceNotFoundException", "message": "Device does not exist." }).to_string(),
                ),
            }
        }
        ("ForgetDevice", _) => {
            let mut s = state.lock().unwrap();
            let refresh = s.access.get(body["AccessToken"].as_str().unwrap_or_default()).cloned();
            let key = body["DeviceKey"].as_str().unwrap_or_default().to_string();
            match refresh.and_then(|r| s.devices.get_mut(&r)) {
                // A forgotten device renews no more, as an unconfirmed one.
                Some((d, confirmed)) if *d == key => {
                    *confirmed = false;
                    s.forgets += 1;
                    (200, "{}".to_string())
                }
                _ => (
                    400,
                    json!({ "__type": "ResourceNotFoundException", "message": "Device does not exist." }).to_string(),
                ),
            }
        }
        ("RevokeToken", _) => {
            if scenario.revoke_unsupported {
                return (400, fixture("cognito-revoke-unsupported.json"));
            }
            let token = body["Token"].as_str().unwrap_or_default().to_string();
            let mut s = state.lock().unwrap();
            s.revokes += 1;
            s.refresh.remove(&token);
            let ids: Vec<String> = s
                .issued_under
                .iter()
                .filter(|(_, r)| **r == token)
                .map(|(i, _)| i.clone())
                .collect();
            for i in ids {
                s.ids.remove(&i);
            }
            (200, "{}".into())
        }
        _ => (
            400,
            json!({ "__type": "InvalidParameterException", "message": "Unsupported request." }).to_string(),
        ),
    }
}

/// Whether the request carries a live ID token as the stub expects it, and
/// counts the read toward `expire_after`.
fn authorized(req: &Request, state: &Mutex<State>, scenario: &Scenario, what: &str) -> bool {
    let mut s = state.lock().unwrap();
    let auth = req.headers.get("authorization").cloned().unwrap_or_default();
    if auth.starts_with("Bearer ") {
        s.leaks.push(format!("{what}: a Bearer scheme"));
    }
    if !s.ids.contains(&auth) {
        return false;
    }
    s.reads += 1;
    if scenario.expire_after.is_some_and(|n| s.reads > n) {
        s.ids.clear();
        return false;
    }
    true
}

fn file_for(uri: &str) -> Option<&'static str> {
    Some(match uri {
        "documents/2001.pdf" => "doc-2001.pdf",
        "documents/2002.pdf" => "doc-2002.pdf",
        "files/3001.pdf" => "file-3001.pdf",
        "files/3002.png" => "file-3002.png",
        "attachments/7102a.pdf" => "att-7102a.pdf",
        "attachments/9101.pdf" => "att-9101.pdf",
        _ => return None,
    })
}

fn graphql(req: &Request, host: &str, state: &Mutex<State>, scenario: &Scenario) -> (u16, String) {
    let body: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
    let op = body["operationName"].as_str().unwrap_or("-").to_string();
    let document = body["query"].as_str().unwrap_or_default().to_string();
    let vars = &body["variables"];
    {
        let mut s = state.lock().unwrap();
        s.log.push(format!("{host} {op}"));
        if document.contains("mutation") || document.contains("subscription") {
            s.mutations += 1;
        }
        if host == "app" && req.headers.contains_key("x-salve-clinic-token") {
            s.leaks.push(format!("app {op}: the clinic token"));
        }
    }
    if !authorized(req, state, scenario, &format!("{host} {op}")) {
        return (401, fixture("unauthorized.json"));
    }
    if host == "patient" {
        if scenario.patient_api_fails {
            return (502, "<html><body>Bad gateway</body></html>".into());
        }
        if req.headers.get("x-salve-clinic-token").map(String::as_str) != Some(CLINIC_TOKEN) {
            return (401, fixture("unauthorized.json"));
        }
    }
    let ok = |name: &str| (200, fixture(name));
    match (host, op.as_str()) {
        ("app", "GetPatientAndClinic") if scenario.awaiting_sync => (200, fixture("account-awaiting-sync.json")),
        ("app", "GetPatientAndClinic")
            if scenario.sync_after.is_some_and(|n| {
                let mut s = state.lock().unwrap();
                s.account_reads += 1;
                s.account_reads <= n
            }) =>
        {
            (412, fixture("account-awaiting-sync.json"))
        }
        ("app", "GetPatientAndClinic") => ok("patient-and-clinic.json"),
        ("app", "GetPatientId") => ok("patient-id.json"),
        ("app", "GetPatientClinics") => ok("patient-clinics.json"),
        ("app", "GetDocuments") => ok("documents.json"),
        ("app", "GetFiles") if scenario.files_fail => ok("graphql-error.json"),
        ("app", "GetFiles") => ok("files.json"),
        ("app", "GetForms") => ok("forms.json"),
        // FormInput takes integers; a string is refused, as Salve does.
        ("app", "GetForm") if vars["input"]["patientformid"].is_string() => (400, fixture("form-input-not-int.json")),
        ("app", "GetForm") => match vars["input"]["patientformid"].as_i64() {
            Some(4001) => ok("form-4001.json"),
            Some(4003) => ok("form-4003.json"),
            _ => ok("form-not-found.json"),
        },
        ("app", "GetVideoCalls") => {
            let input = &vars["input"];
            if input["page"].as_i64() != Some(1) {
                return ok("video-calls-empty.json");
            }
            match input["dateOperator"].as_str() {
                Some("LTE") => ok("video-calls-past.json"),
                Some("GTE") => ok("video-calls-future.json"),
                _ => (400, fixture("graphql-unknown.json")),
            }
        }
        ("app", "FetchConversations") => ok("conversations-v0.json"),
        ("app", "GetConversation") if vars["conversationId"].as_i64() == Some(8001) => ok("conversation-v0-8001.json"),
        ("patient", "GetConversations") if scenario.v0_messaging => ok("conversations-v3-empty.json"),
        ("patient", "GetConversations") => {
            let mut list: Value = serde_json::from_str(&fixture("conversations-v3.json")).unwrap();
            let mut records = list["data"]["conversations"]["records"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            if scenario.broken_conversation {
                let mut broken = records[0].clone();
                broken["id"] = json!(7009);
                broken["subject"] = json!("Broken conversation");
                records.push(broken);
            }
            for i in 0..scenario.more_conversations.unwrap_or(0) {
                let mut more = records[0].clone();
                more["id"] = json!(7500 + i);
                more["subject"] = json!(format!("Synthetic conversation {i}"));
                records.push(more);
            }
            match page(records, vars, "conversations") {
                Some(answer) => {
                    list["data"]["conversations"] = answer;
                    (200, list.to_string())
                }
                None => (200, fixture("messages-v3-failed.json")),
            }
        }
        ("patient", "GetConversationMessages") if vars["conversationId"].as_i64() == Some(7001) => {
            let records: Vec<Value> = match scenario.long_conversation {
                Some(n) => (0..n)
                    .map(|i| {
                        json!({ "id": format!("m{i}"), "content": format!("Synthetic message {i}"),
                            "sentDate": "2025-03-01T09:00:00.000Z", "deletedDate": null, "systemMessageType": null,
                            "uuid": format!("uuid-m{i}"), "actionedByPatientId": null, "actionedByClinicUserId": "200001",
                            "attachments": [], "patient": null,
                            "clinicUser": { "id": "200001", "firstName": "Nurse", "lastName": "Example" } })
                    })
                    .collect(),
                None => ["messages-v3-7001-page1.json", "messages-v3-7001-page2.json"]
                    .iter()
                    .flat_map(|f| {
                        let v: Value = serde_json::from_str(&fixture(f)).unwrap();
                        v["data"]["conversationMessages"]["records"].as_array().cloned().unwrap_or_default()
                    })
                    .collect(),
            };
            match page(records, vars, "messages") {
                Some(answer) => (200, json!({ "data": { "conversationMessages": answer } }).to_string()),
                None => (200, fixture("messages-v3-failed.json")),
            }
        }
        ("patient", "GetConversationMessages")
            if vars["conversationId"]
                .as_i64()
                .is_some_and(|id| (7500..7500 + scenario.more_conversations.unwrap_or(0) as i64).contains(&id)) =>
        {
            match page(Vec::new(), vars, "messages") {
                Some(answer) => (200, json!({ "data": { "conversationMessages": answer } }).to_string()),
                None => (200, fixture("messages-v3-failed.json")),
            }
        }
        ("patient", "GetConversationMessages") => (200, fixture("messages-v3-failed.json")),
        // `salve api` sends no operation name.
        ("app", "-") if document.contains("patientid") => ok("patient-id.json"),
        _ => (400, fixture("graphql-unknown.json")),
    }
}

/// One page of a list, as Salve pages it: `limit` records from the
/// `cursor`, with a cursor for the next page; a cursor at the end answers an
/// empty page and no cursor. Without a limit the whole list is one page, and
/// the cursor it answers fails when sent back, as Salve's does: `None`.
fn page(records: Vec<Value>, vars: &Value, list: &str) -> Option<Value> {
    let from = match vars["cursor"].as_str() {
        None => 0,
        Some(c) => c.strip_prefix(&format!("{list}-"))?.parse::<usize>().ok()?,
    };
    if from > records.len() {
        return None;
    }
    if from == records.len() && from > 0 {
        return Some(json!({ "cursor": null, "records": [] }));
    }
    let Some(limit) = vars["limit"].as_u64() else {
        return Some(json!({ "cursor": format!("{list}-unlimited"), "records": records }));
    };
    let to = (from + limit as usize).min(records.len());
    Some(json!({ "cursor": format!("{list}-{to}"), "records": records[from..to].to_vec() }))
}

fn serve(stream: TcpStream, port: u16, state: &Mutex<State>, scenario: &Scenario) -> std::io::Result<()> {
    let req = read_request(&stream)?;
    match (req.method.as_str(), req.path.as_str()) {
        ("POST", "/cognito") => {
            let (status, body) = cognito(&req, state, scenario);
            respond(&stream, status, AMZ, body.as_bytes())
        }
        ("POST", "/app/graphql") => {
            let (status, body) = graphql(&req, "app", state, scenario);
            respond(&stream, status, JSON, body.as_bytes())
        }
        ("POST", "/patient/graphql") => {
            let (status, body) = graphql(&req, "patient", state, scenario);
            respond(&stream, status, JSON, body.as_bytes())
        }
        ("POST", "/presign/patient/read") => {
            let body: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
            let uri = body["url"].as_str().unwrap_or_default().to_string();
            {
                let mut s = state.lock().unwrap();
                let conv = req
                    .query
                    .strip_prefix("conversationId=")
                    .map(|c| format!(" conversation {c}"))
                    .unwrap_or_default();
                s.log.push(format!("presign {uri}{conv}"));
            }
            if !authorized(&req, state, scenario, "presign") {
                return respond(&stream, 401, JSON, fixture("unauthorized.json").as_bytes());
            }
            let missing = scenario.missing_file && uri == "documents/2002.pdf";
            match file_for(&uri).filter(|_| !missing) {
                Some(name) => {
                    let link = format!("http://127.0.0.1:{port}/s3/{name}?X-Amz-Signature=dummy-signature");
                    respond(
                        &stream,
                        200,
                        JSON,
                        fixture("presign.json").replace("{LINK}", &link).as_bytes(),
                    )
                }
                None => respond(&stream, 404, JSON, br#"{"message":"Not Found"}"#),
            }
        }
        ("GET", path) if path.starts_with("/s3/") => {
            let name = &path[4..];
            {
                let mut s = state.lock().unwrap();
                s.log.push(format!("s3 {name}"));
                if req.headers.contains_key("authorization") || req.headers.contains_key("x-salve-clinic-token") {
                    s.leaks.push(format!("s3 {name}: a credential"));
                }
            }
            if !req.query.contains("X-Amz-Signature=") {
                return respond(
                    &stream,
                    403,
                    "application/xml",
                    b"<Error><Code>AccessDenied</Code></Error>",
                );
            }
            match name {
                "doc-2001.pdf" if scenario.bad_pdf => {
                    respond(&stream, 200, "application/pdf", b"<html>an error page</html>")
                }
                "doc-2001.pdf" => respond(&stream, 200, "application/pdf", &pdf("consent")),
                "doc-2002.pdf" => respond(&stream, 200, "application/pdf", &pdf("treatment plan")),
                "file-3001.pdf" => respond(&stream, 200, "application/pdf", &pdf("lab results")),
                "file-3002.png" => respond(&stream, 200, "image/png", &png()),
                "att-7102a.pdf" => respond(&stream, 200, "application/pdf", &pdf("instructions")),
                "att-9101.pdf" => respond(&stream, 200, "application/pdf", &pdf("invoice")),
                _ => respond(
                    &stream,
                    404,
                    "application/xml",
                    b"<Error><Code>NoSuchKey</Code></Error>",
                ),
            }
        }
        _ => respond(&stream, 404, "text/html", b"<html>not here</html>"),
    }
}
