//! salve end to end against a stub Salve (`common::Stub`), in process, with
//! the sign-ins in a vault whose key is held in memory
//! (`Vault::new(MemoryKeys, dir)`): no keychain item is read and no real
//! host is reached.
//!
//! The sign-in reads its two lines from an environment variable
//! (`--from-env`), set while the tests hold one lock, so they run one at a
//! time.

mod common;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use clap::{CommandFactory, FromArgMatches};
use common::{Scenario, Stub, CLINIC_ID, CODE, EMAIL, PASSWORD, PATIENT_ID};
use pk_cli_auth::otp::ParkingSlot;
use pk_cli_auth::vault::{MemoryKeys, Vault};
use pk_cli_config::profile::ProfileName;
use pk_cli_config::ConfigStore;
use salve::app::{self, Config, Env, Given};
use salve::auth::LoginSettings;
use salve::cli::Cli;
use salve::session::{Key, SessionStore};
use serde_json::Value;

const SIGN_IN_VAR: &str = "SALVE_E2E_SIGN_IN";
const WRONG_VAR: &str = "SALVE_E2E_WRONG_SIGN_IN";
const STRANGER_VAR: &str = "SALVE_E2E_STRANGER_SIGN_IN";

static LOCK: Mutex<()> = Mutex::new(());
static N: AtomicUsize = AtomicUsize::new(0);

struct H {
    dir: PathBuf,
    keys: Arc<MemoryKeys>,
    stub: Stub,
    _lock: MutexGuard<'static, ()>,
}

impl H {
    fn new(scenario: Scenario) -> H {
        let lock = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // SAFETY: the tests in this file hold LOCK, so no other thread of
        // theirs reads the environment meanwhile.
        unsafe {
            std::env::set_var(SIGN_IN_VAR, format!("{EMAIL}\n{PASSWORD}"));
            std::env::set_var(WRONG_VAR, format!("{EMAIL}\nwrong-password"));
            std::env::set_var(STRANGER_VAR, ["someone@example.com", PASSWORD].join("\n"));
            std::env::remove_var("SALVE_PROFILE");
            std::env::remove_var(salve::endpoints::STUB_ENV);
        }
        let dir = std::env::temp_dir().join(format!(
            "salve-e2e-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        H {
            dir,
            keys: Arc::new(MemoryKeys::new()),
            stub: Stub::start(scenario),
            _lock: lock,
        }
    }

    fn config(&self) -> PathBuf {
        self.dir.join("config.json")
    }

    /// One command's exit code.
    fn run(&self, args: &[&str]) -> i32 {
        let config = self.config().display().to_string();
        let mut full = vec!["salve", "-q", "--config", &config];
        full.extend_from_slice(args);
        let m = Cli::command()
            .try_get_matches_from(&full)
            .unwrap_or_else(|e| panic!("{full:?}: {e}"));
        let cli = Cli::from_arg_matches(&m).unwrap();
        let vault_dir = self.dir.join("vault");
        let keys = self.keys.clone();
        let open = move || Ok(SessionStore::with_vault(Vault::new(keys.clone(), &vault_dir)));
        let env = Env {
            sessions: &open,
            hermetic: true,
            prompts: false,
            stub: Some(self.stub.origin()),
        };
        match app::run(&cli, Given::of(&m), &env) {
            Ok(code) => code,
            Err(e) => e.exit_code(),
        }
    }

    fn store(&self) -> SessionStore {
        SessionStore::with_vault(Vault::new(self.keys.clone(), self.dir.join("vault")))
    }

    fn key(&self, profile: &str) -> Key {
        Key {
            profile: ProfileName::parse(profile).unwrap(),
            org: CLINIC_ID.into(),
            patient: profile.into(),
        }
    }

    fn settings(&self, profile: &str) -> LoginSettings {
        let cfg: Config = ConfigStore::new("salve")
            .with_override(Some(self.config()))
            .load()
            .unwrap();
        cfg.profiles.settings(&ProfileName::parse(profile).unwrap()).unwrap()
    }

    /// Whether a sign-in is waiting on its code for the profile.
    fn waiting(&self, profile: &str) -> bool {
        let store = self.store();
        let p = ProfileName::parse(profile).unwrap();
        let slot = store.slot(&p);
        slot.load().unwrap().is_some()
    }

    fn signed_in(&self, profile: &str) {
        assert_eq!(self.run(&["profiles", "add", profile]), 0);
        assert_eq!(
            self.run(&["auth", "login", "--profile", profile, "--from-env", SIGN_IN_VAR]),
            3,
            "the code is texted and the sign-in waits"
        );
        assert_eq!(self.run(&["auth", "login", "--profile", profile, "--code", CODE]), 0);
    }

    fn export(&self, profile: &str, name: &str, extra: &[&str]) -> (i32, PathBuf) {
        let out = self.dir.join(name);
        let out_s = out.display().to_string();
        let mut args = vec!["records", "export", "--profile", profile, "-o", &out_s];
        args.extend_from_slice(extra);
        (self.run(&args), out)
    }

    fn count(&self, entry: &str) -> usize {
        self.stub.log().iter().filter(|l| l.as_str() == entry).count()
    }
}

impl Drop for H {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// The stream's lines: header, resources, trailer.
fn lines(path: &Path) -> Vec<Value> {
    std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

fn ids(stream: &[Value], kind: &str) -> Vec<String> {
    stream
        .iter()
        .filter(|r| r["resourceType"] == kind)
        .map(|r| r["id"].as_str().unwrap().to_string())
        .collect()
}

fn find<'a>(stream: &'a [Value], kind: &str, id: &str) -> &'a Value {
    stream
        .iter()
        .find(|r| r["resourceType"] == kind && r["id"] == id)
        .unwrap_or_else(|| panic!("no {kind}/{id}"))
}

fn skips(trailer: &Value) -> Vec<(String, String)> {
    trailer["skipped"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| {
            (
                s["code"].as_str().unwrap().to_string(),
                s["search"]
                    .as_str()
                    .or(s["id"].as_str())
                    .unwrap_or_default()
                    .to_string(),
            )
        })
        .collect()
}

fn decoded(binary: &Value) -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(binary["data"].as_str().unwrap())
        .unwrap()
}

#[test]
fn sign_in_with_a_texted_code_export_documents_and_sign_out() {
    let h = H::new(Scenario::default());
    assert_eq!(h.run(&["profiles", "add", "adult1"]), 0);

    // The password is proved, then Salve texts a code: without a terminal
    // the sign-in is parked and the command is exit 3.
    assert_eq!(
        h.run(&["auth", "login", "--profile", "adult1", "--from-env", SIGN_IN_VAR]),
        3
    );
    assert_eq!(h.stub.codes_sent(), 1);
    assert!(h.waiting("adult1"));
    assert_eq!(h.settings("adult1").clinic_id, None);
    // A wrong code is refused and the sign-in still waits.
    assert_eq!(h.run(&["auth", "login", "--profile", "adult1", "--code", "000000"]), 3);
    assert!(h.waiting("adult1"));
    // The right one finishes it.
    assert_eq!(h.run(&["auth", "login", "--profile", "adult1", "--code", CODE]), 0);
    assert!(!h.waiting("adult1"));
    assert_eq!(h.stub.sign_ins(), 1);
    let settings = h.settings("adult1");
    assert_eq!(settings.clinic_id.as_deref(), Some(CLINIC_ID));
    assert_eq!(settings.clinic.as_deref(), Some("Example Fertility"));
    assert_eq!(settings.label.as_deref(), Some("adult1"));
    let s = h.store().get(&h.key("adult1")).unwrap().expect("a stored sign-in");
    assert_eq!(s.patient_id, PATIENT_ID);
    assert_eq!(s.birth_date.as_deref(), Some("1990-01-01"));
    assert_eq!(s.clinic_token().as_deref(), Some(common::CLINIC_TOKEN));

    // The password never left salve: SRP proves it.
    for body in h.stub.cognito_bodies() {
        assert!(!body.contains(PASSWORD), "the password was sent: {body}");
    }
    // A second sign-in without --overwrite is refused before anything is sent.
    let before = h.stub.log().len();
    assert_eq!(
        h.run(&["auth", "login", "--profile", "adult1", "--from-env", SIGN_IN_VAR]),
        2
    );
    assert_eq!(h.stub.log().len(), before);

    let (code, out) = h.export("adult1", "export", &[]);
    assert_eq!(code, 0);
    let stream = lines(&out.join("records.ndjson"));
    let header = &stream[0];
    assert_eq!(header["schema"], "records-stream/v1");
    assert_eq!(header["method"], "portal");
    assert_eq!(header["organization"]["id"], CLINIC_ID);
    assert_eq!(header["organization"]["vendor"], "salve");
    assert_eq!(header["patient"]["id"], PATIENT_ID);
    assert_eq!(header["patient"]["label"], "adult1");
    let trailer = stream.last().unwrap();
    assert_eq!(trailer["complete"], true);
    assert_eq!(trailer["skipped"].as_array().unwrap().len(), 0, "{trailer}");
    let counts = &trailer["counts"];
    assert_eq!(counts["Patient"], 1);
    assert_eq!(counts["DocumentReference"], 7);
    assert_eq!(counts["Binary"], 7);
    assert_eq!(counts["Communication"], 3);
    assert_eq!(counts["Encounter"], 3);

    let patient = find(&stream, "Patient", PATIENT_ID);
    assert_eq!(patient["name"][0]["text"], "Jane Example");
    assert_eq!(patient["birthDate"], "1990-01-01");
    for r in &stream[1..stream.len() - 1] {
        assert_eq!(r["meta"]["source"], "salve:app", "{r}");
        assert_eq!(r["meta"]["tag"][0]["code"], "mapped-from-salve", "{r}");
    }

    // Documents and files, each with its file.
    let consent = find(&stream, "DocumentReference", "doc-2001");
    assert_eq!(consent["content"][0]["attachment"]["url"], "Binary/doc-2001");
    assert_eq!(consent["content"][0]["attachment"]["contentType"], "application/pdf");
    assert_eq!(consent["date"], "2025-02-03T15:04:05.000Z");
    assert!(decoded(find(&stream, "Binary", "doc-2001")).starts_with(b"%PDF"));
    let plan = find(&stream, "DocumentReference", "doc-2002");
    assert_eq!(plan["content"][0]["attachment"]["contentType"], "application/pdf");
    let scan = find(&stream, "Binary", "file-3002");
    assert_eq!(scan["contentType"], "image/png");

    // Forms the patient answered: the finished one final, the started one
    // preliminary, the one never opened left out.
    let history = find(&stream, "DocumentReference", "form-4001-2");
    assert_eq!(history["docStatus"], "final");
    let kept: Value = serde_json::from_slice(&decoded(find(&stream, "Binary", "form-4001-2"))).unwrap();
    assert_eq!(kept["submission"]["allergies"], "None");
    assert!(kept["definition"]["pages"].is_array());
    assert_eq!(
        find(&stream, "DocumentReference", "form-4003-1")["docStatus"],
        "preliminary"
    );
    assert!(!ids(&stream, "DocumentReference")
        .iter()
        .any(|i| i.starts_with("form-4002")));

    // Messages from the newer messaging, both pages; deleted and system
    // messages left out.
    let comms = ids(&stream, "Communication");
    assert_eq!(comms, ["cmsg-7101", "cmsg-7102", "cmsg-7105"]);
    let asked = find(&stream, "Communication", "cmsg-7101");
    assert_eq!(asked["sender"]["reference"], format!("Patient/{PATIENT_ID}"));
    assert_eq!(asked["topic"]["text"], "Medication question");
    let answered = find(&stream, "Communication", "cmsg-7102");
    assert_eq!(answered["sender"]["display"], "Nurse Example");
    assert_eq!(
        answered["payload"][1]["contentReference"]["reference"],
        "DocumentReference/att-uuid-7102a"
    );
    let att = find(&stream, "DocumentReference", "att-uuid-7102a");
    assert_eq!(att["context"]["related"][0]["reference"], "Communication/cmsg-7102");
    assert_eq!(h.count("presign attachments/7102a.pdf conversation 7001"), 1);

    // Video visits: past ones finished, the coming one planned.
    assert_eq!(find(&stream, "Encounter", "video-5001")["status"], "finished");
    let coming = find(&stream, "Encounter", "video-5003");
    assert_eq!(coming["status"], "planned");
    assert_eq!(coming["class"]["code"], "VR");

    // Nothing was written to Salve, and no credential went where it does
    // not belong.
    assert_eq!(h.stub.mutations(), 0);
    assert_eq!(h.stub.leaks(), Vec::<String>::new());

    // documents/v1.
    assert_eq!(h.run(&["documents", "list", "--profile", "adult1"]), 0);
    let one = h.dir.join("consent.pdf");
    let one_s = one.display().to_string();
    assert_eq!(
        h.run(&["documents", "download", "doc-2001", "--profile", "adult1", "-o", &one_s]),
        0
    );
    assert!(std::fs::read(&one).unwrap().starts_with(b"%PDF"));
    assert_eq!(
        h.run(&["documents", "download", "doc-2001", "--profile", "adult1", "-o", &one_s]),
        2
    );
    assert_eq!(
        h.run(&["documents", "download", "doc-9999", "--profile", "adult1", "-o", &one_s]),
        4
    );
    let all = h.dir.join("all");
    let all_s = all.display().to_string();
    assert_eq!(
        h.run(&["documents", "download", "--all", "--profile", "adult1", "-o", &all_s]),
        0
    );
    let mut saved: Vec<String> = std::fs::read_dir(&all)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    saved.sort();
    assert_eq!(
        saved,
        [
            "Consent form.pdf",
            "Instructions.pdf",
            "Lab results.pdf",
            "Treatment plan.pdf",
            "Ultrasound.png"
        ]
    );

    // The passthrough reads, and refuses a write before sending it.
    assert_eq!(h.run(&["api", "{ me { patientid } }", "--profile", "adult1"]), 0);
    let before = h.stub.log().len();
    assert_eq!(h.run(&["api", "mutation { deleteAccount }", "--profile", "adult1"]), 2);
    assert_eq!(
        h.run(&[
            "api",
            "{ me { patientid } }",
            "--variables",
            "[1]",
            "--profile",
            "adult1"
        ]),
        2
    );
    assert_eq!(h.stub.log().len(), before);
    assert_eq!(h.stub.mutations(), 0);

    assert_eq!(h.run(&["auth", "status", "--check", "--profile", "adult1"]), 0);
    assert_eq!(h.run(&["patients", "list", "--profile", "adult1"]), 0);

    // Signing out revokes the sign-in at Salve, then removes it.
    assert_eq!(h.run(&["auth", "logout", "--profile", "adult1"]), 0);
    assert_eq!(h.stub.revokes(), 1);
    assert!(!h.stub.holds_sign_in());
    assert!(h.store().get(&h.key("adult1")).unwrap().is_none());
    assert_eq!(h.run(&["records", "export", "--profile", "adult1", "--ndjson"]), 3);
}

#[test]
fn since_leaves_out_what_is_dated_before() {
    let h = H::new(Scenario::default());
    h.signed_in("adult1");
    let (code, out) = h.export("adult1", "since", &["--since", "2025-01-01"]);
    assert_eq!(code, 0);
    let stream = lines(&out.join("records.ndjson"));
    let docs = ids(&stream, "DocumentReference");
    assert!(!docs.contains(&"doc-2002".to_string()), "{docs:?}");
    assert!(docs.contains(&"doc-2001".to_string()));
    assert!(
        docs.contains(&"form-4001-2".to_string()),
        "forms carry no date and stay"
    );
    assert!(!ids(&stream, "Binary").contains(&"doc-2002".to_string()));
    let visits = ids(&stream, "Encounter");
    assert!(!visits.contains(&"video-5002".to_string()), "{visits:?}");
    assert_eq!(stream[0]["since"], "2025-01-01");
    assert_eq!(
        h.run(&[
            "records",
            "export",
            "--profile",
            "adult1",
            "--since",
            "2025-13-01",
            "--ndjson"
        ]),
        2
    );
}

#[test]
fn the_first_messaging_is_read_when_the_newer_has_none() {
    for scenario in [
        Scenario {
            v0_messaging: true,
            ..Scenario::default()
        },
        Scenario {
            patient_api_fails: true,
            ..Scenario::default()
        },
    ] {
        let h = H::new(scenario);
        h.signed_in("adult1");
        let (code, out) = h.export("adult1", "v0", &[]);
        assert_eq!(code, 0);
        let stream = lines(&out.join("records.ndjson"));
        assert_eq!(ids(&stream, "Communication"), ["msg-9001", "msg-9002"]);
        let invoice = find(&stream, "Communication", "msg-9001");
        assert_eq!(invoice["sender"]["display"], "Billing Example");
        assert_eq!(invoice["topic"]["text"], "Billing");
        assert_eq!(
            find(&stream, "Communication", "msg-9002")["sender"]["reference"],
            format!("Patient/{PATIENT_ID}")
        );
        assert!(decoded(find(&stream, "Binary", "att-uuid-9101")).starts_with(b"%PDF"));
        assert_eq!(h.count("presign attachments/9101.pdf conversation 8001"), 1);
        assert_eq!(stream.last().unwrap()["complete"], true);
    }
}

#[test]
fn what_salve_does_not_serve_is_a_skip() {
    let h = H::new(Scenario {
        files_fail: true,
        bad_pdf: true,
        missing_file: true,
        ..Scenario::default()
    });
    h.signed_in("adult1");
    let (code, out) = h.export("adult1", "skips", &[]);
    assert_eq!(code, 0);
    let stream = lines(&out.join("records.ndjson"));
    let trailer = stream.last().unwrap();
    assert_eq!(trailer["complete"], true);
    let skipped = skips(trailer);
    assert!(skipped.contains(&("upstream".into(), "GetFiles".into())), "{skipped:?}");
    assert!(
        skipped.contains(&("verify_failed".into(), "doc-2001".into())),
        "{skipped:?}"
    );
    assert!(skipped.contains(&("no_file".into(), "doc-2002".into())), "{skipped:?}");
    // The documents stay, without the files that were not served.
    let consent = find(&stream, "DocumentReference", "doc-2001");
    assert!(consent["content"][0]["attachment"].get("url").is_none());
    assert!(!ids(&stream, "Binary").contains(&"doc-2001".to_string()));
    assert!(!ids(&stream, "DocumentReference").iter().any(|i| i.starts_with("file-")));
    // documents list says what it could not read and lists the rest.
    assert_eq!(h.run(&["documents", "list", "--profile", "adult1"]), 0);
    let one = h.dir.join("bad.pdf");
    let one_s = one.display().to_string();
    assert_eq!(
        h.run(&["documents", "download", "doc-2001", "--profile", "adult1", "-o", &one_s]),
        5
    );
    assert!(!one.exists(), "a file that is not what it says is not saved");
}

#[test]
fn lapsed_tokens_are_renewed_and_written_back() {
    let h = H::new(Scenario {
        expire_after: Some(6),
        ..Scenario::default()
    });
    h.signed_in("adult1");
    let first = h.store().get(&h.key("adult1")).unwrap().unwrap();
    let (code, out) = h.export("adult1", "renewed", &[]);
    assert_eq!(code, 0);
    assert_eq!(lines(&out.join("records.ndjson")).last().unwrap()["complete"], true);
    assert_eq!(h.stub.refreshes(), 2);
    let after = h.store().get(&h.key("adult1")).unwrap().unwrap();
    assert_ne!(
        after.id_token.expose(),
        first.id_token.expose(),
        "the renewed token is kept"
    );
    assert_eq!(after.refresh_token.expose(), first.refresh_token.expose());
    assert_eq!(h.stub.sign_ins(), 1, "a renewal is not a sign-in");
    assert_eq!(h.stub.codes_sent(), 1, "a renewal texts no code");

    // Tokens that are about to lapse are renewed before the first read.
    drop(h);
    let h = H::new(Scenario {
        short_tokens: true,
        ..Scenario::default()
    });
    h.signed_in("adult1");
    assert_eq!(h.run(&["patients", "list", "--profile", "adult1"]), 0);
    assert_eq!(h.stub.refreshes(), 0, "patients list reads the stored sign-in only");
    assert_eq!(h.run(&["auth", "status", "--check", "--profile", "adult1"]), 0);
    assert_eq!(h.stub.refreshes(), 1);
}

#[test]
fn a_sign_in_salve_revoked_ends_the_stream_incomplete() {
    let h = H::new(Scenario::default());
    h.signed_in("adult1");
    h.stub.revoke_all();
    let (code, out) = h.export("adult1", "cut", &[]);
    assert_eq!(code, 3);
    assert!(!out.join("records.ndjson").exists());
    let stream = lines(&out.join("records.incomplete.ndjson"));
    let trailer = stream.last().unwrap();
    assert_eq!(trailer["complete"], false);
    assert_eq!(trailer["error"]["code"], "auth");
    assert_eq!(trailer["error"]["exit_code"], 3);
    // auth status --check says so, and is not itself a failure.
    assert_eq!(
        h.run(&["auth", "status", "--check", "--profile", "adult1", "--json"]),
        0
    );
    // A sign-in Salve no longer takes can be replaced.
    assert_eq!(
        h.run(&[
            "auth",
            "login",
            "--profile",
            "adult1",
            "--from-env",
            SIGN_IN_VAR,
            "--overwrite"
        ]),
        3
    );
    assert_eq!(h.run(&["auth", "login", "--profile", "adult1", "--code", CODE]), 0);
    assert_eq!(h.export("adult1", "again", &[]).0, 0);
}

#[test]
fn a_refused_sign_in_stores_nothing_and_is_sent_once() {
    let h = H::new(Scenario::default());
    assert_eq!(h.run(&["profiles", "add", "adult2"]), 0);
    assert_eq!(
        h.run(&["auth", "login", "--profile", "adult2", "--from-env", WRONG_VAR]),
        3
    );
    assert_eq!(h.count("cognito InitiateAuth:USER_SRP_AUTH"), 1);
    assert_eq!(
        h.count("cognito RespondToAuthChallenge:PASSWORD_VERIFIER"),
        1,
        "not retried"
    );
    assert_eq!(h.stub.codes_sent(), 0);
    assert!(!h.waiting("adult2"));
    assert_eq!(
        h.settings("adult2").clinic_id,
        None,
        "nothing is kept of a refused sign-in"
    );
    // An email the pool does not know is refused at the first step.
    assert_eq!(
        h.run(&["auth", "login", "--profile", "adult2", "--from-env", STRANGER_VAR]),
        3
    );
    assert_eq!(h.count("cognito InitiateAuth:USER_SRP_AUTH"), 2);
    assert_eq!(h.count("cognito RespondToAuthChallenge:PASSWORD_VERIFIER"), 1);
    // A --code with nothing waiting is refused without a request.
    let before = h.stub.log().len();
    assert_eq!(h.run(&["auth", "login", "--profile", "adult2", "--code", CODE]), 3);
    assert_eq!(h.stub.log().len(), before);
    // No sign-in: every reading command is exit 3, before any request.
    for cmd in [
        &["patients", "list"][..],
        &["records", "export", "--ndjson"],
        &["documents", "list"],
        &["api", "{ me { patientid } }"],
    ] {
        let mut args = cmd.to_vec();
        args.extend(["--profile", "adult2"]);
        assert_eq!(h.run(&args), 3, "{cmd:?}");
    }
    assert_eq!(h.stub.log().len(), before);
}

#[test]
fn a_code_after_the_window_is_refused() {
    let h = H::new(Scenario::default());
    assert_eq!(h.run(&["profiles", "add", "adult1"]), 0);
    assert_eq!(
        h.run(&["auth", "login", "--profile", "adult1", "--from-env", SIGN_IN_VAR]),
        3
    );
    h.stub.expire_waiting();
    assert_eq!(h.run(&["auth", "login", "--profile", "adult1", "--code", CODE]), 3);
    assert!(h.store().get(&h.key("adult1")).unwrap().is_none());
    // Starting again texts a new code, which finishes it.
    assert_eq!(
        h.run(&["auth", "login", "--profile", "adult1", "--from-env", SIGN_IN_VAR]),
        3
    );
    assert_eq!(h.stub.codes_sent(), 2);
    assert_eq!(h.run(&["auth", "login", "--profile", "adult1", "--code", CODE]), 0);
}

#[test]
fn a_pool_that_asks_no_code_signs_in_at_once() {
    let h = H::new(Scenario {
        no_mfa: true,
        ..Scenario::default()
    });
    assert_eq!(h.run(&["profiles", "add", "adult1"]), 0);
    assert_eq!(
        h.run(&["auth", "login", "--profile", "adult1", "--from-env", SIGN_IN_VAR]),
        0
    );
    assert_eq!(h.stub.codes_sent(), 0);
    assert!(h.store().get(&h.key("adult1")).unwrap().is_some());
}

#[test]
fn an_account_salve_has_not_finished_setting_up_stores_nothing() {
    let h = H::new(Scenario {
        awaiting_sync: true,
        ..Scenario::default()
    });
    assert_eq!(h.run(&["profiles", "add", "adult1"]), 0);
    assert_eq!(
        h.run(&["auth", "login", "--profile", "adult1", "--from-env", SIGN_IN_VAR]),
        3
    );
    assert_eq!(h.run(&["auth", "login", "--profile", "adult1", "--code", CODE]), 3);
    assert_eq!(h.settings("adult1").clinic_id, None);
}

#[test]
fn a_sign_in_waits_while_salve_brings_the_clinics_records_in() {
    let h = H::new(Scenario {
        sync_after: Some(3),
        ..Scenario::default()
    });
    assert_eq!(h.run(&["profiles", "add", "adult1"]), 0);
    assert_eq!(
        h.run(&["auth", "login", "--profile", "adult1", "--from-env", SIGN_IN_VAR]),
        3
    );
    assert_eq!(h.run(&["auth", "login", "--profile", "adult1", "--code", CODE]), 0);
    let reads = h.stub.log().iter().filter(|l| *l == "app GetPatientAndClinic").count();
    assert_eq!(reads, 4, "three answered AwaitingSync, the fourth the records");
    assert_eq!(h.stub.codes_sent(), 1, "one code, however long the wait");
    assert!(h.store().get(&h.key("adult1")).unwrap().is_some());
}

#[test]
fn a_sign_out_salve_does_not_confirm_still_removes_the_sign_in() {
    let h = H::new(Scenario {
        revoke_unsupported: true,
        ..Scenario::default()
    });
    h.signed_in("adult1");
    assert_eq!(h.run(&["auth", "logout", "--profile", "adult1", "--json"]), 0);
    assert!(h.store().get(&h.key("adult1")).unwrap().is_none());
    assert_eq!(h.run(&["auth", "status", "--profile", "adult1"]), 0);
}

#[test]
fn profiles_and_reset() {
    let h = H::new(Scenario::default());
    h.signed_in("adult1");
    assert_eq!(h.run(&["profiles", "add", "adult2"]), 0);
    assert_eq!(
        h.run(&["profiles", "add", "adult2"]),
        0,
        "adding one again changes nothing"
    );
    assert_eq!(h.run(&["profiles", "add", "Adult 2"]), 2);
    assert_eq!(h.run(&["profiles", "list"]), 0);
    assert_eq!(h.run(&["orgs", "list", "--json"]), 0);
    // No profile, or one not configured: exit 2.
    assert_eq!(h.run(&["patients", "list"]), 2);
    assert_eq!(h.run(&["patients", "list", "--profile", "adult9"]), 2);
    // A command that needs no sign-in takes no --profile.
    assert_eq!(h.run(&["profiles", "list", "--profile", "adult1"]), 2);
    // Removing asks, and without a terminal needs --force.
    assert_eq!(h.run(&["profiles", "remove", "adult1"]), 6);
    assert_eq!(h.run(&["profiles", "remove", "adult1", "--force"]), 0);
    assert!(h.store().get(&h.key("adult1")).unwrap().is_none());
    assert_eq!(h.run(&["profiles", "remove", "adult1", "--force"]), 4);
    h.signed_in("adult3");
    assert_eq!(h.run(&["auth", "reset"]), 6);
    assert_eq!(h.run(&["auth", "reset", "--force"]), 0);
    assert!(h.store().get(&h.key("adult3")).unwrap().is_none());
}
