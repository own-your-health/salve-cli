//! The built binary's surface: help, exit codes, the error document,
//! `info`, completions. Offline and hermetic: each test has its own config
//! folder, `SALVE_KEYCHAIN_SERVICE` names a keychain service that holds
//! nothing, and nothing is ever stored, so no keychain item is read or
//! written. A sign-in that would park a waiting code writes the vault, so
//! none is started here; `tests/e2e.rs` covers those in process.

mod common;

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use assert_cmd::Command;
use common::{Scenario, Stub, EMAIL};
use predicates::prelude::*;
use serde_json::Value;

static N: AtomicUsize = AtomicUsize::new(0);

struct T {
    dir: PathBuf,
}

impl T {
    fn new() -> T {
        let dir = std::env::temp_dir().join(format!(
            "salve-surface-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        T { dir }
    }

    fn cmd(&self) -> Command {
        let mut c = Command::cargo_bin("salve").unwrap();
        c.env("SALVE_KEYCHAIN_SERVICE", "piekstra.salve.hermetic-tests")
            .env("XDG_CONFIG_HOME", self.dir.join("config"))
            .env("XDG_DATA_HOME", self.dir.join("data"))
            .env("HOME", self.dir.join("home"))
            .env_remove("SALVE_PROFILE")
            .env_remove("SALVE_STUB_URL")
            .arg("--config")
            .arg(self.dir.join("config.json"));
        c
    }

    fn json(&self, args: &[&str]) -> (i32, Value) {
        let out = self.cmd().args(args).arg("--json").output().unwrap();
        let v = serde_json::from_slice(&out.stdout).unwrap_or(Value::Null);
        (out.status.code().unwrap_or(-1), v)
    }
}

impl Drop for T {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn every_command_has_help() {
    let t = T::new();
    for c in [
        &[][..],
        &["auth"],
        &["auth", "login"],
        &["auth", "status"],
        &["auth", "logout"],
        &["auth", "reset"],
        &["profiles"],
        &["profiles", "list"],
        &["profiles", "add"],
        &["profiles", "remove"],
        &["orgs", "list"],
        &["patients", "list"],
        &["records", "export"],
        &["documents", "list"],
        &["documents", "download"],
        &["api"],
        &["self-update"],
        &["completions"],
        &["info"],
    ] {
        t.cmd().args(c).arg("--help").assert().success();
    }
    t.cmd()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::starts_with("salve "));
    t.cmd()
        .arg("--help")
        .assert()
        .stdout(predicate::str::contains("Unofficial"));
}

#[test]
fn info_names_the_profiles_and_the_login() {
    let t = T::new();
    let (code, v) = t.json(&["info"]);
    assert_eq!(code, 0);
    assert_eq!(v["schema"], "cli-info/v1");
    assert_eq!(v["name"], "salve");
    let text = v.to_string();
    for want in ["health-records/v1", "documents/v1", "login-profiles"] {
        assert!(text.contains(want), "{want}: {text}");
    }
    assert!(!text.contains("\"mcp\""), "a provider CLI has no mcp command");
}

#[test]
fn completions_and_no_color() {
    let t = T::new();
    for shell in ["bash", "zsh", "fish"] {
        t.cmd().args(["completions", shell]).assert().success();
    }
    t.cmd().env("NO_COLOR", "1").arg("info").assert().success();
}

#[test]
fn usage_errors_are_exit_2_with_the_error_document() {
    let t = T::new();
    // Where the records go is checked before anything is read.
    let (code, v) = t.json(&["records", "export", "--profile", "adult1"]);
    assert_eq!(code, 2);
    assert_eq!(v["error"]["code"], "usage", "{v}");
    t.cmd()
        .args(["records", "export", "--profile", "adult1", "--ndjson", "--json"])
        .assert()
        .code(2);
    t.cmd()
        .args([
            "records",
            "export",
            "--profile",
            "adult1",
            "--ndjson",
            "--since",
            "yesterday",
        ])
        .assert()
        .code(2);
    t.cmd().args(["profiles", "add", "Not A Name"]).assert().code(2);
    // The passthrough refuses writes before it reads any sign-in.
    for doc in [
        "mutation { deleteAccount }",
        "subscription { messages { id } }",
        "query A { me { patientid } } mutation B { x }",
        "{ me { patientid }",
        "",
    ] {
        t.cmd().args(["api", doc, "--profile", "adult1"]).assert().code(2);
    }
    t.cmd()
        .args(["documents", "list", "--since", "2025-02-30"])
        .assert()
        .code(2);
    t.cmd().args(["info", "--profile", "adult1"]).assert().code(2);
    // A stub that is not on this machine is refused, and not echoed.
    t.cmd().args(["-q", "profiles", "add", "adult1"]).assert().success();
    t.cmd()
        .env("SALVE_STUB_URL", "https://stub.example.com")
        .args(["auth", "login", "--profile", "adult1", "--stdin"])
        .write_stdin(format!("{EMAIL}\nx\n"))
        .assert()
        .code(2)
        .stderr(predicate::str::contains("stub.example.com").not());
}

#[test]
fn there_is_no_default_profile() {
    let t = T::new();
    // None configured: the remedy names `profiles add`.
    t.cmd()
        .args(["patients", "list"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("profiles add"));
    t.cmd().args(["-q", "profiles", "add", "adult1"]).assert().success();
    // One configured is still not picked.
    t.cmd()
        .args(["patients", "list"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("configured: adult1"));
    t.cmd()
        .args(["patients", "list", "--profile", "adult2"])
        .assert()
        .code(2);
    // The environment's fallback is read.
    t.cmd()
        .env("SALVE_PROFILE", "adult1")
        .args(["patients", "list"])
        .assert()
        .code(3);
}

#[test]
fn a_profile_with_no_sign_in_is_exit_3() {
    let t = T::new();
    t.cmd().args(["-q", "profiles", "add", "adult1"]).assert().success();
    let (code, v) = t.json(&["auth", "status", "--profile", "adult1"]);
    assert_eq!(code, 0);
    assert_eq!(v["schema"], "auth-status/v1");
    assert_eq!(v["authenticated"], false);
    for c in [
        &["patients", "list"][..],
        &["documents", "list"],
        &["documents", "download", "doc-1"],
        &["api", "{ me { patientid } }"],
    ] {
        let mut args = c.to_vec();
        args.extend(["--profile", "adult1"]);
        let (code, v) = t.json(&args);
        assert_eq!(code, 3, "{c:?}");
        assert_eq!(v["error"]["code"], "auth", "{c:?}: {v}");
    }
    // The stream's failure before its header is the error document.
    t.cmd()
        .args(["records", "export", "--profile", "adult1", "--ndjson"])
        .assert()
        .code(3)
        .stdout(predicate::str::is_empty());
    // Logging out with nothing stored is fine.
    t.cmd()
        .args(["-q", "auth", "logout", "--profile", "adult1"])
        .assert()
        .success();
}

#[test]
fn destructive_commands_ask_or_need_force() {
    let t = T::new();
    t.cmd().args(["-q", "profiles", "add", "adult1"]).assert().success();
    t.cmd().args(["profiles", "remove", "adult1"]).assert().code(6);
    t.cmd().args(["auth", "reset"]).assert().code(6);
    t.cmd()
        .args(["-q", "profiles", "remove", "adult1", "--force"])
        .assert()
        .success();
    t.cmd()
        .args(["profiles", "remove", "adult1", "--force"])
        .assert()
        .code(4);
}

#[test]
fn the_sign_in_source_is_checked_before_anything_is_read() {
    let t = T::new();
    t.cmd().args(["-q", "profiles", "add", "adult1"]).assert().success();
    // None given.
    t.cmd().args(["auth", "login", "--profile", "adult1"]).assert().code(2);
    // Two given.
    t.cmd()
        .args([
            "auth",
            "login",
            "--profile",
            "adult1",
            "--stdin",
            "--op-item",
            "op://Private/Item",
        ])
        .assert()
        .code(2);
    // A code beside a password.
    t.cmd()
        .args(["auth", "login", "--profile", "adult1", "--stdin", "--code", "123456"])
        .write_stdin(format!("{EMAIL}\nx\n"))
        .assert()
        .code(2);
    // A value that is not an item is not echoed: it may be the password.
    t.cmd()
        .args(["auth", "login", "--profile", "adult1", "--op-item", "hunter2-secret"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("hunter2").not());
    // One line is not a sign-in, and is not echoed.
    t.cmd()
        .env("SALVE_STUB_URL", "http://127.0.0.1:9")
        .args(["auth", "login", "--profile", "adult1", "--stdin"])
        .write_stdin("only-one-line-secret")
        .assert()
        .code(2)
        .stderr(predicate::str::contains("only-one-line").not());
    // A label that is not one.
    t.cmd()
        .args([
            "auth",
            "login",
            "--profile",
            "adult1",
            "--stdin",
            "--label",
            "Jane Example",
        ])
        .write_stdin(format!("{EMAIL}\nx\n"))
        .assert()
        .code(2);
    // Nothing listening.
    t.cmd()
        .env("SALVE_STUB_URL", "http://127.0.0.1:9")
        .args(["auth", "login", "--profile", "adult1", "--stdin"])
        .write_stdin(format!("{EMAIL}\nx\n"))
        .assert()
        .code(5);
}

#[test]
fn a_refused_password_is_exit_3_and_sent_once() {
    let stub = Stub::start(Scenario::default());
    let t = T::new();
    t.cmd().args(["-q", "profiles", "add", "adult2"]).assert().success();
    let out = t
        .cmd()
        .env("SALVE_STUB_URL", stub.origin())
        .args(["auth", "login", "--profile", "adult2", "--stdin", "--json"])
        .write_stdin(format!("{EMAIL}\nwrong-password\n"))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3));
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["error"]["code"], "auth");
    let said = String::from_utf8_lossy(&out.stderr);
    assert!(!said.contains("wrong-password"), "{said}");
    let proofs = stub
        .log()
        .iter()
        .filter(|l| l.as_str() == "cognito RespondToAuthChallenge:PASSWORD_VERIFIER")
        .count();
    assert_eq!(proofs, 1);
    assert_eq!(stub.codes_sent(), 0);
    for body in stub.cognito_bodies() {
        assert!(!body.contains("wrong-password"), "the password was sent: {body}");
    }
    // One line is refused before Salve is asked at all.
    let before = stub.log().len();
    t.cmd()
        .env("SALVE_STUB_URL", stub.origin())
        .args(["auth", "login", "--profile", "adult2", "--stdin"])
        .write_stdin("only-one-line-secret")
        .assert()
        .code(2);
    assert_eq!(stub.log().len(), before);
}
