//! The test suite's stub Salve as a process, for trying salve by hand on
//! synthetic data: `cargo run --example stub-salve`, then point salve at
//! the address it prints and sign in with the email and password it prints.
//!
//! Use a scratch vault while doing so, so nothing reaches the real one:
//!
//! ```sh
//! export XDG_CONFIG_HOME=$(mktemp -d) SALVE_KEYCHAIN_SERVICE=piekstra.salve.stub
//! export SALVE_STUB_URL=<the address it prints>
//! ```
//!
//! `STUB_SCENARIO` takes a comma-separated list of the cases the tests use:
//! `no-mfa`, `v0-messaging`, `patient-api-fails`, `files-fail`, `bad-pdf`,
//! `missing-file`, `short-tokens`, `refresh-revoked`, `revoke-unsupported`,
//! `awaiting-sync`, `sync-after=N`, `broken-conversation`,
//! `long-conversation=N`, `more-conversations=N`, `untracked-devices`,
//! `confirm-device-fails`, `expire-after=N`.

#[path = "../tests/common/mod.rs"]
mod common;

fn main() {
    let mut scenario = common::Scenario::default();
    for case in std::env::var("STUB_SCENARIO").unwrap_or_default().split(',') {
        match case.trim() {
            "" => {}
            "no-mfa" => scenario.no_mfa = true,
            "v0-messaging" => scenario.v0_messaging = true,
            "patient-api-fails" => scenario.patient_api_fails = true,
            "files-fail" => scenario.files_fail = true,
            "bad-pdf" => scenario.bad_pdf = true,
            "missing-file" => scenario.missing_file = true,
            "short-tokens" => scenario.short_tokens = true,
            "refresh-revoked" => scenario.refresh_revoked = true,
            "revoke-unsupported" => scenario.revoke_unsupported = true,
            "awaiting-sync" => scenario.awaiting_sync = true,
            "broken-conversation" => scenario.broken_conversation = true,
            "untracked-devices" => scenario.untracked_devices = true,
            "confirm-device-fails" => scenario.confirm_device_fails = true,
            other => {
                let count = |prefix: &str| other.strip_prefix(prefix).map(str::parse::<usize>);
                match [
                    count("expire-after="),
                    count("sync-after="),
                    count("long-conversation="),
                    count("more-conversations="),
                ] {
                    [Some(Ok(n)), ..] => scenario.expire_after = Some(n),
                    [_, Some(Ok(n)), ..] => scenario.sync_after = Some(n),
                    [_, _, Some(Ok(n)), _] => scenario.long_conversation = Some(n),
                    [.., Some(Ok(n))] => scenario.more_conversations = Some(n),
                    _ => {
                        eprintln!("unknown STUB_SCENARIO case `{other}`");
                        std::process::exit(2);
                    }
                }
            }
        }
    }
    let stub = common::Stub::start(scenario);
    println!("stub     {}", stub.origin());
    println!("email    {}", common::EMAIL);
    println!("password {}", common::PASSWORD);
    println!("code     {}", common::CODE);
    loop {
        std::thread::park();
    }
}
