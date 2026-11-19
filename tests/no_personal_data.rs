//! The repository carries no personal data; runtime output may.
//!
//! Walks every tracked file (`git ls-files`) for the *shapes* personal data
//! takes (phone numbers, long id numbers, street addresses, email
//! addresses) rather than a list of real values, which would publish what
//! it exists to keep out. Then checks the fixtures positively: every
//! identity-bearing field Salve answers holds one of the dummy shapes
//! `tests/fixtures/README.md` lists.

use std::process::Command;

fn root() -> &'static str {
    env!("CARGO_MANIFEST_DIR")
}

fn tracked_files() -> Vec<String> {
    let out = Command::new("git")
        .args(["ls-files"])
        .current_dir(root())
        .output()
        .expect("git ls-files");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::to_string)
        .collect()
}

fn digits_run(s: &str, min: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for c in s.chars().chain(std::iter::once(' ')) {
        if c.is_ascii_digit() {
            cur.push(c);
        } else {
            if cur.len() >= min {
                out.push(cur.clone());
            }
            cur.clear();
        }
    }
    out
}

/// A digit run is a dummy when it is all one digit, zeros then one digit
/// (`00000001`), or a 555 phone number: `555…`, or any area code with the
/// 555-0100 to 555-0199 lines reserved for fiction.
fn is_dummy_number(n: &str) -> bool {
    let first = n.chars().next().unwrap();
    let head = &n[..n.len() - 1];
    let local = n.strip_prefix('1').filter(|r| r.len() == 10).unwrap_or(n);
    let fictional = local.len() == 10 && &local[3..8] == "55501";
    n.chars().all(|c| c == first)
        || head.chars().all(|c| c == '0')
        || n.starts_with("555")
        || n.starts_with("1555")
        || fictional
}

const PUBLIC_EMAIL_DOMAINS: &[&str] = &["example.com"];

/// The personal-data shapes on one line, each as `kind value`.
/// The line with every hex token of 32 characters or more blanked: a hash,
/// a key or a published constant (the SRP group's prime), never a phone
/// number or a record id.
fn without_hex(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut token = String::new();
    let flush = |token: &mut String, out: &mut String| {
        if token.len() >= 32 {
            out.extend(std::iter::repeat_n('x', token.len()));
        } else {
            out.push_str(token);
        }
        token.clear();
    };
    for c in line.chars() {
        if c.is_ascii_hexdigit() {
            token.push(c);
        } else {
            flush(&mut token, &mut out);
            out.push(c);
        }
    }
    flush(&mut token, &mut out);
    out
}

fn scan_line(line: &str) -> Vec<String> {
    let line = &without_hex(line);
    let mut findings = Vec::new();
    let phoneish = line.replace(['(', ')', '-', '.', ' '], "");
    for n in digits_run(line, 7)
        .into_iter()
        .chain(digits_run(&phoneish, 10).into_iter().filter(|n| n.len() <= 11))
    {
        if !is_dummy_number(&n) {
            findings.push(format!("number {n}"));
        }
    }
    for word in line.split(|c: char| c.is_whitespace() || "\"'<>(),;`".contains(c)) {
        if let Some((local, domain)) = word.split_once('@') {
            let domain = domain.trim_end_matches(|c: char| !(c.is_ascii_alphanumeric() || c == '-'));
            let ok = local.is_empty()
                || !domain.contains('.')
                || PUBLIC_EMAIL_DOMAINS.contains(&domain)
                || domain.ends_with(".example")
                || domain.ends_with("users.noreply.github.com");
            if !ok {
                findings.push(format!("email {word}"));
            }
        }
    }
    let lower = line.to_ascii_lowercase();
    for suffix in [" way", " st", " ave", " blvd", " dr", " ln", " ct", " rd"] {
        if let Some(pos) = lower.find(suffix) {
            let has_number = lower[..pos]
                .split_whitespace()
                .rev()
                .take(4)
                .any(|w| w.len() >= 3 && w.chars().all(|c| c.is_ascii_digit()));
            if has_number && !lower.contains("example st") {
                findings.push(format!("address-like `{}`", line.trim()));
            }
        }
    }
    findings
}

/// `<commit>:<path>:<rule>:<line>`: a 40-character hex commit, a path with
/// no space, a lowercase rule id and a line number.
fn is_fingerprint(line: &str) -> bool {
    let parts: Vec<&str> = line.split(':').collect();
    let [commit, path, rule, number] = parts.as_slice() else {
        return false;
    };
    commit.len() == 40
        && commit.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        && !path.is_empty()
        && !path.contains(char::is_whitespace)
        && !rule.is_empty()
        && rule.bytes().all(|b| b.is_ascii_lowercase() || b == b'-')
        && !number.is_empty()
        && number.bytes().all(|b| b.is_ascii_digit())
}

#[test]
fn a_fingerprint_is_only_a_fingerprint() {
    assert!(is_fingerprint(
        "865517eb837b9fb4fc7d1983f6cc1de7376015f8:src/portal.rs:generic-api-key:1205"
    ));
    assert!(!is_fingerprint(
        "865517eb837b9fb4fc7d1983f6cc1de7376015f8:src/portal.rs:generic-api-key:1205 note"
    ));
    assert!(!is_fingerprint("call 5551234567"));
    assert!(!is_fingerprint("865517e:src/portal.rs:generic-api-key:1205"));
}

#[test]
fn tracked_files_carry_no_personal_data() {
    let files = tracked_files();
    if files.is_empty() {
        // Not a git checkout (a packaged crate): nothing to scan.
        return;
    }
    let mut findings = Vec::new();
    for file in files {
        if file.ends_with(".lock") || file.starts_with("LICENSE") || file == "tests/no_personal_data.rs" {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(format!("{}/{file}", root())) else {
            continue;
        };
        for (i, line) in text.lines().enumerate() {
            // A gitleaks fingerprint's commit hash can hold a phone-length
            // digit run. Such a line is checked for that shape instead, so
            // nothing else can ride along in the file uncommented.
            if file == ".gitleaksignore" && !line.starts_with('#') {
                if !is_fingerprint(line) {
                    findings.push(format!("{file}:{}: not a gitleaks fingerprint", i + 1));
                }
                continue;
            }
            for f in scan_line(line) {
                findings.push(format!("{file}:{}: {f}", i + 1));
            }
        }
    }
    assert!(
        findings.is_empty(),
        "personal-data shapes in tracked files:\n{}",
        findings.join("\n")
    );
}

#[test]
fn no_tracked_file_is_a_raw_capture_or_a_statement() {
    for file in tracked_files() {
        let lower = file.to_ascii_lowercase();
        for ext in [".pdf", ".har", ".csv", ".xlsx", ".raw.json", ".raw.html", ".ndjson"] {
            assert!(
                !lower.ends_with(ext),
                "{file} is tracked; real files, captures and exports never are"
            );
        }
    }
}

/// Every identity field the Salve fixtures carry, by key, wherever it is
/// nested: the patient is Jane Example, the clinic and its staff
/// `Example …`, contact details the reserved ones, dates of birth January
/// firsts, record numbers zeros then one digit.
#[test]
fn identity_fields_in_salve_fixtures_use_dummy_values() {
    fn walk(name: &str, key: &str, v: &serde_json::Value, checked: &mut usize) {
        match v {
            serde_json::Value::Object(map) => {
                for (k, v) in map {
                    walk(name, k, v, checked);
                }
            }
            serde_json::Value::Array(items) => items.iter().for_each(|v| walk(name, key, v, checked)),
            serde_json::Value::String(s) if !s.is_empty() => {
                let party = |s: &str| s.split_whitespace().any(|w| w == "Example");
                // Only the account's answers name a person or the clinic
                // under `name`; elsewhere it is a form's or a visit's title.
                let account = name.ends_with("/patient-and-clinic.json") || name.ends_with("/patient-clinics.json");
                let ok = match key {
                    "name" if account => party(s),
                    "name" => return,
                    "firstname" | "firstName" => ["Jane", "Nurse", "Dr", "Billing"].contains(&s.as_str()),
                    "lastname" | "lastName" => s == "Example",
                    "sender" | "host" => party(s),
                    "email" => s.ends_with("@example.com"),
                    "patientid" => s == "100001",
                    "clinicid" | "_id" => s.starts_with("clinic-"),
                    "CODE_DELIVERY_DESTINATION" => s.ends_with("0000") && s.contains("***"),
                    _ => return,
                };
                assert!(ok, "{name}: `{key}` holds `{s}`, not a dummy");
                *checked += 1;
            }
            _ => {}
        }
    }
    let dir = format!("{}/tests/fixtures/salve", root());
    let mut checked = 0;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let name = path.display().to_string();
        let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        walk(&name, "", &v, &mut checked);
    }
    assert!(
        checked >= 30,
        "only {checked} identity fields found; did the fixtures change?"
    );
}

#[test]
fn the_scanner_flags_real_shapes_and_passes_dummies() {
    for real in [
        "call (772) 404-1234",
        "call 888-555-0200",
        "patient id 9234567812",
        "mail someone@gmail.com",
        "lives at 1234 NW Oak St, Somewhere",
        "record 7342918",
        "a short hex run 9a7342918b",
    ] {
        assert!(!scan_line(real).is_empty(), "missed: {real}");
    }
    for dummy in [
        "call (555) 010-0001",
        "line 888-555-0100",
        "mrn 00000001",
        "user@example.com",
        "100 Example St, Example City",
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74",
    ] {
        assert!(
            scan_line(dummy).is_empty(),
            "false positive: {dummy}: {:?}",
            scan_line(dummy)
        );
    }
}
