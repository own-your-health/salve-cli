//! Salve's APIs, as its web app calls them: GraphQL over `POST`, with the
//! Cognito ID token as the `authorization` header (no scheme), and on the
//! patient API the clinic's token (`x-salve-clinic-token`, the ID token's
//! `custom:clinictoken` claim) beside it.
//!
//! Files are fetched in two steps: `POST <presign>/patient/read` with the
//! file's address answers a short-lived download link, which is fetched
//! with no credential.
//!
//! salve sends queries only. [`check_read`] refuses a document with a
//! mutation or subscription in it before anything is sent, for `salve api`
//! as for salve's own queries.

use pk_cli_core::{CliError, Reason};
use pk_cli_secrets::Secret;
use serde_json::{json, Value};

use crate::cli::BIN;
use crate::cognito::{http_client, net_error, one_line};
use crate::endpoints::Endpoints;
use crate::queries::{Host, Op};

/// A file is at most this large.
pub const MAX_FILE_BYTES: usize = 200 * 1024 * 1024;

/// A GraphQL answer: its `data`, and the messages of any `errors` beside
/// it (a field Salve could not resolve comes back null with one).
#[derive(Debug, Clone)]
pub struct Answer {
    pub data: Value,
    pub errors: Vec<String>,
}

pub struct Api {
    ep: Endpoints,
    http: reqwest::blocking::Client,
    /// A download link is fetched without following a redirect off it.
    files: reqwest::blocking::Client,
}

impl Api {
    pub fn new(ep: &Endpoints) -> Result<Api, CliError> {
        for url in [&ep.app_api, &ep.patient_api, &ep.presign] {
            pk_cli_core::transport::require_secure_url(url)?;
        }
        Ok(Api {
            ep: ep.clone(),
            http: http_client()?,
            files: http_client()?,
        })
    }

    pub fn endpoints(&self) -> &Endpoints {
        &self.ep
    }

    /// One query. `document` must pass [`check_read`]. A refused token is
    /// exit 3 ([`Reason::CredentialRefused`]), which a caller holding a
    /// refresh token answers by renewing once.
    pub fn query(
        &self,
        host: Host,
        name: Option<&str>,
        document: &str,
        variables: &Value,
        id_token: &Secret,
        clinic_token: Option<&str>,
    ) -> Result<Answer, CliError> {
        check_read(document)?;
        let url = match host {
            Host::App => &self.ep.app_api,
            Host::Patient => &self.ep.patient_api,
        };
        let mut req = self
            .http
            .post(url)
            .header("content-type", "application/json")
            .header("authorization", id_token.expose());
        if let (Host::Patient, Some(t)) = (host, clinic_token) {
            req = req.header("x-salve-clinic-token", t);
        }
        let body = json!({ "operationName": name, "variables": variables, "query": document });
        let resp = req.body(body.to_string()).send().map_err(|e| net_error(&e))?;
        let status = resp.status().as_u16();
        let text = resp.text().map_err(|e| net_error(&e))?;
        let what = name.unwrap_or("the query");
        if status == 401 || status == 403 {
            return Err(token_refused());
        }
        let v: Value = serde_json::from_str(&text).map_err(|_| {
            CliError::Upstream(format!(
                "{what} answered HTTP {status} with {}",
                if text.trim_start().starts_with('<') {
                    "a web page, not JSON"
                } else {
                    "something that is not JSON"
                }
            ))
        })?;
        answer(what, status, v)
    }

    /// A file's download link, from its address in a record.
    pub fn file_link(
        &self,
        uri: &str,
        conversation: Option<i64>,
        id_token: &Secret,
        clinic_token: Option<&str>,
    ) -> Result<String, CliError> {
        let mut url = format!("{}/patient/read", self.ep.presign);
        if let Some(c) = conversation {
            url.push_str(&format!("?conversationId={c}"));
        }
        let mut req = self
            .http
            .post(url)
            .header("accept", "application/json")
            .header("content-type", "application/json")
            .header("authorization", id_token.expose());
        if let Some(t) = clinic_token {
            req = req.header("x-salve-clinic-token", t);
        }
        let resp = req
            .body(json!({ "url": uri }).to_string())
            .send()
            .map_err(|e| net_error(&e))?;
        let status = resp.status().as_u16();
        if status == 401 || status == 403 {
            return Err(token_refused());
        }
        if status == 404 {
            return Err(CliError::NotFound("Salve has no file at that address".into()));
        }
        if !(200..300).contains(&status) {
            return Err(CliError::Upstream(format!("the file link answered HTTP {status}")));
        }
        let v: Value = resp
            .json()
            .map_err(|_| CliError::Upstream("the file link answer is not JSON".into()))?;
        let link = v["url"]
            .as_str()
            .filter(|u| !u.is_empty())
            .ok_or_else(|| CliError::Upstream("the file link answer names no link".into()))?;
        if !self.ep.may_fetch(link) {
            return Err(CliError::Upstream(
                "the file link is not an https address; salve does not fetch it".into(),
            ));
        }
        Ok(link.to_string())
    }

    /// A download link's bytes, fetched with no credential.
    pub fn fetch(&self, link: &str) -> Result<Vec<u8>, CliError> {
        let resp = self.files.get(link).send().map_err(|e| net_error(&e))?;
        let status = resp.status().as_u16();
        if status == 403 || status == 404 {
            return Err(CliError::NotFound(format!("the file's link answered HTTP {status}")));
        }
        if !(200..300).contains(&status) {
            return Err(CliError::Upstream(format!("the file's link answered HTTP {status}")));
        }
        if resp.content_length().is_some_and(|n| n as usize > MAX_FILE_BYTES) {
            return Err(CliError::Upstream(format!(
                "the file is larger than {} MB; salve does not fetch it",
                MAX_FILE_BYTES / 1024 / 1024
            )));
        }
        let bytes = resp.bytes().map_err(|e| net_error(&e))?;
        if bytes.len() > MAX_FILE_BYTES {
            return Err(CliError::Upstream(format!(
                "the file is larger than {} MB; salve does not fetch it",
                MAX_FILE_BYTES / 1024 / 1024
            )));
        }
        Ok(bytes.to_vec())
    }
}

/// One of salve's own queries.
pub fn op_query(
    api: &Api,
    op: &Op,
    variables: &Value,
    id_token: &Secret,
    clinic_token: Option<&str>,
) -> Result<Answer, CliError> {
    api.query(op.host, Some(op.name), op.document, variables, id_token, clinic_token)
}

/// Salve no longer takes the ID token: exit 3.
pub fn token_refused() -> CliError {
    CliError::Auth("Salve refused the stored sign-in token".into()).because(Reason::CredentialRefused)
}

/// The app API's own error codes, answered in place of `data`.
fn account_step(code: &str) -> Option<&'static str> {
    match code {
        "Unregistered" => Some("is not registered with a clinic yet"),
        "AwaitingDetails" => Some("is waiting on details the patient gives in Salve's app"),
        "AwaitingSync" => Some("is waiting for the clinic's records to reach Salve"),
        _ => None,
    }
}

fn answer(what: &str, status: u16, v: Value) -> Result<Answer, CliError> {
    if let Some(code) = v["errorCode"].as_str() {
        return Err(match account_step(code) {
            Some(why) => CliError::Auth(format!("the Salve account {why}"))
                .because(Reason::Forbidden)
                .with_remedy("finish it in Salve's app, then run this again".to_string()),
            None => CliError::Upstream(format!("{what} answered error code {}", one_line(code))),
        });
    }
    let errors: Vec<String> = v["errors"]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|e| one_line(e["message"].as_str().unwrap_or("an error")))
                .collect()
        })
        .unwrap_or_default();
    let unauthenticated = v["errors"].as_array().is_some_and(|a| {
        a.iter().any(|e| {
            let code = e["extensions"]["code"].as_str().unwrap_or_default();
            let msg = e["message"].as_str().unwrap_or_default().to_ascii_lowercase();
            code == "UNAUTHENTICATED" || msg.contains("unauthorized") || msg.contains("not authenticated")
        })
    });
    let data = v.get("data").cloned().unwrap_or(Value::Null);
    if data.is_null() || data.as_object().is_some_and(|m| m.values().all(Value::is_null)) {
        if unauthenticated
            || v["message"]
                .as_str()
                .is_some_and(|m| m.eq_ignore_ascii_case("unauthorized"))
        {
            return Err(token_refused());
        }
        if let Some(first) = errors.first() {
            let lower = first.to_ascii_lowercase();
            if lower.contains("not found") || lower.contains("does not exist") {
                return Err(CliError::NotFound(format!("{what}: {first}")));
            }
            return Err(CliError::Upstream(format!("{what} answered: {first}")));
        }
        if !(200..300).contains(&status) {
            return Err(CliError::Upstream(format!("{what} answered HTTP {status}")));
        }
        if data.is_null() {
            return Err(CliError::Upstream(format!("{what} answered no data")));
        }
    }
    if !(200..300).contains(&status) {
        return Err(CliError::Upstream(format!("{what} answered HTTP {status}")));
    }
    Ok(Answer { data, errors })
}

/// Whether a GraphQL document only reads: every operation in it is a query
/// (`query ...` or a bare `{ ... }`), beside any fragments. A mutation or a
/// subscription, or a document that does not parse that far, is exit 2,
/// before a request is made.
pub fn check_read(document: &str) -> Result<(), CliError> {
    let refuse = |why: &str| Err(CliError::Usage(format!("{BIN} sends GraphQL queries only: {why}")));
    let mut depth: i64 = 0;
    let mut paren: i64 = 0;
    let mut word = String::new();
    let mut at_top_start = true;
    let mut definitions = 0;
    let chars: Vec<char> = document.chars().collect();
    let mut i = 0;
    let flush = |word: &mut String,
                 at_top_start: &mut bool,
                 definitions: &mut i32,
                 depth: i64,
                 paren: i64|
     -> Result<(), CliError> {
        if !word.is_empty() && depth == 0 && paren == 0 && *at_top_start {
            *at_top_start = false;
            *definitions += 1;
            match word.as_str() {
                "query" | "fragment" => {}
                "mutation" => return refuse("this document has a mutation"),
                "subscription" => return refuse("this document has a subscription"),
                other => return refuse(&format!("`{}` does not start an operation", one_line(other))),
            }
        }
        word.clear();
        Ok(())
    };
    while i < chars.len() {
        let c = chars[i];
        if c == '#' {
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
            continue;
        }
        if c == '"' {
            flush(&mut word, &mut at_top_start, &mut definitions, depth, paren)?;
            let block = chars.get(i + 1) == Some(&'"') && chars.get(i + 2) == Some(&'"');
            if block {
                i += 3;
                while i + 2 < chars.len() && !(chars[i] == '"' && chars[i + 1] == '"' && chars[i + 2] == '"') {
                    i += 1;
                }
                i += 3;
            } else {
                i += 1;
                while i < chars.len() && chars[i] != '"' {
                    if chars[i] == '\\' {
                        i += 1;
                    }
                    i += 1;
                }
                i += 1;
            }
            continue;
        }
        if c.is_alphanumeric() || c == '_' {
            word.push(c);
            i += 1;
            continue;
        }
        flush(&mut word, &mut at_top_start, &mut definitions, depth, paren)?;
        match c {
            '{' => {
                if depth == 0 && paren == 0 && at_top_start {
                    // A bare selection set: an anonymous query.
                    at_top_start = false;
                    definitions += 1;
                }
                depth += 1;
            }
            '}' => {
                depth -= 1;
                if depth < 0 {
                    return refuse("its braces do not balance");
                }
                if depth == 0 {
                    at_top_start = true;
                }
            }
            '(' => paren += 1,
            ')' => paren -= 1,
            _ => {}
        }
        i += 1;
    }
    flush(&mut word, &mut at_top_start, &mut definitions, depth, paren)?;
    if depth != 0 || paren != 0 {
        return refuse("its braces do not balance");
    }
    if definitions == 0 {
        return refuse("the document is empty");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_queries_are_sent() {
        for ok in [
            "{ me { patientid } }",
            "query { me { patientid } }",
            "query A($x: Int) { me { a(x: $x) } }",
            "query A { ...F } fragment F on Me { patientid }",
            "# a comment with mutation in it\nquery A { me { name } }",
            "query A { me { s(t: \"mutation { x }\") } }",
            "query A { me { s(t: \"\"\"subscription\"\"\") } }",
        ] {
            check_read(ok).unwrap_or_else(|e| panic!("{ok}: {e}"));
        }
        for bad in [
            "mutation { deleteAccountRequest { date } }",
            "mutation DeleteAccount { deleteAccountRequest { date } }",
            "query A { me { id } } mutation B { x }",
            "subscription S { x }",
            "  \n mutation{x}",
            "query A { me { id }",
            "query A { me { id } } }",
            "",
            "# only a comment",
            "schema { query: Q }",
        ] {
            assert_eq!(check_read(bad).unwrap_err().exit_code(), 2, "{bad:?}");
        }
    }

    #[test]
    fn answers_read_as_data_or_exit_codes() {
        let ok = answer("q", 200, json!({ "data": { "me": { "patientid": 1 } } })).unwrap();
        assert_eq!(ok.data["me"]["patientid"], 1);
        let partial = answer(
            "q",
            200,
            json!({ "data": { "me": { "files": null, "patientid": 1 } }, "errors": [{ "message": "files failed" }] }),
        )
        .unwrap();
        assert_eq!(partial.errors, ["files failed"]);
        let unauth = answer(
            "q",
            200,
            json!({ "data": null, "errors": [{ "message": "x", "extensions": { "code": "UNAUTHENTICATED" } }] }),
        );
        assert_eq!(unauth.unwrap_err().exit_code(), 3);
        let gw = answer("q", 200, json!({ "message": "Unauthorized" }));
        assert_eq!(gw.unwrap_err().exit_code(), 3);
        assert_eq!(
            answer("q", 200, json!({ "errorCode": "Unregistered" }))
                .unwrap_err()
                .exit_code(),
            3
        );
        assert_eq!(
            answer("q", 200, json!({ "errorCode": "Error" }))
                .unwrap_err()
                .exit_code(),
            5
        );
        let failed = answer(
            "q",
            200,
            json!({ "data": null, "errors": [{ "message": "Something broke" }] }),
        );
        assert_eq!(failed.unwrap_err().exit_code(), 5);
        let missing = answer(
            "q",
            200,
            json!({ "data": { "me": null }, "errors": [{ "message": "Form not found" }] }),
        );
        assert_eq!(missing.unwrap_err().exit_code(), 4);
        assert_eq!(answer("q", 500, json!({ "data": null })).unwrap_err().exit_code(), 5);
    }
}
