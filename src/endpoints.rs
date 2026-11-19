//! Where salve sends what: Salve's hosts, or a stub on this machine.
//!
//! Salve's web app names its hosts in its own code: Cognito in eu-west-2
//! for the sign-in, `mobile.salvehealth.co` for the app's GraphQL API,
//! `salve-api.salvehealth.co` for the newer patient API its messaging uses,
//! and `s3presign.salvehealth.co`, which turns a file's address into a
//! short-lived download link. These are constants: nothing a user passes
//! or a response says moves a credential to another host.
//!
//! [`STUB_ENV`] points every one of them at a stub on this machine instead,
//! for the tests and the stub example. It accepts only a loopback `http`
//! address, so it can never send a sign-in anywhere else.

use pk_cli_core::CliError;

/// A stub's address (`http://127.0.0.1:<port>`): every call goes there
/// instead. Loopback only; for the tests and the stub example.
pub const STUB_ENV: &str = "SALVE_STUB_URL";

pub const COGNITO_REGION: &str = "eu-west-2";
/// The user pool and the web client Salve's app signs in with, as its
/// public code names them.
pub const USER_POOL_ID: &str = "eu-west-2_PS2EMAFqC";
pub const CLIENT_ID: &str = "3l84pov0p680vfm3qr6dbp7gog";

/// Salve's patient web portal, where `--browser` signs in.
pub const PORTAL: &str = "https://patientwebportal.salvehealth.com";
const COGNITO: &str = "https://cognito-idp.eu-west-2.amazonaws.com/";
const APP_API: &str = "https://mobile.salvehealth.co/app/graphql";
const PATIENT_API: &str = "https://salve-api.salvehealth.co/patient/graphql";
const PRESIGN: &str = "https://s3presign.salvehealth.co";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoints {
    pub cognito: String,
    pub app_api: String,
    pub patient_api: String,
    pub presign: String,
    pub portal: String,
    /// The stub's base, when these are a stub's.
    pub stub: Option<String>,
}

impl Endpoints {
    /// Salve's own.
    pub fn salve() -> Endpoints {
        Endpoints {
            cognito: COGNITO.into(),
            app_api: APP_API.into(),
            patient_api: PATIENT_API.into(),
            presign: PRESIGN.into(),
            portal: PORTAL.into(),
            stub: None,
        }
    }

    /// A stub's, under `base`: a loopback `http` address only.
    pub fn stub(base: &str) -> Result<Endpoints, CliError> {
        let base = base.trim().trim_end_matches('/');
        if !is_loopback_http(base) {
            return Err(CliError::Usage(format!(
                "{STUB_ENV} is a stub on this machine: http://127.0.0.1:<port> (the value given is not shown)"
            )));
        }
        Ok(Endpoints {
            cognito: format!("{base}/cognito"),
            app_api: format!("{base}/app/graphql"),
            patient_api: format!("{base}/patient/graphql"),
            presign: format!("{base}/presign"),
            portal: base.to_string(),
            stub: Some(base.to_string()),
        })
    }

    /// Salve's, or with [`STUB_ENV`] set the stub's.
    pub fn from_env() -> Result<Endpoints, CliError> {
        match std::env::var(STUB_ENV).ok().filter(|v| !v.trim().is_empty()) {
            Some(base) => Endpoints::stub(&base),
            None => Ok(Endpoints::salve()),
        }
    }

    /// The endpoints a stored session was made with.
    pub fn of_session(stub: Option<&str>) -> Result<Endpoints, CliError> {
        match stub {
            Some(base) => Endpoints::stub(base),
            None => Ok(Endpoints::salve()),
        }
    }

    pub fn is_stub(&self) -> bool {
        self.stub.is_some()
    }

    /// The organization id a stub's records carry, else none.
    pub fn label(&self) -> &str {
        if self.is_stub() {
            "stub"
        } else {
            "salve"
        }
    }

    /// Whether a download link may be fetched: https, or the stub's own
    /// loopback address.
    pub fn may_fetch(&self, url: &str) -> bool {
        match &self.stub {
            Some(base) => url.starts_with(&format!("{base}/")),
            None => url.starts_with("https://") && host_of(url).is_some_and(|h| !h.is_empty()),
        }
    }
}

fn host_of(url: &str) -> Option<&str> {
    let rest = url.split_once("://")?.1;
    let authority = rest.split(['/', '?', '#']).next()?;
    if authority.contains('@') {
        return None;
    }
    Some(authority.split(':').next().unwrap_or(authority))
}

fn is_loopback_http(base: &str) -> bool {
    let Some(rest) = base.strip_prefix("http://") else {
        return false;
    };
    if rest.contains(['/', '?', '#', '@']) {
        return false;
    }
    let host = match rest.rsplit_once(':') {
        Some((h, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => h,
        _ => rest,
    };
    matches!(host, "127.0.0.1" | "localhost" | "[::1]")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stub_is_on_this_machine_only() {
        let e = Endpoints::stub("http://127.0.0.1:4567/").unwrap();
        assert_eq!(e.app_api, "http://127.0.0.1:4567/app/graphql");
        assert_eq!(e.stub.as_deref(), Some("http://127.0.0.1:4567"));
        Endpoints::stub("http://localhost:80").unwrap();
        for bad in [
            "https://127.0.0.1:4567",
            "http://example.com",
            "http://127.0.0.1.example.com",
            "http://user@localhost:1",
            "http://127.0.0.1:1/path",
            "ftp://127.0.0.1",
        ] {
            assert_eq!(Endpoints::stub(bad).unwrap_err().exit_code(), 2, "{bad}");
        }
    }

    #[test]
    fn download_links_are_https_or_the_stubs() {
        let real = Endpoints::salve();
        assert!(real.may_fetch("https://bucket.s3.eu-west-2.amazonaws.com/a.pdf?X-Amz-Signature=x"));
        assert!(!real.may_fetch("http://bucket.s3.amazonaws.com/a.pdf"));
        assert!(!real.may_fetch("https://user@files.example"));
        let stub = Endpoints::stub("http://127.0.0.1:9").unwrap();
        assert!(stub.may_fetch("http://127.0.0.1:9/s3/a.pdf"));
        assert!(!stub.may_fetch("https://bucket.s3.amazonaws.com/a.pdf"));
        assert!(!stub.may_fetch("http://127.0.0.1:99/s3/a.pdf"));
    }
}
