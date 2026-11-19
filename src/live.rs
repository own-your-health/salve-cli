//! Salve as a stored sign-in reads it: each call with the ID token, renewed
//! from the refresh token when it is about to lapse or Salve refuses it, and
//! the renewed tokens written back to the vault.
//!
//! A token that worked and is then refused has lapsed, so it is renewed and
//! the call sent once more. A token refused right after its renewal is not
//! renewed again: the sign-in itself is no longer taken. A run renews at
//! most [`MAX_RENEWALS`] times.

use std::cell::{Cell, RefCell};

use pk_cli_core::{CliError, Reason};
use pk_cli_secrets::Secret;
use serde_json::Value;

use crate::cognito::Cognito;
use crate::endpoints::Endpoints;
use crate::pull::Reader;
use crate::queries::{Host, Op};
use crate::salve::{self, Answer, Api};
use crate::session::{Key, Session, SessionStore};

/// Renewals one run makes at most. An ID token lasts an hour, so a run
/// needs more than one only when it is long.
pub const MAX_RENEWALS: u32 = 5;

pub struct Live<'a> {
    api: Api,
    cognito: Cognito,
    session: RefCell<Session>,
    store: &'a SessionStore,
    key: Key,
    renewals: Cell<u32>,
    /// The token was renewed and has not yet been taken.
    fresh: Cell<bool>,
    now: &'a dyn Fn() -> u64,
}

pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl<'a> Live<'a> {
    pub fn new(
        store: &'a SessionStore,
        key: Key,
        session: Session,
        now: &'a dyn Fn() -> u64,
    ) -> Result<Live<'a>, CliError> {
        let ep = Endpoints::of_session(session.stub.as_deref())?;
        Ok(Live {
            api: Api::new(&ep)?,
            cognito: Cognito::new(&ep)?,
            session: RefCell::new(session),
            store,
            key,
            renewals: Cell::new(0),
            fresh: Cell::new(false),
            now,
        })
    }

    pub fn endpoints(&self) -> &Endpoints {
        self.api.endpoints()
    }

    /// How many times this run renewed the tokens.
    pub fn renewals(&self) -> u32 {
        self.renewals.get()
    }

    fn renew(&self) -> Result<(), CliError> {
        self.renewals.set(self.renewals.get() + 1);
        self.fresh.set(true);
        let refresh = Secret::new(self.session.borrow().refresh_token.expose());
        let t = self.cognito.refresh(&refresh)?;
        let mut s = self.session.borrow_mut();
        s.renewed(t, (self.now)());
        self.store.put(&self.key, &s)
    }

    /// `call` with the current tokens: renewed first when a run starts with
    /// them lapsing within two minutes, and when Salve refuses a token that
    /// it took before.
    fn with_tokens<T>(&self, call: impl Fn(&Secret, Option<&str>) -> Result<T, CliError>) -> Result<T, CliError> {
        if self.renewals.get() == 0 && self.session.borrow().lapsing((self.now)()) {
            self.renew()?;
        }
        let attempt = || {
            let s = self.session.borrow();
            let id = Secret::new(s.id_token.expose());
            let clinic = s.clinic_token();
            drop(s);
            let result = call(&id, clinic.as_deref());
            if result.is_ok() {
                self.fresh.set(false);
            }
            result
        };
        match attempt() {
            Err(e)
                if e.reason() == Some(Reason::CredentialRefused)
                    && !self.fresh.get()
                    && self.renewals.get() < MAX_RENEWALS =>
            {
                self.renew()?;
                attempt()
            }
            other => other,
        }
    }

    /// Any query: `salve api`'s.
    pub fn raw(&self, host: Host, document: &str, variables: &Value) -> Result<Answer, CliError> {
        self.with_tokens(|id, clinic| self.api.query(host, None, document, variables, id, clinic))
    }
}

impl Reader for Live<'_> {
    fn query(&self, op: &Op, variables: &Value) -> Result<Answer, CliError> {
        self.with_tokens(|id, clinic| salve::op_query(&self.api, op, variables, id, clinic))
    }

    fn file(&self, uri: &str, conversation: Option<i64>) -> Result<Vec<u8>, CliError> {
        let link = self.with_tokens(|id, clinic| self.api.file_link(uri, conversation, id, clinic))?;
        self.api.fetch(&link)
    }
}
