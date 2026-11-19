//! The command tree (piekstra-cli/1, health-records/v1, documents/v1).

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};
use clap_complete::Shell;
use pk_cli_auth::otp::CodeArgs;
use pk_cli_browser::BrowserArgs;
use pk_cli_core::{CommonArgs, RangeArgs};
use pk_cli_secrets::SecretSourceArgs;
use pk_cli_selfupdate::SelfUpdateArgs;

pub const BIN: &str = "salve";

/// The environment's fallback for --profile.
pub const PROFILE_ENV: &str = "SALVE_PROFILE";

/// Salve, the patient app fertility clinics use (patientwebportal.salvehealth.com):
/// documents and files, messages and their attachments, forms and video
/// visits, as health-records/v1 for a records store. Read-only; unofficial,
/// not affiliated with or endorsed by Salve Health or any clinic.
#[derive(Parser, Debug)]
#[command(name = BIN, version, about, long_about = None)]
pub struct Cli {
    #[command(flatten)]
    pub common: CommonArgs,

    /// Override the config file location.
    #[arg(long, global = true, value_name = "PATH")]
    pub config: Option<PathBuf>,

    /// The login to use: a profile added with `salve profiles add <NAME>`
    /// and signed in with `salve auth login --profile <NAME>`. There is no
    /// default profile.
    #[arg(long, global = true, env = PROFILE_ENV, value_name = "NAME")]
    pub profile: Option<String>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// The Salve sign-in, one per --profile.
    #[command(subcommand)]
    Auth(AuthCmd),
    /// The logins: one profile per Salve account (profile-list/v1).
    #[command(subcommand)]
    Profiles(ProfilesCmd),
    /// The clinics the profiles' accounts belong to (org-list/v1).
    #[command(subcommand)]
    Orgs(OrgsCmd),
    /// The patient a profile's login reads (patient-list/v1).
    #[command(subcommand)]
    Patients(PatientsCmd),
    /// The patient's records as records-stream/v1, for `medrec import --from salve`.
    #[command(subcommand)]
    Records(RecordsCmd),
    /// The clinic's documents, the record's files and message attachments (documents/v1).
    #[command(subcommand)]
    Documents(DocumentsCmd),
    /// One GraphQL query to Salve as --profile, printed as the JSON it
    /// answers: `salve api '{ me { patientid } }'`. Queries only: a mutation
    /// or subscription is refused before a request is made.
    Api(ApiArgs),
    /// Update to the latest release from GitHub.
    SelfUpdate(SelfUpdateArgs),
    /// Print a shell completion script.
    Completions { shell: Shell },
    /// Machine-readable capability discovery (cli-info/v1).
    Info,
}

#[derive(Subcommand, Debug)]
pub enum AuthCmd {
    /// Sign in to Salve as --profile and keep the sign-in in salve's vault:
    /// encrypted files under ~/.config/salve/vault/, sealed with a key held
    /// in the OS keychain (auth-login/v1).
    ///
    /// The email and password come from --stdin (two lines: email, then
    /// password), --from-env <VAR> (the same two lines), --op-item
    /// <op://VAULT/ITEM> (its username and password fields, read with the
    /// 1Password CLI), or --browser, which opens Salve's own sign-in page in
    /// the profile's own Chrome profile and reads the sign-in once you are
    /// in. Never on the command line, and never stored.
    ///
    /// Salve texts a code to the account's phone. At a terminal salve asks
    /// for it; otherwise it exits 3 and `--code <CODE>` finishes the sign-in
    /// within about 3 minutes, Cognito's limit.
    Login(LoginCmd),
    /// Whether the profile's sign-in is stored, and with --check whether
    /// Salve still takes it (auth-status/v1).
    Status {
        /// Ask Salve (one read, renewing the tokens if they lapsed).
        #[arg(long)]
        check: bool,
    },
    /// Revoke the profile's sign-in at Salve and remove it, then the
    /// browser profile its --browser sign-in keeps (auth-logout/v1).
    Logout,
    /// Remove every profile's stored sign-in and the vault's key from the
    /// keychain (auth-reset/v1). Asks first; without a terminal it needs
    /// --force (exit 6).
    Reset {
        /// Do not ask.
        #[arg(long)]
        force: bool,
    },
}

#[derive(Args, Debug)]
pub struct LoginCmd {
    /// The household's own name for the patient (`adult1`), kept in local
    /// config only. Defaults to the profile's name.
    #[arg(long, value_name = "WHO")]
    pub label: Option<String>,
    #[command(flatten)]
    pub source: SecretSourceArgs,
    /// A 1Password login item, op://VAULT/ITEM: its `username` and
    /// `password` fields are read with `op read`, one bounded call each.
    #[arg(long, value_name = "op://VAULT/ITEM", conflicts_with_all = ["stdin", "from_env", "browser"])]
    pub op_item: Option<String>,
    #[command(flatten)]
    pub code: CodeArgs,
    #[command(flatten)]
    pub browser: BrowserArgs,
    /// Replace the sign-in already stored for the profile.
    #[arg(long)]
    pub overwrite: bool,
}

#[derive(Subcommand, Debug)]
pub enum ProfilesCmd {
    /// The configured profiles, by name (profile-list/v1).
    #[command(visible_alias = "ls")]
    List,
    /// Add a profile: 1 to 32 lowercase letters, digits, `-` or `_`,
    /// starting with a letter or a digit (profile-add/v1).
    Add { name: String },
    /// Remove a profile with its stored sign-in and the browser profile its
    /// --browser sign-in keeps (profile-remove/v1). Asks first; without a
    /// terminal it needs --force (exit 6).
    Remove {
        name: String,
        /// Do not ask.
        #[arg(long)]
        force: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum OrgsCmd {
    /// The clinics the configured profiles signed in to (org-list/v1). Reads
    /// the local config only.
    #[command(visible_alias = "ls")]
    List,
}

#[derive(Subcommand, Debug)]
pub enum PatientsCmd {
    /// The profile's patient (patient-list/v1).
    #[command(visible_alias = "ls")]
    List,
}

#[derive(Subcommand, Debug)]
pub enum RecordsCmd {
    /// The patient's records as records-stream/v1: Patient, DocumentReference
    /// and Binary (documents, files, forms, message attachments),
    /// Communication (messages) and Encounter (video visits).
    Export(ExportArgs),
}

#[derive(Args, Debug)]
pub struct ExportArgs {
    /// The patient: its id from `salve patients list`, or its label. May be
    /// omitted: a login reads one patient.
    #[arg(long, value_name = "ID")]
    pub patient: Option<String>,
    /// Only what is dated on or after this day (YYYY-MM-DD). Forms carry no
    /// date of their own and are always included (the stream header lists
    /// what is unbounded in since_unbounded).
    #[arg(long, value_name = "YYYY-MM-DD")]
    pub since: Option<String>,
    /// Write the stream to stdout (`| medrec import --from salve`). The
    /// stream is the output, so --json with it is a usage error.
    #[arg(long, conflicts_with = "output")]
    pub ndjson: bool,
    /// Write the stream to DIR/records.ndjson instead (synthetic data from
    /// the stub only: real records go straight into medrec).
    #[arg(short, long, value_name = "DIR")]
    pub output: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
pub enum DocumentsCmd {
    /// The documents: what the clinic sent, files on the record and message
    /// attachments (document-list/v1).
    #[command(visible_alias = "ls")]
    List(RangeArgs),
    /// Save one document, or `--all` of them (document-download/v1,
    /// document-download-batch/v1).
    #[command(visible_alias = "get")]
    Download(DownloadArgs),
}

#[derive(Args, Debug)]
pub struct DownloadArgs {
    /// A document id from `salve documents list`.
    #[arg(required_unless_present = "all", conflicts_with = "all")]
    pub id: Option<String>,
    /// Every document.
    #[arg(long)]
    pub all: bool,
    /// The file to write (`-` for stdout), or with --all the folder.
    #[arg(short, long, value_name = "PATH")]
    pub output: Option<PathBuf>,
    /// Replace a file that is already there.
    #[arg(long)]
    pub overwrite: bool,
}

/// `salve api <QUERY> [--variables JSON] [--patient-api]`.
#[derive(Args, Debug, Clone)]
pub struct ApiArgs {
    /// A GraphQL query document. Queries only.
    pub query: String,
    /// The query's variables, a JSON object.
    #[arg(long, value_name = "JSON")]
    pub variables: Option<String>,
    /// Send it to the patient API (salve-api.salvehealth.co, the newer
    /// messaging's) instead of the app's (mobile.salvehealth.co).
    #[arg(long)]
    pub patient_api: bool,
}
