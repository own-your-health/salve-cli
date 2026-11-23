# AGENTS.md — salve-cli

`salve` is a read-only CLI for Salve, the patient app fertility clinics give
their patients. It signs in as the patient (Amazon Cognito, SRP and a texted
code), reads the GraphQL APIs Salve's own web app calls, and emits FHIR for
the household's medical-records system (`records-stream/v1`, `medrec import
--from salve`). It conforms to piekstra-cli/1 and the `health-records/v1` and
`documents/v1` profiles, on the `pk-cli-*` crates from
[cli-common](https://github.com/piekstra/cli-common) and `pk-med-records`
from [medical-common](https://github.com/own-your-health/medical-common), which owns
the records stream, the export file and the profile's DTOs. Every `pk-cli-*`
stays on the cli-common tag medical-common pins.

## Layout

| File | Owns |
|---|---|
| `src/cli.rs` | the clap tree |
| `src/app.rs` | the commands, argument checks, output; `Env` (where sign-ins are kept, whether the run is hermetic, whether it may prompt, and a stub's address) and `run`, which the in-process tests call |
| `src/auth.rs` | `auth login` (stdin, environment, 1Password, browser, `--code`), `status`, `logout`, `reset`; `LoginSettings`, the profile's clinic and label in config |
| `src/srp.rs` | Cognito's SRP: the password's proof, never the password |
| `src/cognito.rs` | the Cognito calls: sign-in, the texted code, renewal, revocation, and how its errors map to exit codes |
| `src/endpoints.rs` | Salve's hosts, as constants, or a loopback stub's |
| `src/salve.rs` | the GraphQL client, the file links and downloads, `check_read`, and how answers map to exit codes |
| `src/queries.rs` | every query salve sends, as the web app writes it |
| `src/live.rs` | a stored sign-in as a reader: renews lapsing tokens and writes them back |
| `src/session.rs` | `SessionStore`: a profile's sign-in in the vault, keyed `<profile>/<clinic>/<label>`, and the waiting sign-in's slot; the only code that knows where they live |
| `src/model.rs` | Salve's answers, every field optional and lenient about its JSON type |
| `src/pull.rs` | `Reader`, the documents listing and the export: every list in order, both messagings, skips, `--since` |
| `src/fhir.rs` | the FHIR mapping, by hand |
| `docs/api.md` | the route decision, every call, and the traps |

## Medical data rules

These come from the household's plan and are not negotiable.

- The repository carries no personal data, in code, fixtures, docs, commits,
  pull requests or issues: no names, clinics the household uses, ids or real
  answers. Fixtures are synthetic (`tests/fixtures/README.md`);
  `tests/no_personal_data.rs` scans every tracked file and checks every
  identity field in the fixtures against its dummy value.
- Records and their contents are never sent to an outside service: no
  health-data aggregator, cloud OCR or other company's API. A Claude session
  is not one of these (the household's decision, 2026-11-17). A session may
  read the household's real records when the work needs it; real data stays
  out of tracked files, commits, pull requests and issues, and out of
  messages to other sessions unless they need it. A raw capture is deleted
  from `/tmp` once it has served.
- `records export -o DIR` is refused for Salve itself (only the stub on this
  machine may write a file); real records go straight into medrec through a
  pipe.
- No FHIR, SMART or DICOM libraries, no aggregators, no AWS or Amplify SDK,
  no one else's integration. The household's own crates (cli-common,
  medical-common) are not third party. General-purpose crates (big integers,
  SHA-256, HMAC) are fine.
- Read-only. salve sends only the queries in `src/queries.rs`, and
  `check_read` refuses any GraphQL document with a mutation or subscription,
  `salve api`'s included. A write would need SPEC §1.3's confirmation gate
  and a change to this paragraph in the same commit. The one exception is
  Cognito's device record: a sign-in confirms its device, as Salve's app
  does, and `auth logout` forgets it (`src/cognito.rs`).
- No credential, token, code, session handle or download link is printed,
  logged or put on a command line. The password is never stored, and SRP
  means it is never sent.

## Profiles and sign-ins

A profile is cli-common's (`pk_cli_config::profile`, DESIGN.md §2.5):
configured in salve's config (`profiles add`), resolved by
`profile::resolve` (missing, malformed or unknown is exit 2 listing the
configured names; a lone profile is never picked). A profile's settings
(clinic id and name, label) are saved by its first successful sign-in.

A sign-in is one vault entry (`pk_cli_auth::vault::Vault::for_binary`: one
keychain item, `vault-key` in `piekstra.salve`, and an encrypted file per
entry under `~/.config/salve/vault/`). A sign-in waiting on its code is the
entry `pending/<profile>`, through `pk_cli_auth::otp`'s parking slot, for
at most `auth::CODE_WINDOW_SECS`. `profiles remove` removes the sign-in and
the browser profile before the profile; `auth reset` is `Vault::clear`.

## Salve

Read `docs/api.md` before changing a call. Every call is one request, never
retried, 60 seconds at most, following no redirect. A refused password or
code is spent once.

**The texted code costs the patient something.** Every sign-in texts one to
a real phone, and Cognito limits how many it sends. Sign in to the real
account only when the work needs it and the person is there to read the
code, and never in a loop. The test suite never reaches Cognito.

Map Salve by reading its web app's code and, signed in, its traffic (the
`browser-explore` loop). Be gentle: one request at a time, no crawling.

## Tests are offline, always

`cargo test` reads no real keychain item or browser profile, contacts
nothing beyond loopback, and reads no real record.

- `tests/common/mod.rs`: a stub Salve on 127.0.0.1. It holds one user's SRP
  verifier and checks the proof as Cognito does, texts the dummy code,
  issues, renews and revokes tokens, answers the GraphQL queries from
  `tests/fixtures/salve/`, serves files through presigned links, and logs
  every request and any credential sent where it does not belong.
- `tests/e2e.rs`: every command in process (`app::run`) against the stub,
  with sign-ins in `Vault::new(MemoryKeys, dir)` and prompts off: the parked
  code, export, both messagings, skips, renewal, a revoked sign-in, refused
  passwords and codes, documents, the passthrough's refusals, sign-out,
  reset. It asserts the password is never sent and nothing writes.
- `tests/cli_surface.rs`: the binary, with `SALVE_KEYCHAIN_SERVICE` set to
  an empty service and a per-test `XDG_CONFIG_HOME`; only paths that store
  nothing: every `--help`, exit codes, the JSON error, `info`, completions,
  `NO_COLOR`, a refused sign-in against the stub.
- `tests/srp_vector.rs`: the SRP maths against AWS's reference client.
- `tests/fixture_shapes.rs`: the models over the fixtures, and each
  fixture's keys against its query's selection.
- `tests/no_personal_data.rs`.

`examples/stub-salve.rs` runs the same stub as a process, for driving the
binary by hand (README § Development). That writes a vault key to the
keychain under the scratch service: remove it with `auth reset --force`
using the same build, because macOS asks before a rebuilt binary reads it.

`make verify` = fmt-check, clippy, test, smoke.
