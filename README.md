# salve

Unofficial; not affiliated with or endorsed by Salve Health (Salve
Technologies Ltd) or any clinic.

`salve` reads a patient's records from Salve, the patient app fertility
clinics give their patients, and hands them to the household's
medical-records system as FHIR (`records-stream/v1`, read by `medrec import
--from salve`). It covers the documents the clinic sent, the files on the
record, messages and their attachments, the forms the patient filled in, and
video visits. It is read-only: it sends Salve's own queries, and none of the
app's writes.

Salve publishes no patient API. salve reads the APIs Salve's own web app
calls, as the patient, with the patient's sign-in. `docs/api.md` records how
that was decided and every call salve makes.

## Install

```sh
cargo install --git https://github.com/piekstra/salve-cli --locked
# or download a release: salve-<target>.tar.gz, then `salve self-update` later
```

## Use

One profile per Salve account:

```sh
salve profiles add adult1
salve auth login --profile adult1 --op-item "op://Private/Salve"   # Salve texts a code; type it when asked
salve auth status --profile adult1 --check    # one read: does Salve still take the sign-in?
salve patients list --profile adult1
salve documents list --profile adult1
salve documents download --all --profile adult1 -o ~/Archive/Salve
salve records export --profile adult1 --ndjson | head -1    # the stream's header

# medrec runs the export itself:
medrec config set providers salve
medrec import --from salve --from-profile adult1 --patient <id> --profile <records folder>

# One GraphQL query, printed as the data it answers (docs/api.md lists them):
salve api '{ me { patientid } }' --profile adult1
```

Every command that reads Salve takes `--profile <NAME>` (or
`SALVE_PROFILE`). There is no default profile, and a lone profile is never
picked: without one, or with one not configured, the command is exit 2 and
lists the configured profiles. `profiles`, `orgs`, `auth reset`, `info`,
`self-update` and `completions` take no `--profile`.

Every command takes `--json` and prints one schema-tagged document, except
`records export --ndjson`, whose NDJSON stream is the output (`--json` with
it is exit 2).

| Command | Output schema |
| --- | --- |
| `patients list` | `patient-list/v1` |
| `records export` | `records-stream/v1` (NDJSON) |
| `documents list` / `download` | `document-list/v1` / `document-download/v1`, `document-download-batch/v1` |
| `orgs list` | `org-list/v1`: the clinics the profiles signed in to, from local config |
| `api` | `api-response/v1`: the query's `data` and `errors`, as Salve answers them |
| `auth login` / `status` / `logout` / `reset` | `auth-login/v1` / `auth-status/v1` / `auth-logout/v1` / `auth-reset/v1` |
| `profiles list` / `add` / `remove` | `profile-list/v1` / `profile-add/v1` / `profile-remove/v1` |
| `info` | `cli-info/v1`: profiles `health-records/v1` and `documents/v1`, capability `login-profiles` |

Exit codes: 0 ok, 2 usage (including a GraphQL document with a mutation in
it), 3 not signed in, a refused password or code, or a sign-in Salve no
longer takes, 4 not found (a document id Salve does not list), 5 Salve's
answer could not be read or it failed, 6 a destructive command (`auth
reset`, `profiles remove`) without a terminal to ask on and without
`--force`.

## Signing in

Salve signs in with Amazon Cognito, which proves the password without it
ever being sent (SRP), then texts a code to the account's phone. The email
and password come from one of:

| Flag | Where they come from |
| --- | --- |
| `--op-item op://VAULT/ITEM` | the 1Password item's `username` and `password` fields, one `op read` each (1Password may ask to approve) |
| `--stdin` | two lines on stdin: the email, then the password |
| `--from-env VAR` | the same two lines in an environment variable |
| `--browser` | Salve's own sign-in page, in a Chrome window salve opens; you type the code there, and salve reads the sign-in once you are in |

They are never taken on the command line and never stored. A refused
password is exit 3, sent once and never retried.

At a terminal, salve asks for the texted code. Without one, it keeps the
waiting sign-in in its vault and exits 3; `salve auth login --profile
<NAME> --code <CODE>` (or `--code -` to read it from stdin) finishes it.
Cognito holds a waiting sign-in about 3 minutes. A wrong code is exit 3 and
the sign-in still waits.

What is kept is Cognito's tokens. The ID token lasts an hour; salve renews it
from the refresh token when it is about to lapse or Salve refuses it, with no
password or code, and writes the renewed one back. When the refresh token
lapses or is revoked, every reading command is exit 3 naming the sign-in
that starts again (`auth login --profile <NAME> --overwrite`). With a
sign-in already stored for the profile, `auth login` is exit 2 unless
`--overwrite`.

| What | Where | Removed by |
| --- | --- | --- |
| The sign-in: the ID, access and refresh tokens, when they lapse, the patient's id, name and birth date, the clinic's id and name, the sign-in time; one entry `<profile>/<clinic>/<label>` | salve's vault: one encrypted, owner-only (`0600`) file per entry under `~/.config/salve/vault/`, sealed with one key, the keychain item `vault-key` in service `piekstra.salve` | `salve auth logout --profile <NAME>`, which first revokes the sign-in at Salve; `salve auth reset` removes every entry and the key |
| A sign-in waiting on its code | the same vault, entry `pending/<profile>` | finishing it, or `auth logout` |
| The Chrome profile `--browser` signs in through, one per profile | `~/Library/Application Support/piekstra.salve/browser-profile-<profile>`, owner-only (`0700`); under `$XDG_DATA_HOME` on Linux | `salve auth logout --profile <NAME>`, after the sign-in |
| The profile's clinic and label | salve's config file | `salve profiles remove <NAME>`, after its sign-in and browser profile |

## What the export carries

| Salve | FHIR |
| --- | --- |
| The signed-in patient | `Patient`, with the birth date from the sign-in |
| Documents the clinic sent, files on the record | `DocumentReference` and `Binary` |
| Forms the patient started or finished | `DocumentReference` (`final` once submitted, `preliminary` before) and a `Binary` holding Salve's JSON: the form and the answers. Forms never opened stay out |
| Video visits | `Encounter`, class virtual, `planned` before its start and `finished` after |
| Messages | `Communication`, the conversation as its topic; each attachment a `DocumentReference` and `Binary`. Deleted and system messages stay out |

Every resource carries `meta.source` `salve:app`, a stable id, and a tag
saying it was mapped from Salve. A `Binary` follows the resource that names
it. What Salve does not serve (a list that fails, a file that is missing or
not the PDF it claims to be) is a skip in the stream's trailer with its
code, not an error. A sign-in Salve stops taking mid-export ends the stream
incomplete (`complete: false`, exit 3), and medrec files nothing from it.

`--since D` leaves out what is dated before D. Forms and the patient carry
no date of their own and are always included; the header lists them in
`since_unbounded`.

`-o DIR` writes the stream to `DIR/records.ndjson` instead (`0600`, under a
temporary name renamed into place). It is for the stub on this machine only:
against Salve it is exit 2, and real records go straight into medrec.

## Development

`make verify` runs fmt-check, clippy, the tests and the smoke test. The
tests are offline: a stub Salve on 127.0.0.1 checks the SRP proof as
Cognito does and answers from synthetic fixtures (`tests/fixtures/README.md`),
and sign-ins live in an in-memory vault. See `AGENTS.md` and
`CONTRIBUTING.md`.

To try salve by hand on synthetic data, run the same stub as a process and
point salve at it and at a scratch vault:

```sh
cargo run --example stub-salve        # prints its address, email, password and code
export XDG_CONFIG_HOME=$(mktemp -d) SALVE_KEYCHAIN_SERVICE=piekstra.salve.stub-$(date +%s)
export SALVE_STUB_URL=<address>
salve profiles add test
printf '%s\n' patient@example.com right-password | salve auth login --profile test --stdin
salve auth login --profile test --code 123456
```

The scratch service holds a vault key while you try it: `salve auth reset
--force` removes it, with the same build that made it (a rebuilt binary is a
new code identity, and macOS asks before it reads an item another build
made). `STUB_SCENARIO` (`no-mfa`, `v0-messaging`, `patient-api-fails`,
`files-fail`, `bad-pdf`, `missing-file`, `short-tokens`, `refresh-revoked`,
`revoke-unsupported`, `awaiting-sync`, `expire-after=N`) makes it answer the
way the tests' cases do.

## License

MIT or Apache-2.0, at your option.
