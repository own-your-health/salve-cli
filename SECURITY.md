# Security

Report a vulnerability privately through GitHub's "Report a vulnerability"
(Security tab), not in an issue.

## What salve touches

- Contacts no server except GitHub, for `self-update`, and Salve's hosts,
  which are constants in salve (`docs/api.md`): Amazon Cognito in eu-west-2
  for the sign-in, Salve's two GraphQL APIs, its file-link service, and the
  short-lived `https` download links that service answers. Every request is
  a sign-in step, a renewal, a revocation, one of salve's queries or a file,
  sent once, never retried, with a 60-second limit, following no redirect.
  `salve api` is held to queries, checked before anything is sent.
- Reads the email and password once per sign-in from stdin, a named
  environment variable, or a 1Password item (`op read`, one bounded call per
  field), or not at all with `--browser`, where they are typed into Salve's
  own page. The password is never sent: Cognito's SRP proves it. Neither is
  stored, logged or put on a command line. The texted code is read at the
  terminal, from `--code`, or from stdin with `--code -`.
- Stores one credential per profile, Cognito's ID, access and refresh
  tokens, with the patient's id, name and birth date and the clinic's id and
  name, as one vault entry; and, for about 3 minutes, a sign-in waiting on
  its code. The vault (`pk_cli_auth::vault`) is encrypted owner-only files
  under `~/.config/salve/vault/`, with one key in the keychain (service
  `piekstra.salve`, account `vault-key`).
- Keeps one Chrome profile per salve profile for `auth login --browser`:
  `~/Library/Application Support/piekstra.salve/browser-profile-<profile>`
  (under `$XDG_DATA_HOME` on Linux), owner-only (`0700`). It holds Salve's
  site storage, including its tokens. `--fresh-profile` signs in without it.
- Writes only where asked: `documents download` (owner-only `0600` files,
  never replacing one without `--overwrite`, each checked against what its
  type says it is) and `records export -o` (the stub on this machine only).
- `auth logout --profile <NAME>` has Salve forget the sign-in's device and
  revokes the sign-in (a failure of either is a warning; the sign-in is
  removed anyway), then removes it, any sign-in
  waiting on a code, and the Chrome profile. `profiles remove <NAME>` removes
  the same without contacting Salve, and `auth reset` every sign-in and the
  vault key. Revocation signs out this sign-in only, not the patient's
  phone.
- The config file holds the profile names and each one's clinic and label.

## What salve never does

- Writes to Salve: no message is sent or marked read, no form submitted, no
  document marked read, no setting changed. Salve's mutations are listed in
  `docs/api.md`; none is ever sent. The one exception is Cognito's own
  device record: a sign-in confirms its device (`ConfirmDevice`), as Salve's
  app does, which adds `salve (command line)` to the account's devices.
  `auth logout` forgets it (`ForgetDevice`), and so does a sign-in that
  stores nothing.
- Sends a record or its contents anywhere but stdout or a file you name.
- Sends a credential to a host it was not issued for: the ID token goes to
  Salve's APIs and file-link service only, the clinic's token to the patient
  API and file-link service only, and a download link is fetched with no
  credential.
