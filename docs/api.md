# Salve's patient app API

Salve (Salve Technologies Ltd) is a patient app that fertility clinics give
their patients: messages with the care team, documents and files, forms and
video visits. A clinic's records reach it from the clinic's own system. The
web version is a Next.js app at `https://patientwebportal.salvehealth.com`.
It signs in with Amazon Cognito and reads two GraphQL APIs. salve calls them
the way the app does.

Everything below was read from the web app's code (build
`SLwjbRWPWnATD9snq-Tbr`, downloaded 2026-11-19) and from two unauthenticated
probes of Cognito and the APIs, except where it says otherwise. The first
real sign-in confirmed the sign-in: the SRP proof, the texted
code and the tokens, and the app API's `AwaitingSync` answer for an account
whose clinic had not finished linking it (below). A real export then read
every list below, and corrected two things the code alone had not shown: the
form's numbers are integers, and how the message lists page (both in Traps).
`tests/fixture_shapes.rs` pins what salve expects, so a difference shows
there first.

## Route

| Question | Answer, 2026-11-19 |
| --- | --- |
| A patient FHIR API (ONC certified, SMART on FHIR) | None. Salve is a patient-engagement app, not an EHR, and publishes no FHIR endpoint, patient API or SMART launch. A clinic's certified EHR, where it has one, is a separate route with its own CLI |
| A developer program | None public: no documentation, sandbox or sign-up, and no export or data-access feature in the app beyond deleting the account |
| The terms | Salve's end-user licence forbids automated access to the service. They raise nothing beyond automated access |
| The route | The web app's own APIs, signed in as the patient, read-only |

salve reads only the signed-in patient's own records, one request at a time,
each list once, and sends none of the app's writes (below).

## Hosts

| Host | What |
| --- | --- |
| `cognito-idp.eu-west-2.amazonaws.com` | the sign-in: user pool `eu-west-2_PS2EMAFqC`, web client `3l84pov0p680vfm3qr6dbp7gog` (no client secret) |
| `mobile.salvehealth.co/app/graphql` | the app API: the patient, clinic, documents, files, forms, video visits, the first messaging |
| `salve-api.salvehealth.co/patient/graphql` | the patient API: the newer messaging |
| `s3presign.salvehealth.co` | turns a file's address into a short-lived download link |
| `patientwebportal.salvehealth.com` | the web app; `--browser` signs in there |

These are constants in salve. Nothing a user passes or an answer says moves
a credential to another host. `SALVE_STUB_URL` points all of them at a stub
on this machine, for tests, and accepts only a loopback `http` address.

## Sign-in

Every Cognito call is `POST https://cognito-idp.eu-west-2.amazonaws.com/`
with `content-type: application/x-amz-json-1.1` and `x-amz-target:
AWSCognitoIdentityProviderService.<Action>`.

| Step | Call | Answer |
| --- | --- | --- |
| Start | `InitiateAuth`, `AuthFlow: USER_SRP_AUTH`, `AuthParameters: {USERNAME: <email>, SRP_A}` | `ChallengeName: PASSWORD_VERIFIER`, `ChallengeParameters: {SALT, SRP_B, SECRET_BLOCK, USER_ID_FOR_SRP, USERNAME}` |
| Prove the password | `RespondToAuthChallenge`, `ChallengeName: PASSWORD_VERIFIER`, `ChallengeResponses: {USERNAME: <USER_ID_FOR_SRP>, PASSWORD_CLAIM_SECRET_BLOCK, TIMESTAMP, PASSWORD_CLAIM_SIGNATURE}` | `ChallengeName: SMS_MFA`, `Session`, `ChallengeParameters: {CODE_DELIVERY_DESTINATION}` (the masked number); or `AuthenticationResult` for an account without a code |
| The texted code | `RespondToAuthChallenge`, `ChallengeName: SMS_MFA`, `Session`, `ChallengeResponses: {USERNAME, SMS_MFA_CODE}` | `AuthenticationResult: {IdToken, AccessToken, RefreshToken, ExpiresIn}` |
| Confirm the device | `ConfirmDevice`, `{AccessToken, DeviceKey, DeviceName, DeviceSecretVerifierConfig: {PasswordVerifier, Salt}}`, no `ClientId` | `{UserConfirmationNecessary}` |
| Renew | `InitiateAuth`, `AuthFlow: REFRESH_TOKEN_AUTH`, `AuthParameters: {REFRESH_TOKEN, DEVICE_KEY}` | a new `IdToken` and `AccessToken`; no new refresh token |
| Sign out | `RevokeToken`, `{ClientId, Token: <refresh token>}` | `{}`; the refresh token and the tokens it issued stop working |

The two probes, with an invented email and no password:

| Probe | Answer |
| --- | --- |
| `InitiateAuth` with `USER_PASSWORD_AUTH` | `InvalidParameterException`: the flow is not enabled for this client |
| `InitiateAuth` with `USER_SRP_AUTH` | `UserNotFoundException` |

So the web client takes SRP only, and the password is proved, never sent.
salve implements Cognito's SRP variant itself (`src/srp.rs`):

- `N` is RFC 5054's 3072-bit prime, `g = 2`, `k = H(pad(N) | pad(g))`, with
  SHA-256 and `pad` the even-length hex with a leading `00` when the top bit
  is set.
- `A = g^a` for 128 random bytes `a`, sent as unpadded lowercase hex.
- `u = H(pad(A) | pad(B))`;
  `x = H(pad(salt) | H(poolName | userId | ":" | password))`, where the
  pool name is what follows `_` in the pool's id (`PS2EMAFqC`) and `userId`
  is `USER_ID_FOR_SRP`, not the email.
- `S = (B - k·g^x)^(a + u·x) mod N`. The key is HKDF-SHA256 with salt
  `pad(u)` and input `pad(S)`, info `"Caldera Derived Key"`, first 16 bytes.
- The signature is base64 of HMAC-SHA256 under that key of
  `poolName | userId | base64-decoded SECRET_BLOCK | TIMESTAMP`.
- `TIMESTAMP` is `EEE MMM d HH:mm:ss UTC yyyy` in UTC, with the day **not**
  zero-padded (`Thu Nov 5 09:07:03 UTC 2026`).

`tests/srp_vector.rs` checks `k`, `A`, the key and the signature against
AWS's own client (`amazon-cognito-identity-js` 6.1.2) run on fixed,
invented inputs. A mistake in this maths would look exactly like a wrong
password, and each wrong password counts toward the pool's limit.

The web app keeps the tokens in local storage, as Amplify does:
`CognitoIdentityServiceProvider.<client>.LastAuthUser` names the user, and
`CognitoIdentityServiceProvider.<client>.<user>.idToken`, `.accessToken` and
`.refreshToken` hold the tokens. `auth login --browser` reads them from
there once the person has signed in on the page.

The ID token carries the patient's `given_name`, `family_name`,
`birthdate`, `email`, `phone_number`, `sub`, and two claims of Salve's:
`custom:clinictoken`, which the patient API takes beside the sign-in, and
`custom:consentid`.

## The APIs

Both are GraphQL over `POST`, `content-type: application/json`, body
`{"operationName", "variables", "query"}`, with:

| Header | Value |
| --- | --- |
| `authorization` | the **ID token**, bare: no `Bearer` |
| `x-salve-clinic-token` | the ID token's `custom:clinictoken`; the patient API and the file-link service only |

Introspection is disabled. Without a token both answer `{"message":
"Unauthorized"}`. A field Salve cannot resolve comes back `null` with an
`errors` entry, under HTTP 200. An account the clinic has not finished
setting up answers `{"errorCode": ...}` in place of `data`:
`Unregistered`, `AwaitingDetails`, `AwaitingSync` or `Error`.

### What salve reads

The selections are the web app's own (`src/queries.rs`), without its
client-only `@client` fields.

| Query | API | Variables | What |
| --- | --- | --- | --- |
| `GetPatientAndClinic` | app | none | `me {email name patientid}`, `clinic {_id name}` |
| `GetPatientId` | app | none | `me {patientid firstname lastname}` |
| `GetDocuments` | app | none | what the clinic sent: `id name uri readdate filetype sentdate uuid` |
| `GetFiles` | app | none | files on the record, aliased as the app does: `name: filename`, `uri: url`, `sentdate: date` |
| `GetForms` | app | none | the forms assigned: `id patientformid version name type progressStatus` (`Complete`, `InProgress`, `NotStarted`) |
| `GetForm` | app | `input: {id, patientformid, version}` | one form's `definition` and `latestsubmission {submission issubmitted}` |
| `GetVideoCalls` | app | `input: {date, order, dateOperator, page, size}`: `LTE` with `DESC` for past visits, `GTE` with `ASC` for coming ones | `... on VideoCall {id title host startdate enddate duration}` |
| `GetConversations` | patient | `limit`, `cursor` | a page of the newer messaging's conversations, and the next page's `cursor` |
| `GetConversationMessages` | patient | `conversationId`, `limit`, `cursor` | a page of messages, and the next page's `cursor` |
| `FetchConversations` | app | none | the first messaging's conversations |
| `GetConversation` | app | `conversationId` | `conversationV2`: its messages, some in `MessageGroup`s, files as `MessageFileMetadata` |

The app chooses its messaging by a remote setting. salve reads the newer
one first, and the first one when the newer has no conversation for the
patient or does not answer.

`salve api` sends one query document to either API and prints `data`. It
refuses any document with a `mutation` or `subscription` before it reads a
sign-in (`salve::check_read`), so it cannot send the app's writes either.

### Files

| Step | Call | Answer |
| --- | --- | --- |
| A link | `POST https://s3presign.salvehealth.co/patient/read`, with `?conversationId=<id>` for a message's file; `authorization` and `x-salve-clinic-token` as above; body `{"url": <the file's uri>}` | `{"url": <a presigned S3 link>}` |
| The bytes | `GET` that link, with **no** credential | the file |

salve fetches only an `https` link, follows no redirect from it, caps a
file at 200 MB, and checks a PDF or image against its first bytes. A file
that is not what it claims to be is a skip, not a document.

### What salve never sends

The app's writes, read from its code and never called by salve:
`SendFileMessageV2`, `CreateConversation`, `CreateConversationMessage`,
`MarkDocumentAsRead`, `SubmitPatientForm`, `SetActiveClinic`,
`UpsertAccountPreferences`, `UpdatePreferences`, `UpdateLastLogin`,
`RegisterDevice`, `UnregisterDevice`, `RegisterConsent`, `RegisterPatient`,
`JoinVideoCall` and `DeleteAccount`. Reading a document does not mark it
read: salve sends no `MarkDocumentAsRead`.

The clinic's information library (articles and videos for every patient) is
not read: it is not the patient's record.

## How it maps

| Salve | FHIR |
| --- | --- |
| The patient (`me`, and the ID token's birth date) | `Patient` |
| A document the clinic sent | `DocumentReference` `doc-<id>` and `Binary` |
| A file on the record | `DocumentReference` `file-<id>` and `Binary` |
| A form the patient started or finished | `DocumentReference` `form-<patientformid>-<version>` (`final` when submitted, `preliminary` before) and a `Binary` holding Salve's JSON: the definition and the answers |
| A video visit | `Encounter` `video-<id>`, class `VR`, `planned` before its start and `finished` after |
| A message | `Communication` `cmsg-<id>` (newer messaging) or `msg-<id>` (first), the conversation as its `topic`; deleted and system messages are left out |
| A message's file | `DocumentReference` `att-<uuid>` and `Binary`, its context the message |

A form is kept as Salve's JSON because its schema is Salve's own and not
published; a `QuestionnaireResponse` would mean guessing it.

## Traps

- **SRP only.** The web client refuses `USER_PASSWORD_AUTH`, so there is no
  simple sign-in to fall back to. The maths is checked offline against AWS's
  client; never debug it against the real pool.
- **The timestamp's day is unpadded.** `Nov 05` instead of `Nov 5` fails
  the signature, which Cognito reports as a wrong password.
- **`USERNAME` changes between steps.** The first step takes the email; the
  proof and the code take `USER_ID_FOR_SRP`.
- **Every sign-in texts a code**, and Cognito holds the waiting sign-in for
  about 3 minutes. Without a terminal, `auth login` parks it in the vault and
  exits 3; `auth login --code -`, with the code on stdin, finishes it. A code sent while nobody
  is there to read it is wasted, and Cognito limits how many it sends.
- **The ID token, not the access token, and no `Bearer`.** The APIs refuse
  anything else as unauthorized.
- **The clinic token goes to the patient API and the file-link service
  only**, from the ID token's claim; the app API never gets it.
- **Errors arrive under HTTP 200**, as `data: null` beside `errors`, or as
  `errorCode` in place of `data`. salve reads the body, not the status.
- **`AwaitingSync` is HTTP 412** with `{"errorCode": "AwaitingSync"}`, and
  it is a state of the account, not a failed request: the clinic has not
  finished linking the patient. Salve's web app shows a "syncing" page that
  reads `GetPatientAndClinic` every 2 seconds until the clinic is there, and
  sends nothing to start the sync. A sign-in reads it every 3 seconds for up
  to 3 minutes the same way, then stops and keeps nothing. On the first real
  sign-in it did not clear in those 3 minutes.
- **A list comes whole without a limit, and its cursor then points past the
  end.** `conversations` and `conversationMessages` answer every page with a
  cursor, and the cursor from a page asked for without a limit fails when
  sent back ("Failed to fetch conversation messages"). With a limit, the
  cursor at the end answers an empty page and no cursor. salve asks for 100
  a page and follows the cursor only after a full page; a short or empty
  page is the end. One
  conversation that fails is a skip for that conversation only.
- **`FormInput` takes `patientformid` and `version` as integers**, as the
  form list answers them; a string is refused ("Int cannot represent
  non-integer value").
- **The pool tracks devices.** The sign-in's `AuthenticationResult` also
  carries `NewDeviceMetadata: {DeviceKey, DeviceGroupKey}`, and each access
  token names the device (`device_key`). A renewal is refused with
  `NotAuthorizedException` "Invalid Refresh Token." unless it names the
  device and the device was confirmed first. Real sign-ins confirmed this.
  A renewal naming no device is refused. So is one naming the device before
  `ConfirmDevice`. One naming it after `ConfirmDevice` is taken. salve
  confirms the device the way AWS's reference client does
  (`generateHashDevice`: a random password hashed with the device group and
  key under a random salt). It drops the password, so it never signs in as
  the device, and a device never stands in for the texted code.
- **Renewal answers no refresh token.** The one from the sign-in is kept
  until it lapses or is revoked. A token that worked and is then refused is
  renewed once; a token refused right after its renewal means the sign-in
  itself is gone (exit 3).
- **`RevokeToken` signs out this sign-in only**, not the patient's phone.
- **Download links are credentials** while they last. salve never logs,
  prints or keeps one.
- **Two messagings.** Which one a clinic's patients see is Salve's remote
  setting; salve reads both ways.
