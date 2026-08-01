# TOTP

TOTP means Time-Based One-Time Password.

In this project, TOTP refers to authenticator-app based MFA, not email OTP and not SMS OTP.

Examples of compatible authenticator apps include Aegis, 1Password, Bitwarden, Google Authenticator, Microsoft Authenticator, and similar tools.

## Core Idea

TOTP is based on a shared secret.

The server generates a secret during enrollment. The user scans a QR code with an authenticator app. The QR code contains an `otpauth://` URI that gives the app the secret and parameters required to generate codes.

After enrollment:

- the server stores the secret;
- the authenticator app stores the same secret;
- both sides use the current time to compute the expected code;
- the user submits the code shown by the app;
- the server recalculates the expected code and compares it.

The server does not send the six-digit code to the user. It verifies a code generated independently by the authenticator app.

## Secret vs Code

The TOTP secret is long-lived and security-critical.

The TOTP code is short-lived and usually changes every 30 seconds.

The distinction matters:

- the secret must be stored securely and never logged;
- the code may be submitted by the user but must not be stored as a reusable credential;
- compromising the secret compromises all future codes;
- compromising one code should only affect a short time window.

## Simple Mental Model

Think about the TOTP flow in three different layers:

```text
Base32      = text format used to transport/display the secret
TotpSecret  = server-side object that represents an acceptable shared secret
TOTP code   = short six-digit code generated later from the secret + current time
```

What has been implemented first in `v0.5.0`:

- `Base32`, because authenticator apps expect secrets in this format;
- `TotpSecret`, because the project needs a safe object for generating and validating shared secrets;
- `otpauth://` URI generation, because authenticator apps need a standard provisioning payload;
- code generation and verification, because the server must independently compute and check submitted codes;
- persistence structure, because enrollment state and verification parameters must survive requests.

What has not been implemented yet:

- the QR code;
- the HTTP enrollment screens;
- the first-code confirmation flow;
- TOTP enforcement during login.

So Base32, `TotpSecret`, provisioning URIs, and persistence records are not the login code shown by the authenticator app. They are the foundation that allows the app and the server to share the same secret and parameters before codes can be generated and verified.

## The `otpauth://` URI

Authenticator apps commonly understand URIs shaped like this:

```text
otpauth://totp/Issuer:account@example.com?secret=BASE32SECRET&issuer=Issuer&algorithm=SHA1&digits=6&period=30
```

The URI tells the app:

- the account label;
- the issuer/service name;
- the shared secret;
- the hash algorithm;
- the number of digits;
- the time period.

The QR code shown during enrollment is a visual encoding of this URI.

The URI is not the QR code itself. The QR code is only a visual container that encodes this URI so the authenticator app can read it.

The provisioning chain is:

```text
TotpSecret
    -> Base32
    -> otpauth:// URI
    -> QR code
    -> authenticator app
```

With the default project settings, the URI communicates:

```text
Type        = TOTP
Service     = Modern Auth Lab
Account     = dev@example.com
Secret      = Base32 shared secret
Algorithm   = SHA1
Digits      = 6
Period      = 30 seconds
```

The project keeps these values configurable:

- `issuer`, the service/provider shown by the app;
- `accountLabel`, the account shown by the app;
- `algorithm`, currently allowed as `SHA1`, `SHA256`, or `SHA512`;
- `digits`, currently allowed as `6` or `8`;
- `period`, the code validity period in seconds.

Defaulting to `SHA1`, `6` digits, and `30` seconds is a compatibility choice. SHA1 is not recommended for new general-purpose signatures, but TOTP commonly uses HMAC-SHA1 with a shared secret and short time window. The class remains configurable so stronger algorithms can be tested without changing the provisioning model.

## Code Generation

TOTP code generation is deterministic.

The authenticator app and the server do not communicate when a code is generated. They independently compute the same code because they share:

- the same secret;
- the same algorithm;
- the same number of digits;
- the same period;
- approximately the same time.

Conceptually:

```text
TOTP code = function(secret, current time, algorithm, digits, period)
```

TOTP is based on HOTP:

```text
HOTP = secret + counter
TOTP = secret + time-derived counter
```

For TOTP, the counter is:

```text
counter = floor(timestamp / period)
```

With the common 30-second period, every timestamp in the same 30-second time step produces the same code.

This project generates codes as strings, not integers, because leading zeroes are valid:

```text
000123
```

## Code Verification Window

TOTP verification usually accepts a small clock window.

With:

```text
window = 1
```

the server checks:

```text
currentStep - 1
currentStep
currentStep + 1
```

In other words:

- previous step;
- current step;
- next step.

If the period is 30 seconds, this tolerates approximately:

```text
30 seconds before
30 seconds after
```

Important: this does not mean the same code is valid for exactly 90 seconds. It means the server accepts codes calculated for three possible time steps.

Example:

```text
period = 30
window = 1
server timestamp = 12:00:31
currentStep = floor(timestamp / 30)
```

The server tests:

- code for the previous step;
- code for the current step;
- code for the next step.

This is useful when:

- the phone clock is slightly behind;
- the server clock is slightly ahead;
- the user submits a code close to the moment it expires.

The window should stay small:

- with `window = 2`, the server accepts 5 steps;
- with `window = 3`, the server accepts 7 steps;
- the brute-force surface increases as the number of accepted steps grows.

For this project, `window = 1` is the default compromise: understandable, realistic, and still narrow.

## Per-Enrollment Parameters

The TOTP parameters used during enrollment must be treated as part of that enrollment.

When the user scans the QR code, the authenticator app stores:

- the shared secret;
- the algorithm;
- the number of digits;
- the period.

The app does not automatically learn future server-side policy changes.

This means the server must later verify codes with the same parameters that were active when the user enrolled. If a user enrolled with:

```text
Algorithm = SHA1
Digits    = 6
Period    = 30
```

the server must continue verifying that user's TOTP codes with `SHA1`, `6`, and `30` until the user completes a controlled migration or replacement flow.

Changing a global TOTP policy abruptly can lock users out:

```text
app still generates SHA1 / 6 / 30
server suddenly expects SHA512 / 8 / 60
result: codes no longer match
```

Future persistence must therefore store TOTP parameters with the enrollment record, not rely only on a global configuration.

## Persistence Model

The database does not store the temporary six-digit code.

It stores the TOTP enrollment record:

- user id;
- protected secret payload;
- secret nonce;
- secret key id;
- algorithm;
- digits;
- period;
- lifecycle status;
- confirmation timestamp;
- last accepted time step;
- revocation timestamp.

The important distinction is:

```text
stored credential = long-lived enrollment state
submitted code    = short-lived proof generated from that state
```

The current schema uses these secret-storage fields:

```text
secret_ciphertext
secret_nonce
secret_key_id
```

This is intentional. A raw TOTP secret is equivalent to a reusable MFA factor. If an attacker obtains the secret, they can generate future valid codes. The repository therefore models protected storage from the start instead of introducing a plain `secret` column.

Actual encryption and key loading are still introduced in a later enrollment/application step. The persistence schema is already shaped so that this later step can store encrypted secret material without changing the database contract.

Credential lifecycle status:

```text
pending = secret has been generated, but the user has not proven possession yet
active  = user has submitted a valid first code and TOTP can be used
revoked = credential must no longer be accepted
```

Why `pending` matters:

- scanning a QR code does not prove the user saved it correctly;
- enrollment should become active only after the user submits a valid code;
- abandoned setup attempts should not silently become usable MFA credentials.

Why `last_used_time_step` matters:

- TOTP codes can be replayed inside their accepted time step;
- the verifier returns the accepted time step;
- persistence can later remember that time step and reject reuse.

The schema currently allows only one `pending` or `active` TOTP credential per user. This matches the practical limitation of TOTP: if the same QR code is copied to multiple phones, the server cannot distinguish those phones anyway. Passkeys will later handle true per-device lifecycle and per-device revocation.

## Lifecycle And Recovery

TOTP lifecycle management is about the server-side credential attached to a user account.

It is not the same thing as the 30-second validity window of a six-digit code.

Lifecycle questions include:

- is TOTP active for this user?
- when was it confirmed?
- when was it last used?
- can the user disable it safely?
- what happens if the authenticator app entry is deleted?
- what happens if the phone is lost?

Authenticator apps do not notify the server when the user deletes an entry locally. The server still has an active TOTP credential until the user completes a server-side disable, reset, or recovery flow.

The project separates two flows:

```text
normal disable = user still has the authenticator app and submits a valid TOTP code
recovery       = user cannot submit a current TOTP code and needs another pre-established recovery method
```

Normal disable must require the current TOTP code because disabling MFA weakens the account.

Lost-authenticator recovery must be stricter than normal disable. It must not become a password-only bypass.

The first planned self-service recovery mechanism is recovery codes:

- generated by the server;
- shown once;
- stored only as hashes;
- single-use;
- never logged;
- rate-limited when submitted;
- auditable through security events.

Recovery codes must be created before the user loses the authenticator. If a user has no usable recovery method, the system should fail closed until a stronger recovery policy exists.

Recovery codes use password-style hashing because the server does not need to recover the original code. It only needs to verify a submitted code.

This is different from TOTP secret storage:

```text
TOTP secret   -> encrypted because the server must decrypt it to generate expected codes
Recovery code -> hashed because the server only verifies a submitted backup credential
```

The plain recovery code exists only at generation/display time. After that, only the hash remains in storage.

## Secret Protection Before Storage

The TOTP secret must be protected before it is written to SQLite.

This matters because the TOTP secret is reusable MFA material:

```text
attacker has one six-digit code -> short-lived risk
attacker has the TOTP secret    -> can generate future codes
```

The project uses libsodium `secretbox` for this protection layer.

### Why Encryption, Not Hashing?

Passwords and TOTP secrets are stored differently because the server uses them differently.

For a password:

```text
user submits password
server hashes submitted password
server compares hash with stored hash
original password is not needed
```

That is why password storage uses one-way hashing.

For TOTP:

```text
user submits six-digit code
server decrypts stored TOTP secret
server recomputes expected code from secret + time
server compares submitted code with expected code
original TOTP secret is required
```

That is why TOTP secret storage needs reversible encryption, not password hashing.

Hashing the TOTP secret would break verification because the server would no longer be able to recover the original secret needed to compute expected codes.

`secretbox` is authenticated encryption. It provides:

- confidentiality, so the stored payload does not reveal the secret;
- integrity, so modified ciphertext cannot be decrypted silently;
- nonce-based encryption, so encrypting the same secret twice produces different stored payloads.

The stored fields are:

- `secret_ciphertext`, the Base64-encoded encrypted secret;
- `secret_nonce`, the Base64-encoded nonce used for encryption;
- `secret_key_id`, the identifier of the key used to encrypt the secret.

The `secret_key_id` is not a secret. It tells the application which encryption key should be used to decrypt the payload. This prepares future key rotation without changing the credential table.

The encryption key itself must not be stored in SQLite. Future HTTP enrollment wiring will load it from trusted configuration, such as an environment variable or secret manager.

## Server Encryption Key Configuration

The server encryption key is not the user's TOTP secret.

It is a separate application secret used to protect user TOTP secrets before they are stored.

The server needs this key because TOTP verification requires recovering the original user TOTP secret.

Without a server encryption key, the project would have only two bad options:

- store the user TOTP secret in plain text, which is unsafe if SQLite leaks;
- hash the user TOTP secret, which would make verification impossible because hashes are not reversible.

The encryption key solves this:

```text
store time:
user TOTP secret + server encryption key -> encrypted payload in SQLite

verify time:
encrypted payload from SQLite + server encryption key -> original user TOTP secret
```

So the key acts like an application-level storage protection key. It is required to lock and unlock stored TOTP secrets.

Mental model:

```text
user TOTP secret        = the thing Google Authenticator also knows
server encryption key   = the application's key used to encrypt that secret in storage
SQLite                  = stores encrypted user TOTP secrets, not the server key
```

If an attacker steals only the SQLite file, they should not immediately get usable TOTP secrets. If the same attacker also steals the server encryption key, then they can decrypt those secrets. This is why the key must live outside the database and outside Git.

For local development, the project expects:

```text
TOTP_SECRET_ENCRYPTION_KEY=Base64Encoded32ByteKey
```

The recommended local file is:

```text
.env.local
```

This file is ignored by Git. The repository includes `.env.example` as the safe template that can be committed.

The raw key must be exactly 32 bytes because libsodium `secretbox` requires a 32-byte symmetric key. The environment variable uses Base64 only as a transport format, so the binary key can be safely copied into a shell or local environment file.

Generate a local development key with:

```sh
php -r 'echo base64_encode(random_bytes(SODIUM_CRYPTO_SECRETBOX_KEYBYTES)), PHP_EOL;'
```

Create or replace `.env.local` directly with:

```sh
php -r 'echo "TOTP_SECRET_ENCRYPTION_KEY=", base64_encode(random_bytes(SODIUM_CRYPTO_SECRETBOX_KEYBYTES)), PHP_EOL;' > .env.local
chmod 600 .env.local
```

This command is useful for a local demo, but it replaces the existing local key. If existing TOTP credentials were encrypted with the previous key, they will no longer be decryptable.

Important rules:

- commit `.env.example`, never `.env.local`;
- do not commit this value;
- do not store it in SQLite;
- do not log it;
- rotate it only through a planned migration strategy;
- losing it means encrypted TOTP secrets cannot be decrypted.

The project also stores a `secret_key_id` next to each encrypted secret. The key id is not secret. It exists to support future key rotation by saying which server key encrypted a given credential.

The current implementation keeps encryption separate from the repository:

```text
TotpSecret
    -> TotpSecretProtector
    -> ProtectedTotpSecret
    -> UserTotpCredentialRepository
```

This separation keeps responsibilities clear:

- TOTP primitives generate and validate secrets;
- the protector encrypts and decrypts secrets;
- the repository stores already-protected secret material.

## Enrollment Setup Page

The first setup page is an authenticated page that starts or resumes a pending TOTP enrollment.

Current local route:

```text
GET /account/totp/setup
```

The page currently shows:

- the `otpauth://` provisioning URI;
- the manual Base32 secret;
- setup status showing whether a pending enrollment was created or resumed.

This is intentionally an intermediate learning step before QR code rendering and first-code confirmation.

Security implications:

- the page must require a fully authenticated session;
- the session must carry the authenticated user id and email;
- the URI and manual secret contain the user TOTP secret;
- the URI and manual secret must only be shown during setup;
- the pending credential must not become active until the user confirms a valid first code.

Why the page resumes a pending enrollment:

```text
user opens setup page
server creates pending secret
user refreshes page
server reuses the same pending secret
```

This avoids generating a new secret on every refresh and keeps the setup experience understandable. A future reset/restart action can explicitly revoke or replace pending setup state.

What is not done yet:

- no QR code rendering;
- no TOTP requirement during login;
- no setup restart/recovery flow.

## Enrollment Confirmation

TOTP must not become active immediately after the setup page is displayed.

Showing an `otpauth://` URI or QR code only proves that the server generated a secret. It does not prove that the user successfully saved that secret in an authenticator app.

The confirmation step solves this:

```text
server has pending secret
user scans/adds secret in authenticator app
app generates a six-digit code
user submits that code
server verifies code from the pending secret
server activates TOTP only if the code is valid
```

Current local route:

```text
POST /account/totp/setup
```

Security controls:

- the route requires a fully authenticated session;
- the form is protected by CSRF;
- invalid CSRF and invalid TOTP code both produce a generic failure;
- the pending credential remains pending on failure;
- the credential becomes `active` only after a valid code;
- the accepted time step is recorded as `last_used_time_step`.

Recording `last_used_time_step` during confirmation prepares replay prevention. If the same time-step code is submitted again later, future login verification can compare against this stored value and reject reuse.

What is still not done yet:

- TOTP requirement during login;
- TOTP-specific rate limiting;
- recovery/reset flow.

## QR Code Rendering

The QR code is not a new authentication secret.

It is a visual representation of the existing `otpauth://` provisioning URI.

Conceptually:

```text
TotpSecret
    -> Base32
    -> otpauth:// URI
    -> QR code image
    -> authenticator app scan
```

The QR code contains the same secret-bearing provisioning data already shown in text form on the setup page. Scanning it is just easier than manually copying the Base32 secret and parameters.

The project renders the QR code as an inline SVG data URI:

```text
data:image/svg+xml;base64,...
```

Why inline SVG data URI:

- no QR file is written to disk;
- no extra public route is needed to serve the QR;
- the QR exists only in the authenticated setup page response;
- tests can verify that a real SVG QR payload is produced.

Security implications:

- the QR code must be treated like the `otpauth://` URI because it contains the TOTP secret;
- it must not be logged;
- it must not be stored as an asset;
- it should only appear during enrollment setup;
- future hardening should add cache-control headers for secret-bearing pages.

The project uses a dedicated QR code dependency instead of hand-rolling QR generation. QR encoding includes matrix generation, error correction, data modes, masks, and output rendering. Reimplementing that logic would add unnecessary security and compatibility risk for this project.

The dependency is isolated behind a small project service:

```text
TotpSetupController
    -> TotpQrCodeRenderer
    -> chillerlan/php-qrcode
```

This keeps the HTTP controller independent from the third-party API. If the QR library changes later, the expected edit should stay mostly inside `TotpQrCodeRenderer`.

No interface is introduced yet. For this milestone, an interface would not add much value because the project has only one QR rendering implementation and the controller tests can use the real renderer safely. A dedicated interface becomes useful later if the project needs multiple QR renderers, a fake renderer for broader tests, or a frontend/client-side QR strategy.

## Multi-Device Behavior

TOTP is not device-specific.

If two phones scan the same QR code, both phones store the same secret and generate the same codes. The server cannot distinguish which phone generated a valid TOTP code.

Implications:

- TOTP can work on multiple devices;
- the server cannot revoke only one copied TOTP device;
- losing one device usually requires resetting or replacing the TOTP secret;
- Passkeys provide better per-device lifecycle management than TOTP.

## Security Implications

TOTP implementation must handle:

- secret generation quality;
- secret storage protection;
- enrollment confirmation before activation;
- limited time-window tolerance;
- replay prevention for recently used time steps;
- rate limiting of submitted codes;
- security event logging;
- recovery and lost-device flows.

## Project Scope

For `v0.5.0`, the project should focus on TOTP foundation:

- secret generation;
- `otpauth://` URI generation;
- code generation and verification;
- tests for valid, invalid, and time-window behavior;
- initial documentation and ADRs.

The complete login flow using Password + TOTP belongs to a later milestone.
