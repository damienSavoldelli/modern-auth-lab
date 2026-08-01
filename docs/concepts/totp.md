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

## Secret Protection Before Storage

The TOTP secret must be protected before it is written to SQLite.

This matters because the TOTP secret is reusable MFA material:

```text
attacker has one six-digit code -> short-lived risk
attacker has the TOTP secret    -> can generate future codes
```

The project uses libsodium `secretbox` for this protection layer.

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
