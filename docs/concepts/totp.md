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
- `TotpSecret`, because the project needs a safe object for generating and validating shared secrets.

What has not been implemented yet:

- the `otpauth://` URI;
- the QR code;
- the six-digit TOTP code calculation;
- the submitted-code verification flow.

So Base32 and `TotpSecret` are not the login code shown by the authenticator app. They are the foundation that allows the app and the server to share the same secret before codes can be generated.

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
