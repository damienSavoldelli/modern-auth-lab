# 0014 - TOTP Secret Storage

## Status

Accepted

## Context

TOTP uses a long-lived shared secret. The authenticator app and the server both need this secret to generate matching time-based codes.

That secret is not equivalent to a temporary six-digit code. If the secret is compromised, an attacker can generate future valid TOTP codes.

## Decision

The TOTP credential schema must not model the secret as a plain `secret` column.

The persistence model stores protected secret material through:

- `secret_ciphertext`;
- `secret_nonce`;
- `secret_key_id`.

TOTP enrollment parameters are stored per credential:

- `algorithm`;
- `digits`;
- `period`.

Credential lifecycle state is explicit:

- `pending`;
- `active`;
- `revoked`.

The schema also stores `last_used_time_step` so future verification code can reject replay of an already accepted TOTP time step.

## Consequences

The database contract is ready for encryption at rest before the HTTP enrollment flow is introduced.

The repository remains a persistence boundary. It does not decrypt, generate, or verify TOTP secrets or codes.

Future work must add application-level secret protection and key loading before real enrollment writes secrets to persistence.

The project initially allows only one `pending` or `active` TOTP credential per user. This reflects the fact that TOTP is not device-specific and does not support reliable per-device revocation.
