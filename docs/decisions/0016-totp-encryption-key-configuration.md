# 0016 - TOTP Encryption Key Configuration

## Status

Accepted

## Context

TOTP secrets must be encrypted before persistence, but they also need to be decrypted later so the server can verify submitted authenticator-app codes.

That means the application needs a server-side symmetric encryption key.

This key is not the user's TOTP secret. It is an application secret used to protect many user TOTP secrets in storage.

The application needs this key because TOTP verification is not one-way. The server must recover the original user TOTP secret to compute the expected code for the current time step.

Without this key, the project would either store TOTP secrets in plain text or hash them. Plain text weakens the database compromise story. Hashing breaks TOTP verification because the original secret cannot be recovered from a hash.

## Decision

The local runtime reads the TOTP encryption key from:

```text
TOTP_SECRET_ENCRYPTION_KEY
```

For reproducible local demos, the application loads `.env.local` when it exists.

The repository commits `.env.example` as the safe template and keeps `.env.local` ignored by Git.

The value must be Base64 text that decodes to exactly 32 bytes.

The default key id is:

```text
local
```

The key id is stored with protected TOTP credentials so future key rotation can identify which key encrypted each secret.

## Consequences

Enrollment cannot run safely without this key.

The key must not be committed, stored in SQLite, or logged.

Losing the key makes encrypted TOTP secrets unrecoverable.

Future production-oriented work should replace direct environment loading with a richer secret-management strategy when the project needs it.

## Rejected Alternatives

Generating a new key automatically at each startup was rejected because previously encrypted TOTP secrets would become undecryptable.

Storing the key in SQLite was rejected because a database leak would include both the encrypted TOTP secrets and the key needed to decrypt them.

Hardcoding a development key was rejected because it normalizes unsafe secret handling and makes accidental reuse more likely.
