# 0015 - TOTP Secret Encryption

## Status

Accepted

## Context

TOTP enrollment generates a long-lived shared secret. The server needs this secret later to verify authenticator-app codes.

If the secret is stored in plain text, a database leak allows attackers to generate future MFA codes. This is more serious than leaking one submitted six-digit code because the secret remains valid until replacement or revocation.

## Decision

TOTP secrets must be encrypted before persistence.

The project uses PHP's Sodium extension and libsodium `secretbox` for authenticated symmetric encryption.

The protected persistence payload contains:

- encrypted ciphertext;
- nonce;
- key id.

The key id is stored with the credential so future key rotation can identify which key was used.

The encryption key itself must not be stored in SQLite.

## Consequences

`ext-sodium` is now an explicit Composer platform requirement.

The repository stores protected secret material only. It does not encrypt, decrypt, generate, or verify TOTP codes.

Future enrollment wiring must provide a real 32-byte encryption key from trusted configuration, such as an environment variable or secret manager.

Tampered ciphertext fails decryption instead of producing a silent corrupted secret.

## Rejected Alternatives

Storing the Base32 TOTP secret directly was rejected because it makes a database compromise equivalent to MFA-secret compromise.

Using password hashing was rejected because TOTP verification requires recovering the secret to compute expected codes. Password hashes are intentionally one-way and cannot support TOTP code generation.
