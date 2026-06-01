# 0008: User Password Foundation

## Context

The project now has session primitives, CSRF token primitives, and SQLite persistence. It can introduce the first user and password authentication domain pieces without building the full HTTP login flow yet.

The goal is to establish password storage and verification boundaries before wiring forms, sessions, rate limiting, and security events.

## Decision

Introduce:

- `users` table migration.
- `User` domain model.
- `UserRepository`.
- `PasswordHasher`.
- `PasswordAuthenticator`.
- `PasswordAuthenticationResult`.

Passwords are hashed through PHP's native password API:

- `password_hash`
- `password_verify`
- `password_needs_rehash`

The password authentication workflow returns an explicit result object. It does not mutate the session and does not expose whether failure came from a missing user or an invalid password.

## Consequences

- User persistence is available for future login flows.
- Password hashing policy is centralized.
- Password verification is testable without HTTP routes.
- Future login handlers can decide when to mark the session as `password_verified`.
- Full login, rate limiting, security events, and route protection remain separate concerns.

## Rejected Alternatives

- Adding HTTP login in the same step: rejected to keep persistence, password verification, and HTTP/session transitions reviewable.
- Storing plaintext or reversible passwords: rejected because passwords must only be stored as one-way hashes.
- Adding TOTP or Passkeys now: rejected because password authentication must be stable before MFA layers are introduced.
