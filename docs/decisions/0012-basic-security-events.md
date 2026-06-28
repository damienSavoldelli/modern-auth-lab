# 0012: Basic Security Events

## Context

The project now has password login, a protected account route, logout, and an initial rate-limiting branch.

Modern authentication systems need security events before MFA, trusted devices, fallback controls, and recovery flows are added.

## Decision

Add SQLite-backed security events.

The initial event model records:

- Event type.
- Optional user id.
- Optional normalized email.
- Server-observed client IP.
- Creation timestamp.

The first recorded events are:

- `password_login_succeeded`
- `password_login_failed`
- `logout_succeeded`
- `logout_csrf_failed`

The event table intentionally does not store passwords, tokens, CSRF values, session ids, or arbitrary request payloads.

## Consequences

- Authentication behavior can now leave an auditable trail.
- Future rate limiting, fallback controls, and recovery flows can build on a concrete event model.
- The current model is intentionally small and may need retention rules before production use.
- Logout events do not yet include a user id because the session does not store an authenticated user id.

## Rejected Alternatives

- Logging to plain files: rejected because the project already has SQLite persistence and needs queryable events.
- Storing arbitrary metadata JSON immediately: rejected to avoid collecting unnecessary sensitive data too early.
- Adding user-agent tracking now: rejected until the trusted-device and known-browser model is designed.
