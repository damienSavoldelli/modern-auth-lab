# 0010: Full Session Login Without MFA

## Context

The project has password verification, explicit session states, CSRF-protected login submission, and SQLite-backed users.

The next milestone needs the mechanics of a complete authenticated session before TOTP and Passkeys are introduced.

## Decision

For this milestone, a successful password login marks the session as `fully_authenticated`.

Add:

- Redirect to `/account` after successful password authentication.
- `GET /account` as the first protected route.
- Redirect anonymous users from `/account` to `/login`.
- `POST /logout` protected by a CSRF token.
- Session destruction after valid logout.

This is a temporary pre-MFA login model. Later MFA milestones will reintroduce the distinction between password verification and full authentication for TOTP and Passkey flows.

## Consequences

- The project now has a complete session lifecycle: login, protected route, and logout.
- Route protection remains server-side and is based on explicit session state.
- Logout is intentionally a CSRF-protected `POST`, not a `GET` link.
- The password-only full login behavior must not be mistaken for the final v1.0 security posture.

## Rejected Alternatives

- Waiting for TOTP before adding protected routes: rejected because route protection and logout should be understood independently first.
- Using `GET /logout`: rejected because logout changes server-side state and should not be triggerable by a simple cross-site navigation.
- Adding broad authorization abstractions now: rejected because there is only one protected route.
