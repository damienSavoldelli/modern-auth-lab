# 0005: Session Strategy

## Context

Modern authentication requires explicit server-side session states before password, TOTP, Passkey, fallback, trusted-device, or recovery flows are implemented.

The project needs secure session primitives without introducing login behavior yet.

## Decision

Introduce a minimal session foundation:

- `AuthSessionState` models authentication states.
- `AuthSession` stores and reads the authentication state from session storage.
- `SessionCookieOptions` defines cookie security options.
- `NativeSession` wraps PHP native session operations.

The first supported authentication states are:

- `anonymous`
- `password_verified`
- `mfa_pending`
- `fully_authenticated`

Session cookies default to:

- `HttpOnly`
- `SameSite=Lax`
- `Secure` by default

Local HTTP development can explicitly create request-aware cookie options with `Secure=false`.

The `/health` route does not start a session. Sessions should be started only when a route or workflow actually needs session state.

## Consequences

- Partial authentication is represented separately from full authentication.
- Future login and MFA flows can rotate the session ID after privilege changes.
- Tests can validate authentication state transitions without invoking PHP global session behavior.
- Native PHP session calls are isolated behind a small wrapper.

## Rejected Alternatives

- Starting sessions for all requests: rejected because diagnostic and public routes should not create unnecessary session cookies.
- Storing authentication state directly in route handlers: rejected because it would duplicate security-sensitive state handling.
- Adding CSRF tokens in this milestone: rejected because CSRF should be introduced as a focused follow-up once session primitives exist.
