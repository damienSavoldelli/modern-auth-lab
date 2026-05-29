# 0006: CSRF Strategy

## Context

Session-backed authentication requires CSRF protection before login forms, MFA forms, Passkey management actions, trusted-device changes, or recovery actions are introduced.

The project needs CSRF primitives without coupling them to a specific form or controller yet.

## Decision

Use a synchronizer-token strategy backed by server-side session storage.

Introduce:

- `CsrfToken`
- `CsrfTokenManager`
- `CsrfTokenException`

Tokens are:

- generated with `random_bytes`
- encoded as hexadecimal strings
- stored server-side by token id
- validated with `hash_equals`
- consumable for single-use workflows when needed

The CSRF layer does not start sessions by itself. It receives storage from the session layer.

## Consequences

- Future forms can issue and validate CSRF tokens without duplicating token logic.
- Security-sensitive POST actions can be protected before authentication workflows exist.
- Token validation is timing-safe.
- The caller decides whether a token is reusable for a form or consumed after one successful submission.

## Rejected Alternatives

- Stateless double-submit cookies: rejected for now because the project already uses server-side sessions and needs explicit session-backed state.
- Global token id only: rejected because distinct token ids make future workflows easier to audit and test.
- Adding CSRF middleware immediately: rejected because there are no unsafe HTTP routes yet.
