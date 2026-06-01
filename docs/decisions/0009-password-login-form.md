# 0009: Password Login Form

## Context

The project has user persistence, password hashing, password verification, session primitives, and CSRF token primitives.

The next step is a minimal HTTP password login form that verifies a password and records partial authentication state without treating the user as fully authenticated.

## Decision

Add:

- `GET /login`
- `POST /login`
- Minimal HTML login form.
- CSRF token in the login form.
- CSRF validation on login submission.
- Password verification through `PasswordAuthenticator`.
- Session state transition to `password_verified` after successful password verification.
- Session ID rotation after the authentication state changes.
- Generic failed login response.

The login route does not set `fully_authenticated`. MFA is still required before full authentication in later milestones.

## Consequences

- Password verification is now available through HTTP.
- Partial authentication remains distinct from full authentication.
- CSRF protection is applied to the login form from the beginning.
- The current local login flow requires a user to exist in the database before successful login is possible.

## Rejected Alternatives

- Marking users as fully authenticated after password verification: rejected because v1.0 requires MFA-capable flows.
- Adding logout in this milestone: rejected because logout belongs to the full session login milestone.
- Adding rate limiting immediately: rejected because it is planned for the full session login milestone.
- Adding public registration: rejected because this milestone focuses on password login, not account creation UX.
