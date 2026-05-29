# Security Model

The project treats authentication as a sequence of explicit security states, not as a single login flag.

## Security Goals

- Protect user accounts against credential theft, MFA bypass, replay, brute force, and unsafe recovery.
- Keep Passkey and TOTP fallback behavior auditable.
- Make trusted-device decisions explicit and revocable.
- Avoid leaking whether an account exists during authentication failures.
- Keep security logs useful without exposing secrets.

## Core Rules

- Partial authentication is not full authentication.
- Password verification, MFA challenge creation, MFA verification, fallback eligibility, and full authentication are separate states.
- Session state must remain server-side and must distinguish partial authentication from full authentication.
- Fallback TOTP is a controlled path, not a public bypass.
- Server-side validation is required for all security-sensitive behavior.
- Unsafe session-backed requests must use CSRF protection before form-based authentication or account management actions are introduced.
- Challenges must expire.
- Sessions must rotate after privilege changes.
- Security events must avoid secrets and raw tokens.

## Sensitive Data

Security-critical data includes:

- Password hashes.
- TOTP secrets.
- Recovery codes.
- WebAuthn credential material.
- Trusted-device tokens.
- Session identifiers.
- CSRF tokens.
- MFA challenges.

These values must not appear in logs, errors, fixtures, screenshots, or frontend state.

## Privacy Position

Trusted-device and risk checks should use the minimum data needed. The project should prefer explainable risk signals over invasive browser fingerprinting.
