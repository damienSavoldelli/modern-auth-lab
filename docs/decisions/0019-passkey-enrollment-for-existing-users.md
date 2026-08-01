# 0019 - Passkey Enrollment For Existing Users

## Status

Accepted

## Context

The project currently has password login, TOTP enrollment, Password + TOTP login, and TOTP lifecycle/recovery foundations.

It does not yet have public user signup.

The next milestone introduces Passkeys/WebAuthn. The word "registration" can be ambiguous because WebAuthn uses it to mean "create a public-key credential", while product authentication flows often use "registration" to mean "create a new account".

Mixing these two meanings would make the project harder to understand and would introduce account-creation questions before the MFA model is ready.

## Decision

`v0.8.0` will implement Passkey enrollment for existing authenticated users.

In this project:

- "signup" means creating a new user account;
- "Passkey enrollment" means adding a WebAuthn credential to an existing user account;
- Passkey enrollment must happen from a fully authenticated account-security context;
- Passkeys do not replace TOTP by default;
- Passwordless signup is deferred.

The first Passkey flow should therefore start from `/account/security`, not from a public signup page.

## Consequences

The project can introduce WebAuthn without changing the account lifecycle.

The implementation can focus on:

- challenge generation;
- browser WebAuthn calls;
- server-side attestation/assertion verification;
- credential persistence;
- multiple credentials per user;
- future login integration.

The project avoids prematurely deciding:

- public signup UX;
- email verification;
- passwordless account recovery;
- account bootstrap policy for users who have no password;
- mandatory Passkey-only accounts.

## Rejected Alternatives

Public signup with Passkey was rejected for this milestone because it requires identity creation, email verification, recovery policy, and account bootstrap decisions.

Replacing TOTP with Passkeys was rejected because TOTP remains useful as a compatible MFA method and controlled fallback.

Passwordless login without password was deferred because the current roadmap first teaches Password + TOTP and Password + Passkey as explicit MFA flows.
