# Authentication Flows

The project contains two main authentication flows.

## Flow 1: Password Plus TOTP

Expected high-level states:

1. Anonymous.
2. Password submitted.
3. Password verified.
4. TOTP challenge pending.
5. TOTP verified.
6. Fully authenticated.

Security implications:

- Password verification must not create a fully authenticated session.
- TOTP challenges must expire.
- Failed attempts must be rate-limited.
- Session rotation is required after full authentication.

## Flow 2: Password Plus Passkey With Controlled TOTP Fallback

Expected high-level states:

1. Anonymous.
2. Password submitted.
3. Password verified.
4. Passkey challenge pending.
5. Passkey verified.
6. Fully authenticated.

Fallback path:

1. Password verified.
2. Passkey unavailable or not usable.
3. Fallback eligibility evaluated.
4. TOTP fallback challenge pending.
5. TOTP fallback verified.
6. Fully authenticated.

Security implications:

- Fallback eligibility is a server-side decision.
- The fallback route must not be freely accessible.
- Known device, coherent IP context, browser context, rate limits, and security logs may contribute to fallback eligibility.
- Suspicious fallback attempts must fail closed.

## Shared Requirements

- Authentication state must be explicit.
- Account existence must not be leaked through failure responses.
- Security events must be recorded for successful and failed sensitive actions.
- Recovery behavior must be designed before lost-device flows are implemented.
