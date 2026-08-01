# Authentication Flows

The project contains two main authentication flows.

The long-term model is multi-method MFA. Passkeys do not remove TOTP by default. The server decides which methods are allowed for the current user and risk context, then the user can choose among the allowed and technically available methods.

Target method roles:

```text
Passkey         = preferred phishing-resistant MFA method when available
TOTP            = compatible multi-platform MFA method and controlled fallback
Recovery codes  = exceptional account recovery method
Trusted device  = controlled friction reduction
```

The browser and device also matter. A user may have a Passkey registered, but the current browser, device, platform policy, or cross-device setup may prevent Passkey use in that moment.

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

Method selection path:

1. Password verified.
2. Server loads active MFA methods for the user.
3. Server applies security policy and risk checks.
4. Frontend detects whether WebAuthn/Passkeys are available in the current browser/device context.
5. User chooses from allowed and compatible methods.
6. Server verifies the selected method.

Security implications:

- Fallback eligibility is a server-side decision.
- The fallback route must not be freely accessible.
- Frontend capability checks can improve UX, but they do not authorize fallback by themselves.
- Known device, coherent IP context, browser context, rate limits, and security logs may contribute to fallback eligibility.
- Suspicious fallback attempts must fail closed.

## Shared Requirements

- Authentication state must be explicit.
- Account existence must not be leaked through failure responses.
- Security events must be recorded for successful and failed sensitive actions.
- Recovery behavior must be designed before lost-device flows are implemented.
