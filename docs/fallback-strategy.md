# Fallback Strategy

Fallback exists to preserve account recovery and usability without turning MFA into a bypass.

TOTP lost-authenticator recovery and future Passkey fallback are related but not identical:

- TOTP recovery helps a user regain access when they cannot produce their current TOTP code.
- Passkey fallback helps a user complete authentication when the primary Passkey path is unavailable.

Both must be controlled server-side and auditable, but they may use different eligibility rules.

## Principle

TOTP fallback for Passkey users is controlled access. It is not a public alternate login path.

## Eligibility Signals

Fallback eligibility may consider:

- Password verification state.
- Known trusted device.
- Coherent IP context.
- Known browser context.
- Recent successful authentication history.
- Rate-limit state.
- Security event history.
- Recovery policy.

These signals are server-side inputs. Frontend state can assist UX but must not decide eligibility.

## Fail-Closed Behavior

Fallback must fail closed when:

- The authentication state is unclear.
- The challenge is missing or expired.
- The device context is suspicious.
- Rate limits are exceeded.
- The account has no valid fallback method.

## Auditing

Fallback attempts should produce structured security events for:

- Eligibility accepted.
- Eligibility rejected.
- TOTP fallback challenge created.
- TOTP fallback verification succeeded.
- TOTP fallback verification failed.
- Suspicious fallback behavior detected.

## UX/Security Tradeoff

Fallback improves recovery and cross-device usability, but it can weaken Passkey security if it is easier to attack than the primary factor. The implementation must make that tradeoff explicit.
