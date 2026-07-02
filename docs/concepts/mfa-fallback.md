# MFA Fallback

MFA fallback is a controlled recovery path, not a freely available alternate login path.

The project must avoid turning fallback into the weakest authentication route.

## Core Idea

Fallback exists for cases such as:

- lost authenticator app;
- unavailable Passkey device;
- device migration;
- account recovery.

Fallback must be gated by explicit eligibility rules.

## Security Implications

A fallback path can bypass the strongest factor if it is too easy to access.

Fallback decisions should consider:

- whether the browser/device is known;
- whether the IP or network context is coherent;
- whether recent authentication events look suspicious;
- whether recovery attempts are rate-limited;
- whether the action is logged;
- whether step-up verification is required.

## Project Scope

Fallback is not part of `v0.5.0`.

For TOTP foundation, the important rule is to avoid designing TOTP as an uncontrolled bypass. TOTP enrollment, reset, and replacement must later become auditable lifecycle operations.
