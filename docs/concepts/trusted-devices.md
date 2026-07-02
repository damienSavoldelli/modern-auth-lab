# Trusted Devices

Trusted devices are remembered client environments used to improve authentication decisions.

They are not a replacement for authentication. They are risk signals.

## Core Idea

A trusted device model can help answer questions such as:

- has this browser completed MFA before?
- is this device still trusted?
- should fallback be allowed from this environment?
- should a sensitive action require step-up verification?

## Security Implications

Trusted-device tokens must be:

- high entropy;
- stored securely;
- revocable;
- bound to server-side records;
- protected from exposure in frontend state;
- audited when created, used, or revoked.

Raw browser fingerprinting should be avoided unless clearly justified.

## Project Scope

Trusted devices are not part of `v0.5.0`.

They will matter later for MFA fallback, recovery, and multi-device behavior. TOTP foundation should not assume trusted-device behavior exists yet.
