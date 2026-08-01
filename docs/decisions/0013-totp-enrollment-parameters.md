# 0013: TOTP Enrollment Parameters

## Context

TOTP enrollment sends configuration to the authenticator app through the `otpauth://` provisioning URI.

The important parameters are:

- shared secret;
- algorithm;
- digits;
- period.

Once the user scans the QR code, the authenticator app stores those parameters locally. The app does not automatically learn future server-side policy changes.

The project now has pure TOTP primitives for secrets, provisioning URIs, and code generation. Before adding verification or persistence, it needs a clear rule for how these parameters will be treated.

## Decision

TOTP parameters must be treated as enrollment-specific data.

Future TOTP persistence must store the parameters required to verify each enrollment:

- secret;
- algorithm;
- digits;
- period;
- enrollment status;
- confirmation timestamp;
- last used time step when replay protection is introduced.

The application must not assume that a single global TOTP configuration can safely verify every existing enrollment forever.

New enrollments may use newer defaults in the future, but existing enrollments must continue to be verified with the parameters used when they were activated until a controlled migration or replacement flow succeeds.

## Consequences

- Changing TOTP defaults later will not automatically break existing users.
- Persistence and verification code must load algorithm, digits, and period from the enrollment record.
- TOTP lifecycle and reset flows must handle old and new enrollment parameters explicitly.
- Documentation and tests should avoid implying that TOTP parameters are global-only configuration.

## Rejected Alternatives

- Using only global TOTP configuration: rejected because changing defaults can lock out users whose authenticator apps still use previous parameters.
- Forcing all users to re-enroll immediately when defaults change: rejected because it is operationally risky and creates avoidable account recovery pressure.
- Ignoring algorithm and period in persistence: rejected because authenticator apps generate codes from the exact parameters received during enrollment.
