# 0017 - TOTP QR Code Rendering

## Status

Accepted

## Context

TOTP enrollment needs to transmit the `otpauth://` provisioning URI to an authenticator app.

Manual Base32 entry works, but it is error-prone and inconvenient for local demos and real users.

Authenticator apps commonly scan a QR code that contains the same provisioning URI.

## Decision

The project uses `chillerlan/php-qrcode` to render the provisioning URI as an SVG data URI.

The third-party library is isolated behind `TotpQrCodeRenderer`, a project-owned service used by the setup controller.

The QR code is rendered into the authenticated setup page and is not written to disk.

No dedicated interface is introduced yet.

## Consequences

The project adds one runtime dependency dedicated to QR code generation.

The dependency is kept behind a narrow local service so future library replacement should not require controller rewrites.

The setup page becomes practical to test with a real authenticator app.

The QR code must be treated as secret-bearing because it contains the same data as the `otpauth://` URI.

Future HTTP hardening should add no-store cache headers for setup responses.

## Rejected Alternatives

Hand-rolling QR generation was rejected because QR encoding includes data modes, matrix generation, error correction, mask selection, and output rendering.

Generating QR files under `public/` was rejected because it would create secret-bearing files that need cleanup and access control.

Client-side QR generation was deferred because the current enrollment page is server-rendered and does not need extra frontend complexity yet.

Adding a QR renderer interface now was rejected because the project has only one implementation. A local wrapper gives most of the decoupling benefit without adding premature abstraction.
