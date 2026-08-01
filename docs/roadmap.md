# Roadmap

Modern Auth Lab is a progressive project for exploring modern web authentication, MFA, Passkeys/WebAuthn, secure fallback design, testing strategy, mutation testing, and CI/CD.

The project evolves through explicit versions. Each version must remain understandable, testable, and reviewable.

## Versioning Model

- `main` represents the most recent project version.
- Stable learning milestones are preserved with Git tags and GitHub releases.
- Early milestones may use `v0.x` tags before the full `v1.0` scope is complete.
- Release notes should explain both delivered behavior and security decisions.

## v1.0 Scope

v1.0 focuses on a complete vanilla JavaScript and PHP authentication lab.

Expected capabilities:

- Password-based login.
- Password plus TOTP flow.
- Password plus Passkey flow.
- Secure TOTP fallback for Passkey users.
- Multiple Passkeys per user.
- Passkey naming, revocation, and last-used tracking.
- Trusted-device handling.
- Cross-device Passkey authentication.
- Security event logging.
- Brute-force and fallback abuse protections.
- Backend tests with coverage.
- Frontend tests with coverage.
- Backend mutation testing.
- Frontend mutation testing.
- GitHub Actions quality pipeline.

## v1.1 Scope

v1.1 focuses on frontend type safety and developer experience.

Expected capabilities:

- Migration from vanilla JavaScript modules to TypeScript.
- WebAuthn type modeling.
- Stronger frontend test structure.
- TypeScript-aware CI checks.
- Improved maintainability without changing the security model unnecessarily.

## Initial Milestones

1. Establish agent and documentation discipline.
2. Define project architecture and authentication boundaries.
3. Initialize backend tooling with Composer and PHP structure.
4. Initialize frontend tooling with Vite and vanilla JavaScript modules.
5. Add the first test and quality scripts.
6. Implement the minimal HTTP foundation.
7. Implement password authentication states.
8. Add TOTP enrollment and verification.
9. Add Passkey registration and authentication.
10. Add controlled fallback strategy.
11. Add trusted-device and recovery behavior.
12. Add coverage, mutation testing, and CI quality gates progressively.

## Versioned Milestones

This section tracks the concrete milestone roadmap used by the project.

### `v0.1.0 - Project Foundation`

Goal: establish the initial project foundation.

### `v0.1.1 - Agent / Workflow Updates`

Goal: refine agent behavior, workflow rules, release formatting, and collaboration discipline.

### `v0.2.0 - Session, CSRF And SQLite Foundation`

Goal: introduce the first session, CSRF, and SQLite foundations.

### `v0.3.0 - User And Password Foundation`

Goal: introduce users, password hashing, password verification, and the minimal password login form.

### `v0.4.0 - Full Session Login`

Goal: complete the password-only session login flow before MFA enforcement.

### `v0.4.1 - Code Documentation Pass`

Goal: add professional PHPDoc and implementation comments to improve code readability.

### `v0.5.0 - TOTP Foundation`

Goal: build authenticator-app TOTP foundations before wiring TOTP into login.

Delivered branches:

- `feature/totp-domain`
  - Base32 encoding and decoding.
  - TOTP secret generation and validation.
  - `otpauth://` provisioning URI generation.
  - HOTP/TOTP code generation.
  - TOTP enrollment parameter decision.
  - TOTP code verification with a small time-window tolerance.
- `feature/totp-persistence`
  - SQLite migration for TOTP enrollments.
  - Repository for TOTP enrollment records.
  - Store user id, secret, algorithm, digits, period, status, confirmation timestamp, and last used time step.
  - Integration tests for persistence behavior.
- `feature/totp-enrollment`
  - Start a pending TOTP enrollment.
  - Generate a pending secret.
  - Produce an `otpauth://` provisioning URI.
  - Confirm enrollment with a valid TOTP code.
  - Activate TOTP only after confirmation.
  - Add initial TOTP security events.

Out of scope for `v0.5.0`:

- Requiring TOTP during login.
- Replacing the password-only full session login flow.
- Passkeys/WebAuthn.
- Trusted devices.
- Recovery flows.
- SMS or email OTP.
- Complex frontend enrollment UI.

### `v0.5.1 - Workflow Configuration`

Goal: add project workflow configuration for PRs, releases, and local AI-agent settings.

### `v0.6.0 - Password + TOTP Flow`

Goal: require TOTP after password verification.

Planned scope:

- Password success moves the session to `mfa_pending`.
- TOTP challenge form.
- Valid TOTP code moves the session to `fully_authenticated`.
- TOTP-specific rate limiting.
- Effective anti-replay using the last accepted time step.
- Security events for TOTP success and failure.
- Pending TOTP enrollment expiration and cleanup behavior.
- Tests for the complete Password + TOTP login flow.

Out of scope for `v0.6.0`:

- Passkeys/WebAuthn.
- Trusted devices.
- Recovery codes.
- Lost-authenticator recovery flow.
- User-facing TOTP disable/reset flow.
- SMS or email OTP.

### `v0.6.1 - Historical Implementation Notes`

Goal: complete historical implementation notes for earlier milestones and improve agent documentation guidance.

Delivered scope:

- Agent documentation reading map.
- Agent documentation update rules.
- Historical implementation notes for `v0.1.0` through `v0.4.0`.
- Documentation-only patch release.

### `v0.7.0 - TOTP Lifecycle And Recovery` _(in progress)_

Goal: manage TOTP loss, reset, disable, and recovery behavior.

Planned scope:

- Account security page showing active TOTP status.
- Disable TOTP when the user still has access to their authenticator.
- Require recent authentication before disabling TOTP.
- Require current TOTP code before normal TOTP disable.
- Add recovery path when the authenticator is lost.
- Add recovery codes or recovery challenge foundation.
- Log TOTP disable, reset, recovery start, and recovery success/failure events.
- Add user notification after TOTP disable or reset.
- Document why authenticator apps cannot notify the server when an entry is deleted locally.

### `v0.8.0 - Passkey / WebAuthn Foundation`

Goal: add WebAuthn registration and authentication primitives.

Planned scope:

- Registration challenge generation.
- Authentication challenge generation.
- Credential storage model.
- Origin, RP ID, challenge, user presence, and user verification validation.
- Signature counter handling when available.
- Backend tests and focused frontend WebAuthn modules.

### `v0.9.0 - Password + Passkey Flow`

Goal: add the Password + Passkey authentication path.

Planned scope:

- Password plus Passkey login.
- Multiple Passkeys per user.
- Passkey naming.
- Individual Passkey revocation.
- Last-used tracking.
- Cross-device authentication support.

### `v0.10.0 - Secure Fallback Strategy`

Goal: add controlled fallback for MFA recovery.

Planned scope:

- Controlled TOTP fallback for Passkey users.
- Fallback eligibility rules.
- Known environment checks.
- Coherent IP/browser checks.
- Suspicious environment detection.
- Security events for fallback attempts.

### `v0.11.0 - Trusted Devices And Recovery`

Goal: add auditable device and recovery lifecycle behavior.

Planned scope:

- Trusted device records.
- Device revocation.
- Lost-device handling.
- Recovery flows.
- Recovery security events.

### `v0.12.0 - Quality Gates And CI/CD`

Goal: automate project quality checks.

Planned scope:

- GitHub Actions backend checks.
- GitHub Actions frontend checks.
- PHPUnit coverage.
- Vitest coverage.
- PHPStan.
- PHP CS Fixer.
- ESLint.
- Prettier.
- Progressive quality gates.

### `v0.13.0 - Mutation Testing`

Goal: measure test strength beyond coverage percentage.

Planned scope:

- Infection PHP.
- StrykerJS.
- Progressive mutation score targets.
- Documentation about coverage vs mutation testing.

### `v1.0.0 - Modern Auth Lab JavaScript Edition`

Goal: complete the vanilla JavaScript and PHP authentication lab.

Expected scope:

- Password + TOTP flow.
- Password + Passkey flow.
- Secure fallback strategy.
- Trusted devices.
- Multi-passkey lifecycle.
- Recovery behavior.
- Coverage.
- Mutation testing.
- CI/CD.
- Complete documentation.

### `v1.1.0 - TypeScript Frontend Migration`

Goal: improve frontend type safety and developer experience.

Expected scope:

- Migrate frontend modules to TypeScript.
- Add WebAuthn type modeling.
- Improve frontend test structure.
- Add TypeScript-aware checks.

## Explicit Non-Goals For Early Stages

- No Laravel or Symfony at the beginning.
- No JWT at the beginning.
- No complex SPA architecture at the beginning.
- No premature OAuth or external identity provider.
- No large abstraction layer before the core flows are understood.

## Release Criteria

A milestone can be tagged when:

- The documented scope is implemented.
- Relevant tests pass.
- Security-sensitive decisions are documented.
- Known limitations are explicit.
- The user-facing learning objective is clear.
