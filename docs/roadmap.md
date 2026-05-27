# Roadmap

Modern Auth Lab is a progressive educational project for learning modern web authentication, MFA, Passkeys/WebAuthn, secure fallback design, testing strategy, mutation testing, and CI/CD.

The project evolves through explicit versions. Each version must remain understandable, testable, and reviewable.

## Versioning Model

- `main` represents the most recent educational version.
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
