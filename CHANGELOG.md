# Changelog

All notable changes to Modern Auth Lab will be documented in this file.

The format follows Keep a Changelog conventions, and this project uses semantic versioning for project milestones.

## [0.2.0] - 2026-06-01

### Added

- Added server-side session primitives and explicit authentication session states.
- Added secure session cookie options with `HttpOnly`, `SameSite=Lax`, and `Secure` defaults.
- Added CSRF token primitives for future session-backed forms and unsafe requests.
- Added SQLite persistence foundation using PDO.
- Added migration tracking with `schema_migrations`.
- Added runtime directory structure under `var/data/`.
- Added ADRs for session, CSRF, and SQLite persistence strategies.

### Changed

- Updated README, security, and architecture documentation for the backend security foundation.

### Not Included Yet

- Password login.
- User tables.
- Password hashing.
- TOTP.
- Passkeys/WebAuthn.
- Trusted devices.
- Recovery flows.
- libSQL remote runtime.
- CI/CD.

## [0.1.1] - 2026-05-28

### Changed

- Added the default Delivery Workflow for roadmap work.
- Added the release notes format for future releases.
- Documented the historical release notes format used by `v0.1.0`.
- Replaced project-facing `educational` wording with more professional milestone language.

## [0.1.0] - 2026-05-28

### Added

- Added agent development guidelines in `AGENTS.md`.
- Added project roadmap and documentation structure.
- Added architecture, security, authentication flow, Passkey, and fallback strategy notes.
- Added architecture decision records.
- Added PHP 8.5+ backend tooling with Composer.
- Added PHPUnit 12, PHPStan, and PHP CS Fixer.
- Added Vite frontend tooling with vanilla JavaScript ES modules.
- Added native CSS foundation.
- Added Vitest, V8 coverage, ESLint, and Prettier.
- Added minimal PHP HTTP foundation with `public/` as the web root.
- Added `GET /health` diagnostic route.
- Added initial backend and frontend tests.

### Verified

- `composer test`
- `composer analyse`
- `composer cs:check`
- `npm run build`
- `npm test`
- `npm run lint`
- `npm run format`

### Not Included Yet

- Password authentication.
- Sessions.
- CSRF protection.
- TOTP.
- Passkeys/WebAuthn.
- Trusted devices.
- Recovery flows.
- SQLite/libSQL persistence.
- CI/CD.

[0.2.0]: https://github.com/damienSavoldelli/modern-auth-lab/releases/tag/v0.2.0
[0.1.1]: https://github.com/damienSavoldelli/modern-auth-lab/releases/tag/v0.1.1
[0.1.0]: https://github.com/damienSavoldelli/modern-auth-lab/releases/tag/v0.1.0
