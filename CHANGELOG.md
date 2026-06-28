# Changelog

All notable changes to Modern Auth Lab will be documented in this file.

The format follows Keep a Changelog conventions, and this project uses semantic versioning for project milestones.

## [0.4.1] - 2026-06-28

### Added

- Added PHPDoc class documentation across the PHP application source.
- Added PHPDoc documentation for public methods across the PHP application source.
- Added targeted expert comments for security-sensitive implementation decisions.

### Changed

- Updated `composer analyse` to run PHPStan with an explicit `512M` memory limit.

## [0.4.0] - 2026-06-28

### Added

- Added password-only full session login for the current pre-MFA milestone.
- Added redirect to `/account` after successful password authentication.
- Added protected `GET /account` route.
- Added CSRF-protected `POST /logout`.
- Added session destruction after logout.
- Added initial session-backed login rate limiting.
- Added SQLite-backed `security_events` table.
- Added security event logging for password login success, password login failure, logout success, and invalid logout CSRF attempts.
- Added ADRs for full session login, initial login rate limiting, and basic security events.

### Changed

- Updated the login flow from partial `password_verified` state to temporary `fully_authenticated` state for this pre-MFA milestone.
- Updated README with full session login, rate limiting, and security event status.

### Not Included Yet

- TOTP.
- Passkeys/WebAuthn.
- Trusted devices.
- Recovery flows.
- CSRF middleware.
- Distributed or database-backed rate limiting.
- Security event retention policy.
- CI/CD.

## [0.3.0] - 2026-06-28

### Added

- Added `users` persistence schema.
- Added `User` domain model.
- Added `UserRepository`.
- Added password hashing and verification with PHP native password APIs.
- Added password authentication workflow.
- Added minimal password login form.
- Added CSRF validation for login submission.
- Added `password_verified` session state transition after successful password verification.
- Added session ID rotation after password verification.
- Added local development user seed command.
- Added ADRs for user password foundation and password login form.

### Changed

- Updated README with login and development user instructions.

### Not Included Yet

- Full authenticated session state.
- Logout.
- Private route protection.
- Rate limiting.
- Security event logging.
- TOTP.
- Passkeys/WebAuthn.
- Trusted devices.
- Recovery flows.

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

[0.4.1]: https://github.com/damienSavoldelli/modern-auth-lab/releases/tag/v0.4.1
[0.4.0]: https://github.com/damienSavoldelli/modern-auth-lab/releases/tag/v0.4.0
[0.3.0]: https://github.com/damienSavoldelli/modern-auth-lab/releases/tag/v0.3.0
[0.2.0]: https://github.com/damienSavoldelli/modern-auth-lab/releases/tag/v0.2.0
[0.1.1]: https://github.com/damienSavoldelli/modern-auth-lab/releases/tag/v0.1.1
[0.1.0]: https://github.com/damienSavoldelli/modern-auth-lab/releases/tag/v0.1.0
