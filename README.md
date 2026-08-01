# Modern Auth Lab

Modern Auth Lab is a progressive security project for exploring modern web authentication with PHP, vanilla JavaScript, TOTP, Passkeys/WebAuthn, controlled MFA fallback strategies, tests, coverage, mutation testing, and CI/CD.

The project is intentionally built step by step. It starts with a small framework-free foundation before adding authentication behavior.

## Current Status

Implemented foundation:

- Agent development rules.
- Project roadmap and security documentation.
- PHP 8.5 backend tooling with Composer.
- PHPUnit, PHPStan, and PHP CS Fixer.
- Vite frontend tooling with vanilla JavaScript.
- Vitest, V8 coverage, ESLint, and Prettier.
- Minimal PHP HTTP foundation with `public/` as the web root.
- `GET /health` diagnostic route.
- Server-side session primitives and explicit authentication session states.
- CSRF token primitives for future session-backed forms and unsafe requests.
- SQLite persistence foundation with migration tracking.
- User persistence schema, repository, password hashing, and password verification workflow.
- Minimal password login form with CSRF validation.
- Password-only full session login for the current pre-MFA milestone.
- Protected `/account` route.
- CSRF-protected logout.
- Initial session-backed login rate limiting.
- SQLite-backed basic security events.
- Authenticator-app TOTP enrollment with QR code setup.
- Password + TOTP login flow for users with active TOTP.
- TOTP challenge anti-replay protection.
- TOTP challenge rate limiting.
- TOTP challenge security events.
- Pending TOTP enrollment expiration.
- Account security page for TOTP lifecycle status.
- Normal TOTP disable with current authenticator code.
- TOTP recovery-code generation, hash-only storage, one-time display, and service-level verification.

Not implemented yet:

- CSRF middleware.
- Passkeys/WebAuthn.
- Trusted devices.
- Login recovery with recovery-code submission.
- User-facing SQLite/libSQL persistence features.
- CI/CD.

## Requirements

- PHP 8.5+
- Composer 2+
- Node.js 22+
- npm 10+
- SQLite PDO extension

## Runtime Configuration

The application reads local runtime configuration from `.env.local` when the file exists. The repository commits `.env.example` as the safe template.

Required local variables:

```env
TOTP_SECRET_ENCRYPTION_KEY=
TOTP_RATE_LIMIT_MAX_ATTEMPTS=5
TOTP_RATE_LIMIT_LOCK_SECONDS=300
```

`TOTP_SECRET_ENCRYPTION_KEY` must contain a Base64-encoded 32-byte key used to encrypt TOTP secrets before SQLite persistence.

Generate a local key:

```bash
php -r 'echo "TOTP_SECRET_ENCRYPTION_KEY=", base64_encode(random_bytes(SODIUM_CRYPTO_SECRETBOX_KEYBYTES)), PHP_EOL;'
```

The rate-limit variables control the TOTP challenge brute-force protection:

- `TOTP_RATE_LIMIT_MAX_ATTEMPTS`: failed TOTP submissions before temporary lockout.
- `TOTP_RATE_LIMIT_LOCK_SECONDS`: lockout duration in seconds.

## Installation

Install backend dependencies:

```bash
composer install
```

Install frontend dependencies:

```bash
npm install
```

## Backend Commands

Start the PHP development server:

```bash
composer serve
```

The `serve` script disables Composer's default process timeout so the local
server can stay open during manual demos.

Health check:

```bash
curl http://127.0.0.1:8080/health
```

Run backend checks:

```bash
composer test
composer analyse
composer cs:check
```

Create a local development user:

```bash
composer seed:dev-user
```

Development credentials:

```text
Email: dev@example.com
Password: DevPassword123!
```

Login page:

```text
http://127.0.0.1:8080/login
```

Protected account page:

```text
http://127.0.0.1:8080/account
```

Account security page:

```text
http://127.0.0.1:8080/account/security
```

## Frontend Commands

Start the Vite development server:

```bash
npm run dev
```

Run frontend checks:

```bash
npm run build
npm test
npm run coverage
npm run lint
npm run format
```

## Project Structure

```text
assets/       Frontend JavaScript and CSS
docs/         Roadmap, security notes, architecture notes, and decisions
public/       Public web root
src/          PHP application source
tests/        Backend and frontend tests
```

## Security Direction

Security-sensitive decisions must remain server-side. Frontend code may improve user experience, but it must not decide authentication, authorization, MFA fallback eligibility, recovery state, or trusted-device policy.

Authentication will be modeled as explicit states. Partial authentication must not be treated as a full authenticated session.

## Documentation

Start with:

- [Roadmap](docs/roadmap.md)
- [Architecture](docs/architecture.md)
- [Security model](docs/security.md)
- [Authentication flows](docs/auth-flows.md)
- [Fallback strategy](docs/fallback-strategy.md)
- [Security concepts](docs/concepts/README.md)
- [TOTP concept note](docs/concepts/totp.md)
- [Passkeys and WebAuthn concept note](docs/concepts/passkeys.md)
- [v0.5.0 TOTP foundation implementation notes](docs/implementation-notes/v0.5-totp-foundation.md)
- [v0.6.0 Password + TOTP flow implementation notes](docs/implementation-notes/v0.6-password-totp-flow.md)
- [v0.7.0 TOTP lifecycle and recovery implementation notes](docs/implementation-notes/v0.7-totp-lifecycle-recovery.md)
- [v0.8.0 Passkey / WebAuthn foundation implementation notes](docs/implementation-notes/v0.8-passkey-webauthn-foundation.md)
- [Decision records](docs/decisions/README.md)

## Versioning

`main` represents the latest project version. Stable milestones are preserved with Git tags and GitHub releases.
