# Architecture

The architecture starts as modern vanilla PHP with explicit boundaries. The goal is to make authentication behavior easy to understand, test, and audit.

## Architectural Direction

- PHP 8.5+ with strict typing.
- Composer with PSR-4 autoloading.
- SQLite first, with libSQL compatibility considered later.
- Vanilla JavaScript ES modules through Vite.
- Native CSS with modern CSS features before considering utility frameworks.
- Small services, repositories, middleware, and HTTP handlers.

## Boundary Rules

- HTTP handlers parse requests and produce responses.
- Services coordinate application workflows.
- Repositories persist and retrieve data.
- Middleware handles cross-cutting HTTP concerns.
- Security decisions live server-side.
- Frontend modules improve interaction but do not make trusted authentication decisions.
- Runtime persistence files live under `var/` and are not committed.

## Initial Backend Shape

The expected backend shape will be introduced progressively:

```text
public/
src/
  Http/
  Application/
  Domain/
  Infrastructure/
tests/
```

The first backend milestone introduces `public/` as the only intended web root and starts with minimal HTTP primitives under `src/Http/`.

## Initial Frontend Shape

The expected frontend shape will be introduced progressively:

```text
assets/
  js/
  css/
tests/
  frontend/
```

TypeScript is intentionally deferred to v1.1.

## Design Constraints

- Keep the first implementation small.
- Avoid framework conventions before they are needed.
- Keep authentication state explicit.
- Keep security-sensitive behavior easy to test.
- Prefer repository scripts over ad hoc commands once tooling exists.
