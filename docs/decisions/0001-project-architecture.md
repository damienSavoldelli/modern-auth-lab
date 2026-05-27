# 0001: Project Architecture

## Context

Modern Auth Lab is an educational security project. It must demonstrate modern authentication flows without hiding core concepts behind a full-stack framework at the beginning.

The project needs enough structure to remain maintainable while avoiding premature abstraction.

## Decision

Use a progressive vanilla architecture:

- PHP 8.3+ backend.
- Composer and PSR-4 autoloading.
- SQLite first, with libSQL compatibility considered later.
- Explicit services, repositories, middleware, and HTTP handlers.
- Vanilla JavaScript ES modules with Vite.
- TypeScript deferred to v1.1.
- Native modern CSS first.

Security-sensitive decisions remain server-side. Frontend code can improve UX but must not be trusted for authorization, authentication, fallback eligibility, or recovery decisions.

## Consequences

- The project remains readable and pedagogical.
- Authentication states can be modeled explicitly.
- Tests can target domain and application behavior without requiring a large framework.
- More wiring code may be needed than in a framework.
- Some conventions must be documented and enforced by repository scripts as the project grows.

## Rejected Alternatives

- Laravel or Symfony at the beginning: rejected because the framework would hide too many early learning decisions.
- JWT at the beginning: rejected because server-managed sessions are clearer for the initial authentication state model.
- Complex SPA architecture at the beginning: rejected because authentication concepts are the current focus.
- TypeScript in v1.0: rejected because the first version intentionally teaches vanilla JavaScript before the v1.1 migration.
