# 0003: Frontend Tooling

## Context

The project needs a modern frontend foundation for v1.0 without becoming a complex SPA.

The initial frontend must support vanilla JavaScript modules, modern CSS, tests, coverage, linting, and formatting. TypeScript is intentionally deferred to v1.1.

## Decision

Use Vite with vanilla JavaScript ES modules.

Initial frontend tooling:

- Vite for development and production builds.
- Vitest for frontend tests.
- V8 coverage through `@vitest/coverage-v8`.
- ESLint 9 with flat config.
- Prettier for formatting.
- Native CSS with cascade layers and custom properties.

Frontend code can improve UX but must not be trusted for authentication, authorization, fallback eligibility, recovery, or security policy decisions.

## Consequences

- The frontend remains lightweight and easy to inspect.
- The project gets modern build, test, lint, and format commands early.
- CSS stays close to the platform and avoids premature design dependencies.
- TypeScript migration remains a clear v1.1 learning step.
- Security decisions remain server-side.

## Rejected Alternatives

- React, Vue, or another SPA framework at the beginning: rejected because auth architecture is the learning focus.
- Tailwind CSS at the beginning: rejected because native CSS is enough for the initial UI foundation.
- TypeScript in v1.0: rejected because the roadmap intentionally teaches vanilla JavaScript before migration.
