# 0004: HTTP Foundation

## Context

The backend needs a minimal HTTP boundary before sessions, CSRF, authentication, MFA, or persistence are introduced.

The project should expose only a public document root while keeping source code, tests, documentation, and dependencies outside the web root.

## Decision

Use a small front controller in `public/index.php` and introduce minimal HTTP primitives:

- `ModernAuthLab\Http\Response`.
- `ModernAuthLab\Http\Router`.
- `GET /health` as the first diagnostic route.

Use the PHP built-in server for local development through `composer serve`.

No `.htaccess` is added yet because Apache deployment is not part of the current milestone. Web-server hardening will be documented when a real web-server target is introduced.

## Consequences

- `public/` becomes the only intended web root.
- HTTP behavior can be tested without starting a server.
- The router stays intentionally limited to exact method and path matching.
- Future middleware can be introduced only when a concrete cross-cutting concern appears.
- Apache-specific security rules are deferred until the deployment model is explicit.

## Rejected Alternatives

- Direct PHP files outside `public/`: rejected because it weakens the web boundary.
- Adding `.htaccess` now: rejected because it would encode Apache assumptions before the project has a web-server target.
- Adding a framework router now: rejected because exact routes are enough for the first HTTP milestone.
