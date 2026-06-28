# 0011: Initial Login Rate Limiting

## Context

The password login flow now creates a full session for the pre-MFA milestone.

The project needs an initial brute-force protection before introducing more advanced security event storage, global throttling, trusted devices, or MFA fallback controls.

## Decision

Add a session-backed login rate limiter.

The limiter:

- Tracks failed login attempts by normalized email and server-observed client IP.
- Uses `REMOTE_ADDR` only for now.
- Does not trust forwarded proxy headers.
- Blocks after repeated failures in a fixed window.
- Clears the counter after successful authentication for the same identifier.

The current thresholds are intentionally simple:

- 5 failed attempts.
- 15 minute attempt window.
- 5 minute temporary lock.

## Consequences

- The login flow now has a first anti-brute-force control.
- The behavior is testable without adding persistence tables or external services.
- The limiter is local to the current PHP session and is not a complete distributed brute-force defense.
- Future milestones can move rate limiting to SQLite/libSQL-backed security state if needed.

## Rejected Alternatives

- Adding a dependency: rejected because the first limiter can be implemented clearly with standard PHP.
- Trusting `X-Forwarded-For`: rejected until the project has an explicit trusted proxy model.
- Adding database-backed rate limiting immediately: rejected because security event persistence is planned as a separate milestone slice.
