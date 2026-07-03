# Agent Guidelines

This repository is a progressive security lab focused on modern web authentication with PHP, SQLite/libSQL, vanilla JavaScript, WebAuthn/Passkeys, TOTP, testing, coverage, mutation testing, and CI/CD.

The agent must work incrementally. Each step should be understandable, reviewable, and aligned with the current project stage.

## Priority Order

When priorities conflict, use this order:

1. Correctness
2. Architecture consistency
3. Tests
4. Simplicity
5. Performance
6. Token efficiency

Security-sensitive correctness includes authentication state, authorization, input validation, secret handling, session integrity, MFA challenge integrity, recovery behavior, and auditability.

## Core Principles

- Keep architecture and business logic clearly separated.
- Prefer explicit, readable code over clever abstractions.
- Preserve a professional, progressive, and maintainable structure.
- Introduce complexity only when it solves a real current problem.
- Explain important security and architecture decisions before or with implementation.
- Generate only the code required for the current validated step.
- Wait for validation before moving to the next project stage.

## Runtime Baseline

- Backend code targets PHP 8.5+.
- Do not lower the PHP baseline without an explicit decision record.
- Prefer the latest stable actively supported PHP runtime for new backend code.
- Tooling choices must remain compatible with the documented runtime baseline.

## Expected Agent Behavior

The agent must:

- Preserve strict conventions once established.
- Keep naming consistent with the existing codebase.
- Prefer minimal diffs.
- Make security assumptions explicit.
- Treat authentication, MFA, recovery, and trusted-device logic as security-sensitive.
- Protect user changes and never revert unrelated work.
- Keep explanations concise unless deeper teaching is requested.

The agent must not:

- Refactor unrelated files.
- Modify CI without request.
- Introduce dependencies without justification.
- Generate the entire application in one step.
- Add Laravel, Symfony, JWT, or SPA complexity at the initial stage.
- Hide security simplifications.
- Skip validation of security-critical inputs.
- Invent production behavior with mock implementations.

## Limits Of Responsibility

The agent is responsible for:

- Implementing the requested step with minimal, coherent changes.
- Maintaining architectural consistency.
- Highlighting security risks and tradeoffs.
- Adding or updating tests when behavior changes.
- Keeping the repository understandable for learning purposes.

The agent is not responsible for:

- Expanding scope beyond the current step.
- Replacing the agreed stack without request.
- Introducing large framework conventions prematurely.
- Optimizing for production scale before the learning model requires it.

## Workflow Rules

- Understand the existing files before editing.
- Make small, reviewable changes.
- Explain the objective of each step.
- Explain technical choices and security implications.
- Explain UX/security tradeoffs when relevant.
- Run relevant tests or checks when available.
- Report checks that could not be run.
- Do not continue to a new roadmap phase without explicit validation.
- For roadmap work, follow the Delivery Workflow before editing files.

## Pedagogical Documentation Workflow

Security-sensitive milestones such as TOTP, Passkeys/WebAuthn, MFA fallback, recovery, trusted devices, and security event handling must be treated as teaching material as well as implementation work.

For these milestones, the agent must:

- Explain the objective before implementation.
- Explain the security model, assets, trust boundaries, and threat assumptions.
- Explain where the work happens in the codebase before editing files.
- Break the work into small conceptual steps that the user can reproduce.
- Explain each important implementation step before moving to the next one.
- Add professional PHPDoc and meaningful comments for new security-sensitive code.
- Update project documentation with reusable technical explanations.
- Include reliable sources when useful, preferring primary standards and established security references.
- After each major concept or implementation block, ask the user whether the explanation is clear before continuing.
- Avoid moving to the next conceptual block until the user validates or asks to proceed.

Documentation created for these milestones should support future technical articles. It should capture not only what was implemented, but also why the design was chosen, what was deferred, and which security tradeoffs remain.

## Delivery Workflow

Default delivery flow for roadmap work:

1. Create a feature branch from up-to-date `main` before starting a new roadmap step.
2. Use focused branch names such as `feature/session-foundation`, `feature/sqlite-foundation`, or `docs/update-roadmap`.
3. Implement the smallest coherent change for the current step.
4. Add or update tests when behavior changes.
5. Run the relevant backend and frontend checks.
6. Commit with a clear conventional message.
7. Push the branch when requested.
8. Open a Pull Request when CI/review workflow is available or when the user asks for it.
9. CI must pass before merge once CI exists.
10. Merge only after validation.
11. Update `CHANGELOG.md` and release notes before tagging a release.
12. Tag a version only for validated release milestones.

Small exceptions:

- Tiny documentation fixes may be committed directly to `main` when explicitly approved.
- Emergency corrections may be committed directly to `main` when branching would add unnecessary overhead.
- Never create or move release tags without explicit validation.

## Release Notes Format

When the user asks for release content, use the current release note format unless they explicitly request another structure.

Release title format:

```text
vX.Y.Z - Short Milestone Title
```

Current release note format for future releases:

```md
## What changed

## Why it matters

## Notes

## Stability Statement

## Scope Clarification

## Operational Guidance
```

Optional sections:

- Include `Stability Statement` only when the release changes stability expectations, compatibility, runtime baseline, persistence, CI/CD, or security posture.
- Include `Scope Clarification` only when it helps distinguish delivered scope from deferred scope.
- Include `Operational Guidance` only when users need commands, migration steps, setup instructions, or deployment guidance.

Historical release note exception:

- `v0.1.0` used the initial foundation format:
  - short foundation release description
  - `Added`
  - `Verified`
  - `Not Included Yet`
  - `Notes`
- Do not rewrite historical release notes unless explicitly requested.

## Pull Request Format

When the user asks for Pull Request content, use this structure:

```md
## Scope

## Why

## Validation

## Out of Scope
```

Use `Scope` for the concrete changes included in the branch.

Use `Why` for the architectural, security, or workflow reason behind the change.

Use `Validation` for commands run, checks passed, and any checks that could not be run.

Use `Out of Scope` to clearly state what the branch intentionally does not implement.

## Project Commands

Use repository scripts before calling tools directly.

Backend commands:

- Install PHP dependencies: `composer install`
- Start backend dev server: `composer serve`
- Run backend tests: `composer test`
- Run backend coverage: `composer test:coverage`
- Run backend static analysis: `composer analyse`
- Check backend code style: `composer cs:check`
- Fix backend code style: `composer cs:fix`
- Create local development user: `composer seed:dev-user`

Frontend commands:

- Install frontend dependencies: `npm install`
- Start frontend dev server: `npm run dev`
- Build frontend assets: `npm run build`
- Run frontend tests: `npm test`
- Run frontend tests in watch mode: `npm run test:watch`
- Run frontend coverage: `npm run coverage`
- Run frontend lint: `npm run lint`
- Check frontend formatting: `npm run format`
- Fix frontend formatting: `npm run format:fix`

## Architecture Rules

- Separate HTTP concerns, application logic, persistence, validation, and presentation.
- Keep authentication flows explicit and traceable.
- Prefer services for domain workflows and repositories for persistence.
- Keep middleware focused on cross-cutting HTTP concerns.
- Avoid framework-style complexity until it is justified by the roadmap.
- Preserve a scalable structure without creating unused layers.
- Keep frontend modules small and purpose-driven.
- Keep security-sensitive code easy to audit.

## Scalable Structure Rules

- Start simple, but leave clear extension points.
- Prefer feature-oriented grouping only when it improves comprehension.
- Keep shared utilities small and stable.
- Avoid catch-all helper files.
- Keep security logs, rate limiting, MFA challenges, sessions, and trusted devices as distinct concepts.
- Design passkey lifecycle operations as auditable actions: creation, naming, use, last-used update, revocation, and recovery.

## Authentication State Rules

- Authentication flows must be modeled as explicit states.
- Do not represent partial authentication as a fully authenticated session.
- Password-verified, MFA-pending, trusted-device-verified, fallback-eligible, and fully-authenticated states must remain distinct.
- Fallback MFA access must require an explicit eligibility decision.
- Recovery and lost-device flows must not bypass MFA policy without an auditable security decision.
- Session rotation is required after privilege changes or successful completion of authentication.

## Threat Modeling Rules

- Identify the asset being protected before implementing security-sensitive behavior.
- State the attacker capability considered for authentication, MFA, recovery, and trusted-device flows.
- Document trust boundaries between browser, server, session store, database, external authenticators, and email or recovery channels when introduced.
- Prefer fail-closed behavior for uncertain authentication states.
- Revisit threat assumptions when adding passkeys, recovery, trusted devices, cross-device authentication, or fallback flows.
- Avoid security controls that cannot be explained, tested, or audited.

## Data Classification Rules

- Classify stored data as public, internal, sensitive, secret, or security-critical.
- Treat password hashes, TOTP secrets, recovery codes, WebAuthn credential material, trusted-device tokens, session identifiers, CSRF tokens, and MFA challenges as security-critical.
- Never expose security-critical values in logs, errors, fixtures, screenshots, frontend state, or documentation examples.
- Store only the minimum security context required for the implemented flow.
- Prefer derived, truncated, or hashed identifiers when full values are not required.

## Security Rules

- Never log API keys.
- Never expose secrets.
- Validate user input.
- Sanitize filesystem paths.
- Use secure session defaults.
- Prefer HttpOnly, Secure, and SameSite cookies where applicable.
- Rotate sessions after privilege changes.
- Expire authentication and WebAuthn challenges.
- Validate WebAuthn origin, RP ID, challenge, user presence, and user verification requirements.
- Track and evaluate WebAuthn signature counters when available.
- Rate-limit login, MFA, recovery, and fallback attempts.
- Treat TOTP fallback as controlled access, not a freely reachable bypass.
- Record security-relevant events for authentication decisions.
- Keep trusted-device rules explicit and revocable.

## Frontend Security Boundary

- Frontend code may improve UX but must not be trusted for authorization or authentication decisions.
- Server-side validation is required for all security-sensitive actions.
- WebAuthn browser results must be verified server-side.
- Client-side risk indicators are advisory only.
- Never place secrets, privileged decisions, or fallback eligibility in frontend-only state.

## Security Event Rules

- Security events must use stable event names.
- Events should include actor, target, outcome, reason, timestamp, request context, and risk signal when relevant.
- Do not log secrets, raw tokens, full TOTP codes, full credential IDs, recovery codes, or full session identifiers.
- Authentication failures should be observable without leaking account existence.
- Security logs must support investigation of passkey registration, passkey use, passkey revocation, fallback use, recovery attempts, and trusted-device changes.

## Privacy Rules

- Collect only the context needed for security decisions.
- Avoid storing raw high-entropy browser fingerprints.
- Prefer coarse, explainable risk signals over invasive fingerprinting.
- Define retention expectations for security logs and trusted-device metadata.
- Avoid storing raw IP history unless the current step explicitly justifies it.
- Make privacy/security tradeoffs explicit when device recognition or risk scoring is introduced.

## Testing Discipline

- Add tests close to the behavior being introduced.
- Prefer focused tests over broad, fragile tests.
- Keep tests readable as learning material.
- Cover security-sensitive edge cases.
- Use coverage as a signal, not as the only quality target.
- Use mutation testing to validate test strength when the project reaches that stage.
- Do not weaken tests to make implementation easier.
- Do not mark behavior as complete if the relevant checks fail.

## Decision Records

- Security, architecture, dependency, and workflow decisions must be documented when they affect future implementation.
- Prefer short ADR-style notes in `docs/decisions/` for non-trivial choices.
- Each decision should include context, decision, consequences, and rejected alternatives.
- Do not create decision records for obvious local implementation details.

## Code Modification Policy

- Prefer patch-style edits.
- Never rewrite entire files without explicit reason.
- Preserve existing architecture.
- Preserve naming consistency.
- Preserve public APIs unless requested.
- Keep changes scoped to the requested behavior.
- Avoid generated boilerplate that is not immediately used.
- Do not leave formatting-only changes in unrelated files.

## Dependency Policy

- Prefer the standard library first.
- Avoid adding dependencies unless justified.
- Every new dependency must provide clear value.
- Keep the project lightweight.
- Prefer mature, maintained packages for security-critical standards.
- Explain why a dependency is needed before adding it.
- Avoid dependencies that hide important project concepts too early.

## Error Handling Rules

- Never swallow exceptions silently.
- Raise explicit errors.
- Provide actionable error messages.
- Validate external API responses.
- Fail closed for security-sensitive flows.
- Avoid leaking secrets or sensitive state in errors.
- Log security events without exposing credentials, tokens, or recovery secrets.

## Performance Rules

- Avoid unnecessary filesystem reads.
- Avoid duplicate API calls.
- Prefer streaming for large files.
- Keep CLI startup lightweight.
- Avoid unnecessary database queries.
- Use indexes when persistence rules require lookup performance.
- Do not optimize prematurely at the expense of clarity.

## Token Efficiency

- Do not reread unchanged files.
- Prefer minimal diffs.
- Never output unchanged code.
- Avoid long explanations unless requested.
- Summarize before expanding.
- Read only files relevant to the task.
- Avoid scanning the entire repository unless required.
- Prefer targeted searches with `rg`.
- Reuse known context from the current step.

## Anti-Chaos Rules

- One roadmap step at a time.
- One clear purpose per change.
- No speculative abstractions.
- No unrelated formatting churn.
- No silent behavior changes.
- No hidden global state unless explicitly justified.
- No duplicated authentication logic across layers.
- No mixing persistence, HTTP rendering, and domain decisions in the same unit.

## Agent Output Format

For code changes, always provide:

1. Problem
2. Root cause
3. Minimal fix
4. Tests added
5. Optional improvements

If no tests are added, explain why.

## Forbidden Behaviors

- No speculative refactoring.
- No TODO placeholders without request.
- No commented dead code.
- No mock implementations in production code.
- No unrelated CI changes.
- No dependency additions without a clear reason.
- No broad rewrites for narrow requests.
- No weakening security checks for convenience.
- No hiding unfinished behavior behind vague comments.
