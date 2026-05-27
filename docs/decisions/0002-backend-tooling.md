# 0002: Backend Tooling

## Context

The project needs a minimal PHP backend foundation before implementing authentication behavior.

The backend must stay readable and framework-free at the beginning, while still supporting tests, static analysis, and code style checks.

## Decision

Use Composer as the backend package manager and project command entry point.

Initial backend tooling:

- PHP 8.5+.
- PSR-4 autoloading with the `ModernAuthLab\` namespace.
- PHPUnit 12 for tests.
- PHPStan 2.x for static analysis.
- PHP CS Fixer 3.x for formatting.
- SQLite support through PDO extensions.

PHP 8.5 is the minimum runtime because the project intentionally targets the latest stable actively supported PHP branch for new backend code.

PHPUnit 12 is used because the project baseline satisfies its PHP requirement.

## Consequences

- Backend code can be tested from the beginning.
- Static analysis starts early and can be tightened progressively.
- Formatting rules are explicit and automated.
- Composer scripts become the preferred command interface.
- The project requires PHP and Composer to be available locally before checks can run.

## Rejected Alternatives

- No backend tooling yet: rejected because early tests and conventions reduce future drift.
- PHP 8.3 as the baseline: rejected because it is already in security-only support.
- PHP 8.4 as the baseline: rejected because the project now chooses the latest stable branch instead of a compatibility baseline.
- Pest at the beginning: rejected because PHPUnit keeps the initial testing layer closer to standard PHP tooling.
- Laravel Pint: rejected because PHP CS Fixer keeps style configuration explicit without introducing Laravel conventions.
