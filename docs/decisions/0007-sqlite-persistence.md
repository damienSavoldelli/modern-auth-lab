# 0007: SQLite Persistence

## Context

The project needs local persistence before user accounts, password authentication, TOTP, Passkeys, trusted devices, or recovery flows can be implemented.

Persistence should start with a local, deterministic, testable SQLite setup before introducing libSQL or remote database concerns.

## Decision

Use SQLite through PDO as the first persistence runtime.

Introduce:

- `DatabaseConfig`
- `SqliteConnectionFactory`
- `Migration`
- `MigrationRepository`
- `MigrationRunner`
- `CreateSchemaMigrationsTable`

Local runtime database files live under:

```text
var/data/
```

Runtime files under `var/` are ignored by Git, while `.gitkeep` files preserve the directory structure.

The first migration concern is only migration tracking through `schema_migrations`. Domain tables are intentionally deferred.

## Consequences

- Persistence can be tested locally without external services.
- Migrations become explicit before domain tables are introduced.
- Future repositories can share a single PDO connection boundary.
- libSQL compatibility remains possible once the persistence contract is stable.

## Rejected Alternatives

- Adding user tables immediately: rejected because this milestone focuses on persistence mechanics, not authentication domain modeling.
- Introducing libSQL immediately: rejected because remote database behavior adds secrets, network failure modes, and deployment concerns too early.
- Using an ORM immediately: rejected because direct PDO keeps the storage model visible and testable at this stage.
