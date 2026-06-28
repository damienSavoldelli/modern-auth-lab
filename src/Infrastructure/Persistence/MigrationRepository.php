<?php

declare(strict_types=1);

namespace ModernAuthLab\Infrastructure\Persistence;

use PDO;

/**
 * Persists and queries applied migration versions.
 *
 * The repository owns only migration metadata. It does not execute schema SQL;
 * that responsibility belongs to MigrationRunner.
 */
final readonly class MigrationRepository
{
    /**
     * Receive the PDO connection that stores migration metadata.
     */
    public function __construct(
        private PDO $pdo,
    ) {}

    /**
     * Create the migration tracking table if it does not exist.
     */
    public function ensureStorageExists(): void
    {
        $this->pdo->exec(<<<'SQL'
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version TEXT PRIMARY KEY,
                applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            SQL);
    }

    /**
     * Check whether a migration version has already been applied.
     */
    public function has(string $version): bool
    {
        $statement = $this->pdo->prepare('SELECT 1 FROM schema_migrations WHERE version = :version');
        $statement->execute(['version' => $version]);

        return $statement->fetchColumn() !== false;
    }

    /**
     * Mark a migration version as applied.
     */
    public function record(string $version): void
    {
        $statement = $this->pdo->prepare('INSERT INTO schema_migrations (version) VALUES (:version)');
        $statement->execute(['version' => $version]);
    }

    /**
     * Return applied migration versions in deterministic order.
     *
     * @return list<string>
     */
    public function all(): array
    {
        $statement = $this->pdo->query('SELECT version FROM schema_migrations ORDER BY version ASC');

        if ($statement === false) {
            return [];
        }

        /** @var list<string> $versions */
        $versions = $statement->fetchAll(PDO::FETCH_COLUMN);

        return $versions;
    }
}
