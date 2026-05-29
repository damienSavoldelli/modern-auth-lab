<?php

declare(strict_types=1);

namespace ModernAuthLab\Infrastructure\Persistence;

use PDO;

final readonly class MigrationRepository
{
    public function __construct(
        private PDO $pdo,
    ) {}

    public function ensureStorageExists(): void
    {
        $this->pdo->exec(<<<'SQL'
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version TEXT PRIMARY KEY,
                applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            SQL);
    }

    public function has(string $version): bool
    {
        $statement = $this->pdo->prepare('SELECT 1 FROM schema_migrations WHERE version = :version');
        $statement->execute(['version' => $version]);

        return $statement->fetchColumn() !== false;
    }

    public function record(string $version): void
    {
        $statement = $this->pdo->prepare('INSERT INTO schema_migrations (version) VALUES (:version)');
        $statement->execute(['version' => $version]);
    }

    /**
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
