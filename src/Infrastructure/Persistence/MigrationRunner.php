<?php

declare(strict_types=1);

namespace ModernAuthLab\Infrastructure\Persistence;

use PDO;
use Throwable;

/**
 * Executes pending migrations inside database transactions.
 *
 * A failed migration is rolled back and rethrown so startup cannot silently run
 * on a partially migrated schema.
 */
final readonly class MigrationRunner
{
    /**
     * @param PDO $pdo Configured SQLite connection.
     * @param MigrationRepository $repository Applied migration repository.
     * @param list<Migration> $migrations
     */
    public function __construct(
        private PDO $pdo,
        private MigrationRepository $repository,
        private array $migrations,
    ) {}

    /**
     * Apply each pending migration exactly once.
     *
     * @return void
     *
     * @throws \Throwable When migration SQL or metadata recording fails.
     */
    public function run(): void
    {
        $this->repository->ensureStorageExists();

        foreach ($this->migrations as $migration) {
            if ($this->repository->has($migration->version())) {
                continue;
            }

            $this->pdo->beginTransaction();

            try {
                $this->pdo->exec($migration->up());
                $this->repository->record($migration->version());
                $this->pdo->commit();
            } catch (Throwable $exception) {
                $this->pdo->rollBack();

                throw $exception;
            }
        }
    }
}
