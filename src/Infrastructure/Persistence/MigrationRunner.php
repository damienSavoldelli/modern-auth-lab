<?php

declare(strict_types=1);

namespace ModernAuthLab\Infrastructure\Persistence;

use PDO;
use Throwable;

final readonly class MigrationRunner
{
    /**
     * @param list<Migration> $migrations
     */
    public function __construct(
        private PDO $pdo,
        private MigrationRepository $repository,
        private array $migrations,
    ) {}

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
